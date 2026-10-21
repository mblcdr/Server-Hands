//! HPKE (RFC 9180) base mode: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305.
//! Plus the binary plaintext format for passphrases.

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use zeroize::Zeroizing;

use crate::codec::{lp, sha256};
use crate::error::{Error, Result};
use crate::Passphrase;

type K = X25519HkdfSha256;

pub const PLAINTEXT_VERSION: u8 = 1;
pub const PAD_TO: usize = 256;
pub const MAX_PW_LEN: usize = 1024;
pub const MAX_ENTRIES: usize = 32;

pub fn gen_ephemeral() -> (Zeroizing<Vec<u8>>, Vec<u8>) {
    let (sk, pk) = K::gen_keypair();
    (
        Zeroizing::new(sk.to_bytes().to_vec()),
        pk.to_bytes().to_vec(),
    )
}

/// Deterministic keypair for test vectors only.
pub fn ephemeral_from_ikm(ikm: &[u8]) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
    let (sk, pk) = K::derive_keypair(ikm);
    (
        Zeroizing::new(sk.to_bytes().to_vec()),
        pk.to_bytes().to_vec(),
    )
}

pub fn hpke_info(
    server_pub: &[u8; 32],
    req_id: &[u8; 16],
    client_nonce: &[u8; 32],
    device_id: &[u8; 16],
) -> Vec<u8> {
    lp(&[
        b"hands/v1/hpke",
        &sha256(server_pub),
        req_id,
        client_nonce,
        device_id,
    ])
}

/// AAD = length-prefixed, strictly ascending list of raw 16-byte LUKS UUIDs.
pub fn hpke_aad(uuids: &[[u8; 16]]) -> Result<Vec<u8>> {
    if uuids.windows(2).any(|w| w[0] >= w[1]) {
        return Err(Error);
    }
    let fields: Vec<&[u8]> = uuids.iter().map(|u| u.as_slice()).collect();
    Ok(lp(&fields))
}

/// Returns `(enc, ciphertext || tag)`.
pub fn seal(
    eph_pub: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let pk = <K as hpke::Kem>::PublicKey::from_bytes(eph_pub).map_err(|_| Error)?;
    let (enc, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, K>(
        &OpModeS::Base,
        &pk,
        info,
        plaintext,
        aad,
    )
    .map_err(|_| Error)?;
    Ok((enc.to_bytes().to_vec(), ct))
}

pub fn open(
    eph_priv: &[u8],
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let sk = <K as hpke::Kem>::PrivateKey::from_bytes(eph_priv).map_err(|_| Error)?;
    let enc = <K as hpke::Kem>::EncappedKey::from_bytes(enc).map_err(|_| Error)?;
    let pt = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, K>(
        &OpModeR::Base,
        &sk,
        &enc,
        info,
        ct,
        aad,
    )
    .map_err(|_| Error)?;
    Ok(Zeroizing::new(pt))
}

/// `version(1) || count(1) || count x (uuid[16] || len_be16 || pw) || zero padding to a multiple of 256`.
/// Entries must be strictly ascending by uuid.
pub fn encode_plaintext(entries: &[([u8; 16], &[u8])]) -> Result<Zeroizing<Vec<u8>>> {
    if entries.is_empty()
        || entries.len() > MAX_ENTRIES
        || entries.windows(2).any(|w| w[0].0 >= w[1].0)
        || entries
            .iter()
            .any(|(_, p)| p.is_empty() || p.len() > MAX_PW_LEN)
    {
        return Err(Error);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(PAD_TO));
    out.push(PLAINTEXT_VERSION);
    out.push(entries.len() as u8);
    for (u, p) in entries {
        out.extend_from_slice(u);
        out.extend_from_slice(&(p.len() as u16).to_be_bytes());
        out.extend_from_slice(p);
    }
    let padded = out.len().div_ceil(PAD_TO) * PAD_TO;
    out.resize(padded, 0);
    Ok(out)
}

pub fn decode_plaintext(buf: &[u8]) -> Result<Vec<([u8; 16], Passphrase)>> {
    let mut i = 0usize;
    let take = |i: &mut usize, n: usize| -> Result<&[u8]> {
        let s = buf.get(*i..*i + n).ok_or(Error)?;
        *i += n;
        Ok(s)
    };
    if take(&mut i, 1)?[0] != PLAINTEXT_VERSION {
        return Err(Error);
    }
    let count = take(&mut i, 1)?[0] as usize;
    if count == 0 || count > MAX_ENTRIES || !buf.len().is_multiple_of(PAD_TO) {
        return Err(Error);
    }
    let mut out: Vec<([u8; 16], Passphrase)> = Vec::with_capacity(count);
    for _ in 0..count {
        let uuid: [u8; 16] = take(&mut i, 16)?.try_into().unwrap();
        let len = u16::from_be_bytes(take(&mut i, 2)?.try_into().unwrap()) as usize;
        if len == 0 || len > MAX_PW_LEN {
            return Err(Error);
        }
        if let Some((prev, _)) = out.last() {
            if *prev >= uuid {
                return Err(Error);
            }
        }
        out.push((uuid, Passphrase::from_bytes(take(&mut i, len)?.to_vec())));
    }
    if buf[i..].iter().any(|b| *b != 0) {
        return Err(Error);
    }
    Ok(out)
}

/// 6-digit short authentication string shown on both ends during pairing.
pub fn sas(server_pub: &[u8], device_spki: &[u8], token: &[u8]) -> String {
    let h = sha256(
        &[
            b"hands/v1/sas".as_slice(),
            &lp(&[server_pub, device_spki, token]),
        ]
        .concat(),
    );
    let n = u32::from_be_bytes(h[..4].try_into().unwrap()) % 1_000_000;
    format!("{n:06}")
}
