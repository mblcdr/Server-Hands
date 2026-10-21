//! Signatures. Server: Ed25519 (raw 64-byte). Device: ECDSA P-256/SHA-256, DER signature,
//! public key as X.509 SubjectPublicKeyInfo DER (what Android's Keystore produces).

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use p256::ecdsa::{DerSignature, VerifyingKey as P256Verifying};
use p256::pkcs8::DecodePublicKey;

use crate::codec::{b64d, b64e, lp, sha256, signed_bytes};
use crate::error::{Error, Result};
use crate::{Envelope, DOMAIN_APPROVE};

pub fn server_sign(sk: &SigningKey, domain: &[u8], body: &[u8]) -> Envelope {
    let sig = sk.sign(&signed_bytes(domain, body));
    Envelope {
        body: b64e(body),
        sig: b64e(&sig.to_bytes()),
    }
}

/// Verifies the envelope and only then returns the body bytes for parsing.
pub fn server_verify(pk: &[u8], domain: &[u8], env: &Envelope) -> Result<Vec<u8>> {
    let pk: [u8; 32] = pk.try_into().map_err(|_| Error)?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| Error)?;
    let body = b64d(&env.body)?;
    let sig: [u8; 64] = b64d(&env.sig)?.try_into().map_err(|_| Error)?;
    vk.verify_strict(&signed_bytes(domain, &body), &Signature::from_bytes(&sig))
        .map_err(|_| Error)?;
    Ok(body)
}

pub fn device_id(spki_der: &[u8]) -> [u8; 16] {
    let h = sha256(spki_der);
    h[..16].try_into().unwrap()
}

/// The exact bytes the device signs when approving a request.
pub fn approve_message(
    req_id: &[u8; 16],
    client_nonce: &[u8; 32],
    enc: &[u8],
    ct: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let body = lp(&[req_id, client_nonce, enc, &sha256(ct), aad]);
    signed_bytes(DOMAIN_APPROVE, &body)
}

/// Verify a device signature (DER) over `message` with the device's SPKI DER public key.
pub fn device_verify(spki_der: &[u8], message: &[u8], sig_der: &[u8]) -> Result<()> {
    use p256::ecdsa::signature::Verifier;
    let vk = P256Verifying::from_public_key_der(spki_der).map_err(|_| Error)?;
    let sig = DerSignature::try_from(sig_der).map_err(|_| Error)?;
    vk.verify(message, &sig).map_err(|_| Error)
}
