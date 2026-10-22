//! Signatures. Server: Ed25519 (raw 64-byte). Device: ECDSA P-256/SHA-256, DER signature,
//! public key as X.509 SubjectPublicKeyInfo DER (what Android's Keystore produces).

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use p256::ecdsa::{DerSignature, VerifyingKey as P256Verifying};
use p256::pkcs8::DecodePublicKey;

use crate::codec::{b64d, b64e, lp, sha256, signed_bytes};
use crate::error::{Error, Result};
use crate::{Envelope, DOMAIN_APPROVE, DOMAIN_SCRIPT_APPROVE};

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

/// The exact bytes the approval key signs (after a biometric) to authorise one run of one script.
/// Bound to the server, the device, the script and a challenge the server issued for exactly this.
pub fn script_approve_message(
    server_pub: &[u8; 32],
    device_id: &[u8; 16],
    script: &str,
    challenge: &[u8; 32],
) -> Vec<u8> {
    signed_bytes(
        DOMAIN_SCRIPT_APPROVE,
        &lp(&[server_pub, device_id, script.as_bytes(), challenge]),
    )
}

/// Verify a device signature (DER) over `message` with the device's SPKI DER public key.
pub fn device_verify(spki_der: &[u8], message: &[u8], sig_der: &[u8]) -> Result<()> {
    use p256::ecdsa::signature::Verifier;
    let vk = P256Verifying::from_public_key_der(spki_der).map_err(|_| Error)?;
    let sig = DerSignature::try_from(sig_der).map_err(|_| Error)?;
    vk.verify(message, &sig).map_err(|_| Error)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same bytes as `ScriptApproveMessageTest` in the Kotlin client: both sides must build this identically.
    #[test]
    fn script_approve_message_layout_is_pinned() {
        let m = script_approve_message(&[1; 32], &[2; 16], "bio", &[3; 32]);
        assert_eq!(
            crate::codec::hex_encode(&m),
            "68616e64732f76312f7363726970742d617070726f76650000000020010101010101010101010101010101010101010101010101010101010101010100000010020202020202020202020202020202020000000362696f000000200303030303030303030303030303030303030303030303030303030303030303"
        );
    }
}
