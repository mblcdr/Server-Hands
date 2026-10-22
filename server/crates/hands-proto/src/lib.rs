//! Wire types and secret handling for the Server Hands protocol (see docs/protocol.md).
//! Crypto (HPKE, Ed25519, P-256) is added in Phase 1 against the shared test vectors.

pub mod codec;
pub mod error;
pub mod seal;
pub mod sign;
pub mod wire;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Raw passphrase bytes. Deliberately has no `Debug`, `Display`, `Clone` or `Serialize`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Passphrase(Vec<u8>);

impl Passphrase {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriveInfo {
    pub luks_uuid: String,
    pub label: String,
    pub size: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    /// base64url of the exact signed body bytes
    pub body: String,
    /// base64url signature over `domain_label || 0x00 || body_bytes`
    pub sig: String,
}

pub const DOMAIN_SERVER_REPLY: &[u8] = b"hands/v1/server-reply";
pub const DOMAIN_DEVICE_REQUEST: &[u8] = b"hands/v1/device-request";
pub const DOMAIN_APPROVE: &[u8] = b"hands/v1/approve";
pub const DOMAIN_PAIR: &[u8] = b"hands/v1/pair";
pub const DOMAIN_SCRIPT_APPROVE: &[u8] = b"hands/v1/script-approve";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_exposes_bytes() {
        let p = Passphrase::from_bytes(b"x".to_vec());
        assert_eq!(p.expose(), b"x");
    }
}
