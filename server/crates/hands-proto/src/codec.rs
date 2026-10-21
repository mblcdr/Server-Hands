use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

pub fn b64e(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64d(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).map_err(|_| Error)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Length-prefixed concatenation: each field is `u32be len || bytes`. Unambiguous by construction.
pub fn lp(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(fields.iter().map(|f| f.len() + 4).sum());
    for f in fields {
        out.extend_from_slice(&(f.len() as u32).to_be_bytes());
        out.extend_from_slice(f);
    }
    out
}

/// `domain_label || 0x00 || body`: the exact bytes that get signed.
pub fn signed_bytes(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + 1 + body.len());
    out.extend_from_slice(domain);
    out.push(0);
    out.extend_from_slice(body);
    out
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return Err(Error);
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| Error))
        .collect()
}

/// Parses a hyphenated textual UUID (8-4-4-4-12) into raw bytes.
pub fn uuid_parse(text: &str) -> Result<[u8; 16]> {
    let b = text.as_bytes();
    if b.len() != 36 || [8, 13, 18, 23].iter().any(|&i| b[i] != b'-') {
        return Err(Error);
    }
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    hex_decode(&hex)?.try_into().map_err(|_| Error)
}

pub fn uuid_format(raw: &[u8; 16]) -> String {
    let h = hex_encode(raw);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}
