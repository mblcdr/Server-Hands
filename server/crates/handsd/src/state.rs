//! Request/nonce/device state with injectable time. All secrets are `Zeroizing`/`Passphrase`.

use std::collections::HashMap;

use hands_proto::seal::{decode_plaintext, hpke_aad, hpke_info, open};
use hands_proto::sign::{approve_message, device_verify};
use hands_proto::{DriveInfo, Passphrase};
use zeroize::Zeroizing;

pub const NONCE_WINDOW_SECS: u64 = 120;
pub const FAIL_LIMIT: usize = 5;
pub const FAIL_WINDOW_SECS: u64 = 600;
pub const LOCKOUT_SECS: u64 = 300;

/// `(req_id, expires_at, eph_pub, drives)`
pub type PendingView = ([u8; 16], u64, Vec<u8>, Vec<DriveInfo>);

pub trait Clock {
    fn now(&self) -> u64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Why an approval was refused. Internal only: the wire reply collapses these (see `wire_code`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    UnknownDevice,
    UnknownRequest,
    Expired,
    AlreadyConsumed,
    NonceUnknownOrReplayed,
    NonceStale,
    BadSignature,
    BadCiphertext,
    DriveMismatch,
    RateLimited,
}

impl Refusal {
    /// Constant-shape wire error code: callers cannot distinguish unknown device from bad signature.
    pub fn wire_code(self) -> &'static str {
        match self {
            Refusal::Expired => "expired",
            Refusal::AlreadyConsumed | Refusal::NonceUnknownOrReplayed | Refusal::NonceStale => {
                "replayed"
            }
            Refusal::RateLimited => "rate_limited",
            _ => "unauthorized",
        }
    }
}

struct Request {
    expires_at: u64,
    drives: Vec<DriveInfo>,
    eph_pub: Vec<u8>,
    eph_priv: Option<Zeroizing<Vec<u8>>>, // None once consumed
}

struct Nonce {
    device: [u8; 16],
    seen_at: u64,
    used: bool,
}

#[derive(Default)]
struct Failures {
    times: Vec<u64>,
    locked_until: u64,
}

pub struct State<C: Clock> {
    clock: C,
    server_pub: [u8; 32],
    requests: HashMap<[u8; 16], Request>,
    nonces: HashMap<[u8; 32], Nonce>,
    devices: HashMap<[u8; 16], Vec<u8>>, // device_id -> SPKI DER
    failures: HashMap<[u8; 16], Failures>,
}

impl<C: Clock> State<C> {
    pub fn new(clock: C, server_pub: [u8; 32]) -> Self {
        Self {
            clock,
            server_pub,
            requests: HashMap::new(),
            nonces: HashMap::new(),
            devices: HashMap::new(),
            failures: HashMap::new(),
        }
    }

    pub fn add_device(&mut self, spki: Vec<u8>) -> [u8; 16] {
        let id = hands_proto::sign::device_id(&spki);
        self.devices.insert(id, spki);
        id
    }

    pub fn revoke_device(&mut self, id: &[u8; 16]) -> bool {
        self.devices.remove(id).is_some()
    }

    pub fn device_spki(&self, id: &[u8; 16]) -> Option<&[u8]> {
        self.devices.get(id).map(|v| v.as_slice())
    }

    pub fn now(&self) -> u64 {
        self.clock.now()
    }

    /// Counts a wrong passphrase against the device (the signature was fine, the drive refused).
    pub fn record_bad_passphrase(&mut self, device: &[u8; 16]) {
        let now = self.clock.now();
        self.record_failure(device, now);
    }

    /// Creates a pending request with a fresh ephemeral key held only in memory.
    pub fn create_request(
        &mut self,
        req_id: [u8; 16],
        drives: Vec<DriveInfo>,
        ttl_secs: u64,
    ) -> Vec<u8> {
        let (priv_key, pub_key) = hands_proto::seal::gen_ephemeral();
        let now = self.clock.now();
        self.requests.insert(
            req_id,
            Request {
                expires_at: now + ttl_secs,
                drives,
                eph_pub: pub_key.clone(),
                eph_priv: Some(priv_key),
            },
        );
        pub_key
    }

    /// Called when a paired device lists requests. Records its nonce for one later approval.
    pub fn register_nonce(
        &mut self,
        device: &[u8; 16],
        nonce: [u8; 32],
        ts: u64,
    ) -> Result<(), Refusal> {
        let now = self.clock.now();
        self.prune(now);
        if !self.devices.contains_key(device) {
            return Err(Refusal::UnknownDevice);
        }
        self.check_lockout(device, now)?;
        if now.abs_diff(ts) > NONCE_WINDOW_SECS {
            return Err(Refusal::NonceStale);
        }
        if self.nonces.contains_key(&nonce) {
            return Err(Refusal::NonceUnknownOrReplayed);
        }
        self.nonces.insert(
            nonce,
            Nonce {
                device: *device,
                seen_at: now,
                used: false,
            },
        );
        Ok(())
    }

    /// Pending, unexpired requests as (req_id, eph_pub, drives).
    pub fn pending(&self) -> Vec<([u8; 16], Vec<u8>, Vec<DriveInfo>)> {
        let now = self.clock.now();
        self.requests
            .iter()
            .filter(|(_, r)| r.eph_priv.is_some() && r.expires_at > now)
            .map(|(id, r)| (*id, r.eph_pub.clone(), r.drives.clone()))
            .collect()
    }

    /// Pending, unexpired requests as (req_id, expires_at, eph_pub, drives).
    pub fn pending_views(&self) -> Vec<PendingView> {
        let now = self.clock.now();
        let mut v: Vec<_> = self
            .requests
            .iter()
            .filter(|(_, r)| r.eph_priv.is_some() && r.expires_at > now)
            .map(|(id, r)| (*id, r.expires_at, r.eph_pub.clone(), r.drives.clone()))
            .collect();
        v.sort_by_key(|(_, exp, _, _)| *exp);
        v
    }

    /// Drops every pending request (their ephemeral keys are zeroized), e.g. before re-enumerating drives.
    pub fn clear_pending(&mut self) {
        self.requests.retain(|_, r| r.eph_priv.is_none());
    }

    /// Full approve path. On success returns the (uuid, passphrase) pairs; the ephemeral key is destroyed
    /// as soon as the signature and nonce have been accepted, whether or not decryption then succeeds.
    #[allow(clippy::too_many_arguments)]
    pub fn approve(
        &mut self,
        device: &[u8; 16],
        req_id: &[u8; 16],
        client_nonce: &[u8; 32],
        enc: &[u8],
        ct: &[u8],
        sig_der: &[u8],
        aad_uuids: &[[u8; 16]],
    ) -> Result<Vec<([u8; 16], Passphrase)>, Refusal> {
        let now = self.clock.now();
        self.prune(now);
        let result = self.approve_inner(
            now,
            device,
            req_id,
            client_nonce,
            enc,
            ct,
            sig_der,
            aad_uuids,
        );
        if let Err(e) = result {
            if matches!(
                e,
                Refusal::BadSignature
                    | Refusal::BadCiphertext
                    | Refusal::DriveMismatch
                    | Refusal::UnknownDevice
            ) {
                self.record_failure(device, now);
            }
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn approve_inner(
        &mut self,
        now: u64,
        device: &[u8; 16],
        req_id: &[u8; 16],
        client_nonce: &[u8; 32],
        enc: &[u8],
        ct: &[u8],
        sig_der: &[u8],
        aad_uuids: &[[u8; 16]],
    ) -> Result<Vec<([u8; 16], Passphrase)>, Refusal> {
        let spki = self
            .devices
            .get(device)
            .ok_or(Refusal::UnknownDevice)?
            .clone();
        self.check_lockout(device, now)?;

        let req = self
            .requests
            .get_mut(req_id)
            .ok_or(Refusal::UnknownRequest)?;
        if req.eph_priv.is_none() {
            return Err(Refusal::AlreadyConsumed);
        }
        if req.expires_at <= now {
            return Err(Refusal::Expired);
        }

        let n = self
            .nonces
            .get_mut(client_nonce)
            .ok_or(Refusal::NonceUnknownOrReplayed)?;
        if n.device != *device || n.used {
            return Err(Refusal::NonceUnknownOrReplayed);
        }
        if now.saturating_sub(n.seen_at) > NONCE_WINDOW_SECS {
            return Err(Refusal::NonceStale);
        }

        let aad = hpke_aad(aad_uuids).map_err(|_| Refusal::DriveMismatch)?;
        let msg = approve_message(req_id, client_nonce, enc, ct, &aad);
        device_verify(&spki, &msg, sig_der).map_err(|_| Refusal::BadSignature)?;

        // Signature good: burn the nonce and the ephemeral key now, no matter what happens next.
        n.used = true;
        let eph_priv = req.eph_priv.take().ok_or(Refusal::AlreadyConsumed)?;

        let info = hpke_info(&self.server_pub, req_id, client_nonce, device);
        let pt = open(&eph_priv, enc, &info, &aad, ct).map_err(|_| Refusal::BadCiphertext)?;
        drop(eph_priv);
        let entries = decode_plaintext(&pt).map_err(|_| Refusal::BadCiphertext)?;

        // The sealed set must equal the AAD set and be a subset of what this request asked for.
        let same_set = entries.len() == aad_uuids.len()
            && entries.iter().zip(aad_uuids).all(|((u, _), a)| u == a);
        let allowed = entries
            .iter()
            .all(|(u, _)| req.drives.iter().any(|d| uuid_matches(&d.luks_uuid, u)));
        if !same_set || !allowed {
            return Err(Refusal::DriveMismatch);
        }
        Ok(entries)
    }

    fn check_lockout(&self, device: &[u8; 16], now: u64) -> Result<(), Refusal> {
        match self.failures.get(device) {
            Some(f) if f.locked_until > now => Err(Refusal::RateLimited),
            _ => Ok(()),
        }
    }

    fn record_failure(&mut self, device: &[u8; 16], now: u64) {
        let f = self.failures.entry(*device).or_default();
        f.times
            .retain(|t| now.saturating_sub(*t) <= FAIL_WINDOW_SECS);
        f.times.push(now);
        if f.times.len() >= FAIL_LIMIT {
            f.locked_until = now + LOCKOUT_SECS;
            f.times.clear();
        }
    }

    fn prune(&mut self, now: u64) {
        self.nonces
            .retain(|_, n| now.saturating_sub(n.seen_at) <= NONCE_WINDOW_SECS * 2);
        self.requests.retain(|_, r| r.expires_at + 3600 > now);
    }
}

/// Compares a textual LUKS UUID (hyphenated) with raw bytes.
fn uuid_matches(text: &str, raw: &[u8; 16]) -> bool {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    hex.len() == 32
        && (0..16).all(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok() == Some(raw[i]))
}
