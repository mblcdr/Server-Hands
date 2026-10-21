use std::cell::Cell;
use std::rc::Rc;

use ed25519_dalek::SigningKey;
use hands_proto::seal::*;
use hands_proto::sign::{approve_message, device_id};
use hands_proto::DriveInfo;
use handsd::state::*;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey as DevKey};
use p256::pkcs8::EncodePublicKey;

#[derive(Clone)]
struct FakeClock(Rc<Cell<u64>>);
impl Clock for FakeClock {
    fn now(&self) -> u64 {
        self.0.get()
    }
}

const U1: [u8; 16] = [
    0x56, 0xc8, 0x65, 0x2e, 0x7d, 0xf0, 0x42, 0x16, 0xb3, 0x18, 0x17, 0x8b, 0x62, 0x61, 0x96, 0x93,
];
const U2: [u8; 16] = [
    0x67, 0x4b, 0x16, 0x86, 0x3f, 0x1b, 0x4b, 0x99, 0x8b, 0x75, 0x7e, 0xb8, 0xd7, 0xd7, 0x4a, 0xaa,
];
const REQ: [u8; 16] = [0x11; 16];
const NONCE: [u8; 32] = [0x22; 32];

fn drive(u: &[u8; 16], label: &str) -> DriveInfo {
    let h = hex_lower(u);
    DriveInfo {
        luks_uuid: format!(
            "{}-{}-{}-{}-{}",
            &h[0..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..32]
        ),
        label: label.into(),
        size: 1,
    }
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct Rig {
    st: State<FakeClock>,
    now: Rc<Cell<u64>>,
    server_pub: [u8; 32],
    dev: DevKey,
    dev_id: [u8; 16],
    eph_pub: Vec<u8>,
}

impl Rig {
    fn new() -> Self {
        let now = Rc::new(Cell::new(1_000_000));
        let server_pub = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes();
        let mut st = State::new(FakeClock(now.clone()), server_pub);
        let dev = DevKey::from_bytes(&[7u8; 32].into()).unwrap();
        let spki = dev
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let dev_id = st.add_device(spki);
        let eph_pub = st.create_request(REQ, vec![drive(&U1, "Disk-1"), drive(&U2, "Disk-2")], 600);
        st.register_nonce(&dev_id, NONCE, now.get()).unwrap();
        Rig {
            st,
            now,
            server_pub,
            dev,
            dev_id,
            eph_pub,
        }
    }

    /// A well-formed approval for the given drives, signed by `signer`, sealed with `server_pub_in_info`.
    fn build(
        &self,
        signer: &DevKey,
        server_pub_in_info: &[u8; 32],
        drives: &[([u8; 16], &[u8])],
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<[u8; 16]>) {
        let uuids: Vec<[u8; 16]> = drives.iter().map(|d| d.0).collect();
        let aad = hpke_aad(&uuids).unwrap();
        let info = hpke_info(server_pub_in_info, &REQ, &NONCE, &self.dev_id);
        let pt = encode_plaintext(drives).unwrap();
        let (enc, ct) = seal(&self.eph_pub, &info, &aad, &pt).unwrap();
        let sig: DerSignature = signer.sign(&approve_message(&REQ, &NONCE, &enc, &ct, &aad));
        (enc, ct, sig.as_bytes().to_vec(), uuids)
    }

    fn good(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<[u8; 16]>) {
        self.build(
            &self.dev,
            &self.server_pub,
            &[(U1, b"pw-one"), (U2, b"pw-two")],
        )
    }

    fn approve(
        &mut self,
        m: &(Vec<u8>, Vec<u8>, Vec<u8>, Vec<[u8; 16]>),
    ) -> Result<usize, Refusal> {
        let id = self.dev_id;
        self.st
            .approve(&id, &REQ, &NONCE, &m.0, &m.1, &m.2, &m.3)
            .map(|e| {
                assert_eq!(e[0].1.expose(), b"pw-one");
                e.len()
            })
    }
}

#[test]
fn happy_path() {
    let mut r = Rig::new();
    let m = r.good();
    assert_eq!(r.approve(&m), Ok(2));
}

#[test]
fn replay_of_a_valid_approval_is_refused() {
    let mut r = Rig::new();
    let m = r.good();
    r.approve(&m).unwrap();
    assert_eq!(r.approve(&m), Err(Refusal::AlreadyConsumed));
}

#[test]
fn replay_with_a_new_request_but_old_nonce_is_refused() {
    let mut r = Rig::new();
    let m = r.good();
    r.approve(&m).unwrap();
    r.st.create_request([0x12; 16], vec![drive(&U1, "Disk-1")], 600);
    let id = r.dev_id;
    let res =
        r.st.approve(&id, &[0x12; 16], &NONCE, &m.0, &m.1, &m.2, &m.3);
    assert_eq!(res.err(), Some(Refusal::NonceUnknownOrReplayed));
}

#[test]
fn expired_request_is_refused() {
    let mut r = Rig::new();
    let m = r.good();
    r.now.set(r.now.get() + 601);
    // nonce is also stale by now; either way nothing is accepted, and expiry is reported first
    assert_eq!(r.approve(&m), Err(Refusal::Expired));
}

#[test]
fn stale_nonce_is_refused() {
    let mut r = Rig::new();
    let m = r.good();
    r.now.set(r.now.get() + NONCE_WINDOW_SECS + 1);
    assert_eq!(r.approve(&m), Err(Refusal::NonceStale));
}

#[test]
fn nonce_must_be_registered_by_the_same_device() {
    let mut r = Rig::new();
    let m = r.good();
    let other = DevKey::from_bytes(&[8u8; 32].into()).unwrap();
    let other_id = r.st.add_device(
        other
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec(),
    );
    assert_eq!(
        device_id(
            other
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes()
        ),
        other_id
    );
    let res =
        r.st.approve(&other_id, &REQ, &NONCE, &m.0, &m.1, &m.2, &m.3);
    assert_eq!(res.err(), Some(Refusal::NonceUnknownOrReplayed));
    // the legitimate device can still complete afterwards
    assert_eq!(r.approve(&m), Ok(2));
}

#[test]
fn unknown_device_is_refused_and_indistinguishable_on_the_wire_from_bad_signature() {
    let mut r = Rig::new();
    let m = r.good();
    let ghost = [0x77; 16];
    let a =
        r.st.approve(&ghost, &REQ, &NONCE, &m.0, &m.1, &m.2, &m.3)
            .err()
            .unwrap();
    let forged = r.build(
        &DevKey::from_bytes(&[9u8; 32].into()).unwrap(),
        &r.server_pub,
        &[(U1, b"pw-one"), (U2, b"pw-two")],
    );
    let b = r.approve(&forged).err().unwrap();
    assert_eq!((a, b), (Refusal::UnknownDevice, Refusal::BadSignature));
    assert_eq!(a.wire_code(), b.wire_code());
}

#[test]
fn bad_signature_does_not_burn_the_request_or_nonce() {
    let mut r = Rig::new();
    let forged = r.build(
        &DevKey::from_bytes(&[9u8; 32].into()).unwrap(),
        &r.server_pub,
        &[(U1, b"pw-one"), (U2, b"pw-two")],
    );
    assert_eq!(r.approve(&forged), Err(Refusal::BadSignature));
    let m = r.good();
    assert_eq!(r.approve(&m), Ok(2));
}

#[test]
fn approval_bound_to_a_different_server_key_is_rejected_and_burns_the_ephemeral_key() {
    let mut r = Rig::new();
    let rogue_pub = SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes();
    let m = r.build(&r.dev, &rogue_pub, &[(U1, b"pw-one"), (U2, b"pw-two")]);
    assert_eq!(r.approve(&m), Err(Refusal::BadCiphertext));
    // ephemeral key is gone: even a correct approval can no longer succeed on this request
    let good = r.good();
    assert_eq!(r.approve(&good), Err(Refusal::AlreadyConsumed));
    assert!(r.st.pending().is_empty());
}

#[test]
fn drive_not_in_request_is_rejected() {
    let mut r = Rig::new();
    let stranger = [0xab; 16];
    let m = r.build(&r.dev, &r.server_pub, &[(U1, b"pw-one"), (stranger, b"x")]);
    // sorted order matters: U1 (0x56) < 0xab, so the set is valid but contains an unrequested drive
    assert_eq!(r.approve(&m), Err(Refusal::DriveMismatch));
}

#[test]
fn subset_of_requested_drives_is_allowed() {
    let mut r = Rig::new();
    let m = r.build(&r.dev, &r.server_pub, &[(U1, b"pw-one")]);
    assert_eq!(r.approve(&m), Ok(1));
}

#[test]
fn repeated_bad_signatures_lock_the_device_out_then_recover() {
    let mut r = Rig::new();
    let forged = r.build(
        &DevKey::from_bytes(&[9u8; 32].into()).unwrap(),
        &r.server_pub,
        &[(U1, b"pw-one"), (U2, b"pw-two")],
    );
    for _ in 0..FAIL_LIMIT {
        assert_eq!(r.approve(&forged), Err(Refusal::BadSignature));
    }
    let m = r.good();
    assert_eq!(r.approve(&m), Err(Refusal::RateLimited));
    // lockout also blocks new nonces
    let id = r.dev_id;
    assert_eq!(
        r.st.register_nonce(&id, [0x33; 32], r.now.get()),
        Err(Refusal::RateLimited)
    );
    // after the lockout, a fresh nonce works again
    r.now.set(r.now.get() + LOCKOUT_SECS + 1);
    r.st.register_nonce(&id, [0x34; 32], r.now.get()).unwrap();
}

#[test]
fn nonce_registration_rejects_replay_and_clock_skew() {
    let mut r = Rig::new();
    let id = r.dev_id;
    let now = r.now.get();
    assert_eq!(
        r.st.register_nonce(&id, NONCE, now),
        Err(Refusal::NonceUnknownOrReplayed)
    );
    assert_eq!(
        r.st.register_nonce(&id, [0x40; 32], now - NONCE_WINDOW_SECS - 1),
        Err(Refusal::NonceStale)
    );
    assert_eq!(
        r.st.register_nonce(&id, [0x41; 32], now + NONCE_WINDOW_SECS + 1),
        Err(Refusal::NonceStale)
    );
    assert_eq!(
        r.st.register_nonce(&[0x55; 16], [0x42; 32], now),
        Err(Refusal::UnknownDevice)
    );
}

#[test]
fn revoked_device_cannot_approve() {
    let mut r = Rig::new();
    let m = r.good();
    let id = r.dev_id;
    r.st.revoke_device(&id);
    assert_eq!(r.approve(&m), Err(Refusal::UnknownDevice));
}
