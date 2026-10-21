//! Regenerates protocol/vectors/v1.json. Keys, ids and passphrases are fixed fake test data;
//! only the HPKE `enc`/`ct` vary per run (HPKE sealing is randomized), so regenerate deliberately.
//!   cargo run -p hands-proto --example gen_vectors

use ed25519_dalek::SigningKey;
use hands_proto::codec::{b64d, b64e, sha256};
use hands_proto::seal::*;
use hands_proto::sign::*;
use hands_proto::*;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey as P256Signing};
use p256::pkcs8::EncodePublicKey;
use serde_json::{json, Value};

fn h(b: &[u8]) -> String {
    hex::encode(b)
}

fn flip(mut v: Vec<u8>, at: usize) -> Vec<u8> {
    let i = at % v.len();
    v[i] ^= 0x01;
    v
}

fn uuid(s: &str) -> [u8; 16] {
    hex::decode(s.replace('-', "")).unwrap().try_into().unwrap()
}

fn main() {
    let server_sk = SigningKey::from_bytes(&[0x01; 32]);
    let server_pub = server_sk.verifying_key().to_bytes();
    let other_server_pub = SigningKey::from_bytes(&[0x02; 32])
        .verifying_key()
        .to_bytes();

    let dev_sk = P256Signing::from_bytes(&[0x07u8; 32].into()).unwrap();
    let dev_spki = dev_sk
        .verifying_key()
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec();
    let dev_id = device_id(&dev_spki);

    let req_id = [0x11u8; 16];
    let nonce = [0x22u8; 32];
    let (eph_priv, eph_pub) = ephemeral_from_ikm(&[0x33u8; 32]);

    // Signed server reply envelope.
    let body = br#"{"client_nonce":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI","server_time":1760000000,"requests":[]}"#;
    let env = server_sign(&server_sk, DOMAIN_SERVER_REPLY, body);
    assert!(server_verify(&server_pub, DOMAIN_SERVER_REPLY, &env).is_ok());

    // HPKE approve message for three drives.
    let u1 = uuid("00000000-0000-4000-8000-000000000001");
    let u2 = uuid("00000000-0000-4000-8000-000000000002");
    let u3 = uuid("00000000-0000-4000-8000-000000000003");
    let pws: [([u8; 16], &[u8]); 3] = [
        (u1, b"FAKE-pass-one-not-a-real-secret"),
        (u2, "FAKE-pass-two-\u{1F511}-utf8".as_bytes()),
        (u3, b"FAKE-pass-three"),
    ];
    let pt = encode_plaintext(&pws).unwrap();
    let info = hpke_info(&server_pub, &req_id, &nonce, &dev_id);
    let aad = hpke_aad(&[u1, u2, u3]).unwrap();
    let (enc, ct) = seal(&eph_pub, &info, &aad, &pt).unwrap();
    assert_eq!(**open(&eph_priv, &enc, &info, &aad, &ct).unwrap(), **pt);

    let msg = approve_message(&req_id, &nonce, &enc, &ct, &aad);
    let sig: DerSignature = dev_sk.sign(&msg);
    assert!(device_verify(&dev_spki, &msg, sig.as_bytes()).is_ok());

    let tok = [0x44u8; 32];
    let sas_v = sas(&server_pub, &dev_spki, &tok);

    // ---- negatives: every one must be rejected ----
    let mut neg: Vec<Value> = vec![];
    let mut bad_env = env.clone();
    let mut sig_bytes = b64d(&bad_env.sig).unwrap();
    sig_bytes[0] ^= 1;
    bad_env.sig = b64e(&sig_bytes);
    neg.push(json!({"name":"envelope_flipped_signature","kind":"envelope_verify","server_pub":h(&server_pub),"domain":"hands/v1/server-reply","envelope":bad_env}));
    let mut tampered = env.clone();
    tampered.body = b64e(&flip(body.to_vec(), 5));
    neg.push(json!({"name":"envelope_tampered_body","kind":"envelope_verify","server_pub":h(&server_pub),"domain":"hands/v1/server-reply","envelope":tampered}));
    neg.push(json!({"name":"envelope_wrong_server_key","kind":"envelope_verify","server_pub":h(&other_server_pub),"domain":"hands/v1/server-reply","envelope":env}));
    neg.push(json!({"name":"envelope_wrong_domain","kind":"envelope_verify","server_pub":h(&server_pub),"domain":"hands/v1/pair","envelope":env}));

    let open_case = |name: &str, enc: &[u8], info: &[u8], aad: &[u8], ct: &[u8]| json!({"name":name,"kind":"hpke_open","eph_priv":h(&eph_priv),"enc":h(enc),"info":h(info),"aad":h(aad),"ct":h(ct)});
    let other_nonce = [0x23u8; 32];
    neg.push(open_case(
        "hpke_wrong_client_nonce",
        &enc,
        &hpke_info(&server_pub, &req_id, &other_nonce, &dev_id),
        &aad,
        &ct,
    ));
    neg.push(open_case(
        "hpke_wrong_req_id",
        &enc,
        &hpke_info(&server_pub, &[0x12u8; 16], &nonce, &dev_id),
        &aad,
        &ct,
    ));
    neg.push(open_case(
        "hpke_wrong_server_key_in_info",
        &enc,
        &hpke_info(&other_server_pub, &req_id, &nonce, &dev_id),
        &aad,
        &ct,
    ));
    neg.push(open_case(
        "hpke_wrong_device",
        &enc,
        &hpke_info(&server_pub, &req_id, &nonce, &[0x99u8; 16]),
        &aad,
        &ct,
    ));
    neg.push(open_case(
        "hpke_wrong_aad_subset",
        &enc,
        &info,
        &hpke_aad(&[u1, u2]).unwrap(),
        &ct,
    ));
    neg.push(open_case(
        "hpke_flipped_ciphertext",
        &enc,
        &info,
        &aad,
        &flip(ct.clone(), 3),
    ));
    neg.push(open_case(
        "hpke_truncated_ciphertext",
        &enc,
        &info,
        &aad,
        &ct[..ct.len() - 1],
    ));
    neg.push(open_case(
        "hpke_flipped_enc",
        &flip(enc.clone(), 0),
        &info,
        &aad,
        &ct,
    ));

    let dev_case = |name: &str, message: &[u8], sig: &[u8], spki: &[u8]| json!({"name":name,"kind":"device_verify","spki":h(spki),"message":h(message),"sig":h(sig)});
    neg.push(dev_case(
        "device_swapped_req_id",
        &approve_message(&[0x12u8; 16], &nonce, &enc, &ct, &aad),
        sig.as_bytes(),
        &dev_spki,
    ));
    neg.push(dev_case(
        "device_swapped_ciphertext",
        &approve_message(&req_id, &nonce, &enc, &flip(ct.clone(), 0), &aad),
        sig.as_bytes(),
        &dev_spki,
    ));
    let other_dev = P256Signing::from_bytes(&[0x08u8; 32].into()).unwrap();
    let other_spki = other_dev
        .verifying_key()
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec();
    neg.push(dev_case(
        "device_wrong_key",
        &msg,
        sig.as_bytes(),
        &other_spki,
    ));
    neg.push(dev_case(
        "device_garbage_signature",
        &msg,
        &[0u8; 10],
        &dev_spki,
    ));

    // Plaintext format negatives.
    let mut nonzero_pad = pt.to_vec();
    *nonzero_pad.last_mut().unwrap() = 1;
    let build = |entries: &[(&[u8; 16], &[u8])]| {
        let mut v = vec![PLAINTEXT_VERSION, entries.len() as u8];
        for (u, p) in entries {
            v.extend_from_slice(*u);
            v.extend_from_slice(&(p.len() as u16).to_be_bytes());
            v.extend_from_slice(p);
        }
        v.resize(PAD_TO, 0);
        v
    };
    let unsorted = build(&[(&u2, b"b"), (&u1, b"a")]);
    let dup = build(&[(&u1, b"a"), (&u1, b"a")]);
    let mut bad_version = pt.to_vec();
    bad_version[0] = 2;
    let mut not_padded = pt.to_vec();
    not_padded.pop();
    for (name, v) in [
        ("plaintext_nonzero_padding", nonzero_pad),
        ("plaintext_unsorted_uuids", unsorted),
        ("plaintext_duplicate_uuid", dup),
        ("plaintext_bad_version", bad_version),
        ("plaintext_not_multiple_of_pad", not_padded),
    ] {
        neg.push(json!({"name":name,"kind":"plaintext_decode","bytes":h(&v)}));
    }

    let doc = json!({
        "version": 1,
        "note": "FAKE test data only. Regenerate with `cargo run -p hands-proto --example gen_vectors`.",
        "keys": {
            "server_ed25519_seed": h(&[0x01u8; 32]),
            "server_ed25519_pub": h(&server_pub),
            "device_p256_secret": h(&[0x07u8; 32]),
            "device_spki_der": h(&dev_spki),
            "device_id": h(&dev_id),
            "eph_ikm": h(&[0x33u8; 32]),
            "eph_priv": h(&eph_priv),
            "eph_pub": h(&eph_pub),
        },
        "ids": { "req_id": h(&req_id), "client_nonce": h(&nonce), "sha256_of_server_pub": h(&sha256(&server_pub)) },
        "envelope": { "domain": "hands/v1/server-reply", "body_utf8": String::from_utf8(body.to_vec()).unwrap(), "envelope": env },
        "approve": {
            "entries": pws.iter().map(|(u, p)| json!({"uuid": h(u), "passphrase_hex": h(p)})).collect::<Vec<_>>(),
            "plaintext": h(&pt),
            "info": h(&info),
            "aad": h(&aad),
            "enc": h(&enc),
            "ct": h(&ct),
            "signed_message": h(&msg),
            "device_sig_der": h(sig.as_bytes()),
        },
        "sas": { "token": h(&tok), "expected": sas_v },
        "negative": neg,
    });

    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../protocol/vectors/v1.json");
    std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    println!("wrote {}", path.display());
}
