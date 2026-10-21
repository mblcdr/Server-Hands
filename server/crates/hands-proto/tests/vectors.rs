//! Runs protocol/vectors/v1.json. The Kotlin implementation must pass the same file.

use hands_proto::codec::b64e;
use hands_proto::seal::*;
use hands_proto::sign::*;
use hands_proto::*;
use serde_json::Value;

fn load() -> Value {
    let p =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../protocol/vectors/v1.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("run gen_vectors first")).unwrap()
}

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn arr<const N: usize>(v: &Value) -> [u8; N] {
    hx(v).try_into().unwrap()
}

fn domain(s: &str) -> &'static [u8] {
    match s {
        "hands/v1/server-reply" => DOMAIN_SERVER_REPLY,
        "hands/v1/device-request" => DOMAIN_DEVICE_REQUEST,
        "hands/v1/approve" => DOMAIN_APPROVE,
        "hands/v1/pair" => DOMAIN_PAIR,
        _ => panic!("unknown domain"),
    }
}

#[test]
fn positive_vectors() {
    let v = load();
    let server_pub = hx(&v["keys"]["server_ed25519_pub"]);

    // Envelope verifies and yields the body.
    let env: Envelope = serde_json::from_value(v["envelope"]["envelope"].clone()).unwrap();
    let body = server_verify(
        &server_pub,
        domain(v["envelope"]["domain"].as_str().unwrap()),
        &env,
    )
    .unwrap();
    assert_eq!(
        body,
        v["envelope"]["body_utf8"].as_str().unwrap().as_bytes()
    );
    assert_eq!(env.body, b64e(&body));

    // Device id derivation.
    let spki = hx(&v["keys"]["device_spki_der"]);
    assert_eq!(device_id(&spki).to_vec(), hx(&v["keys"]["device_id"]));

    // HPKE info/aad derivation reproduces the vector, then the ciphertext opens.
    let a = &v["approve"];
    let req_id: [u8; 16] = arr(&v["ids"]["req_id"]);
    let nonce: [u8; 32] = arr(&v["ids"]["client_nonce"]);
    let dev_id: [u8; 16] = arr(&v["keys"]["device_id"]);
    let sp: [u8; 32] = server_pub.clone().try_into().unwrap();
    let info = hpke_info(&sp, &req_id, &nonce, &dev_id);
    assert_eq!(info, hx(&a["info"]));
    let uuids: Vec<[u8; 16]> = a["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| arr(&e["uuid"]))
        .collect();
    let aad = hpke_aad(&uuids).unwrap();
    assert_eq!(aad, hx(&a["aad"]));

    // Ephemeral key derivation from IKM matches.
    let (eph_priv, eph_pub) = ephemeral_from_ikm(&hx(&v["keys"]["eph_ikm"]));
    assert_eq!(*eph_priv, hx(&v["keys"]["eph_priv"]));
    assert_eq!(eph_pub, hx(&v["keys"]["eph_pub"]));

    let pt = open(&eph_priv, &hx(&a["enc"]), &info, &aad, &hx(&a["ct"])).unwrap();
    assert_eq!(*pt, hx(&a["plaintext"]));
    let decoded = decode_plaintext(&pt).unwrap();
    for (e, (u, p)) in a["entries"].as_array().unwrap().iter().zip(decoded.iter()) {
        assert_eq!(*u, arr::<16>(&e["uuid"]));
        assert_eq!(p.expose(), hx(&e["passphrase_hex"]).as_slice());
    }

    // Approve signature.
    let msg = approve_message(&req_id, &nonce, &hx(&a["enc"]), &hx(&a["ct"]), &aad);
    assert_eq!(msg, hx(&a["signed_message"]));
    device_verify(&spki, &msg, &hx(&a["device_sig_der"])).unwrap();

    // SAS.
    let s = &v["sas"];
    assert_eq!(
        sas(&server_pub, &spki, &hx(&s["token"])),
        s["expected"].as_str().unwrap()
    );
}

#[test]
fn seal_roundtrip_fresh() {
    let (sk, pk) = gen_ephemeral();
    let info = b"i".to_vec();
    let aad = b"a".to_vec();
    let (enc, ct) = seal(&pk, &info, &aad, b"hello").unwrap();
    assert_eq!(&**open(&sk, &enc, &info, &aad, &ct).unwrap(), b"hello");
}

#[test]
fn negative_vectors_are_all_rejected() {
    let v = load();
    let cases = v["negative"].as_array().unwrap();
    assert!(cases.len() >= 20);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let rejected = match c["kind"].as_str().unwrap() {
            "envelope_verify" => {
                let env: Envelope = serde_json::from_value(c["envelope"].clone()).unwrap();
                server_verify(
                    &hx(&c["server_pub"]),
                    domain(c["domain"].as_str().unwrap()),
                    &env,
                )
                .is_err()
            }
            "hpke_open" => open(
                &hx(&c["eph_priv"]),
                &hx(&c["enc"]),
                &hx(&c["info"]),
                &hx(&c["aad"]),
                &hx(&c["ct"]),
            )
            .is_err(),
            "device_verify" => {
                device_verify(&hx(&c["spki"]), &hx(&c["message"]), &hx(&c["sig"])).is_err()
            }
            "plaintext_decode" => decode_plaintext(&hx(&c["bytes"])).is_err(),
            k => panic!("unknown kind {k}"),
        };
        assert!(rejected, "negative vector accepted: {name}");
    }
}

/// Interop, other direction: a ciphertext sealed by the Kotlin implementation opens in Rust.
#[test]
fn kotlin_sealed_vector_opens_in_rust() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../protocol/vectors");
    let k: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("v1-kotlin.json")).unwrap())
            .unwrap();
    let v = load();
    let eph_priv = hx(&v["keys"]["eph_priv"]);
    let pt = open(
        &eph_priv,
        &hx(&k["enc"]),
        &hx(&k["info"]),
        &hx(&k["aad"]),
        &hx(&k["ct"]),
    )
    .unwrap();
    assert_eq!(*pt, hx(&k["plaintext"]));
    let decoded = decode_plaintext(&pt).unwrap();
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].1.expose(), b"FAKE-kotlin-sealed-one");
    assert_eq!(decoded[1].1.expose(), b"FAKE-kotlin-sealed-two");
}
