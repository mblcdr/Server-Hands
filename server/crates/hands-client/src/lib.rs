//! Reference client for handsd: pinned TLS, software P-256 device key, the same message flow the phone
//! app implements. Used by handsd's end-to-end test and for manual tests against a real box.
//! The device key lives in a plain file: do not use this as the production client.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hands_proto::codec::{b64d, b64e, ct_eq, sha256, signed_bytes, uuid_parse};
use hands_proto::seal::{encode_plaintext, hpke_aad, hpke_info, sas, seal};
use hands_proto::sign::{approve_message, device_id, script_approve_message, server_verify};
use hands_proto::wire::*;
use hands_proto::{Envelope, DOMAIN_DEVICE_REQUEST, DOMAIN_PAIR, DOMAIN_SERVER_REPLY};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::EncodePublicKey;
use rand_core::{OsRng, RngCore};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub type Res<T> = Result<T, String>;

#[derive(Clone, Serialize, Deserialize)]
pub struct Pin {
    pub host: String,
    pub port: u16,
    pub spki: String,
    pub sid: String,
}

pub struct PairingQr {
    pub pin: Pin,
    pub token: String,
}

/// Parses `hands://pair?v=1&host=..&port=..&spki=..&sid=..&tok=..`.
pub fn parse_qr(url: &str) -> Res<PairingQr> {
    let q = url
        .strip_prefix("hands://pair?")
        .ok_or("not a hands://pair URL")?;
    let get = |k: &str| {
        q.split('&')
            .find_map(|kv| kv.strip_prefix(k).and_then(|r| r.strip_prefix('=')))
            .map(str::to_string)
            .ok_or(format!("missing {k}"))
    };
    if get("v")? != "1" {
        return Err("unsupported version".into());
    }
    let pin = Pin {
        host: get("host")?,
        port: get("port")?.parse().map_err(|_| "bad port")?,
        spki: get("spki")?,
        sid: get("sid")?,
    };
    Ok(PairingQr {
        pin,
        token: get("tok")?,
    })
}

pub struct Device {
    key: SigningKey,
}

impl Device {
    pub fn generate() -> Self {
        Self {
            key: SigningKey::random(&mut OsRng),
        }
    }
    pub fn from_bytes(b: &[u8]) -> Res<Self> {
        Ok(Self {
            key: SigningKey::from_slice(b).map_err(|_| "bad device key")?,
        })
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.to_bytes().to_vec()
    }
    pub fn spki(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec()
    }
    pub fn id(&self) -> [u8; 16] {
        device_id(&self.spki())
    }
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let sig: DerSignature = self.key.sign(msg);
        sig.as_bytes().to_vec()
    }
}

pub struct Client {
    pub pin: Pin,
    pub device: Device,
}

pub struct Listing {
    pub client_nonce: [u8; 32],
    pub reply: ListReply,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Debug)]
struct PinVerifier {
    spki_sha256: Vec<u8>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let (_, cert) = x509_parser::parse_x509_certificate(end_entity)
            .map_err(|_| rustls::Error::General("cert".into()))?;
        if ct_eq(
            &sha256(cert.tbs_certificate.subject_pki.raw),
            &self.spki_sha256,
        ) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("pin mismatch".into()))
        }
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("tls1.2 not allowed".into()))
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            m,
            c,
            d,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl Client {
    async fn post(&self, path: &str, body: String) -> Res<(u16, String)> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let spki = b64d(&self.pin.spki).map_err(|_| "bad spki pin")?;
        let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| e.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinVerifier {
                spki_sha256: spki,
                provider,
            }))
            .with_no_client_auth();
        let tcp = TcpStream::connect((self.pin.host.as_str(), self.pin.port))
            .await
            .map_err(|e| e.to_string())?;
        let tls = TlsConnector::from(Arc::new(cfg))
            .connect(ServerName::try_from("server-hands").unwrap(), tcp)
            .await
            .map_err(|e| format!("tls: {e}"))?;
        let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|e| e.to_string())?;
        tokio::spawn(conn);
        let req = hyper::Request::post(path)
            .header("host", "server-hands")
            .header("content-type", "application/json")
            .body(Full::new(bytes::Bytes::from(body)))
            .map_err(|e| e.to_string())?;
        let resp = tx.send_request(req).await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| e.to_string())?
            .to_bytes();
        Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
    }

    fn verified_body(&self, domain: &[u8], text: &str) -> Res<Vec<u8>> {
        let env: Envelope = serde_json::from_str(text).map_err(|_| "bad envelope")?;
        let sid = b64d(&self.pin.sid).map_err(|_| "bad sid pin")?;
        server_verify(&sid, domain, &env).map_err(|_| "server signature invalid".to_string())
    }

    fn api_error(status: u16, text: &str) -> String {
        let code = serde_json::from_str::<ErrorBody>(text)
            .map(|e| e.error)
            .unwrap_or_default();
        format!("server refused ({status} {code})")
    }

    /// Blocks until the operator confirms on the server. `show_sas` is called first so it can be displayed.
    pub async fn pair(&self, token_b64: &str, name: &str, show_sas: impl FnOnce(&str)) -> Res<()> {
        let tok = b64d(token_b64).map_err(|_| "bad token")?;
        let sid = b64d(&self.pin.sid).map_err(|_| "bad sid")?;
        show_sas(&sas(&sid, &self.device.spki(), &tok));
        let body = serde_json::to_string(&PairRequest {
            tok: token_b64.to_string(),
            device_pub: b64e(&self.device.spki()),
            device_name: name.to_string(),
        })
        .unwrap();
        let (status, text) = self.post("/v1/pair", body).await?;
        if status != 200 {
            return Err(Self::api_error(status, &text));
        }
        let ack: PairAck = serde_json::from_slice(&self.verified_body(DOMAIN_PAIR, &text)?)
            .map_err(|_| "bad ack")?;
        if b64d(&ack.device_id).ok().as_deref() != Some(&self.device.id()[..]) {
            return Err("ack for a different device".into());
        }
        Ok(())
    }

    /// Signs `body` (built from a fresh nonce), posts it to `path` and returns the verified reply body.
    async fn signed_call(&self, path: &str, nonce: &[u8; 32], body: Vec<u8>) -> Res<Vec<u8>> {
        let env = Envelope {
            sig: b64e(
                &self
                    .device
                    .sign(&signed_bytes(DOMAIN_DEVICE_REQUEST, &body)),
            ),
            body: b64e(&body),
        };
        let (status, text) = self
            .post(path, serde_json::to_string(&env).unwrap())
            .await?;
        if status != 200 {
            return Err(Self::api_error(status, &text));
        }
        let reply = self.verified_body(DOMAIN_SERVER_REPLY, &text)?;
        let echoed: serde_json::Value = serde_json::from_slice(&reply).map_err(|_| "bad reply")?;
        if echoed["client_nonce"] != b64e(nonce)
            || echoed["server_time"]
                .as_u64()
                .is_some_and(|t| t.abs_diff(now()) > 60)
        {
            return Err("stale or mismatched reply".into());
        }
        Ok(reply)
    }

    fn fresh_nonce() -> [u8; 32] {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    pub async fn list(&self) -> Res<Listing> {
        let nonce = Self::fresh_nonce();
        let body = serde_json::to_vec(&ListBody {
            device_id: b64e(&self.device.id()),
            client_nonce: b64e(&nonce),
            ts: now(),
        })
        .unwrap();
        let reply = self.signed_call("/v1/requests/list", &nonce, body).await?;
        let reply: ListReply = serde_json::from_slice(&reply).map_err(|_| "bad list reply")?;
        Ok(Listing {
            client_nonce: nonce,
            reply,
        })
    }

    pub async fn scripts(&self) -> Res<ScriptsReply> {
        let nonce = Self::fresh_nonce();
        let body = serde_json::to_vec(&ListBody {
            device_id: b64e(&self.device.id()),
            client_nonce: b64e(&nonce),
            ts: now(),
        })
        .unwrap();
        let reply = self.signed_call("/v1/scripts/list", &nonce, body).await?;
        serde_json::from_slice(&reply).map_err(|_| "bad scripts reply".into())
    }

    /// Runs a script that needs no biometric approval.
    pub async fn run_script(&self, name: &str) -> Res<ScriptRunReply> {
        self.run_script_with(name, None, None).await
    }

    /// Runs a script with an optional challenge and approval signature (both for `biometric_protection`).
    pub async fn run_script_with(
        &self,
        name: &str,
        challenge: Option<&str>,
        approval_sig: Option<&[u8]>,
    ) -> Res<ScriptRunReply> {
        let nonce = Self::fresh_nonce();
        let body = serde_json::to_vec(&ScriptRunBody {
            device_id: b64e(&self.device.id()),
            client_nonce: b64e(&nonce),
            ts: now(),
            script: name.into(),
            challenge: challenge.map(str::to_string),
            approval_sig: approval_sig.map(b64e),
        })
        .unwrap();
        let reply = self.signed_call("/v1/scripts/run", &nonce, body).await?;
        serde_json::from_slice(&reply).map_err(|_| "bad run reply".into())
    }

    /// Registers `approval` (the stand-in for the phone's biometric-bound key) with the server.
    pub async fn register_approval_key(&self, approval: &Device) -> Res<()> {
        let nonce = Self::fresh_nonce();
        let body = serde_json::to_vec(&ApprovalKeyBody {
            device_id: b64e(&self.device.id()),
            client_nonce: b64e(&nonce),
            ts: now(),
            approval_pub: b64e(&approval.spki()),
        })
        .unwrap();
        self.signed_call("/v1/device/approval-key", &nonce, body)
            .await
            .map(|_| ())
    }

    pub async fn script_challenge(&self, name: &str) -> Res<ScriptChallengeReply> {
        let nonce = Self::fresh_nonce();
        let body = serde_json::to_vec(&ScriptChallengeBody {
            device_id: b64e(&self.device.id()),
            client_nonce: b64e(&nonce),
            ts: now(),
            challenge_for: name.into(),
        })
        .unwrap();
        let reply = self
            .signed_call("/v1/scripts/challenge", &nonce, body)
            .await?;
        serde_json::from_slice(&reply).map_err(|_| "bad challenge reply".into())
    }

    /// The whole biometric-protected flow: challenge, signature by `approval`, run.
    pub async fn run_script_approved(&self, name: &str, approval: &Device) -> Res<ScriptRunReply> {
        let c = self.script_challenge(name).await?;
        let challenge: [u8; 32] = b64d(&c.challenge)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or("bad challenge")?;
        let sid: [u8; 32] = b64d(&self.pin.sid)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or("bad sid")?;
        let sig = approval.sign(&script_approve_message(
            &sid,
            &self.device.id(),
            name,
            &challenge,
        ));
        self.run_script_with(name, Some(&c.challenge), Some(&sig))
            .await
    }

    /// Seals the passphrases to the request's ephemeral key and approves. `drives` need not be sorted.
    pub async fn approve(
        &self,
        listing: &Listing,
        req_index: usize,
        drives: &[(&str, &[u8])],
    ) -> Res<ApproveReply> {
        let req = listing
            .reply
            .requests
            .get(req_index)
            .ok_or("no such request")?;
        let req_id: [u8; 16] = b64d(&req.req_id)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or("bad req_id")?;
        let e_pub = b64d(&req.e_pub).map_err(|_| "bad e_pub")?;
        let sid: [u8; 32] = b64d(&self.pin.sid)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or("bad sid")?;

        let mut entries: Vec<([u8; 16], &[u8])> = drives
            .iter()
            .map(|(u, p)| Ok((uuid_parse(u).map_err(|_| "bad uuid")?, *p)))
            .collect::<Res<_>>()?;
        entries.sort_by_key(|(u, _)| *u);
        let uuids: Vec<[u8; 16]> = entries.iter().map(|(u, _)| *u).collect();
        let aad = hpke_aad(&uuids).map_err(|_| "duplicate uuid")?;
        let info = hpke_info(&sid, &req_id, &listing.client_nonce, &self.device.id());
        let plain = encode_plaintext(&entries).map_err(|_| "bad passphrase set")?;
        let (enc, ct) = seal(&e_pub, &info, &aad, &plain).map_err(|_| "seal failed")?;
        let sig = self.device.sign(&approve_message(
            &req_id,
            &listing.client_nonce,
            &enc,
            &ct,
            &aad,
        ));

        let body = serde_json::to_string(&ApproveRequest {
            device_id: b64e(&self.device.id()),
            client_nonce: b64e(&listing.client_nonce),
            uuids: uuids.iter().map(hands_proto::codec::uuid_format).collect(),
            enc: b64e(&enc),
            ct: b64e(&ct),
            sig: b64e(&sig),
        })
        .unwrap();
        let (status, text) = self
            .post(&format!("/v1/requests/{}/approve", req.req_id), body)
            .await?;
        if status != 200 {
            return Err(Self::api_error(status, &text));
        }
        let reply: ApproveReply =
            serde_json::from_slice(&self.verified_body(DOMAIN_SERVER_REPLY, &text)?)
                .map_err(|_| "bad approve reply")?;
        if reply.client_nonce != b64e(&listing.client_nonce) || reply.req_id != req.req_id {
            return Err("approve reply does not match request".into());
        }
        Ok(reply)
    }
}
