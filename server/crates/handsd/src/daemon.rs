//! Transport-independent request handling: pairing, listing, approving. No secret is ever logged.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use hands_proto::codec::{
    b64d, b64e, ct_eq, hex_decode, hex_encode, signed_bytes, uuid_format, uuid_parse,
};
use hands_proto::seal::sas;
use hands_proto::sign::{device_id, device_verify, script_approve_message, server_sign};
use hands_proto::wire::*;
use hands_proto::{Envelope, DOMAIN_DEVICE_REQUEST, DOMAIN_PAIR, DOMAIN_SERVER_REPLY};
use p256::pkcs8::DecodePublicKey;
use rand_core::{OsRng, RngCore};
use tokio::sync::oneshot;

use crate::config::{Config, ScriptCfg, ScriptMode};
use crate::host::Host;
use crate::luks::UnlockResult;
use crate::state::{Refusal, State, SystemClock};
use crate::store::{new_device_record, DeviceRecord, Store};

pub const PAIR_TOKEN_TTL: Duration = Duration::from_secs(300);
const SCRIPT_CHALLENGE_TTL: Duration = Duration::from_secs(60);
const MAX_SCRIPT_CHALLENGES: usize = 64;
const PAIR_MAX_BAD_TOKENS: u8 = 5;

pub struct Presented {
    pub sas: String,
    pub name: String,
    pub decide: oneshot::Sender<bool>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RunState {
    Idle,
    Queued,
    Running,
    Ok,
    Failed,
}

impl RunState {
    fn as_str(self) -> &'static str {
        match self {
            RunState::Idle => "idle",
            RunState::Queued => "queued",
            RunState::Running => "running",
            RunState::Ok => "ok",
            RunState::Failed => "failed",
        }
    }
    fn busy(self) -> bool {
        matches!(self, RunState::Queued | RunState::Running)
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A challenge issued for one device to approve one script. Single use.
struct ScriptChallenge {
    challenge: [u8; 32],
    device: [u8; 16],
    script: String,
    expires: Instant,
}

struct PairSession {
    token: [u8; 32],
    expires: Instant,
    bad: u8,
    presented: Option<oneshot::Sender<Presented>>,
}

pub struct Ctx {
    pub cfg: Config,
    pub identity: SigningKey,
    pub server_pub: [u8; 32],
    pub spki_sha256: [u8; 32],
    pub store: Store,
    pub host: Arc<dyn Host>,
    state: Mutex<State<SystemClock>>,
    devices: Mutex<Vec<DeviceRecord>>,
    pairing: Mutex<Option<PairSession>>,
    unlock_gate: tokio::sync::Mutex<()>,
    /// script name -> (state, unix time it finished)
    scripts: Mutex<std::collections::HashMap<String, (RunState, u64)>>,
    challenges: Mutex<Vec<ScriptChallenge>>,
}

pub type Reply = (u16, String);

fn err(code: &str) -> Reply {
    let status = match code {
        "unauthorized" => 401,
        "replayed" => 409,
        "expired" => 410,
        "rate_limited" => 429,
        "unknown_script" => 404,
        "approval_required" => 403,
        "not_unlocked" | "busy" | "conflict" => 409,
        "internal" => 500,
        _ => 400,
    };
    (
        status,
        serde_json::to_string(&ErrorBody { error: code.into() }).unwrap(),
    )
}

fn refusal(r: Refusal) -> Reply {
    err(r.wire_code())
}

impl Ctx {
    pub fn new(
        cfg: Config,
        identity: SigningKey,
        spki_sha256: [u8; 32],
        store: Store,
        host: Arc<dyn Host>,
    ) -> Arc<Self> {
        let server_pub = identity.verifying_key().to_bytes();
        let mut state = State::new(SystemClock, server_pub);
        let devices = store.load_devices();
        for d in &devices {
            if let Some(spki) = d.spki_bytes() {
                state.add_device(spki);
            }
        }
        Arc::new(Ctx {
            cfg,
            identity,
            server_pub,
            spki_sha256,
            store,
            host,
            state: Mutex::new(state),
            devices: Mutex::new(devices),
            pairing: Mutex::new(None),
            unlock_gate: tokio::sync::Mutex::new(()),
            scripts: Mutex::new(Default::default()),
            challenges: Mutex::new(Vec::new()),
        })
    }

    /// Makes sure exactly one pending request covers the drives that are locked right now.
    pub fn refresh_requests(&self) {
        let locked = self.host.locked_drives();
        let mut st = self.state.lock().unwrap();
        if locked.is_empty() {
            st.clear_pending();
            return;
        }
        let covers = |drives: &[hands_proto::DriveInfo]| {
            drives.len() == locked.len()
                && drives
                    .iter()
                    .all(|d| locked.iter().any(|l| l.luks_uuid == d.luks_uuid))
        };
        if st.pending_views().iter().any(|(_, _, _, d)| covers(d)) {
            return;
        }
        st.clear_pending();
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        st.create_request(id, locked, self.cfg.request_ttl_secs);
    }

    fn sign_reply(&self, domain: &[u8], body: &impl serde::Serialize) -> Reply {
        let bytes = serde_json::to_vec(body).unwrap();
        let env = server_sign(&self.identity, domain, &bytes);
        (200, serde_json::to_string(&env).unwrap())
    }

    pub async fn route(self: &Arc<Self>, method: &str, path: &str, body: &[u8]) -> Reply {
        if method != "POST" {
            return err("bad_request");
        }
        match path {
            "/v1/pair" => self.pair(body).await,
            "/v1/requests/list" => self.list(body),
            "/v1/scripts/list" => self.scripts_list(body),
            "/v1/scripts/challenge" => self.scripts_challenge(body),
            "/v1/scripts/run" => self.scripts_run(body),
            "/v1/device/approval-key" => self.register_approval_key(body),
            p => match p
                .strip_prefix("/v1/requests/")
                .and_then(|r| r.strip_suffix("/approve"))
            {
                Some(id) => self.approve(id, body).await,
                None => err("bad_request"),
            },
        }
    }

    // ---- pairing -------------------------------------------------------------------------------

    /// Control side: opens a pairing window and returns the one-time token plus the channel on which
    /// the phone's request will arrive.
    pub fn pair_start(&self) -> ([u8; 32], oneshot::Receiver<Presented>) {
        let mut token = [0u8; 32];
        OsRng.fill_bytes(&mut token);
        let (tx, rx) = oneshot::channel();
        *self.pairing.lock().unwrap() = Some(PairSession {
            token,
            expires: Instant::now() + PAIR_TOKEN_TTL,
            bad: 0,
            presented: Some(tx),
        });
        (token, rx)
    }

    pub fn pair_cancel(&self) {
        *self.pairing.lock().unwrap() = None;
    }

    async fn pair(self: &Arc<Self>, body: &[u8]) -> Reply {
        let Ok(req) = serde_json::from_slice::<PairRequest>(body) else {
            return err("bad_request");
        };
        let (Ok(tok), Ok(spki)) = (b64d(&req.tok), b64d(&req.device_pub)) else {
            return err("bad_request");
        };
        if req.device_name.is_empty()
            || req.device_name.len() > 64
            || p256::ecdsa::VerifyingKey::from_public_key_der(&spki).is_err()
        {
            return err("bad_request");
        }
        let tx = {
            let mut slot = self.pairing.lock().unwrap();
            let Some(sess) = slot.as_mut() else {
                return err("unauthorized");
            };
            if Instant::now() >= sess.expires {
                *slot = None;
                return err("unauthorized");
            }
            if !ct_eq(&tok, &sess.token) {
                sess.bad += 1;
                if sess.bad >= PAIR_MAX_BAD_TOKENS {
                    *slot = None;
                }
                return err("unauthorized");
            }
            let tx = sess.presented.take();
            *slot = None; // single use: burned as soon as it is presented
            match tx {
                Some(tx) => tx,
                None => return err("unauthorized"),
            }
        };
        let (decide_tx, decide_rx) = oneshot::channel();
        let code = sas(&self.server_pub, &spki, &tok);
        if tx
            .send(Presented {
                sas: code,
                name: req.device_name.clone(),
                decide: decide_tx,
            })
            .is_err()
        {
            return err("unauthorized");
        }
        match tokio::time::timeout(PAIR_TOKEN_TTL, decide_rx).await {
            Ok(Ok(true)) => {}
            _ => return err("unauthorized"),
        }
        let id = device_id(&spki);
        let mut st = self.state.lock().unwrap();
        let now = st.now();
        st.add_device(spki.clone());
        let mut devices = self.devices.lock().unwrap();
        devices.retain(|d| d.id_bytes() != Some(id));
        devices.push(new_device_record(&id, &spki, &req.device_name, now));
        if self.store.save_devices(&devices).is_err() {
            return err("internal");
        }
        drop(devices);
        drop(st);
        self.sign_reply(
            DOMAIN_PAIR,
            &PairAck {
                device_id: b64e(&id),
                server_time: now,
            },
        )
    }

    pub fn devices(&self) -> Vec<DeviceRecord> {
        self.devices.lock().unwrap().clone()
    }

    /// Revokes by full or unambiguous-prefix hex id.
    pub fn revoke(&self, id_hex: &str) -> Result<DeviceRecord, String> {
        let mut devices = self.devices.lock().unwrap();
        let matches: Vec<usize> = devices
            .iter()
            .enumerate()
            .filter(|(_, d)| !id_hex.is_empty() && d.id.starts_with(id_hex))
            .map(|(i, _)| i)
            .collect();
        let [i] = matches[..] else {
            return Err("no unique device matches".into());
        };
        let rec = devices.remove(i);
        self.store
            .save_devices(&devices)
            .map_err(|e| e.to_string())?;
        if let Some(id) = rec.id_bytes() {
            self.state.lock().unwrap().revoke_device(&id);
        }
        Ok(rec)
    }

    /// Forgets a device's approval key so its phone can register a new one (e.g. after its biometrics changed).
    pub fn reset_approval_key(&self, id_hex: &str) -> Result<DeviceRecord, String> {
        let mut devices = self.devices.lock().unwrap();
        let matches: Vec<usize> = devices
            .iter()
            .enumerate()
            .filter(|(_, d)| !id_hex.is_empty() && d.id.starts_with(id_hex))
            .map(|(i, _)| i)
            .collect();
        let [i] = matches[..] else {
            return Err("no unique device matches".into());
        };
        devices[i].approval_spki = None;
        self.store
            .save_devices(&devices)
            .map_err(|e| e.to_string())?;
        Ok(devices[i].clone())
    }

    pub fn pending_count(&self) -> usize {
        self.state.lock().unwrap().pending_views().len()
    }

    // ---- list ----------------------------------------------------------------------------------

    /// Verifies a device-signed envelope and registers its nonce. `ids` picks (device_id, client_nonce, ts)
    /// out of the body, which is parsed only to find which key to verify with; nothing in it is used
    /// until the signature has checked out. Returns the parsed body.
    fn authenticate<T: serde::de::DeserializeOwned>(
        &self,
        body: &[u8],
        ids: impl Fn(&T) -> (&str, &str, u64),
    ) -> Result<T, Reply> {
        let Ok(env) = serde_json::from_slice::<Envelope>(body) else {
            return Err(err("bad_request"));
        };
        let (Ok(msg), Ok(sig)) = (b64d(&env.body), b64d(&env.sig)) else {
            return Err(err("bad_request"));
        };
        let Ok(claimed) = serde_json::from_slice::<T>(&msg) else {
            return Err(err("bad_request"));
        };
        let (device_id, client_nonce, ts) = ids(&claimed);
        let Some(dev): Option<[u8; 16]> = b64d(device_id).ok().and_then(|v| v.try_into().ok())
        else {
            return Err(err("bad_request"));
        };
        let spki = match self.state.lock().unwrap().device_spki(&dev) {
            Some(s) => s.to_vec(),
            None => return Err(err("unauthorized")),
        };
        if device_verify(&spki, &signed_bytes(DOMAIN_DEVICE_REQUEST, &msg), &sig).is_err() {
            return Err(err("unauthorized"));
        }
        let Some(nonce): Option<[u8; 32]> = b64d(client_nonce).ok().and_then(|v| v.try_into().ok())
        else {
            return Err(err("bad_request"));
        };
        if let Err(r) = self.state.lock().unwrap().register_nonce(&dev, nonce, ts) {
            return Err(refusal(r));
        }
        Ok(claimed)
    }

    fn list(&self, body: &[u8]) -> Reply {
        let claimed =
            match self.authenticate::<ListBody>(body, |b| (&b.device_id, &b.client_nonce, b.ts)) {
                Ok(v) => v,
                Err(r) => return r,
            };
        self.refresh_requests();
        let st = self.state.lock().unwrap();
        let requests = st
            .pending_views()
            .into_iter()
            .map(|(id, exp, e_pub, drives)| RequestView {
                req_id: b64e(&id),
                expires_at: exp,
                drives,
                e_pub: b64e(&e_pub),
                status: "pending".into(),
            })
            .collect();
        let reply = ListReply {
            client_nonce: claimed.client_nonce,
            server_time: st.now(),
            requests,
        };
        drop(st);
        self.sign_reply(DOMAIN_SERVER_REPLY, &reply)
    }

    // ---- approve -------------------------------------------------------------------------------

    async fn approve(self: &Arc<Self>, req_id_b64: &str, body: &[u8]) -> Reply {
        let Ok(req) = serde_json::from_slice::<ApproveRequest>(body) else {
            return err("bad_request");
        };
        let fixed = |s: &str| b64d(s).ok();
        let (Some(req_id), Some(dev), Some(nonce), Some(enc), Some(ct), Some(sig)) = (
            fixed(req_id_b64).and_then(|v| <[u8; 16]>::try_from(v).ok()),
            fixed(&req.device_id).and_then(|v| <[u8; 16]>::try_from(v).ok()),
            fixed(&req.client_nonce).and_then(|v| <[u8; 32]>::try_from(v).ok()),
            fixed(&req.enc),
            fixed(&req.ct),
            fixed(&req.sig),
        ) else {
            return err("bad_request");
        };
        let Ok(uuids) = req
            .uuids
            .iter()
            .map(|u| uuid_parse(u))
            .collect::<Result<Vec<_>, _>>()
        else {
            return err("bad_request");
        };

        let entries = match self
            .state
            .lock()
            .unwrap()
            .approve(&dev, &req_id, &nonce, &enc, &ct, &sig, &uuids)
        {
            Ok(e) => e,
            Err(r) => return refusal(r),
        };
        // From here the request is consumed whatever happens; unlocks are serialised.
        let _gate = self.unlock_gate.lock().await;
        let host = self.host.clone();
        let Ok(results) = tokio::task::spawn_blocking(move || host.unlock(entries)).await else {
            return err("internal");
        };
        {
            let mut st = self.state.lock().unwrap();
            for (_, r) in &results {
                if *r == UnlockResult::BadPassphrase {
                    st.record_bad_passphrase(&dev);
                }
            }
        }
        let unlocked: Vec<[u8; 16]> = results
            .iter()
            .filter(|(_, r)| r.is_unlocked())
            .map(|(u, _)| *u)
            .collect();
        let host = self.host.clone();
        let all_done = tokio::task::spawn_blocking(move || {
            let all_done = host.locked_drives().is_empty();
            host.after_unlock(&unlocked, all_done);
            all_done
        })
        .await
        .unwrap_or(false);
        if all_done {
            self.run_auto_scripts();
        }
        self.refresh_requests();

        let reply = ApproveReply {
            client_nonce: req.client_nonce,
            req_id: req_id_b64.to_string(),
            results: results
                .iter()
                .map(|(u, r)| DriveResult {
                    luks_uuid: uuid_format(u),
                    result: r.as_str().into(),
                })
                .collect(),
        };
        self.sign_reply(DOMAIN_SERVER_REPLY, &reply)
    }

    /// Startup: if nothing is locked (e.g. unlocked from the OMV GUI first) still bring dependents up.
    pub fn startup_sync(self: &Arc<Self>) {
        self.refresh_requests();
        if self.host.locked_drives().is_empty()
            && self.host.any_open()
            && !self.cfg.run_dir.join("unlocked").exists()
        {
            self.host.after_unlock(&[], true);
            self.run_auto_scripts();
        }
    }

    // ---- post-unlock scripts -------------------------------------------------------------------

    fn unlocked(&self) -> bool {
        self.cfg.run_dir.join("unlocked").exists()
    }

    fn script_views(&self) -> Vec<ScriptView> {
        let states = self.scripts.lock().unwrap();
        self.cfg
            .scripts
            .iter()
            .map(|s| {
                let (state, finished_at) =
                    states.get(&s.name).copied().unwrap_or((RunState::Idle, 0));
                ScriptView {
                    name: s.name.clone(),
                    label: s.display().to_string(),
                    mode: match s.mode {
                        ScriptMode::Auto => "auto",
                        ScriptMode::Manual => "manual",
                    }
                    .into(),
                    state: state.as_str().into(),
                    finished_at,
                    requires_confirmation: s.requires_confirmation,
                    biometric_protection: s.biometric_protection,
                }
            })
            .collect()
    }

    /// Moves a script to `Queued` unless it is already queued or running.
    fn claim_script(&self, name: &str) -> bool {
        let mut m = self.scripts.lock().unwrap();
        if m.get(name).is_some_and(|(s, _)| s.busy()) {
            return false;
        }
        m.insert(name.to_string(), (RunState::Queued, 0));
        true
    }

    /// Blocking. The script must have been claimed.
    fn execute_script(&self, s: &ScriptCfg, trigger: &str) {
        self.scripts
            .lock()
            .unwrap()
            .insert(s.name.clone(), (RunState::Running, 0));
        let ok = self.host.run_script(s, trigger);
        let state = if ok { RunState::Ok } else { RunState::Failed };
        self.scripts
            .lock()
            .unwrap()
            .insert(s.name.clone(), (state, unix_now()));
    }

    /// Starts the `auto` scripts, one after the other in config order, without blocking the caller.
    fn run_auto_scripts(self: &Arc<Self>) {
        let todo: Vec<ScriptCfg> = self
            .cfg
            .scripts
            .iter()
            .filter(|s| s.mode == ScriptMode::Auto && self.claim_script(&s.name))
            .cloned()
            .collect();
        if todo.is_empty() {
            return;
        }
        let ctx = self.clone();
        std::thread::spawn(move || {
            for s in &todo {
                ctx.execute_script(s, "auto");
            }
        });
    }

    fn scripts_list(&self, body: &[u8]) -> Reply {
        let claimed =
            match self.authenticate::<ListBody>(body, |b| (&b.device_id, &b.client_nonce, b.ts)) {
                Ok(v) => v,
                Err(r) => return r,
            };
        let reply = ScriptsReply {
            client_nonce: claimed.client_nonce,
            server_time: self.state.lock().unwrap().now(),
            unlocked: self.unlocked(),
            scripts: self.script_views(),
        };
        self.sign_reply(DOMAIN_SERVER_REPLY, &reply)
    }

    /// Registers the phone's biometric-bound approval key. The first key sticks: the same key again is fine,
    /// a different one needs `handsctl reset-approval-key` (or re-pairing), so a stolen unlocked phone
    /// cannot swap in a key that skips the biometric.
    fn register_approval_key(&self, body: &[u8]) -> Reply {
        let claimed = match self
            .authenticate::<ApprovalKeyBody>(body, |b| (&b.device_id, &b.client_nonce, b.ts))
        {
            Ok(v) => v,
            Err(r) => return r,
        };
        let Ok(spki) = b64d(&claimed.approval_pub) else {
            return err("bad_request");
        };
        if p256::ecdsa::VerifyingKey::from_public_key_der(&spki).is_err() {
            return err("bad_request");
        }
        let Some(dev) = b64d(&claimed.device_id)
            .ok()
            .and_then(|v| <[u8; 16]>::try_from(v).ok())
        else {
            return err("bad_request");
        };
        let mut devices = self.devices.lock().unwrap();
        let Some(rec) = devices.iter_mut().find(|d| d.id_bytes() == Some(dev)) else {
            return err("unauthorized");
        };
        match rec.approval_spki.as_deref().and_then(|s| b64d(s).ok()) {
            Some(existing) if !ct_eq(&existing, &spki) => return err("conflict"),
            Some(_) => {}
            None => {
                rec.approval_spki = Some(b64e(&spki));
                if self.store.save_devices(&devices).is_err() {
                    return err("internal");
                }
            }
        }
        drop(devices);
        self.sign_reply(
            DOMAIN_SERVER_REPLY,
            &ApprovalKeyReply {
                client_nonce: claimed.client_nonce,
            },
        )
    }

    fn approval_spki(&self, dev: &[u8; 16]) -> Option<Vec<u8>> {
        self.devices
            .lock()
            .unwrap()
            .iter()
            .find(|d| d.id_bytes() == Some(*dev))
            .and_then(|d| d.approval_spki.as_deref().and_then(|s| b64d(s).ok()))
    }

    /// Issues the single-use challenge a `biometric_protection` script run must be signed over.
    fn scripts_challenge(&self, body: &[u8]) -> Reply {
        let claimed = match self
            .authenticate::<ScriptChallengeBody>(body, |b| (&b.device_id, &b.client_nonce, b.ts))
        {
            Ok(v) => v,
            Err(r) => return r,
        };
        let Some(script) = self
            .cfg
            .scripts
            .iter()
            .find(|s| s.name == claimed.challenge_for)
        else {
            return err("unknown_script");
        };
        let Some(dev) = b64d(&claimed.device_id)
            .ok()
            .and_then(|v| <[u8; 16]>::try_from(v).ok())
        else {
            return err("bad_request");
        };
        if !script.biometric_protection {
            return err("bad_request");
        }
        // Refuse early so the user is not asked for a biometric that could not start the script anyway.
        if script.requires_unlock && !self.unlocked() {
            return err("not_unlocked");
        }
        if self.approval_spki(&dev).is_none() {
            return err("approval_required");
        }
        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        let expires = Instant::now() + SCRIPT_CHALLENGE_TTL;
        {
            let mut all = self.challenges.lock().unwrap();
            let now = Instant::now();
            all.retain(|c| c.expires > now && !(c.device == dev && c.script == script.name));
            if all.len() >= MAX_SCRIPT_CHALLENGES {
                return err("rate_limited");
            }
            all.push(ScriptChallenge {
                challenge,
                device: dev,
                script: script.name.clone(),
                expires,
            });
        }
        self.sign_reply(
            DOMAIN_SERVER_REPLY,
            &ScriptChallengeReply {
                client_nonce: claimed.client_nonce,
                script: script.name.clone(),
                challenge: b64e(&challenge),
                expires_at: unix_now() + SCRIPT_CHALLENGE_TTL.as_secs(),
            },
        )
    }

    /// Checks the approval for a `biometric_protection` script and burns the challenge, pass or fail.
    fn check_script_approval(
        &self,
        dev: &[u8; 16],
        script: &str,
        run: &ScriptRunBody,
    ) -> Result<(), Reply> {
        let (Some(challenge), Some(sig)) = (
            run.challenge
                .as_deref()
                .and_then(|c| b64d(c).ok())
                .and_then(|c| <[u8; 32]>::try_from(c).ok()),
            run.approval_sig.as_deref().and_then(|s| b64d(s).ok()),
        ) else {
            return Err(err("approval_required"));
        };
        let Some(spki) = self.approval_spki(dev) else {
            return Err(err("approval_required"));
        };
        let found = {
            let mut all = self.challenges.lock().unwrap();
            let now = Instant::now();
            let pos = all.iter().position(|c| {
                ct_eq(&c.challenge, &challenge) && c.device == *dev && c.script == script
            });
            let taken = pos.map(|i| all.swap_remove(i));
            all.retain(|c| c.expires > now);
            taken
        };
        match found {
            None => return Err(err("approval_required")),
            Some(c) if c.expires <= Instant::now() => return Err(err("expired")),
            Some(_) => {}
        }
        let msg = script_approve_message(&self.server_pub, dev, script, &challenge);
        if device_verify(&spki, &msg, &sig).is_err() {
            return Err(err("unauthorized"));
        }
        Ok(())
    }

    fn scripts_run(self: &Arc<Self>, body: &[u8]) -> Reply {
        let claimed = match self
            .authenticate::<ScriptRunBody>(body, |b| (&b.device_id, &b.client_nonce, b.ts))
        {
            Ok(v) => v,
            Err(r) => return r,
        };
        let Some(script) = self.cfg.scripts.iter().find(|s| s.name == claimed.script) else {
            return err("unknown_script");
        };
        if script.requires_unlock && !self.unlocked() {
            return err("not_unlocked");
        }
        if script.biometric_protection {
            let Some(dev) = b64d(&claimed.device_id)
                .ok()
                .and_then(|v| <[u8; 16]>::try_from(v).ok())
            else {
                return err("bad_request");
            };
            if let Err(r) = self.check_script_approval(&dev, &script.name, &claimed) {
                return r;
            }
        }
        if !self.claim_script(&script.name) {
            return err("busy");
        }
        let (ctx, s) = (self.clone(), script.clone());
        std::thread::spawn(move || ctx.execute_script(&s, "manual"));
        self.sign_reply(
            DOMAIN_SERVER_REPLY,
            &ScriptRunReply {
                client_nonce: claimed.client_nonce,
                script: claimed.script,
                state: RunState::Queued.as_str().into(),
            },
        )
    }
}

pub fn parse_id16(s: &str) -> Option<[u8; 16]> {
    hex_decode(s).ok()?.try_into().ok()
}

pub fn fmt_id(id: &[u8; 16]) -> String {
    hex_encode(id)
}
