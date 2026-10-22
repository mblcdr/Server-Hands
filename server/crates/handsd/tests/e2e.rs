//! End to end over real TLS: pairing with SAS confirmation, listing, approving, unlock results.
//! The host is faked (no cryptsetup); everything else is the production code path.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hands_client::{Client, Device, Pin};
use hands_proto::codec::uuid_parse;
use hands_proto::{DriveInfo, Passphrase};
use handsd::config::{Config, DriveCfg, ScriptCfg, ScriptMode};
use handsd::host::Host;
use handsd::luks::UnlockResult;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

const UUID: &str = "00000000-0000-4000-8000-000000000001";
const PASS: &[u8] = b"correct horse battery staple";

#[derive(Default)]
struct FakeHost {
    locked: Mutex<Vec<DriveInfo>>,
    mounted: Mutex<Vec<[u8; 16]>>,
    post_unlock_runs: AtomicUsize,
    scripts_run: Mutex<Vec<String>>,
}

impl Host for FakeHost {
    fn locked_drives(&self) -> Vec<DriveInfo> {
        self.locked.lock().unwrap().clone()
    }
    fn any_open(&self) -> bool {
        false
    }
    fn unlock(&self, entries: Vec<([u8; 16], Passphrase)>) -> Vec<([u8; 16], UnlockResult)> {
        entries
            .into_iter()
            .map(|(u, p)| {
                if p.expose() == PASS {
                    self.locked
                        .lock()
                        .unwrap()
                        .retain(|d| uuid_parse(&d.luks_uuid).unwrap() != u);
                    (u, UnlockResult::Ok)
                } else {
                    (u, UnlockResult::BadPassphrase)
                }
            })
            .collect()
    }
    fn run_script(&self, script: &handsd::config::ScriptCfg, _trigger: &str) -> bool {
        self.scripts_run.lock().unwrap().push(script.name.clone());
        script.name != "bad"
    }
    fn after_unlock(&self, unlocked: &[[u8; 16]], all_done: bool) {
        self.mounted.lock().unwrap().extend_from_slice(unlocked);
        if all_done {
            self.post_unlock_runs.fetch_add(1, Ordering::SeqCst);
        }
    }
}

struct Env {
    run_dir: PathBuf,
    host: Arc<FakeHost>,
    control: PathBuf,
    port: u16,
}

static N: AtomicUsize = AtomicUsize::new(0);

async fn start() -> Env {
    let dir = std::env::temp_dir().join(format!(
        "hk{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let cfg = Config {
        state_dir: dir.join("state"),
        run_dir: dir.join("run"),
        drives: vec![DriveCfg {
            luks_uuid: UUID.into(),
            label: "Disk-1".into(),
        }],
        scripts: ["auto1", "man1", "bad", "free", "bio"]
            .iter()
            .map(|n| ScriptCfg {
                name: n.to_string(),
                label: None,
                path: format!("/opt/{n}.sh").into(),
                mode: if *n == "auto1" {
                    ScriptMode::Auto
                } else {
                    ScriptMode::Manual
                },
                timeout_secs: 5,
                requires_unlock: *n != "free" && *n != "bio",
                requires_confirmation: *n == "bio",
                biometric_protection: *n == "bio",
            })
            .collect(),
        ..Config::default()
    };
    let host = Arc::new(FakeHost::default());
    host.locked.lock().unwrap().push(DriveInfo {
        luks_uuid: UUID.into(),
        label: "Disk-1".into(),
        size: 4_000_000_000_000,
    });
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let control = cfg.run_dir.join("control.sock");
    tokio::spawn(handsd::run(cfg, host.clone(), Some(listener)));
    for _ in 0..200 {
        if control.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Env {
        run_dir: dir.join("run"),
        host,
        control,
        port,
    }
}

struct Ctl {
    lines: tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    wr: tokio::net::unix::OwnedWriteHalf,
}

impl Ctl {
    async fn connect(env: &Env) -> Self {
        let (rd, wr) = UnixStream::connect(&env.control)
            .await
            .unwrap()
            .into_split();
        Ctl {
            lines: BufReader::new(rd).lines(),
            wr,
        }
    }
    async fn call(&mut self, v: Value) -> Value {
        self.wr
            .write_all(format!("{v}\n").as_bytes())
            .await
            .unwrap();
        serde_json::from_str(&self.lines.next_line().await.unwrap().unwrap()).unwrap()
    }
}

/// Pairs a fresh device; the operator accepts or rejects. Returns the client on success.
async fn pair(env: &Env, accept: bool) -> Result<Client, String> {
    let mut ctl = Ctl::connect(env).await;
    let s = ctl.call(json!({"cmd": "pair_start"})).await;
    let pin = Pin {
        host: "127.0.0.1".into(),
        port: env.port,
        spki: s["spki"].as_str().unwrap().into(),
        sid: s["sid"].as_str().unwrap().into(),
    };
    let token = s["token"].as_str().unwrap().to_string();
    let client = Client {
        pin,
        device: Device::generate(),
    };

    let phone = async {
        let mut shown = String::new();
        let r = client
            .pair(&token, "test phone", |c| shown = c.to_string())
            .await;
        (r, shown)
    };
    let operator = async {
        let w = ctl.call(json!({"cmd": "pair_wait"})).await;
        let c = ctl
            .call(json!({"cmd": "pair_confirm", "accept": accept}))
            .await;
        assert_eq!(c["ok"], true);
        w
    };
    let ((res, shown), waited) = tokio::join!(phone, operator);
    assert_eq!(
        waited["sas"].as_str().unwrap(),
        shown,
        "both sides must show the same SAS"
    );
    res.map(|_| client)
}

#[tokio::test]
async fn pair_list_approve_unlocks_and_runs_post_unlock() {
    let env = start().await;
    let client = pair(&env, true).await.unwrap();

    let listing = client.list().await.unwrap();
    assert_eq!(listing.reply.requests.len(), 1);
    let r = &listing.reply.requests[0];
    assert_eq!(
        (r.drives[0].luks_uuid.as_str(), r.drives[0].label.as_str()),
        (UUID, "Disk-1")
    );

    let reply = client.approve(&listing, 0, &[(UUID, PASS)]).await.unwrap();
    assert_eq!(reply.results[0].result, "ok");
    assert_eq!(
        env.host.mounted.lock().unwrap().as_slice(),
        &[uuid_parse(UUID).unwrap()]
    );
    assert_eq!(env.host.post_unlock_runs.load(Ordering::SeqCst), 1);
    assert!(
        client.list().await.unwrap().reply.requests.is_empty(),
        "nothing left to unlock"
    );
}

#[tokio::test]
async fn wrong_passphrase_yields_fresh_request_and_old_one_is_dead() {
    let env = start().await;
    let client = pair(&env, true).await.unwrap();
    let first = client.list().await.unwrap();
    let reply = client.approve(&first, 0, &[(UUID, b"nope")]).await.unwrap();
    assert_eq!(reply.results[0].result, "bad_passphrase");
    assert_eq!(env.host.post_unlock_runs.load(Ordering::SeqCst), 0);

    let second = client.list().await.unwrap();
    assert_eq!(second.reply.requests.len(), 1);
    assert_ne!(
        second.reply.requests[0].req_id,
        first.reply.requests[0].req_id
    );
    assert_ne!(
        second.reply.requests[0].e_pub, first.reply.requests[0].e_pub,
        "fresh ephemeral key"
    );

    // Replaying the first (consumed) request fails.
    assert!(client.approve(&first, 0, &[(UUID, PASS)]).await.is_err());
    // The retry works.
    assert_eq!(
        client
            .approve(&second, 0, &[(UUID, PASS)])
            .await
            .unwrap()
            .results[0]
            .result,
        "ok"
    );
}

#[tokio::test]
async fn unpaired_device_and_wrong_pin_are_refused() {
    let env = start().await;
    let paired = pair(&env, true).await.unwrap();

    let stranger = Client {
        pin: paired.pin.clone(),
        device: Device::generate(),
    };
    assert!(stranger.list().await.err().unwrap().contains("401"));

    let mut bad_pin = paired.pin.clone();
    bad_pin.spki = hands_proto::codec::b64e(&[0u8; 32]);
    let impostor_view = Client {
        pin: bad_pin,
        device: Device::generate(),
    };
    assert!(impostor_view.list().await.err().unwrap().contains("tls"));
}

#[tokio::test]
async fn operator_rejection_and_bad_token_do_not_pair() {
    let env = start().await;
    assert!(pair(&env, false).await.is_err());

    let mut ctl = Ctl::connect(&env).await;
    let s = ctl.call(json!({"cmd": "pair_start"})).await;
    let pin = Pin {
        host: "127.0.0.1".into(),
        port: env.port,
        spki: s["spki"].as_str().unwrap().into(),
        sid: s["sid"].as_str().unwrap().into(),
    };
    let c = Client {
        pin,
        device: Device::generate(),
    };
    let wrong = hands_proto::codec::b64e(&[9u8; 32]);
    assert!(c
        .pair(&wrong, "x", |_| {})
        .await
        .err()
        .unwrap()
        .contains("401"));
    // the real token still works afterwards (one wrong guess does not burn it)
    let token = s["token"].as_str().unwrap().to_string();
    let phone = c.pair(&token, "x", |_| {});
    let operator = async {
        ctl.call(json!({"cmd": "pair_wait"})).await;
        ctl.call(json!({"cmd": "pair_confirm", "accept": true}))
            .await;
    };
    let (r, _) = tokio::join!(phone, operator);
    r.unwrap();
}

#[tokio::test]
async fn revoked_device_is_locked_out() {
    let env = start().await;
    let client = pair(&env, true).await.unwrap();
    client.list().await.unwrap();

    let mut ctl = Ctl::connect(&env).await;
    let devs = ctl.call(json!({"cmd": "devices"})).await;
    let id = devs["devices"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(
        ctl.call(json!({"cmd": "revoke", "id": id})).await["ok"],
        true
    );
    assert!(client.list().await.err().unwrap().contains("401"));
}

async fn wait_state(client: &Client, name: &str, want: &str) {
    for _ in 0..200 {
        let r = client.scripts().await.unwrap();
        if r.scripts.iter().any(|s| s.name == name && s.state == want) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("script {name} never reached {want}");
}

#[tokio::test]
async fn scripts_wait_for_unlock_then_auto_runs_and_manual_is_phone_started() {
    let env = start().await;
    let client = pair(&env, true).await.unwrap();

    let before = client.scripts().await.unwrap();
    assert!(!before.unlocked);
    assert!(before.scripts.iter().all(|s| s.state == "idle"));
    assert!(client
        .run_script("man1")
        .await
        .err()
        .unwrap()
        .contains("409"));
    assert!(client
        .run_script("nope")
        .await
        .err()
        .unwrap()
        .contains("404"));

    let listing = client.list().await.unwrap();
    client.approve(&listing, 0, &[(UUID, PASS)]).await.unwrap();
    // The fake host does not write the marker the real one does.
    std::fs::write(env.run_dir.join("unlocked"), b"").unwrap();

    wait_state(&client, "auto1", "ok").await;
    let mid = client.scripts().await.unwrap();
    assert!(mid.unlocked);
    assert_eq!(
        mid.scripts.iter().find(|s| s.name == "man1").unwrap().state,
        "idle"
    );

    client.run_script("man1").await.unwrap();
    wait_state(&client, "man1", "ok").await;
    client.run_script("bad").await.unwrap();
    wait_state(&client, "bad", "failed").await;
    assert_eq!(
        env.host.scripts_run.lock().unwrap().as_slice(),
        ["auto1", "man1", "bad"]
    );
}

#[tokio::test]
async fn manual_script_without_requires_unlock_runs_while_drives_are_locked() {
    let env = start().await;
    let client = pair(&env, true).await.unwrap();

    assert!(!client.scripts().await.unwrap().unlocked);
    client.run_script("free").await.unwrap();
    wait_state(&client, "free", "ok").await;
    assert_eq!(env.host.scripts_run.lock().unwrap().as_slice(), ["free"]);
}

#[tokio::test]
async fn biometric_script_needs_a_registered_key_and_a_fresh_server_challenge() {
    let env = start().await;
    let client = pair(&env, true).await.unwrap();
    let approval = hands_client::Device::generate();

    let views = client.scripts().await.unwrap().scripts;
    let bio = views.iter().find(|s| s.name == "bio").unwrap();
    assert!(bio.biometric_protection && bio.requires_confirmation);
    let free = views.iter().find(|s| s.name == "free").unwrap();
    assert!(!free.biometric_protection && !free.requires_confirmation);

    // No key registered yet: no challenge, and a plain run is refused.
    assert!(client
        .script_challenge("bio")
        .await
        .unwrap_err()
        .contains("403"));
    assert!(client.run_script("bio").await.unwrap_err().contains("403"));
    // Challenges exist only for protected scripts.
    assert!(client
        .script_challenge("free")
        .await
        .unwrap_err()
        .contains("400"));
    assert!(client
        .script_challenge("nope")
        .await
        .unwrap_err()
        .contains("404"));

    client.register_approval_key(&approval).await.unwrap();
    client.register_approval_key(&approval).await.unwrap(); // same key again is fine
    let other = hands_client::Device::generate();
    assert!(client
        .register_approval_key(&other)
        .await
        .unwrap_err()
        .contains("409"));

    // Still refused without the approval.
    assert!(client.run_script("bio").await.unwrap_err().contains("403"));
    assert!(env.host.scripts_run.lock().unwrap().is_empty());

    // The full flow works while the drives are locked (this script does not require the unlock).
    client.run_script_approved("bio", &approval).await.unwrap();
    wait_state(&client, "bio", "ok").await;
    assert_eq!(env.host.scripts_run.lock().unwrap().as_slice(), ["bio"]);
}

#[tokio::test]
async fn biometric_approval_is_single_use_and_bound_to_key_script_and_device() {
    use hands_proto::codec::{b64d, b64e};
    use hands_proto::sign::script_approve_message;

    let env = start().await;
    let client = pair(&env, true).await.unwrap();
    let approval = hands_client::Device::generate();
    client.register_approval_key(&approval).await.unwrap();
    let sid: [u8; 32] = b64d(&client.pin.sid).unwrap().try_into().unwrap();
    let sign = |script: &str, challenge: &str| {
        let ch: [u8; 32] = b64d(challenge).unwrap().try_into().unwrap();
        approval.sign(&script_approve_message(
            &sid,
            &client.device.id(),
            script,
            &ch,
        ))
    };

    // A challenge cannot be replayed once used.
    let c = client.script_challenge("bio").await.unwrap();
    let sig = sign("bio", &c.challenge);
    client
        .run_script_with("bio", Some(&c.challenge), Some(&sig))
        .await
        .unwrap();
    wait_state(&client, "bio", "ok").await;
    assert!(client
        .run_script_with("bio", Some(&c.challenge), Some(&sig))
        .await
        .unwrap_err()
        .contains("403"));

    // A signature from a different key is refused, and burns the challenge.
    let c = client.script_challenge("bio").await.unwrap();
    let forged = hands_client::Device::generate().sign(&{
        let ch: [u8; 32] = b64d(&c.challenge).unwrap().try_into().unwrap();
        script_approve_message(&sid, &client.device.id(), "bio", &ch)
    });
    assert!(client
        .run_script_with("bio", Some(&c.challenge), Some(&forged))
        .await
        .unwrap_err()
        .contains("401"));
    let good = sign("bio", &c.challenge);
    assert!(client
        .run_script_with("bio", Some(&c.challenge), Some(&good))
        .await
        .unwrap_err()
        .contains("403"));

    // A signature over another script name does not verify.
    let c = client.script_challenge("bio").await.unwrap();
    let wrong_script = sign("man1", &c.challenge);
    assert!(client
        .run_script_with("bio", Some(&c.challenge), Some(&wrong_script))
        .await
        .unwrap_err()
        .contains("401"));

    // A made-up challenge is refused.
    let made_up = b64e(&[7u8; 32]);
    let sig = sign("bio", &made_up);
    assert!(client
        .run_script_with("bio", Some(&made_up), Some(&sig))
        .await
        .unwrap_err()
        .contains("403"));
}
