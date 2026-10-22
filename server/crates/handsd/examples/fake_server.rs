//! Interop fixture for the Kotlin client tests: the real daemon over real TLS with a fake host.
//! One drive (UUID below) unlocks with passphrase "correct horse battery staple". Pairing is
//! auto-confirmed. Prints one JSON line (`host`, `port`, `spki`, `sid`, `token`) once ready.
//!   cargo run -p handsd --example fake_server
//! Env: HANDS_FAKE_BIND (default 127.0.0.1), HANDS_FAKE_HOST (printed host, e.g. 10.0.2.2 for an emulator).

use std::sync::{Arc, Mutex};

use hands_proto::codec::uuid_parse;
use hands_proto::{DriveInfo, Passphrase};
use handsd::config::{Config, DriveCfg, ScriptCfg, ScriptMode};
use handsd::host::Host;
use handsd::luks::UnlockResult;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const UUID: &str = "00000000-0000-4000-8000-000000000001";
const PASS: &[u8] = b"correct horse battery staple";

struct Fake(Mutex<Vec<DriveInfo>>, std::path::PathBuf);

impl Host for Fake {
    fn locked_drives(&self) -> Vec<DriveInfo> {
        self.0.lock().unwrap().clone()
    }
    fn any_open(&self) -> bool {
        false
    }
    fn unlock(&self, entries: Vec<([u8; 16], Passphrase)>) -> Vec<([u8; 16], UnlockResult)> {
        entries
            .into_iter()
            .map(|(u, p)| {
                if p.expose() == PASS {
                    self.0
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
    fn after_unlock(&self, _: &[[u8; 16]], all_done: bool) {
        if all_done {
            let _ = std::fs::write(self.1.join("unlocked"), b"");
        }
    }
    fn run_script(&self, _: &ScriptCfg, _: &str) -> bool {
        true
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let dir = std::env::temp_dir().join(format!("hands-fake-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let cfg = Config {
        state_dir: dir.join("state"),
        run_dir: dir.join("run"),
        drives: vec![DriveCfg {
            luks_uuid: UUID.into(),
            label: "Disk-1".into(),
        }],
        scripts: vec![
            ScriptCfg {
                name: "demo".into(),
                label: Some("Demo containers".into()),
                path: "/bin/true".into(),
                mode: ScriptMode::Manual,
                timeout_secs: 5,
                requires_unlock: true,
                requires_confirmation: false,
                biometric_protection: false,
            },
            ScriptCfg {
                name: "secure".into(),
                label: Some("Reboot".into()),
                path: "/bin/true".into(),
                mode: ScriptMode::Manual,
                timeout_secs: 5,
                requires_unlock: false,
                requires_confirmation: true,
                biometric_protection: true,
            },
        ],
        ..Config::default()
    };
    let host = Arc::new(Fake(
        Mutex::new(vec![DriveInfo {
            luks_uuid: UUID.into(),
            label: "Disk-1".into(),
            size: 4_000_000_000_000,
        }]),
        cfg.run_dir.clone(),
    ));
    let listener = std::net::TcpListener::bind(format!(
        "{}:0",
        std::env::var("HANDS_FAKE_BIND").unwrap_or("127.0.0.1".into())
    ))
    .unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let sock = cfg.run_dir.join("control.sock");
    tokio::spawn(handsd::run(cfg, host, Some(listener)));
    while !sock.exists() {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let (rd, mut wr) = tokio::net::UnixStream::connect(&sock)
        .await
        .unwrap()
        .into_split();
    let mut lines = BufReader::new(rd).lines();
    let call = |v: Value| std::future::ready(format!("{v}\n"));
    wr.write_all(call(json!({"cmd": "pair_start"})).await.as_bytes())
        .await
        .unwrap();
    let s: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    println!(
        "{}",
        json!({"host": std::env::var("HANDS_FAKE_HOST").unwrap_or("127.0.0.1".into()), "port": port, "spki": s["spki"], "sid": s["sid"], "token": s["token"]})
    );

    // Auto-confirm whatever pairs (this is a test fixture, there is no operator).
    wr.write_all(call(json!({"cmd": "pair_wait"})).await.as_bytes())
        .await
        .unwrap();
    let _ = lines.next_line().await;
    wr.write_all(
        call(json!({"cmd": "pair_confirm", "accept": true}))
            .await
            .as_bytes(),
    )
    .await
    .unwrap();
    let _ = lines.next_line().await;
    std::future::pending::<()>().await;
}
