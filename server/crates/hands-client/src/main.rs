//! hands-client: manual test client. State (device key + server pin) lives in `--dir` (default ~/.config/hands-client).
//!   hands-client pair 'hands://pair?...' [--name NAME]
//!   hands-client list
//!   hands-client approve <luks-uuid>...      (one passphrase line per uuid on stdin, in the same order)

use std::io::BufRead;
use std::path::PathBuf;

use hands_client::{parse_qr, Client, Device, Pin};
use zeroize::Zeroizing;

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    if let Err(e) = rt.block_on(run()) {
        eprintln!("hands-client: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut take_opt = |name: &str| -> Option<String> {
        let i = args.iter().position(|a| a == name)?;
        args.remove(i);
        (i < args.len()).then(|| args.remove(i))
    };
    let dir = take_opt("--dir").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
            .join(".config/hands-client")
    });
    let name = take_opt("--name").unwrap_or_else(|| "hands-client".into());
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let (key_path, pin_path) = (dir.join("device.key"), dir.join("server.json"));

    let device = match std::fs::read(&key_path) {
        Ok(b) => Device::from_bytes(&Zeroizing::new(b))?,
        Err(_) => {
            let d = Device::generate();
            write_private(&key_path, &d.to_bytes())?;
            d
        }
    };

    match args.first().map(String::as_str) {
        Some("pair") => {
            let qr = parse_qr(args.get(1).ok_or("usage: pair <hands://pair?...>")?)?;
            let client = Client {
                pin: qr.pin.clone(),
                device,
            };
            client
                .pair(&qr.token, &name, |sas| {
                    println!("Confirm on the server console that the code is {sas} ...")
                })
                .await?;
            std::fs::write(&pin_path, serde_json::to_vec_pretty(&qr.pin).unwrap())
                .map_err(|e| e.to_string())?;
            println!("paired");
        }
        Some("list") => {
            let client = load(&pin_path, device)?;
            let l = client.list().await?;
            for (i, r) in l.reply.requests.iter().enumerate() {
                println!("request {i}: id {} expires {}", r.req_id, r.expires_at);
                for d in &r.drives {
                    println!("  {}  {}  {} bytes", d.luks_uuid, d.label, d.size);
                }
            }
            if l.reply.requests.is_empty() {
                println!("no pending requests");
            }
        }
        Some("approve") => {
            let client = load(&pin_path, device)?;
            let uuids = &args[1..];
            if uuids.is_empty() {
                return Err("usage: approve <luks-uuid>...".into());
            }
            let stdin = std::io::stdin();
            let mut passes = vec![];
            for _ in uuids {
                let mut line = Zeroizing::new(String::new());
                stdin
                    .lock()
                    .read_line(&mut line)
                    .map_err(|e| e.to_string())?;
                passes.push(Zeroizing::new(
                    line.trim_end_matches(['\n', '\r']).as_bytes().to_vec(),
                ));
            }
            let listing = client.list().await?;
            let drives: Vec<(&str, &[u8])> = uuids
                .iter()
                .zip(&passes)
                .map(|(u, p)| (u.as_str(), p.as_slice()))
                .collect();
            let reply = client.approve(&listing, 0, &drives).await?;
            for r in reply.results {
                println!("{}  {}", r.luks_uuid, r.result);
            }
        }
        _ => {
            return Err(
                "usage: hands-client [--dir D] pair <url> | list | approve <uuid>...".into(),
            )
        }
    }
    Ok(())
}

fn load(path: &std::path::Path, device: Device) -> Result<Client, String> {
    let pin: Pin = serde_json::from_slice(&std::fs::read(path).map_err(|_| "not paired yet")?)
        .map_err(|e| e.to_string())?;
    Ok(Client { pin, device })
}

fn write_private(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| e.to_string())?;
    f.write_all(data).map_err(|e| e.to_string())
}
