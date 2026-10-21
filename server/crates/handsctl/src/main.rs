//! handsctl: discover | pair | devices | revoke | status | add-phone-key. Talks to handsd over its root-only
//! control socket; `discover` and `add-phone-key` work on the block devices directly.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use hands_proto::codec::{b64e, uuid_format, uuid_parse};
use handsd::config::{Config, DriveCfg};
use handsd::luks::{self, LuksBackend};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use zeroize::Zeroizing;

const USAGE: &str = "usage: handsctl [--config PATH] <command>
  discover [--write]          list LUKS containers and (with --write) put them in the config
  status                      drives, pending requests, paired devices
  pair [--host HOST]          show a pairing QR, confirm the 6-digit code
  devices                     list paired devices
  revoke <device-id-prefix>   revoke a paired device
  add-phone-key <luks-uuid>   add a random keyslot for the phone; prints it once";

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let config_path = take_opt(&mut args, "--config")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/etc/server-hands/config.toml".into());
    let result = match args.first().map(String::as_str) {
        Some("discover") => discover(&config_path, args.iter().any(|a| a == "--write")),
        Some("status") => status(&config_path),
        Some("pair") => pair(&config_path, take_opt(&mut args, "--host")),
        Some("devices") => devices(&config_path),
        Some("revoke") => revoke(&config_path, args.get(1)),
        Some("add-phone-key") => add_phone_key(args.get(1)),
        _ => Err(USAGE.to_string()),
    };
    if let Err(e) = result {
        eprintln!("handsctl: {e}");
        std::process::exit(1);
    }
}

fn take_opt(args: &mut Vec<String>, name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    args.remove(i);
    (i < args.len()).then(|| args.remove(i))
}

fn load_config(path: &Path) -> Result<Config, String> {
    if path.exists() {
        Config::load(path)
    } else {
        Ok(Config::default())
    }
}

struct Control {
    rd: BufReader<UnixStream>,
    wr: UnixStream,
}

impl Control {
    fn connect(cfg: &Config) -> Result<Self, String> {
        let path = cfg.run_dir.join("control.sock");
        let s = UnixStream::connect(&path).map_err(|e| {
            format!(
                "cannot reach handsd at {} ({e}); is it running, and are you root?",
                path.display()
            )
        })?;
        Ok(Self {
            rd: BufReader::new(s.try_clone().map_err(|e| e.to_string())?),
            wr: s,
        })
    }
    fn call(&mut self, v: Value) -> Result<Value, String> {
        writeln!(self.wr, "{v}").map_err(|e| e.to_string())?;
        let mut line = String::new();
        self.rd.read_line(&mut line).map_err(|e| e.to_string())?;
        let r: Value =
            serde_json::from_str(&line).map_err(|_| "handsd closed the connection".to_string())?;
        if r["ok"] == true {
            Ok(r)
        } else {
            Err(r["error"].as_str().unwrap_or("failed").to_string())
        }
    }
}

fn discover(config_path: &Path, write: bool) -> Result<(), String> {
    let found = luks::discover("/etc/crypttab".as_ref());
    if found.is_empty() {
        return Err("no LUKS containers found (run as root)".into());
    }
    let mut drives = vec![];
    for f in &found {
        let label = if f.label.is_empty() {
            f.kernel.clone()
        } else {
            f.label.clone()
        };
        println!(
            "{}  {:<12} {:>8.1} GB  {}{}",
            uuid_format(&f.uuid),
            label,
            f.size as f64 / 1e9,
            f.kernel,
            if f.in_crypttab {
                "  SKIPPED: has a /etc/crypttab entry (systemd would try to unlock it itself)"
            } else if f.active {
                "  (already open)"
            } else {
                ""
            }
        );
        if !f.in_crypttab {
            drives.push(DriveCfg {
                luks_uuid: uuid_format(&f.uuid),
                label,
            });
        }
    }
    if write {
        let mut cfg = load_config(config_path)?;
        cfg.drives = drives;
        std::fs::write(
            config_path,
            toml::to_string_pretty(&cfg).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        println!(
            "wrote {} drive(s) to {}",
            cfg.drives.len(),
            config_path.display()
        );
    } else {
        println!(
            "\n(re-run with --write to store these in {}, then edit labels / post_unlock)",
            config_path.display()
        );
    }
    Ok(())
}

fn status(config_path: &Path) -> Result<(), String> {
    let r = Control::connect(&load_config(config_path)?)?.call(json!({"cmd": "status"}))?;
    for d in r["drives"].as_array().into_iter().flatten() {
        println!(
            "{}  {:<12} {}",
            d["luks_uuid"].as_str().unwrap_or("?"),
            d["label"].as_str().unwrap_or(""),
            d["state"].as_str().unwrap_or("?")
        );
    }
    println!(
        "pending requests: {}   paired devices: {}",
        r["pending"], r["devices"]
    );
    Ok(())
}

fn devices(config_path: &Path) -> Result<(), String> {
    let r = Control::connect(&load_config(config_path)?)?.call(json!({"cmd": "devices"}))?;
    for d in r["devices"].as_array().into_iter().flatten() {
        println!(
            "{}  {}  paired {}",
            d["id"].as_str().unwrap_or("?"),
            d["name"].as_str().unwrap_or(""),
            d["created_at"]
        );
    }
    Ok(())
}

fn revoke(config_path: &Path, id: Option<&String>) -> Result<(), String> {
    let id = id.ok_or("usage: revoke <device-id-prefix>")?;
    let r =
        Control::connect(&load_config(config_path)?)?.call(json!({"cmd": "revoke", "id": id}))?;
    println!(
        "revoked {} ({})",
        r["revoked"].as_str().unwrap_or("?"),
        r["name"].as_str().unwrap_or("")
    );
    println!("Also kill the phone keyslot so a copied vault is useless:  cryptsetup luksKillSlot <device> <slot>");
    Ok(())
}

fn local_ip() -> Option<String> {
    let out = std::process::Command::new("hostname")
        .arg("-I")
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .map(str::to_string)
}

fn pair(config_path: &Path, host: Option<String>) -> Result<(), String> {
    let cfg = load_config(config_path)?;
    let mut ctl = Control::connect(&cfg)?;
    let s = ctl.call(json!({"cmd": "pair_start"}))?;
    let host = host
        .or_else(|| s["host"].as_str().map(str::to_string))
        .or_else(local_ip)
        .ok_or("cannot determine host; pass --host")?;
    let url = format!(
        "hands://pair?v=1&host={host}&port={}&spki={}&sid={}&tok={}",
        s["port"],
        s["spki"].as_str().unwrap_or(""),
        s["sid"].as_str().unwrap_or(""),
        s["token"].as_str().unwrap_or("")
    );
    let qr = qrcode::QrCode::with_error_correction_level(url.as_bytes(), qrcode::EcLevel::L)
        .map_err(|e| e.to_string())?;
    println!("{}", render_qr(&qr));
    println!("{url}\n");
    println!(
        "Scan with the app within {} seconds. Waiting for the phone...",
        s["expires_in"]
    );
    let w = ctl.call(json!({"cmd": "pair_wait"}))?;
    println!(
        "Device \"{}\" wants to pair. Code shown on its screen must be:  {}",
        w["name"].as_str().unwrap_or("?"),
        w["sas"].as_str().unwrap_or("?")
    );
    print!("Does the phone show the same code? [y/N] ");
    std::io::stdout().flush().ok();
    let mut ans = String::new();
    std::io::stdin()
        .read_line(&mut ans)
        .map_err(|e| e.to_string())?;
    let accept = ans.trim().eq_ignore_ascii_case("y");
    ctl.call(json!({"cmd": "pair_confirm", "accept": accept}))?;
    println!("{}", if accept { "paired" } else { "rejected" });
    Ok(())
}

/// Black on white with explicit ANSI colours (two rows per text line), so the code is not inverted on dark
/// terminals. Scanners need dark modules on a light background plus a 4-module light border.
fn render_qr(qr: &qrcode::QrCode) -> String {
    use qrcode::Color;
    const QUIET: usize = 4;
    let w = qr.width();
    let side = w + 2 * QUIET;
    let dark = |x: usize, y: usize| {
        x >= QUIET
            && y >= QUIET
            && x < QUIET + w
            && y < QUIET + w
            && qr[(x - QUIET, y - QUIET)] == Color::Dark
    };
    let paint = |on: bool| if on { 16 } else { 231 }; // xterm black / white
    let mut out = String::new();
    for y in (0..side).step_by(2) {
        for x in 0..side {
            out += &format!(
                "\x1b[38;5;{}m\x1b[48;5;{}m\u{2580}",
                paint(dark(x, y)),
                paint(y + 1 < side && dark(x, y + 1))
            );
        }
        out += "\x1b[0m\n";
    }
    out
}

fn read_secret(prompt: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    eprint!("{prompt}");
    let fd = 0;
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    let tty = unsafe { libc::tcgetattr(fd, &mut old) } == 0;
    if tty {
        let mut quiet = old;
        quiet.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) };
    }
    let mut line = Zeroizing::new(String::new());
    let r = std::io::stdin().lock().read_line(&mut line);
    if tty {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) };
        eprintln!();
    }
    r.map_err(|e| e.to_string())?;
    Ok(Zeroizing::new(
        line.trim_end_matches(['\n', '\r']).as_bytes().to_vec(),
    ))
}

fn add_phone_key(uuid: Option<&String>) -> Result<(), String> {
    let uuid =
        uuid_parse(uuid.ok_or("usage: add-phone-key <luks-uuid>")?).map_err(|_| "bad uuid")?;
    luks::kernel_name(&uuid).ok_or("container not present")?;
    let existing = read_secret("Existing passphrase (recovery): ")?;
    let mut raw = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut raw[..]);
    let phone = Zeroizing::new(b64e(&raw[..]).into_bytes());
    luks::Cryptsetup::open()?.add_key(&luks::by_uuid(&uuid), &existing, &phone)?;
    println!(
        "Phone passphrase for {} (shown once, enter it in the app):",
        uuid_format(&uuid)
    );
    println!("{}", String::from_utf8_lossy(&phone));
    Ok(())
}
