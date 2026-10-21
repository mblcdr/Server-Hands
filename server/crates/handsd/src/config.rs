//! `/etc/server-hands/config.toml`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use hands_proto::codec::uuid_parse;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriveCfg {
    pub luks_uuid: String,
    pub label: String,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostUnlock {
    /// Mount units started (after `reset-failed`) once every configured drive is unlocked and mounted.
    #[serde(default)]
    pub mount_units: Vec<String>,
    /// Started without waiting, after `/run/server-hands/unlocked` exists.
    #[serde(default)]
    pub service_units: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptMode {
    /// Runs by itself as soon as every configured drive is unlocked.
    Auto,
    /// Only runs when started from the phone.
    #[default]
    Manual,
}

/// A script run as root, outside the daemon's sandbox, after the drives are unlocked.
/// The phone can only name a script from this list; it never supplies a path or arguments.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptCfg {
    /// `[A-Za-z0-9_-]{1,32}`; also part of the transient unit name.
    pub name: String,
    /// Shown in the app. Defaults to `name`.
    #[serde(default)]
    pub label: Option<String>,
    /// Absolute path of an executable owned by root and not writable by anyone else.
    pub path: PathBuf,
    #[serde(default)]
    pub mode: ScriptMode,
    #[serde(default = "default_script_timeout")]
    pub timeout_secs: u64,
}

impl ScriptCfg {
    pub fn display(&self) -> &str {
        self.label.as_deref().unwrap_or(&self.name)
    }
}

fn default_script_timeout() -> u64 {
    300
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_ttl")]
    pub request_ttl_secs: u64,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    #[serde(default = "default_run_dir")]
    pub run_dir: PathBuf,
    /// Host or IP printed in the pairing QR. `handsctl pair --host` overrides it.
    #[serde(default)]
    pub advertise_host: Option<String>,
    /// argv prefix used to start the unlock child in its own cgroup. Empty = spawn directly.
    #[serde(default = "default_wrapper")]
    pub unlock_wrapper: Vec<String>,
    #[serde(default, rename = "drive")]
    pub drives: Vec<DriveCfg>,
    #[serde(default)]
    pub post_unlock: PostUnlock,
    #[serde(default, rename = "script")]
    pub scripts: Vec<ScriptCfg>,
}

fn default_listen() -> String {
    "0.0.0.0:7787".into()
}
fn default_ttl() -> u64 {
    600
}
fn default_state_dir() -> PathBuf {
    "/var/lib/server-hands".into()
}
fn default_run_dir() -> PathBuf {
    "/run/server-hands".into()
}
/// ProtectSystem=full (not strict): libcryptsetup keeps its lock files under /run/cryptsetup.
fn default_wrapper() -> Vec<String> {
    [
        "systemd-run",
        "--quiet",
        "--pipe",
        "--wait",
        "--collect",
        "--service-type=exec",
        "--property=MemoryMax=1536M",
        "--property=MemorySwapMax=0",
        "--property=LimitMEMLOCK=infinity",
        "--property=LimitCORE=0",
        "--property=NoNewPrivileges=yes",
        "--property=PrivateTmp=yes",
        "--property=ProtectHome=yes",
        "--property=ProtectSystem=full",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), String> {
        let mut seen = HashSet::new();
        for d in &self.drives {
            let raw =
                uuid_parse(&d.luks_uuid).map_err(|_| format!("bad luks_uuid {:?}", d.luks_uuid))?;
            if !seen.insert(raw) {
                return Err(format!("duplicate luks_uuid {}", d.luks_uuid));
            }
        }
        let mut names = HashSet::new();
        for sc in &self.scripts {
            let ok_name = !sc.name.is_empty()
                && sc.name.len() <= 32
                && sc
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            if !ok_name {
                return Err(format!("bad script name {:?}", sc.name));
            }
            if !names.insert(sc.name.as_str()) {
                return Err(format!("duplicate script name {}", sc.name));
            }
            if !sc.path.is_absolute() {
                return Err(format!("script {}: path must be absolute", sc.name));
            }
            if sc.timeout_secs == 0 || sc.timeout_secs > 3600 {
                return Err(format!("script {}: timeout_secs must be 1..=3600", sc.name));
            }
            if sc
                .label
                .as_ref()
                .is_some_and(|l| l.is_empty() || l.len() > 64)
            {
                return Err(format!("script {}: label must be 1..=64 bytes", sc.name));
            }
        }
        if self.request_ttl_secs == 0 || self.request_ttl_secs > 3600 {
            return Err("request_ttl_secs must be 1..=3600".into());
        }
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        toml::from_str("").expect("empty config is valid")
    }
}
