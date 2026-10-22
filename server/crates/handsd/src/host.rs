//! Everything that touches the machine, behind a trait so the daemon logic is testable off-box.

use std::path::PathBuf;

use hands_proto::{DriveInfo, Passphrase};

use crate::config::{Config, ScriptCfg};
use crate::luks::UnlockResult;
use crate::sysinfo::{self, SystemStatus};
use crate::{system, unlock};

pub trait Host: Send + Sync + 'static {
    /// Configured drives that are present, not in crypttab and not open.
    fn locked_drives(&self) -> Vec<DriveInfo>;
    /// True when at least one configured drive is currently open.
    fn any_open(&self) -> bool;
    /// Blocking. Activates each container; never returns secrets.
    fn unlock(&self, entries: Vec<([u8; 16], Passphrase)>) -> Vec<([u8; 16], UnlockResult)>;
    /// Blocking. Mounts newly unlocked drives; when `all_done`, runs the post-unlock sequence.
    fn after_unlock(&self, unlocked: &[[u8; 16]], all_done: bool);
    /// Blocking. Runs one post-unlock script; true when it succeeded. `trigger` is `auto` or `manual`.
    fn run_script(&self, script: &ScriptCfg, trigger: &str) -> bool;
    /// Blocking. Uptime, CPU and memory counters, drive and pool usage. Read-only.
    fn status(&self) -> SystemStatus {
        SystemStatus::default()
    }
}

pub struct LinuxHost {
    pub cfg: Config,
    pub exe: PathBuf,
}

impl Host for LinuxHost {
    fn locked_drives(&self) -> Vec<DriveInfo> {
        system::locked_drives(&self.cfg, "/etc/crypttab".as_ref())
    }

    fn any_open(&self) -> bool {
        self.cfg.drives.iter().any(|d| {
            hands_proto::codec::uuid_parse(&d.luks_uuid)
                .ok()
                .and_then(|u| crate::luks::kernel_name(&u))
                .is_some_and(|k| crate::luks::is_active(&k))
        })
    }

    fn unlock(&self, entries: Vec<([u8; 16], Passphrase)>) -> Vec<([u8; 16], UnlockResult)> {
        unlock::run_child(&self.cfg.unlock_wrapper, &self.exe, &entries)
    }

    fn after_unlock(&self, unlocked: &[[u8; 16]], all_done: bool) {
        system::mount_drives(unlocked, "/etc/fstab".as_ref());
        if all_done {
            system::post_unlock(&self.cfg.post_unlock, &self.cfg.run_dir);
        }
    }

    fn run_script(&self, script: &ScriptCfg, trigger: &str) -> bool {
        system::run_script(script, trigger)
    }

    fn status(&self) -> SystemStatus {
        sysinfo::collect(&self.cfg)
    }
}
