//! Host integration: process hardening, systemctl, fstab, and the post-unlock sequence.

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hands_proto::codec::uuid_format;

use crate::config::{Config, PostUnlock, ScriptCfg};
use crate::luks;

/// Must run before any secret can exist in the process.
pub fn harden(lock_memory: bool) {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
        if lock_memory {
            libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = lock_memory;
}

/// Drives from the config that are present, not in crypttab and not yet open.
pub fn locked_drives(cfg: &Config, crypttab: &Path) -> Vec<hands_proto::DriveInfo> {
    let tab = luks::crypttab_uuids(crypttab);
    let mut out = vec![];
    for d in &cfg.drives {
        let Ok(uuid) = hands_proto::codec::uuid_parse(&d.luks_uuid) else {
            continue;
        };
        let Some(kernel) = luks::kernel_name(&uuid) else {
            continue;
        };
        if tab.contains(&uuid) || luks::is_active(&kernel) {
            continue;
        }
        out.push(hands_proto::DriveInfo {
            luks_uuid: uuid_format(&uuid),
            label: d.label.clone(),
            size: luks::size_bytes(&kernel),
        });
    }
    out
}

fn systemctl(args: &[&str]) -> bool {
    Command::new("systemctl")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// ext4 superblock UUID of a (decrypted) block device: magic 0xEF53 at 1080, UUID at 1128.
pub fn ext4_uuid(dev: &Path) -> Option<String> {
    let mut f = fs::File::open(dev).ok()?;
    f.seek(SeekFrom::Start(1024)).ok()?;
    let mut sb = [0u8; 0x78];
    f.read_exact(&mut sb).ok()?;
    if u16::from_le_bytes([sb[0x38], sb[0x39]]) != 0xEF53 {
        return None;
    }
    let raw: [u8; 16] = sb[0x68..0x78].try_into().ok()?;
    Some(uuid_format(&raw))
}

/// Mount point of the fstab entry for a filesystem UUID.
pub fn fstab_mountpoint(fstab: &Path, fs_uuid: &str) -> Option<String> {
    let text = fs::read_to_string(fstab).ok()?;
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| {
            let mut it = l.split_whitespace();
            let (src, mp) = (it.next()?, it.next()?);
            let id = src
                .strip_prefix("UUID=")
                .or_else(|| src.strip_prefix("/dev/disk/by-uuid/"))?;
            id.eq_ignore_ascii_case(fs_uuid).then(|| mp.to_string())
        })
}

/// Waits for the decrypted device to carry a readable filesystem, then lets systemd mount it.
fn mount_unlocked(uuid: &[u8; 16], fstab: &Path) {
    let Some(kernel) = luks::kernel_name(uuid) else {
        return;
    };
    let dev = Path::new("/dev/mapper").join(luks::mapper_name(&kernel));
    let deadline = Instant::now() + Duration::from_secs(20);
    let fs_uuid = loop {
        if let Some(u) = ext4_uuid(&dev) {
            break u;
        }
        if Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    if let Some(mp) = fstab_mountpoint(fstab, &fs_uuid) {
        // systemd often wins the race and mounts it already; starting an active unit is a no-op.
        systemctl(&["start", &mp]);
    }
}

pub fn mount_drives(unlocked: &[[u8; 16]], fstab: &Path) {
    for u in unlocked {
        mount_unlocked(u, fstab);
    }
}

/// Pool mounts, the "unlocked" marker, then dependent services (not waited for).
///
/// Pool mounts are restarted rather than started: this is what the OMV mergerfs plugin's "restart pool"
/// does (`systemctl restart <escaped mount point>.mount`), and it makes mergerfs re-read the branch
/// directories that only exist now. On a pool that failed at boot it is simply a start.
pub fn post_unlock(post: &PostUnlock, run_dir: &Path) {
    for unit in &post.mount_units {
        systemctl(&["reset-failed", unit]);
        if !systemctl(&["restart", unit]) {
            eprintln!("handsd: restarting {unit} failed (see journalctl -u {unit})");
        }
    }
    let _ = fs::create_dir_all(run_dir);
    let _ = fs::write(run_dir.join("unlocked"), b"");
    for unit in &post.service_units {
        systemctl(&["start", "--no-block", unit]);
    }
}

/// A script is run as root, so it and its directory must not be changeable by anyone else.
pub fn check_script(path: &Path, owner_uid: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let bad = |m: &fs::Metadata| m.uid() != owner_uid || m.mode() & 0o022 != 0;
    let meta = fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() || meta.mode() & 0o100 == 0 {
        return Err(format!("{} is not an executable file", path.display()));
    }
    if bad(&meta) {
        return Err(format!(
            "{} must be owned by root and not writable by group or others",
            path.display()
        ));
    }
    let dir = path.parent().unwrap_or(Path::new("/"));
    let dmeta = fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if bad(&dmeta) {
        return Err(format!(
            "{} must be owned by root and not writable by group or others",
            dir.display()
        ));
    }
    Ok(())
}

/// Blocking. Runs the script in a transient unit (so outside this daemon's sandbox, with its output in the
/// journal under `server-hands-script-<name>.service`). True when it exited 0 within its time limit.
pub fn run_script(s: &ScriptCfg, trigger: &str) -> bool {
    if let Err(e) = check_script(&s.path, 0) {
        eprintln!("handsd: script {} refused: {e}", s.name);
        return false;
    }
    let ok = Command::new("systemd-run")
        .args([
            "--quiet",
            "--wait",
            "--collect",
            &format!("--unit=server-hands-script-{}", s.name),
            &format!("--description=Server Hands post-unlock script {}", s.name),
            &format!("--property=RuntimeMaxSec={}", s.timeout_secs),
            &format!("--setenv=SERVER_HANDS_TRIGGER={trigger}"),
            "--",
        ])
        .arg(&s.path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|st| st.success())
        .unwrap_or(false);
    eprintln!(
        "handsd: script {} {}",
        s.name,
        if ok { "ok" } else { "failed" }
    );
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fstab_lookup_by_fs_uuid() {
        let p = std::env::temp_dir().join(format!("hk-fstab-{}", std::process::id()));
        std::fs::write(&p, "# c\n/dev/disk/by-uuid/AAAA-1 /srv/dev-disk-by-uuid-AAAA-1 ext4 defaults,nofail 0 2\nUUID=bb /srv/b ext4 nofail 0 2\n").unwrap();
        assert_eq!(
            fstab_mountpoint(&p, "aaaa-1").as_deref(),
            Some("/srv/dev-disk-by-uuid-AAAA-1")
        );
        assert_eq!(fstab_mountpoint(&p, "BB").as_deref(), Some("/srv/b"));
        assert_eq!(fstab_mountpoint(&p, "cc"), None);
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn ext4_superblock_uuid() {
        let p = std::env::temp_dir().join(format!("hk-ext4-{}", std::process::id()));
        let mut img = vec![0u8; 4096];
        img[1024 + 0x38..1024 + 0x3a].copy_from_slice(&0xEF53u16.to_le_bytes());
        img[1024 + 0x68..1024 + 0x78].copy_from_slice(&[0xab; 16]);
        std::fs::write(&p, &img).unwrap();
        assert_eq!(
            ext4_uuid(&p).as_deref(),
            Some("abababab-abab-abab-abab-abababababab")
        );
        img[1024 + 0x38] = 0;
        std::fs::write(&p, &img).unwrap();
        assert_eq!(ext4_uuid(&p), None);
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn script_must_be_executable_and_not_writable_by_others() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = std::env::temp_dir().join(format!("hands-script-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let me = fs::metadata(&dir).unwrap().uid();
        let f = dir.join("s.sh");
        fs::write(&f, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(check_script(&f, me).is_ok());
        assert!(check_script(&f, me + 1).is_err(), "wrong owner");
        fs::set_permissions(&f, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(check_script(&f, me).is_err(), "group writable");
        fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(check_script(&f, me).is_err(), "not executable");
        fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(check_script(&f, me).is_err(), "writable directory");
        let _ = fs::remove_dir_all(&dir);
    }
}
