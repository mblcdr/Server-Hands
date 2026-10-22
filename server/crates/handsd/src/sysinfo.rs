//! Read-only machine status for the app: uptime, CPU, memory, drive and pool usage. Everything comes from
//! /proc and statvfs; nothing here can change the system or touch a secret.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use hands_proto as proto;

use crate::config::Config;
use crate::luks;

/// What the daemon needs from the machine for one status reply (CPU as raw counters; the daemon turns two
/// samples into a percentage).
#[derive(Clone, Default, Debug)]
pub struct SystemStatus {
    pub hostname: String,
    pub kernel: String,
    pub uptime_secs: u64,
    pub load: [f64; 3],
    pub cpus: u32,
    pub cpu_busy: u64,
    pub cpu_total: u64,
    pub mem_total: u64,
    pub mem_available: u64,
    pub swap_total: u64,
    pub swap_free: u64,
    pub drives: Vec<proto::wire::DriveStatus>,
    pub pools: Vec<proto::wire::PoolStatus>,
}

/// `(busy, total)` jiffies from the aggregate `cpu` line of /proc/stat, plus the number of `cpuN` lines.
pub fn parse_stat(text: &str) -> Option<(u64, u64, u32)> {
    let mut lines = text.lines();
    let first = lines.next()?;
    let f: Vec<u64> = first
        .strip_prefix("cpu ")?
        .split_whitespace()
        .filter_map(|v| v.parse().ok())
        .collect();
    if f.len() < 4 {
        return None;
    }
    let total: u64 = f.iter().take(8).sum();
    let idle = f[3] + f.get(4).copied().unwrap_or(0); // idle + iowait
    let cpus = text
        .lines()
        .filter(|l| l.starts_with("cpu") && l[3..].starts_with(|c: char| c.is_ascii_digit()))
        .count() as u32;
    Some((total.saturating_sub(idle), total, cpus.max(1)))
}

/// Busy share in percent between two `(busy, total)` samples.
pub fn cpu_percent(prev: (u64, u64), now: (u64, u64)) -> f64 {
    let (db, dt) = (now.0.saturating_sub(prev.0), now.1.saturating_sub(prev.1));
    if dt == 0 {
        0.0
    } else {
        (db as f64 * 100.0 / dt as f64).clamp(0.0, 100.0)
    }
}

/// `(MemTotal, MemAvailable, SwapTotal, SwapFree)` in bytes.
pub fn parse_meminfo(text: &str) -> (u64, u64, u64, u64) {
    let kb = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix(':'))
            .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
            .map(|v| v * 1024)
            .unwrap_or(0)
    };
    (
        kb("MemTotal"),
        kb("MemAvailable"),
        kb("SwapTotal"),
        kb("SwapFree"),
    )
}

pub fn parse_loadavg(text: &str) -> [f64; 3] {
    let mut it = text.split_whitespace().map(|v| v.parse().unwrap_or(0.0));
    [
        it.next().unwrap_or(0.0),
        it.next().unwrap_or(0.0),
        it.next().unwrap_or(0.0),
    ]
}

/// Decodes the `\040`-style octal escapes of /proc/self/mountinfo fields.
fn unescape_octal(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = (b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0');
            out.push(v);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Debug, PartialEq, Eq)]
pub struct Mount {
    pub dev: (u32, u32),
    pub point: String,
    pub fstype: String,
}

/// Mounts from /proc/self/mountinfo. Later lines win when a path is mounted over, so look from the end.
pub fn parse_mountinfo(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|l| {
            let (pre, post) = l.split_once(" - ")?;
            let f: Vec<&str> = pre.split_whitespace().collect();
            let (maj, min) = f.get(2)?.split_once(':')?;
            Some(Mount {
                dev: (maj.parse().ok()?, min.parse().ok()?),
                point: unescape_octal(f.get(4)?),
                fstype: post.split_whitespace().next()?.to_string(),
            })
        })
        .collect()
}

/// `srv-mergerfs-Pool.mount` -> `/srv/mergerfs/Pool` (systemd path escaping, `\xNN` for odd bytes).
pub fn mount_unit_path(unit: &str) -> Option<String> {
    let stem = unit.strip_suffix(".mount")?;
    if stem == "-" {
        return Some("/".into());
    }
    let mut path = String::new();
    for part in stem.split('-') {
        path.push('/');
        let b = part.as_bytes();
        let mut i = 0;
        let mut raw = Vec::new();
        while i < b.len() {
            if b[i] == b'\\' && b.get(i + 1) == Some(&b'x') && i + 3 < b.len() {
                let v = u8::from_str_radix(std::str::from_utf8(&b[i + 2..i + 4]).ok()?, 16).ok()?;
                raw.push(v);
                i += 4;
            } else {
                raw.push(b[i]);
                i += 1;
            }
        }
        path.push_str(&String::from_utf8_lossy(&raw));
    }
    Some(path)
}

/// `(total, used, avail)` bytes of the filesystem at `path`, df-style.
fn statvfs(path: &str) -> Option<(u64, u64, u64)> {
    let c = std::ffi::CString::new(path).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    let unit = s.f_frsize as u64;
    Some((
        s.f_blocks as u64 * unit,
        (s.f_blocks as u64).saturating_sub(s.f_bfree as u64) * unit,
        s.f_bavail as u64 * unit,
    ))
}

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len() - 1) } == 0;
    if !ok {
        return String::new();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn kernel() -> String {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return String::new();
    }
    let bytes: Vec<u8> = u
        .release
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn drive_statuses(cfg: &Config, mounts: &[Mount]) -> Vec<proto::wire::DriveStatus> {
    cfg.drives
        .iter()
        .map(|d| {
            let mut out = proto::wire::DriveStatus {
                luks_uuid: d.luks_uuid.clone(),
                label: d.label.clone(),
                state: "absent".into(),
                ..Default::default()
            };
            let Some(kernel) = proto::codec::uuid_parse(&d.luks_uuid)
                .ok()
                .and_then(|u| luks::kernel_name(&u))
            else {
                return out;
            };
            out.size = luks::size_bytes(&kernel);
            if !luks::is_active(&kernel) {
                out.state = "locked".into();
                return out;
            }
            out.state = "open".into();
            // Match by device number: how the mount names its source (mapper path, dm-N, by-uuid) varies.
            let dev = Path::new("/dev/mapper").join(luks::mapper_name(&kernel));
            let Ok(rdev) = fs::metadata(&dev).map(|m| m.rdev()) else {
                return out;
            };
            let want = (libc::major(rdev as _) as u32, libc::minor(rdev as _) as u32);
            if let Some(m) = mounts.iter().rev().find(|m| m.dev == want) {
                if let Some((total, used, avail)) = statvfs(&m.point) {
                    out.state = "mounted".into();
                    (out.total, out.used, out.avail) = (total, used, avail);
                }
            }
            out
        })
        .collect()
}

fn pool_statuses(cfg: &Config, mounts: &[Mount]) -> Vec<proto::wire::PoolStatus> {
    cfg.post_unlock
        .mount_units
        .iter()
        .filter_map(|unit| {
            let point = mount_unit_path(unit)?;
            let name = point.rsplit('/').next().unwrap_or(&point).to_string();
            let mut p = proto::wire::PoolStatus {
                name,
                mount_point: point.clone(),
                ..Default::default()
            };
            if let Some(m) = mounts.iter().rev().find(|m| m.point == point) {
                p.fstype = m.fstype.clone();
                if let Some((total, used, avail)) = statvfs(&point) {
                    p.mounted = true;
                    (p.total, p.used, p.avail) = (total, used, avail);
                }
            }
            Some(p)
        })
        .collect()
}

/// Gathers everything for one status reply.
pub fn collect(cfg: &Config) -> SystemStatus {
    let (busy, total, cpus) = parse_stat(&read("/proc/stat")).unwrap_or((0, 0, 1));
    let (mem_total, mem_available, swap_total, swap_free) = parse_meminfo(&read("/proc/meminfo"));
    let mounts = parse_mountinfo(&read("/proc/self/mountinfo"));
    SystemStatus {
        hostname: hostname(),
        kernel: kernel(),
        uptime_secs: read("/proc/uptime")
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<f64>().ok())
            .map(|v| v as u64)
            .unwrap_or(0),
        load: parse_loadavg(&read("/proc/loadavg")),
        cpus,
        cpu_busy: busy,
        cpu_total: total,
        mem_total,
        mem_available,
        swap_total,
        swap_free,
        drives: drive_statuses(cfg, &mounts),
        pools: pool_statuses(cfg, &mounts),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_gives_busy_total_and_cpu_count() {
        let t = "cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 50 0 25 400 25 0 0 0 0 0\ncpu1 50 0 25 400 25 0 0 0 0 0\nintr 1\n";
        assert_eq!(parse_stat(t), Some((150, 1000, 2)));
        assert_eq!(parse_stat("garbage"), None);
    }

    #[test]
    fn cpu_percent_is_a_clamped_delta() {
        assert_eq!(cpu_percent((100, 1000), (150, 1100)), 50.0);
        assert_eq!(cpu_percent((100, 1000), (100, 1000)), 0.0);
        assert_eq!(cpu_percent((100, 1000), (50, 900)), 0.0);
    }

    #[test]
    fn meminfo_and_loadavg() {
        let m = "MemTotal:       16000000 kB\nMemFree: 1 kB\nMemAvailable:   12000000 kB\nSwapTotal: 2048 kB\nSwapFree: 1024 kB\n";
        assert_eq!(
            parse_meminfo(m),
            (
                16_000_000 * 1024,
                12_000_000 * 1024,
                2048 * 1024,
                1024 * 1024
            )
        );
        assert_eq!(
            parse_loadavg("0.52 0.40 0.30 1/200 999"),
            [0.52, 0.40, 0.30]
        );
    }

    #[test]
    fn mountinfo_handles_escapes_and_last_wins() {
        let t = "36 35 253:1 / /srv/dev-disk-by-uuid-AAAA rw,relatime shared:1 - ext4 /dev/mapper/sdb1-crypt rw\n40 35 0:50 / /srv/with\\040space rw - fuse.mergerfs Pool rw\n";
        let m = parse_mountinfo(t);
        assert_eq!(m[0].dev, (253, 1));
        assert_eq!(m[0].fstype, "ext4");
        assert_eq!(m[1].point, "/srv/with space");
        assert_eq!(m[1].fstype, "fuse.mergerfs");
    }

    #[test]
    fn mount_unit_names_become_paths() {
        assert_eq!(
            mount_unit_path("srv-mergerfs-Pool.mount").as_deref(),
            Some("/srv/mergerfs/Pool")
        );
        assert_eq!(
            mount_unit_path("srv-my\\x2ddata.mount").as_deref(),
            Some("/srv/my-data")
        );
        assert_eq!(mount_unit_path("-.mount").as_deref(), Some("/"));
        assert_eq!(mount_unit_path("foo.service"), None);
    }
}
