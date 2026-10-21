//! LUKS container discovery and activation. libcryptsetup is loaded with dlopen so the binary builds
//! without the dev package and the same code compiles on non-Linux dev machines.

use std::ffi::{c_char, c_int, c_void, CString};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use hands_proto::codec::{uuid_format, uuid_parse};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockResult {
    Ok,
    BadPassphrase,
    AlreadyOpen,
    Error,
}

impl UnlockResult {
    pub fn as_str(self) -> &'static str {
        match self {
            UnlockResult::Ok => "ok",
            UnlockResult::BadPassphrase => "bad_passphrase",
            UnlockResult::AlreadyOpen => "already_open",
            UnlockResult::Error => "error",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "ok" => UnlockResult::Ok,
            "bad_passphrase" => UnlockResult::BadPassphrase,
            "already_open" => UnlockResult::AlreadyOpen,
            _ => UnlockResult::Error,
        }
    }
    pub fn is_unlocked(self) -> bool {
        matches!(self, UnlockResult::Ok | UnlockResult::AlreadyOpen)
    }
}

pub fn by_uuid(uuid: &[u8; 16]) -> PathBuf {
    Path::new("/dev/disk/by-uuid").join(uuid_format(uuid))
}

/// Kernel name (`sdb1`) behind `/dev/disk/by-uuid/<luks uuid>`, if the container is present.
pub fn kernel_name(uuid: &[u8; 16]) -> Option<String> {
    let target = fs::read_link(by_uuid(uuid)).ok()?;
    Some(target.file_name()?.to_string_lossy().into_owned())
}

/// A container is open when a device-mapper device holds it.
pub fn is_active(kernel: &str) -> bool {
    fs::read_dir(format!("/sys/class/block/{kernel}/holders"))
        .map(|mut d| d.next().is_some())
        .unwrap_or(false)
}

/// Same naming scheme as the OMV luks plugin, so a unlock here is indistinguishable from the GUI.
pub fn mapper_name(kernel: &str) -> String {
    format!("{kernel}-crypt")
}

pub fn size_bytes(kernel: &str) -> u64 {
    fs::read_to_string(format!("/sys/class/block/{kernel}/size"))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|sectors| sectors * 512)
        .unwrap_or(0)
}

/// UUIDs named by an `/etc/crypttab` entry (systemd would try to unlock those itself).
pub fn crypttab_uuids(path: &Path) -> Vec<[u8; 16]> {
    let Ok(text) = fs::read_to_string(path) else {
        return vec![];
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_whitespace().nth(1))
        .filter_map(|src| {
            let id = src
                .strip_prefix("UUID=")
                .or_else(|| src.strip_prefix("/dev/disk/by-uuid/"))?;
            uuid_parse(id).ok()
        })
        .collect()
}

pub struct Header {
    pub uuid: [u8; 16],
    pub label: String,
    pub version: u16,
}

/// Parses a LUKS1/LUKS2 on-disk header (magic, version, label, UUID at offset 168).
pub fn parse_header(buf: &[u8]) -> Option<Header> {
    if buf.len() < 208 || !(buf.starts_with(b"LUKS\xba\xbe") || buf.starts_with(b"SKUL\xba\xbe")) {
        return None;
    }
    let version = u16::from_be_bytes([buf[6], buf[7]]);
    let cstr = |b: &[u8]| {
        String::from_utf8_lossy(&b[..b.iter().position(|c| *c == 0).unwrap_or(b.len())])
            .into_owned()
    };
    let uuid = uuid_parse(&cstr(&buf[168..208])).ok()?;
    let label = if version == 2 {
        cstr(&buf[24..72])
    } else {
        String::new()
    };
    Some(Header {
        uuid,
        label,
        version,
    })
}

pub struct Found {
    pub uuid: [u8; 16],
    pub label: String,
    pub kernel: String,
    pub size: u64,
    pub active: bool,
    pub in_crypttab: bool,
}

/// Scans `/dev/disk/by-uuid` for LUKS containers. Reads 4 KiB headers, so it needs root.
pub fn discover(crypttab: &Path) -> Vec<Found> {
    let tab = crypttab_uuids(crypttab);
    let Ok(rd) = fs::read_dir("/dev/disk/by-uuid") else {
        return vec![];
    };
    let mut out = vec![];
    for e in rd.flatten() {
        let Ok(mut f) = fs::File::open(e.path()) else {
            continue;
        };
        let mut buf = vec![0u8; 4096];
        if f.read_exact(&mut buf).is_err() {
            continue;
        }
        let Some(h) = parse_header(&buf) else {
            continue;
        };
        let Some(kernel) = fs::read_link(e.path())
            .ok()
            .and_then(|t| t.file_name().map(|n| n.to_string_lossy().into_owned()))
        else {
            continue;
        };
        out.push(Found {
            uuid: h.uuid,
            label: h.label,
            size: size_bytes(&kernel),
            active: is_active(&kernel),
            in_crypttab: tab.contains(&h.uuid),
            kernel,
        });
    }
    out.sort_by_key(|f| f.uuid);
    out
}

pub trait LuksBackend {
    fn activate(&self, device: &Path, name: &str, passphrase: &[u8]) -> UnlockResult;
    fn add_key(&self, device: &Path, existing: &[u8], new: &[u8]) -> Result<(), String>;
}

type CryptInit = unsafe extern "C" fn(*mut *mut c_void, *const c_char) -> c_int;
type CryptLoad = unsafe extern "C" fn(*mut c_void, *const c_char, *mut c_void) -> c_int;
type CryptActivate =
    unsafe extern "C" fn(*mut c_void, *const c_char, c_int, *const c_char, usize, u32) -> c_int;
type CryptKeyslotAdd =
    unsafe extern "C" fn(*mut c_void, c_int, *const c_char, usize, *const c_char, usize) -> c_int;
type CryptFree = unsafe extern "C" fn(*mut c_void);

pub struct Cryptsetup {
    init: CryptInit,
    load: CryptLoad,
    activate: CryptActivate,
    keyslot_add: CryptKeyslotAdd,
    free: CryptFree,
}

impl Cryptsetup {
    pub fn open() -> Result<Self, String> {
        unsafe {
            let mut h = std::ptr::null_mut();
            for name in [c"libcryptsetup.so.12", c"libcryptsetup.so"] {
                h = libc::dlopen(name.as_ptr(), libc::RTLD_NOW);
                if !h.is_null() {
                    break;
                }
            }
            if h.is_null() {
                return Err("libcryptsetup not found (apt install libcryptsetup12)".into());
            }
            let sym = |n: &std::ffi::CStr| -> Result<*mut c_void, String> {
                let p = libc::dlsym(h, n.as_ptr());
                if p.is_null() {
                    Err(format!("missing symbol {}", n.to_string_lossy()))
                } else {
                    Ok(p)
                }
            };
            Ok(Self {
                init: std::mem::transmute::<*mut c_void, CryptInit>(sym(c"crypt_init")?),
                load: std::mem::transmute::<*mut c_void, CryptLoad>(sym(c"crypt_load")?),
                activate: std::mem::transmute::<*mut c_void, CryptActivate>(sym(
                    c"crypt_activate_by_passphrase",
                )?),
                keyslot_add: std::mem::transmute::<*mut c_void, CryptKeyslotAdd>(sym(
                    c"crypt_keyslot_add_by_passphrase",
                )?),
                free: std::mem::transmute::<*mut c_void, CryptFree>(sym(c"crypt_free")?),
            })
        }
    }

    /// Runs `f` on a loaded device handle, freeing it afterwards. Err carries the negative errno.
    fn with_device<T>(&self, device: &Path, f: impl FnOnce(*mut c_void) -> T) -> Result<T, c_int> {
        let path =
            CString::new(device.as_os_str().as_encoded_bytes()).map_err(|_| -libc::EINVAL)?;
        let mut cd: *mut c_void = std::ptr::null_mut();
        unsafe {
            let r = (self.init)(&mut cd, path.as_ptr());
            if r < 0 {
                return Err(r);
            }
            let r = (self.load)(cd, std::ptr::null(), std::ptr::null_mut());
            if r < 0 {
                (self.free)(cd);
                return Err(r);
            }
            let out = f(cd);
            (self.free)(cd);
            Ok(out)
        }
    }
}

impl LuksBackend for Cryptsetup {
    fn activate(&self, device: &Path, name: &str, passphrase: &[u8]) -> UnlockResult {
        let Ok(name) = CString::new(name) else {
            return UnlockResult::Error;
        };
        let r = self.with_device(device, |cd| unsafe {
            (self.activate)(
                cd,
                name.as_ptr(),
                -1,
                passphrase.as_ptr() as *const c_char,
                passphrase.len(),
                0,
            )
        });
        match r {
            Ok(r) if r >= 0 => UnlockResult::Ok,
            Ok(r) if r == -libc::EPERM => UnlockResult::BadPassphrase,
            Ok(r) if r == -libc::EEXIST => UnlockResult::AlreadyOpen,
            _ => UnlockResult::Error,
        }
    }

    fn add_key(&self, device: &Path, existing: &[u8], new: &[u8]) -> Result<(), String> {
        let r = self.with_device(device, |cd| unsafe {
            (self.keyslot_add)(
                cd,
                -1,
                existing.as_ptr() as *const c_char,
                existing.len(),
                new.as_ptr() as *const c_char,
                new.len(),
            )
        });
        match r {
            Ok(r) if r >= 0 => Ok(()),
            Ok(r) if r == -libc::EPERM => Err("existing passphrase rejected".into()),
            Ok(r) | Err(r) => Err(format!("libcryptsetup error {r}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_luks2_header() {
        let mut b = vec![0u8; 4096];
        b[..6].copy_from_slice(b"LUKS\xba\xbe");
        b[6..8].copy_from_slice(&2u16.to_be_bytes());
        b[24..30].copy_from_slice(b"Disk-1");
        b[168..204].copy_from_slice(b"00000000-0000-4000-8000-000000000001");
        let h = parse_header(&b).unwrap();
        assert_eq!((h.version, h.label.as_str()), (2, "Disk-1"));
        assert_eq!(uuid_format(&h.uuid), "00000000-0000-4000-8000-000000000001");
        assert!(parse_header(&[0u8; 4096]).is_none());
    }

    #[test]
    fn crypttab_entries() {
        let dir = std::env::temp_dir().join(format!("hands-crypttab-{}", std::process::id()));
        std::fs::write(
            &dir,
            "# c\nx UUID=00000000-0000-4000-8000-000000000001 none luks\ny /dev/sda none\n",
        )
        .unwrap();
        assert_eq!(crypttab_uuids(&dir).len(), 1);
        std::fs::remove_file(dir).ok();
    }
}
