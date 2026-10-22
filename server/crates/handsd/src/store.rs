//! Persistent state: server identity, TLS key/cert, paired devices. All under the state dir (0700).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use hands_proto::codec::{b64d, b64e, hex_decode, hex_encode, sha256};
use rand_core::{OsRng, RngCore};
use rcgen::PublicKeyData as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub id: String,
    pub spki: String,
    pub name: String,
    pub created_at: u64,
    /// SPKI of the biometric-bound approval key, once the phone registered one. Lost on re-pairing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_spki: Option<String>,
}

impl DeviceRecord {
    pub fn id_bytes(&self) -> Option<[u8; 16]> {
        hex_decode(&self.id).ok()?.try_into().ok()
    }
    pub fn spki_bytes(&self) -> Option<Vec<u8>> {
        b64d(&self.spki).ok()
    }
}

pub struct Tls {
    pub cert_der: Vec<u8>,
    pub key_der: Zeroizing<Vec<u8>>,
    /// SHA-256 of the SubjectPublicKeyInfo; what clients pin.
    pub spki_sha256: [u8; 32],
}

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    fn write_private(&self, name: &str, data: &[u8]) -> std::io::Result<()> {
        let tmp = self.dir.join(format!(".{name}.tmp"));
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, self.dir.join(name))
    }

    pub fn identity(&self) -> std::io::Result<SigningKey> {
        let path = self.dir.join("identity.key");
        match fs::read(&path) {
            Ok(bytes) => {
                let seed = Zeroizing::new(bytes);
                let arr: [u8; 32] = seed
                    .as_slice()
                    .try_into()
                    .map_err(|_| bad("identity.key has wrong length"))?;
                Ok(SigningKey::from_bytes(&arr))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut seed = Zeroizing::new([0u8; 32]);
                OsRng.fill_bytes(&mut seed[..]);
                self.write_private("identity.key", &seed[..])?;
                Ok(SigningKey::from_bytes(&seed))
            }
            Err(e) => Err(e),
        }
    }

    pub fn tls(&self) -> std::io::Result<Tls> {
        let (cert_path, key_path) = (self.dir.join("tls-cert.der"), self.dir.join("tls-key.der"));
        if let (Ok(cert), Ok(key)) = (fs::read(&cert_path), fs::read(&key_path)) {
            let spki = spki_of_cert_key(&key).ok_or_else(|| bad("tls-key.der unreadable"))?;
            return Ok(Tls {
                cert_der: cert,
                key_der: Zeroizing::new(key),
                spki_sha256: sha256(&spki),
            });
        }
        let kp = rcgen::KeyPair::generate().map_err(|_| bad("tls keygen"))?;
        let mut params = rcgen::CertificateParams::new(vec!["server-hands".to_string()])
            .map_err(|_| bad("tls params"))?;
        // Java and Android reject certificates with an empty subject/issuer DN.
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "server-hands");
        let cert = params.self_signed(&kp).map_err(|_| bad("tls sign"))?;
        let key = Zeroizing::new(kp.serialize_der());
        self.write_private("tls-cert.der", cert.der())?;
        self.write_private("tls-key.der", &key)?;
        Ok(Tls {
            cert_der: cert.der().to_vec(),
            key_der: key,
            spki_sha256: sha256(&kp.subject_public_key_info()),
        })
    }

    pub fn load_devices(&self) -> Vec<DeviceRecord> {
        fs::read(self.dir.join("devices.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save_devices(&self, devices: &[DeviceRecord]) -> std::io::Result<()> {
        self.write_private(
            "devices.json",
            &serde_json::to_vec_pretty(devices).map_err(|_| bad("json"))?,
        )
    }
}

fn spki_of_cert_key(pkcs8: &[u8]) -> Option<Vec<u8>> {
    let kp = rcgen::KeyPair::try_from(pkcs8).ok()?;
    Some(kp.subject_public_key_info())
}

fn bad(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string())
}

pub fn new_device_record(id: &[u8; 16], spki: &[u8], name: &str, now: u64) -> DeviceRecord {
    DeviceRecord {
        id: hex_encode(id),
        spki: b64e(spki),
        name: name.to_string(),
        created_at: now,
        approval_spki: None,
    }
}
