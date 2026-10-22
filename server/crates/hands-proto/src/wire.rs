//! JSON wire bodies for the HTTP API (see docs/protocol.md). Binary fields are base64url without padding.
//! Every body rejects unknown fields.

use serde::{Deserialize, Serialize};

use crate::DriveInfo;

/// `POST /v1/requests/list`, body of the device-signed envelope.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListBody {
    pub device_id: String,
    pub client_nonce: String,
    pub ts: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestView {
    pub req_id: String,
    pub expires_at: u64,
    pub drives: Vec<DriveInfo>,
    pub e_pub: String,
    pub status: String,
}

/// Body of the server-signed list reply.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListReply {
    pub client_nonce: String,
    pub server_time: u64,
    pub requests: Vec<RequestView>,
}

/// `POST /v1/requests/{req_id}/approve`. `uuids` are hyphenated LUKS UUIDs, strictly ascending;
/// they become the HPKE AAD.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveRequest {
    pub device_id: String,
    pub client_nonce: String,
    pub uuids: Vec<String>,
    pub enc: String,
    pub ct: String,
    pub sig: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct DriveResult {
    pub luks_uuid: String,
    /// `ok | bad_passphrase | already_open | error`
    pub result: String,
}

/// Body of the server-signed approve reply.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveReply {
    pub client_nonce: String,
    pub req_id: String,
    pub results: Vec<DriveResult>,
}

/// `POST /v1/pair`. Blocks until the operator confirms the SAS on the server console.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairRequest {
    pub tok: String,
    pub device_pub: String,
    pub device_name: String,
}

/// Body of the server-signed pairing ack (domain `hands/v1/pair`).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairAck {
    pub device_id: String,
    pub server_time: u64,
}

#[derive(Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}

/// One post-unlock script as the phone sees it. `state`: `idle | queued | running | ok | failed`.
/// `finished_at` is unix seconds, 0 if it has not finished since the daemon started.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct ScriptView {
    pub name: String,
    pub label: String,
    /// `auto | manual`
    pub mode: String,
    pub state: String,
    pub finished_at: u64,
    /// The app asks "Run X?" before starting it (skipped when `biometric_protection` is on: the prompt is the confirmation).
    pub requires_confirmation: bool,
    /// Starting it needs a fresh biometric signature over a server challenge; the server enforces this.
    pub biometric_protection: bool,
}

/// `POST /v1/scripts/list` takes a device-signed [`ListBody`] envelope and answers with this.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptsReply {
    pub client_nonce: String,
    pub server_time: u64,
    /// True once every configured drive is unlocked; scripts with `requires_unlock` cannot be started before.
    pub unlocked: bool,
    pub scripts: Vec<ScriptView>,
}

/// `POST /v1/scripts/run`, body of the device-signed envelope.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptRunBody {
    pub device_id: String,
    pub client_nonce: String,
    pub ts: u64,
    pub script: String,
    /// Both set for a `biometric_protection` script: the challenge from `scripts/challenge` and the
    /// approval key's signature over [`crate::sign::script_approve_message`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_sig: Option<String>,
}

/// `POST /v1/scripts/challenge`, body of the device-signed envelope. The differently named field keeps it
/// from being accepted as a run request.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptChallengeBody {
    pub device_id: String,
    pub client_nonce: String,
    pub ts: u64,
    pub challenge_for: String,
}

/// Body of the server-signed challenge reply. Single use, tied to this device and script.
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ScriptChallengeReply {
    pub client_nonce: String,
    pub script: String,
    pub challenge: String,
    pub expires_at: u64,
}

/// `POST /v1/device/approval-key`, body of the device-signed envelope. Registers the biometric-bound key
/// (SPKI DER) once; the same key again is accepted, a different one is refused until the operator resets it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalKeyBody {
    pub device_id: String,
    pub client_nonce: String,
    pub ts: u64,
    pub approval_pub: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalKeyReply {
    pub client_nonce: String,
}

/// Body of the server-signed run reply. The script runs in the background; poll the list for the outcome.
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ScriptRunReply {
    pub client_nonce: String,
    pub script: String,
    pub state: String,
}

/// One configured drive in the status reply. `state`: `absent | locked | open | mounted`. `size` is the LUKS
/// container; `total`, `used` and `avail` (bytes) describe the mounted filesystem and are 0 unless `mounted`.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct DriveStatus {
    pub luks_uuid: String,
    pub label: String,
    pub state: String,
    pub size: u64,
    pub total: u64,
    pub used: u64,
    pub avail: u64,
}

/// A pool mount (for example mergerfs) from `post_unlock.mount_units`. Sizes are 0 unless `mounted`.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct PoolStatus {
    pub name: String,
    pub mount_point: String,
    pub fstype: String,
    pub mounted: bool,
    pub total: u64,
    pub used: u64,
    pub avail: u64,
}

/// `POST /v1/status` takes a device-signed [`ListBody`] envelope and answers with this. `cpu_percent` is the
/// busy share (0 to 100) since the previous status call; `mem_available` is the kernel's `MemAvailable`.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub struct StatusReply {
    pub client_nonce: String,
    pub server_time: u64,
    pub hostname: String,
    pub kernel: String,
    pub uptime_secs: u64,
    /// 1, 5 and 15 minute load averages.
    pub load: [f64; 3],
    pub cpus: u32,
    pub cpu_percent: f64,
    pub mem_total: u64,
    pub mem_available: u64,
    pub swap_total: u64,
    pub swap_free: u64,
    pub drives: Vec<DriveStatus>,
    pub pools: Vec<PoolStatus>,
}
