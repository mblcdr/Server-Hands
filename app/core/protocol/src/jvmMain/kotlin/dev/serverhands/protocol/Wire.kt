package dev.serverhands.protocol

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** Strict: unknown fields are rejected, like the server does. Defaults are not encoded. */
internal val WireJson = Json { ignoreUnknownKeys = false }

@Serializable
internal class Envelope(val body: String, val sig: String)

@Serializable
internal class ListBody(
    @SerialName("device_id") val deviceId: String,
    @SerialName("client_nonce") val clientNonce: String,
    val ts: Long,
)

@Serializable
class DriveInfo(@SerialName("luks_uuid") val luksUuid: String, val label: String, val size: Long)

@Serializable
class RequestView(
    @SerialName("req_id") val reqId: String,
    @SerialName("expires_at") val expiresAt: Long,
    val drives: List<DriveInfo>,
    @SerialName("e_pub") val ePub: String,
    val status: String,
)

@Serializable
internal class ListReply(
    @SerialName("client_nonce") val clientNonce: String,
    @SerialName("server_time") val serverTime: Long,
    val requests: List<RequestView>,
)

@Serializable
internal class ScriptRunBody(
    @SerialName("device_id") val deviceId: String,
    @SerialName("client_nonce") val clientNonce: String,
    val ts: Long,
    val script: String,
    val challenge: String? = null,
    @SerialName("approval_sig") val approvalSig: String? = null,
)

@Serializable
internal class ScriptChallengeBody(
    @SerialName("device_id") val deviceId: String,
    @SerialName("client_nonce") val clientNonce: String,
    val ts: Long,
    @SerialName("challenge_for") val challengeFor: String,
)

@Serializable
internal class ScriptChallengeReply(
    @SerialName("client_nonce") val clientNonce: String,
    val script: String,
    val challenge: String,
    @SerialName("expires_at") val expiresAt: Long,
)

@Serializable
internal class ApprovalKeyBody(
    @SerialName("device_id") val deviceId: String,
    @SerialName("client_nonce") val clientNonce: String,
    val ts: Long,
    @SerialName("approval_pub") val approvalPub: String,
)

@Serializable
internal class ApprovalKeyReply(@SerialName("client_nonce") val clientNonce: String)

/** `mode`: auto | manual. `state`: idle | queued | running | ok | failed. `finishedAt` is unix seconds, 0 if never. */
@Serializable
class ScriptView(
    val name: String,
    val label: String,
    val mode: String,
    val state: String,
    @SerialName("finished_at") val finishedAt: Long,
    /** The app asks before running it (unless [biometricProtection] makes the biometric prompt the confirmation). */
    @SerialName("requires_confirmation") val requiresConfirmation: Boolean = false,
    /** Running it needs a biometric signature over a server challenge. */
    @SerialName("biometric_protection") val biometricProtection: Boolean = false,
) {
    val busy: Boolean get() = state == "queued" || state == "running"
}

@Serializable
internal class ScriptsReply(
    @SerialName("client_nonce") val clientNonce: String,
    @SerialName("server_time") val serverTime: Long,
    val unlocked: Boolean,
    val scripts: List<ScriptView>,
)

@Serializable
internal class ScriptRunReply(
    @SerialName("client_nonce") val clientNonce: String,
    val script: String,
    val state: String,
)

@Serializable
internal class ApproveRequest(
    @SerialName("device_id") val deviceId: String,
    @SerialName("client_nonce") val clientNonce: String,
    val uuids: List<String>,
    val enc: String,
    val ct: String,
    val sig: String,
)

@Serializable
class DriveResult(@SerialName("luks_uuid") val luksUuid: String, val result: String)

@Serializable
internal class ApproveReply(
    @SerialName("client_nonce") val clientNonce: String,
    @SerialName("req_id") val reqId: String,
    val results: List<DriveResult>,
)

@Serializable
internal class PairRequest(
    val tok: String,
    @SerialName("device_pub") val devicePub: String,
    @SerialName("device_name") val deviceName: String,
)

@Serializable
internal class PairAck(
    @SerialName("device_id") val deviceId: String,
    @SerialName("server_time") val serverTime: Long,
)

@Serializable
internal class ErrorBody(val error: String)

/** `state`: absent | locked | open | mounted. [size] is the LUKS container; the rest is the mounted filesystem, 0 unless mounted. */
@Serializable
class DriveStatus(
    @SerialName("luks_uuid") val luksUuid: String,
    val label: String,
    val state: String,
    val size: Long,
    val total: Long,
    val used: Long,
    val avail: Long,
)

/** A pool mount such as mergerfs. Sizes are 0 unless [mounted]. */
@Serializable
class PoolStatus(
    val name: String,
    @SerialName("mount_point") val mountPoint: String,
    val fstype: String,
    val mounted: Boolean,
    val total: Long,
    val used: Long,
    val avail: Long,
)

/** Machine status. Sizes are bytes; [cpuPercent] is 0 to 100. */
@Serializable
class ServerStatus(
    @SerialName("client_nonce") internal val clientNonce: String,
    @SerialName("server_time") internal val serverTime: Long,
    val hostname: String,
    val kernel: String,
    @SerialName("uptime_secs") val uptimeSecs: Long,
    val load: List<Double>,
    val cpus: Int,
    @SerialName("cpu_percent") val cpuPercent: Double,
    @SerialName("mem_total") val memTotal: Long,
    @SerialName("mem_available") val memAvailable: Long,
    @SerialName("swap_total") val swapTotal: Long,
    @SerialName("swap_free") val swapFree: Long,
    val drives: List<DriveStatus>,
    val pools: List<PoolStatus>,
)
