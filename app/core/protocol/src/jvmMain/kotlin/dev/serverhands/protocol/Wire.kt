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
)

/** `mode`: auto | manual. `state`: idle | queued | running | ok | failed. `finishedAt` is unix seconds, 0 if never. */
@Serializable
class ScriptView(
    val name: String,
    val label: String,
    val mode: String,
    val state: String,
    @SerialName("finished_at") val finishedAt: Long,
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
