package dev.serverhands.protocol

import dev.serverhands.crypto.Codec
import dev.serverhands.crypto.Domain
import dev.serverhands.crypto.PasswordEntry
import dev.serverhands.crypto.ProtocolException
import dev.serverhands.crypto.Seal
import dev.serverhands.crypto.Signatures
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import java.io.IOException
import java.security.SecureRandom

/** The device key. On Android this is a Keystore key; tests use a software key. */
interface DeviceSigner {
    /** X.509 SubjectPublicKeyInfo DER. */
    val spki: ByteArray
    /** ECDSA P-256 / SHA-256, DER signature. */
    fun sign(message: ByteArray): ByteArray
}

val DeviceSigner.id: ByteArray get() = Signatures.deviceId(spki)

/** The server answered with an error body. Deliberately only the wire code, never details. */
class ServerException(val status: Int, val code: String) : IOException("server refused: $status $code")

class Listing internal constructor(
    internal val clientNonce: ByteArray,
    val serverTime: Long,
    val requests: List<RequestView>,
)

/** Post-unlock scripts. [unlocked] is false until every drive is open; nothing can be started before. */
class Scripts(val unlocked: Boolean, val scripts: List<ScriptView>)

class ApproveResult(val results: List<DriveResult>)

/**
 * Talks to one paired server. Blocking: call it off the main thread. Every server reply is verified
 * against the pinned Ed25519 key and bound to a fresh nonce before anything in it is used.
 */
class ServerClient(
    private val pin: Pin,
    private val signer: DeviceSigner,
    private val nowSecs: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    private val rng = SecureRandom()

    private fun post(path: String, body: String, readTimeoutMs: Int = 15_000): String {
        val c = pinnedConnection(pin, path)
        try {
            c.requestMethod = "POST"
            c.connectTimeout = 8_000
            c.readTimeout = readTimeoutMs
            c.doOutput = true
            c.useCaches = false
            c.setRequestProperty("content-type", "application/json")
            c.outputStream.use { it.write(body.toByteArray()) }
            val status = c.responseCode
            val text = (if (status == 200) c.inputStream else c.errorStream)?.use { it.readBytes().toString(Charsets.UTF_8) } ?: ""
            if (status != 200) {
                val code = try { WireJson.decodeFromString<ErrorBody>(text).error } catch (_: Exception) { "unknown" }
                throw ServerException(status, code)
            }
            return text
        } finally {
            c.disconnect()
        }
    }

    private fun verified(domain: ByteArray, text: String): ByteArray {
        val env = try { WireJson.decodeFromString<Envelope>(text) } catch (_: Exception) { throw ProtocolException() }
        return Signatures.serverVerify(pin.serverPub, domain, env.body, env.sig)
    }

    /** Blocks until the operator confirms the code on the server console. [onSas] fires first. */
    fun pair(token: ByteArray, deviceName: String, onSas: (String) -> Unit) {
        onSas(Seal.sas(pin.serverPub, signer.spki, token))
        val req = WireJson.encodeToString(PairRequest(Codec.b64e(token), Codec.b64e(signer.spki), deviceName))
        val text = post("/v1/pair", req, readTimeoutMs = 330_000)
        val ack = try { WireJson.decodeFromString<PairAck>(String(verified(Domain.PAIR, text))) } catch (_: Exception) { throw ProtocolException() }
        if (!Codec.constantTimeEquals(Codec.b64d(ack.deviceId), signer.id)) throw ProtocolException()
    }

    /** Signs [body] (which carries the fresh nonce), posts it and returns the verified reply bytes. */
    private fun signedCall(path: String, body: ByteArray): ByteArray {
        val sig = signer.sign(Codec.signedBytes(Domain.DEVICE_REQUEST, body))
        val text = post(path, WireJson.encodeToString(Envelope(Codec.b64e(body), Codec.b64e(sig))))
        return verified(Domain.SERVER_REPLY, text)
    }

    private fun freshNonce() = ByteArray(32).also(rng::nextBytes)

    private fun checkFresh(echoed: String, nonce: ByteArray, serverTime: Long? = null) {
        if (echoed != Codec.b64e(nonce) || (serverTime != null && kotlin.math.abs(serverTime - nowSecs()) > 60)) throw ProtocolException()
    }

    fun list(): Listing {
        val nonce = freshNonce()
        val body = WireJson.encodeToString(ListBody(Codec.b64e(signer.id), Codec.b64e(nonce), nowSecs())).toByteArray()
        val reply = try { WireJson.decodeFromString<ListReply>(String(signedCall("/v1/requests/list", body))) } catch (_: SerializationException) { throw ProtocolException() }
        checkFresh(reply.clientNonce, nonce, reply.serverTime)
        return Listing(nonce, reply.serverTime, reply.requests)
    }

    fun scripts(): Scripts {
        val nonce = freshNonce()
        val body = WireJson.encodeToString(ListBody(Codec.b64e(signer.id), Codec.b64e(nonce), nowSecs())).toByteArray()
        val reply = try { WireJson.decodeFromString<ScriptsReply>(String(signedCall("/v1/scripts/list", body))) } catch (_: SerializationException) { throw ProtocolException() }
        checkFresh(reply.clientNonce, nonce, reply.serverTime)
        return Scripts(reply.unlocked, reply.scripts)
    }

    /** Starts the named script (a name the server configured). Returns at once; read the outcome with [scripts]. */
    fun runScript(name: String) {
        val nonce = freshNonce()
        val body = WireJson.encodeToString(ScriptRunBody(Codec.b64e(signer.id), Codec.b64e(nonce), nowSecs(), name)).toByteArray()
        val reply = try { WireJson.decodeFromString<ScriptRunReply>(String(signedCall("/v1/scripts/run", body))) } catch (_: SerializationException) { throw ProtocolException() }
        checkFresh(reply.clientNonce, nonce)
        if (reply.script != name) throw ProtocolException()
    }

    /**
     * Seals [entries] (any order, any subset of the request's drives) to the request's ephemeral key and approves.
     * The entries' passphrases are wiped before this returns, success or not.
     */
    fun approve(listing: Listing, request: RequestView, entries: List<PasswordEntry>): ApproveResult {
        var plain: ByteArray? = null
        try {
            val sorted = entries.sortedWith { a, b -> compareUnsigned(a.uuid, b.uuid) }
            val reqId = Codec.b64d(request.reqId)
            val info = Seal.info(pin.serverPub, reqId, listing.clientNonce, signer.id)
            val aad = Seal.aad(sorted.map { it.uuid })
            plain = Seal.encodePlaintext(sorted)
            val (enc, ct) = Seal.seal(Codec.b64d(request.ePub), info, aad, plain)
            val sig = signer.sign(Signatures.approveMessage(reqId, listing.clientNonce, enc, ct, aad))
            val body = WireJson.encodeToString(
                ApproveRequest(
                    Codec.b64e(signer.id), Codec.b64e(listing.clientNonce),
                    sorted.map { formatUuid(it.uuid) }, Codec.b64e(enc), Codec.b64e(ct), Codec.b64e(sig),
                ),
            )
            val text = post("/v1/requests/${request.reqId}/approve", body, readTimeoutMs = 180_000)
            val reply = try { WireJson.decodeFromString<ApproveReply>(String(verified(Domain.SERVER_REPLY, text))) } catch (_: Exception) { throw ProtocolException() }
            if (reply.clientNonce != Codec.b64e(listing.clientNonce) || reply.reqId != request.reqId) throw ProtocolException()
            return ApproveResult(reply.results)
        } finally {
            plain?.fill(0)
            entries.forEach { it.wipe() }
        }
    }

    companion object {
        fun parseUuid(text: String): ByteArray {
            val hex = text.replace("-", "")
            if (text.length != 36 || hex.length != 32) throw ProtocolException()
            return try { ByteArray(16) { hex.substring(2 * it, 2 * it + 2).toInt(16).toByte() } } catch (_: NumberFormatException) { throw ProtocolException() }
        }

        fun formatUuid(raw: ByteArray): String {
            val h = raw.joinToString("") { "%02x".format(it) }
            return "${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}"
        }

        private fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
            for (i in 0 until minOf(a.size, b.size)) {
                val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
                if (d != 0) return d
            }
            return a.size - b.size
        }
    }
}
