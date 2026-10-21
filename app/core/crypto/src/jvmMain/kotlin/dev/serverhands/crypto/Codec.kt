package dev.serverhands.crypto

import java.security.MessageDigest
import java.util.Base64

/** Opaque failure: callers cannot tell why verification or decoding failed (and no payload leaks). */
class ProtocolException : Exception("protocol error")

object Codec {
    private val enc = Base64.getUrlEncoder().withoutPadding()
    private val dec = Base64.getUrlDecoder()

    fun b64e(bytes: ByteArray): String = enc.encodeToString(bytes)

    fun b64d(s: String): ByteArray = try {
        dec.decode(s)
    } catch (_: IllegalArgumentException) {
        throw ProtocolException()
    }

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    /** `u32be(len) || bytes` per field. */
    fun lp(vararg fields: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream(fields.sumOf { it.size + 4 })
        for (f in fields) {
            out.write(byteArrayOf((f.size ushr 24).toByte(), (f.size ushr 16).toByte(), (f.size ushr 8).toByte(), f.size.toByte()))
            out.write(f)
        }
        return out.toByteArray()
    }

    /** `domain || 0x00 || body`: the exact bytes that get signed. */
    fun signedBytes(domain: ByteArray, body: ByteArray): ByteArray = domain + byteArrayOf(0) + body

    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    fun wipe(vararg arrays: ByteArray) = arrays.forEach { it.fill(0) }
}

object Domain {
    val SERVER_REPLY = "hands/v1/server-reply".toByteArray()
    val DEVICE_REQUEST = "hands/v1/device-request".toByteArray()
    val APPROVE = "hands/v1/approve".toByteArray()
    val PAIR = "hands/v1/pair".toByteArray()
}
