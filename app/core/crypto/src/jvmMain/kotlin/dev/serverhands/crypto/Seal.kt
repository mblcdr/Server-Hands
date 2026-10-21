package dev.serverhands.crypto

import org.bouncycastle.crypto.hpke.HPKE

/** One drive passphrase. Raw bytes only; caller must [wipe] after use. Deliberately has no toString. */
class PasswordEntry(val uuid: ByteArray, val passphrase: ByteArray) {
    fun wipe() = passphrase.fill(0)
    override fun toString(): String = "PasswordEntry(redacted)"
}

/** HPKE RFC 9180 base mode: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305. */
object Seal {
    const val PLAINTEXT_VERSION = 1
    const val PAD_TO = 256
    const val MAX_PW_LEN = 1024
    const val MAX_ENTRIES = 32

    private fun hpke() = HPKE(HPKE.mode_base, HPKE.kem_X25519_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_CHACHA20_POLY1305)

    fun info(serverPub: ByteArray, reqId: ByteArray, clientNonce: ByteArray, deviceId: ByteArray): ByteArray =
        Codec.lp("hands/v1/hpke".toByteArray(), Codec.sha256(serverPub), reqId, clientNonce, deviceId)

    /** [uuids] must be raw 16-byte values in strictly ascending order. */
    fun aad(uuids: List<ByteArray>): ByteArray {
        for (i in 1 until uuids.size) if (compareUnsigned(uuids[i - 1], uuids[i]) >= 0) throw ProtocolException()
        return Codec.lp(*uuids.toTypedArray())
    }

    /** Returns `(enc, ct || tag)`. */
    fun seal(ephPub: ByteArray, info: ByteArray, aad: ByteArray, plaintext: ByteArray): Pair<ByteArray, ByteArray> = try {
        val h = hpke()
        val ctx = h.setupBaseS(h.deserializePublicKey(ephPub), info)
        ctx.encapsulation to ctx.seal(aad, plaintext)
    } catch (_: Exception) {
        throw ProtocolException()
    }

    /** Receiver side; the phone never needs it, but tests and interop do. */
    fun open(ephPriv: ByteArray, ephPub: ByteArray, enc: ByteArray, info: ByteArray, aad: ByteArray, ct: ByteArray): ByteArray = try {
        val h = hpke()
        h.setupBaseR(enc, h.deserializePrivateKey(ephPriv, ephPub), info).open(aad, ct)
    } catch (_: Exception) {
        throw ProtocolException()
    }

    fun deriveEphemeral(ikm: ByteArray): Pair<ByteArray, ByteArray> {
        val h = hpke()
        val kp = h.deriveKeyPair(ikm)
        return h.serializePrivateKey(kp.private) to h.serializePublicKey(kp.public)
    }

    /** `0x01 || count || count x (uuid[16] || len_be16 || pw) || zero padding to a multiple of 256`. */
    fun encodePlaintext(entries: List<PasswordEntry>): ByteArray {
        if (entries.isEmpty() || entries.size > MAX_ENTRIES) throw ProtocolException()
        for (i in entries.indices) {
            val e = entries[i]
            if (e.uuid.size != 16 || e.passphrase.isEmpty() || e.passphrase.size > MAX_PW_LEN) throw ProtocolException()
            if (i > 0 && compareUnsigned(entries[i - 1].uuid, e.uuid) >= 0) throw ProtocolException()
        }
        val len = 2 + entries.sumOf { 16 + 2 + it.passphrase.size }
        val out = ByteArray((len + PAD_TO - 1) / PAD_TO * PAD_TO)
        var i = 0
        out[i++] = PLAINTEXT_VERSION.toByte()
        out[i++] = entries.size.toByte()
        for (e in entries) {
            e.uuid.copyInto(out, i); i += 16
            out[i++] = (e.passphrase.size ushr 8).toByte()
            out[i++] = e.passphrase.size.toByte()
            e.passphrase.copyInto(out, i); i += e.passphrase.size
        }
        return out
    }

    fun decodePlaintext(buf: ByteArray): List<PasswordEntry> {
        var i = 0
        fun need(n: Int) { if (n < 0 || i + n > buf.size) throw ProtocolException() }
        need(2)
        if (buf[i++].toInt() != PLAINTEXT_VERSION) throw ProtocolException()
        val count = buf[i++].toInt() and 0xff
        if (count == 0 || count > MAX_ENTRIES || buf.size % PAD_TO != 0) throw ProtocolException()
        val out = ArrayList<PasswordEntry>(count)
        repeat(count) {
            need(18)
            val uuid = buf.copyOfRange(i, i + 16); i += 16
            val len = ((buf[i].toInt() and 0xff) shl 8) or (buf[i + 1].toInt() and 0xff); i += 2
            if (len == 0 || len > MAX_PW_LEN) throw ProtocolException()
            if (out.isNotEmpty() && compareUnsigned(out.last().uuid, uuid) >= 0) throw ProtocolException()
            need(len)
            out.add(PasswordEntry(uuid, buf.copyOfRange(i, i + len))); i += len
        }
        for (j in i until buf.size) if (buf[j].toInt() != 0) throw ProtocolException()
        return out
    }

    /** 6-digit pairing confirmation code. */
    fun sas(serverPub: ByteArray, deviceSpki: ByteArray, token: ByteArray): String {
        val h = Codec.sha256("hands/v1/sas".toByteArray() + Codec.lp(serverPub, deviceSpki, token))
        val n = ((h[0].toLong() and 0xff) shl 24) or ((h[1].toLong() and 0xff) shl 16) or ((h[2].toLong() and 0xff) shl 8) or (h[3].toLong() and 0xff)
        return (n % 1_000_000L).toString().padStart(6, '0')
    }

    private fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
        val n = minOf(a.size, b.size)
        for (k in 0 until n) {
            val d = (a[k].toInt() and 0xff) - (b[k].toInt() and 0xff)
            if (d != 0) return d
        }
        return a.size - b.size
    }
}
