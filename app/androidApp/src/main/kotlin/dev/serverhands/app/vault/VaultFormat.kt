package dev.serverhands.app.vault

import dev.serverhands.crypto.Codec
import dev.serverhands.crypto.PasswordEntry
import dev.serverhands.crypto.ProtocolException
import dev.serverhands.crypto.Seal
import javax.crypto.Cipher

/**
 * `0x01 || iv[12] || AES-GCM(Seal plaintext format)`, AAD = `lp("hands/v1/vault", SHA-256(server key))` so a blob
 * cannot be moved between servers. The plaintext reuses the wire format: entries ascending by UUID, zero padded to
 * 256 bytes (the blob does not reveal how many drives or how long the passphrases are).
 * The ciphers are supplied initialised (and, on a phone, biometrically authorised) by the caller.
 */
object VaultFormat {
    const val VERSION = 1
    const val IV_LEN = 12

    fun aad(serverPub: ByteArray): ByteArray = Codec.lp("hands/v1/vault".toByteArray(), Codec.sha256(serverPub))

    fun ivOf(blob: ByteArray): ByteArray {
        if (blob.size < 1 + IV_LEN + 16 || blob[0].toInt() != VERSION) throw ProtocolException()
        return blob.copyOfRange(1, 1 + IV_LEN)
    }

    /** [cipher] must be initialised for encryption. Entries are NOT wiped here. */
    fun seal(cipher: Cipher, serverPub: ByteArray, entries: List<PasswordEntry>): ByteArray {
        val plain = Seal.encodePlaintext(entries.sortedWith { a, b -> compare(a.uuid, b.uuid) })
        try {
            cipher.updateAAD(aad(serverPub))
            val ct = cipher.doFinal(plain)
            return byteArrayOf(VERSION.toByte()) + cipher.iv + ct
        } finally {
            plain.fill(0)
        }
    }

    /** [cipher] must be initialised for decryption with [ivOf]. Caller wipes the returned entries. */
    fun open(cipher: Cipher, serverPub: ByteArray, blob: ByteArray): List<PasswordEntry> {
        val plain = try {
            cipher.updateAAD(aad(serverPub))
            cipher.doFinal(blob, 1 + IV_LEN, blob.size - 1 - IV_LEN)
        } catch (_: Exception) {
            throw ProtocolException()
        }
        try {
            return Seal.decodePlaintext(plain)
        } finally {
            plain.fill(0)
        }
    }

    fun compare(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (d != 0) return d
        }
        return a.size - b.size
    }
}
