package dev.serverhands.app

import dev.serverhands.app.vault.EnrolledDrive
import dev.serverhands.app.vault.PairingRecord
import dev.serverhands.app.vault.PairingStore
import dev.serverhands.app.vault.VaultFormat
import dev.serverhands.crypto.PasswordEntry
import dev.serverhands.crypto.ProtocolException
import java.io.File
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import org.junit.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class VaultFormatTest {
    private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val server = ByteArray(32) { 5 }
    private fun enc() = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
    private fun dec(blob: ByteArray) =
        Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, VaultFormat.ivOf(blob))) }
    private fun e(b: Int, pw: String) = PasswordEntry(ByteArray(16) { b.toByte() }, pw.toByteArray())

    @Test
    fun roundTripSortsEntriesAndPads() {
        val blob = VaultFormat.seal(enc(), server, listOf(e(9, "nine"), e(1, "one")))
        // 1 version + 12 iv + 256 padded plaintext + 16 tag, regardless of how short the passphrases are
        assertEquals(1 + 12 + 256 + 16, blob.size)
        val out = VaultFormat.open(dec(blob), server, blob)
        assertEquals(listOf("one", "nine"), out.map { String(it.passphrase) })
    }

    @Test
    fun blobIsBoundToTheServerAndRejectsTampering() {
        val blob = VaultFormat.seal(enc(), server, listOf(e(1, "x")))
        assertFailsWith<ProtocolException> { VaultFormat.open(dec(blob), ByteArray(32) { 6 }, blob) }
        val flipped = blob.copyOf().also { it[blob.size - 20] = (it[blob.size - 20].toInt() xor 1).toByte() }
        assertFailsWith<ProtocolException> { VaultFormat.open(dec(flipped), server, flipped) }
        assertFailsWith<ProtocolException> { VaultFormat.ivOf(byteArrayOf(2) + ByteArray(40)) }
    }

    @Test
    fun ivsDifferBetweenSeals() {
        val a = VaultFormat.seal(enc(), server, listOf(e(1, "x")))
        val b = VaultFormat.seal(enc(), server, listOf(e(1, "x")))
        assert(!VaultFormat.ivOf(a).contentEquals(VaultFormat.ivOf(b)))
    }

    @Test
    fun pairingStoreRoundTripAndClear() {
        val dir = File(System.getProperty("java.io.tmpdir"), "hands-store-${System.nanoTime()}").apply { mkdirs() }
        val store = PairingStore(dir)
        assertNull(store.load())
        val sid = ByteArray(32) { 3 }
        val b64 = dev.serverhands.crypto.Codec::b64e
        val rec = PairingRecord("10.0.0.2", 7787, b64(ByteArray(32) { 4 }), b64(sid), PairingRecord.aliasFor(sid), "Pixel")
            .withDrives(listOf(EnrolledDrive("00000000-0000-4000-8000-000000000001", "Disk-1")))
        store.save(rec)
        store.writeVault(byteArrayOf(1, 2, 3))
        val back = store.load()!!
        assertEquals("Disk-1", back.drives.single().label)
        assertContentEquals(sid, back.serverPub)
        store.clear()
        assertNull(store.load()); assertNull(store.readVault())
        dir.deleteRecursively()
    }
}
