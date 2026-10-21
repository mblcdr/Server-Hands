package dev.serverhands.app.vault

import dev.serverhands.crypto.Codec
import dev.serverhands.protocol.Pin
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File

/** A drive the user enrolled a passphrase for. A passphrase is released only for UUIDs listed here. */
@Serializable
class EnrolledDrive(val uuid: String, val label: String)

/** Public data about the one paired server. Nothing secret: keys live in the Keystore, passphrases in the vault. */
@Serializable
class PairingRecord(
    val host: String,
    val port: Int,
    val spki: String,
    val sid: String,
    val keyAlias: String,
    val deviceName: String,
    val drives: List<EnrolledDrive> = emptyList(),
) {
    val pin: Pin get() = Pin(host, port, Codec.b64d(spki), Codec.b64d(sid))
    val serverPub: ByteArray get() = Codec.b64d(sid)
    fun withDrives(d: List<EnrolledDrive>) = PairingRecord(host, port, spki, sid, keyAlias, deviceName, d)

    companion object {
        fun aliasFor(serverPub: ByteArray) = "hands_device_" + Codec.sha256(serverPub).take(6).joinToString("") { "%02x".format(it) }
    }
}

/** Plain files in the app's private directory, written atomically. */
class PairingStore(private val dir: File) {
    private val record = File(dir, "pairing.json")
    private val vault = File(dir, "vault.bin")

    fun load(): PairingRecord? = try { Json.decodeFromString<PairingRecord>(record.readText()) } catch (_: Exception) { null }

    fun save(p: PairingRecord) = atomicWrite(record, Json.encodeToString(PairingRecord.serializer(), p).toByteArray())

    fun readVault(): ByteArray? = if (vault.exists()) vault.readBytes() else null

    fun writeVault(blob: ByteArray) = atomicWrite(vault, blob)

    fun clearVault() { vault.delete() }

    fun clear() { record.delete(); vault.delete() }

    private fun atomicWrite(f: File, bytes: ByteArray) {
        val tmp = File(dir, f.name + ".tmp")
        tmp.writeBytes(bytes)
        if (!tmp.renameTo(f)) throw java.io.IOException("rename failed")
    }
}
