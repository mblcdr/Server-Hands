package dev.serverhands.app

import android.app.Application
import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.serverhands.app.keys.KeySecurityException
import dev.serverhands.app.keys.KeystoreDeviceSigner
import dev.serverhands.app.keys.VaultKey
import dev.serverhands.app.vault.AuthCancelled
import dev.serverhands.app.vault.AuthFailed
import dev.serverhands.app.vault.Biometrics
import dev.serverhands.app.vault.EnrolledDrive
import dev.serverhands.app.vault.PairingRecord
import dev.serverhands.app.vault.PairingStore
import dev.serverhands.app.vault.VaultFormat
import dev.serverhands.crypto.PasswordEntry
import dev.serverhands.crypto.ProtocolException
import dev.serverhands.protocol.DriveResult
import dev.serverhands.protocol.PairingUri
import dev.serverhands.protocol.RequestView
import dev.serverhands.protocol.Scripts
import dev.serverhands.protocol.ServerClient
import dev.serverhands.protocol.ServerException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException
import javax.net.ssl.SSLException

data class UiState(
    val pairing: PairingRecord? = null,
    val requests: List<RequestView> = emptyList(),
    val sas: String? = null,
    val busy: String? = null,
    val message: String? = null,
    val results: List<DriveResult> = emptyList(),
    val scripts: Scripts? = null,
)

class AppViewModel(app: Application) : AndroidViewModel(app) {
    private val store = PairingStore(app.filesDir)
    private val allowSoftware = BuildConfig.ALLOW_SOFTWARE_KEYS
    private val _state = MutableStateFlow(UiState(pairing = store.load()))
    val state = _state.asStateFlow()

    private fun client(p: PairingRecord): ServerClient {
        val signer = KeystoreDeviceSigner.load(p.keyAlias) ?: throw KeySecurityException("device key is gone; pair again")
        return ServerClient(p.pin, signer)
    }

    /** Runs [block] with a busy label, turning every failure into a user message that never carries secrets. */
    private fun op(label: String, block: suspend () -> Unit) {
        viewModelScope.launch {
            _state.update { it.copy(busy = label, message = null) }
            try {
                block()
            } catch (e: AuthCancelled) {
                _state.update { it.copy(message = "Cancelled.") }
            } catch (e: Exception) {
                _state.update { it.copy(message = describe(e)) }
            } finally {
                _state.update { it.copy(busy = null, sas = null) }
            }
        }
    }

    private fun describe(e: Exception): String = when (e) {
        is ServerException -> when (e.code) {
            "unauthorized" -> "The server does not accept this phone (not paired, or revoked)."
            "rate_limited" -> "Too many failed attempts. Wait a few minutes."
            "not_unlocked" -> "Unlock all drives first."
            "busy" -> "That script is already running."
            "unknown_script" -> "The server no longer has that script. Refresh."
            "expired" -> "That request expired. Refresh."
            "replayed" -> "That request was already used. Refresh."
            else -> "The server refused the request (${e.code})."
        }
        is ProtocolException -> "The server's reply could not be verified. Nothing was sent."
        is SSLException -> "This is not the server you paired with (identity mismatch). Nothing was sent."
        is IOException -> "Cannot reach the server on the local network."
        is KeyPermanentlyInvalidatedException -> {
            VaultKey.delete()
            store.clearVault()
            store.load()?.let { store.save(it.withDrives(emptyList())) }
            _state.update { it.copy(pairing = store.load()) }
            "Biometrics changed, so the vault key was destroyed. Enter the drive passphrases again."
        }
        is KeySecurityException -> e.message ?: "Key error."
        is AuthFailed -> "Authentication failed: ${e.reason}"
        else -> "Unexpected error."
    }

    fun pair(text: String, deviceName: String) = op("Pairing") {
        val uri = try {
            PairingUri.parse(text)
        } catch (_: ProtocolException) {
            _state.update { it.copy(message = "That is not a Server Hands pairing code.") }
            return@op
        }
        val alias = PairingRecord.aliasFor(uri.pin.serverPub)
        val signer = KeystoreDeviceSigner.create(alias, allowSoftware)
        try {
            withContext(Dispatchers.IO) {
                ServerClient(uri.pin, signer).pair(uri.token, deviceName) { sas -> _state.update { it.copy(sas = sas) } }
            }
        } catch (e: Exception) {
            KeystoreDeviceSigner.delete(alias)
            throw e
        }
        val rec = PairingRecord(uri.pin.host, uri.pin.port, dev.serverhands.crypto.Codec.b64e(uri.pin.spkiSha256),
            dev.serverhands.crypto.Codec.b64e(uri.pin.serverPub), alias, deviceName)
        store.clear()
        store.save(rec)
        _state.update { it.copy(pairing = rec, message = "Paired. Refresh to see unlock requests.") }
    }

    fun refresh() = op("Checking server") {
        val p = _state.value.pairing ?: return@op
        val c = client(p)
        val listing = withContext(Dispatchers.IO) { c.list() }
        val scripts = withContext(Dispatchers.IO) { c.scripts() }
        _state.update { it.copy(requests = listing.requests, scripts = scripts, message = if (listing.requests.isEmpty()) "No drives waiting to be unlocked." else null) }
    }

    /** Starts a post-unlock script the server lists, then polls until it is no longer queued or running. */
    fun runScript(name: String) = op("Starting script") {
        val p = _state.value.pairing ?: return@op
        val c = client(p)
        withContext(Dispatchers.IO) { c.runScript(name) }
        repeat(120) {
            val s = withContext(Dispatchers.IO) { c.scripts() }
            _state.update { it.copy(scripts = s) }
            if (s.scripts.none { sc -> sc.busy }) return@op
            kotlinx.coroutines.delay(2_000)
        }
    }

    /** Stores [passphrases] (uuid -> raw bytes, taken over and wiped) in the vault behind a biometric. */
    fun enroll(activity: FragmentActivity, drives: List<dev.serverhands.protocol.DriveInfo>, passphrases: Map<String, ByteArray>) = op("Saving") {
        val p = _state.value.pairing ?: return@op
        val fresh = passphrases.map { (u, pw) -> PasswordEntry(ServerClient.parseUuid(u), pw) }
        var existing = emptyList<PasswordEntry>()
        try {
            Biometrics.unavailableReason(activity)?.let { throw KeySecurityException(it) }
            VaultKey.getOrCreate(allowSoftware)
            val blob = store.readVault()
            if (blob != null) {
                val c = Biometrics.authenticate(activity, VaultKey.decryptCipher(VaultFormat.ivOf(blob)), "Unlock vault", "Add drives to ${p.host}")
                existing = VaultFormat.open(c, p.serverPub, blob)
            }
            val merged = existing.filter { e -> fresh.none { it.uuid.contentEquals(e.uuid) } } + fresh
            val c = Biometrics.authenticate(activity, VaultKey.encryptCipher(allowSoftware), "Save passphrases", "Stored for ${p.host}")
            store.writeVault(VaultFormat.seal(c, p.serverPub, merged))
            val enrolled = (p.drives.filter { d -> drives.none { it.luksUuid == d.uuid } } +
                drives.filter { d -> passphrases.containsKey(d.luksUuid) }.map { EnrolledDrive(it.luksUuid, it.label) })
            val rec = p.withDrives(enrolled)
            store.save(rec)
            _state.update { it.copy(pairing = rec, message = "Saved.") }
        } finally {
            (existing + fresh).forEach { it.wipe() }
            passphrases.values.forEach { it.fill(0) }
        }
    }

    fun unlock(activity: FragmentActivity, request: RequestView) = op("Unlocking") {
        val p = _state.value.pairing ?: return@op
        val client = client(p)
        // Always act on a fresh, verified listing: its nonce is what the approval is bound to.
        val listing = withContext(Dispatchers.IO) { client.list() }
        val req = listing.requests.find { it.reqId == request.reqId }
        if (req == null) {
            _state.update { it.copy(requests = listing.requests, message = "That request is gone. Refreshed.") }
            return@op
        }
        val wanted = req.drives.filter { d -> p.drives.any { it.uuid == d.luksUuid } }
        if (wanted.isEmpty()) {
            _state.update { it.copy(requests = listing.requests, message = "No passphrase is saved for these drives.") }
            return@op
        }
        val blob = store.readVault() ?: throw KeySecurityException("Vault is empty. Enter the passphrases again.")
        val c = Biometrics.authenticate(
            activity, VaultKey.decryptCipher(VaultFormat.ivOf(blob)),
            "Unlock ${p.host}", wanted.joinToString { it.label },
        )
        val all = VaultFormat.open(c, p.serverPub, blob)
        // Release only passphrases for drives this request asks for AND that were enrolled for this server.
        val wantedRaw = wanted.map { ServerClient.parseUuid(it.luksUuid) }
        val chosen = all.filter { e -> wantedRaw.any { it.contentEquals(e.uuid) } }
        all.filter { it !in chosen }.forEach { it.wipe() }
        val result = try {
            withContext(Dispatchers.IO) { client.approve(listing, req, chosen) } // wipes `chosen`
        } finally {
            chosen.forEach { it.wipe() }
        }
        _state.update { it.copy(results = result.results) }
        val after = withContext(Dispatchers.IO) { client.list() }
        val scripts = withContext(Dispatchers.IO) { client.scripts() }
        _state.update { it.copy(requests = after.requests, scripts = scripts, message = null) }
    }

    fun clearResults() = _state.update { it.copy(results = emptyList()) }

    fun forget() {
        _state.value.pairing?.let { KeystoreDeviceSigner.delete(it.keyAlias) }
        VaultKey.delete()
        store.clear()
        _state.value = UiState()
    }
}
