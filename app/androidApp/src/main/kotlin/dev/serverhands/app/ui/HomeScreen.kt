package dev.serverhands.app.ui

import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedSecureTextField
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import dev.serverhands.app.AppViewModel
import dev.serverhands.app.UiState
import dev.serverhands.protocol.DriveInfo
import dev.serverhands.protocol.RequestView
import dev.serverhands.protocol.ScriptView
import dev.serverhands.protocol.Scripts
import java.nio.CharBuffer

@Composable
fun HomeScreen(vm: AppViewModel, activity: FragmentActivity) {
    val ui by vm.state.collectAsStateWithLifecycle()
    var enrolling by remember { mutableStateOf<RequestView?>(null) }
    var confirming by remember { mutableStateOf<ScriptView?>(null) }

    Scaffold { pad ->
        LazyColumn(
            Modifier.fillMaxSize().padding(pad).padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item { Text("Server Hands", style = MaterialTheme.typography.headlineMedium, modifier = Modifier.padding(top = 16.dp)) }
            if (ui.busy != null) item { Column { Text(ui.busy!!); LinearProgressIndicator(Modifier.fillMaxWidth()) } }
            ui.sas?.let { code -> item { SasCard(code) } }
            ui.message?.let { m -> item { Text(m, color = MaterialTheme.colorScheme.primary) } }

            val pairing = ui.pairing
            if (pairing == null) {
                item { PairCard(ui, vm) }
            } else {
                item {
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text("Paired server", style = MaterialTheme.typography.titleMedium)
                            Text("${pairing.host}:${pairing.port}")
                            Text("Key fingerprint", style = MaterialTheme.typography.labelMedium)
                            Text(pairing.pin.fingerprint, fontFamily = FontFamily.Monospace)
                            Text("This phone: ${pairing.deviceName}", style = MaterialTheme.typography.bodySmall)
                            Text("Saved passphrases: ${pairing.drives.joinToString { it.label }.ifEmpty { "none" }}", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
                item { Button(onClick = vm::refresh, enabled = ui.busy == null) { Text("Check for unlock requests") } }
                items(ui.requests, key = { it.reqId }) { r ->
                    RequestCard(r, pairing.drives.map { it.uuid }.toSet(), ui.busy == null,
                        onUnlock = { vm.unlock(activity, r) }, onEnroll = { enrolling = r })
                }
                ui.scripts?.takeIf { it.scripts.isNotEmpty() }?.let { sc ->
                    item {
                        ScriptsCard(sc, ui.busy == null) { s ->
                            // With biometric protection the biometric prompt is the confirmation: no extra dialog.
                            if (s.requiresConfirmation && !s.biometricProtection) confirming = s else vm.runScript(activity, s)
                        }
                    }
                }
                item { TextButton(onClick = vm::forget, enabled = ui.busy == null) { Text("Forget this server") } }
            }
        }
    }

    confirming?.let { s ->
        AlertDialog(
            onDismissRequest = { confirming = null },
            title = { Text("Run ${s.label}?") },
            text = { Text("This starts the script on ${ui.pairing?.host ?: "the server"} right away.") },
            confirmButton = { TextButton(onClick = { confirming = null; vm.runScript(activity, s) }) { Text("Run") } },
            dismissButton = { TextButton(onClick = { confirming = null }) { Text("Cancel") } },
        )
    }

    enrolling?.let { req ->
        val missing = req.drives.filter { d -> ui.pairing?.drives?.none { it.uuid == d.luksUuid } != false }
        EnrollDialog(
            drives = missing.ifEmpty { req.drives },
            onDismiss = { enrolling = null },
            onSave = { map -> enrolling = null; vm.enroll(activity, req.drives, map) },
        )
    }

    if (ui.results.isNotEmpty()) {
        AlertDialog(
            onDismissRequest = vm::clearResults,
            confirmButton = { TextButton(onClick = vm::clearResults) { Text("OK") } },
            title = { Text("Result") },
            text = {
                Column {
                    ui.results.forEach {
                        val name = ui.pairing?.drives?.find { d -> d.uuid == it.luksUuid }?.label ?: it.luksUuid
                        Text("$name: " + when (it.result) {
                            "ok" -> "unlocked"; "already_open" -> "already unlocked"; "bad_passphrase" -> "wrong passphrase"; else -> "failed"
                        })
                    }
                }
            },
        )
    }
}

@Composable
private fun ScriptsCard(scripts: Scripts, enabled: Boolean, onRun: (ScriptView) -> Unit) = Card(Modifier.fillMaxWidth()) {
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Scripts", style = MaterialTheme.typography.titleMedium)
        if (!scripts.unlocked) Text("Drives are locked. Scripts that need the data are refused until they are unlocked.", style = MaterialTheme.typography.bodySmall)
        scripts.scripts.forEach { s ->
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(s.label)
                    Text(
                        (if (s.mode == "auto") "runs automatically" else "manual") + ": " + when (s.state) {
                            "idle" -> "not run yet"; "queued" -> "waiting"; "running" -> "running"
                            "ok" -> "finished"; else -> "failed"
                        } + if (s.biometricProtection) " (needs biometric)" else "",
                        style = MaterialTheme.typography.bodySmall,
                        color = if (s.state == "failed") MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                OutlinedButton(onClick = { onRun(s) }, enabled = enabled && !s.busy) { Text(if (s.state == "failed") "Retry" else "Run") }
            }
        }
    }
}

@Composable
private fun SasCard(code: String) = Card(Modifier.fillMaxWidth()) {
    Column(Modifier.padding(16.dp)) {
        Text("Confirm on the server console that this code matches:")
        Text(code, fontSize = 40.sp, fontFamily = FontFamily.Monospace)
        Text("Pairing continues once the operator confirms.", style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun PairCard(ui: UiState, vm: AppViewModel) {
    var pasted by rememberSaveable { mutableStateOf("") }
    val deviceName = Build.MODEL
    val scan = rememberLauncherForActivityResult(ScanContract()) { r -> r.contents?.let { vm.pair(it, deviceName) } }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Pair with your server", style = MaterialTheme.typography.titleMedium)
            Text("On the server run: sudo handsctl pair", style = MaterialTheme.typography.bodySmall)
            Button(
                enabled = ui.busy == null,
                onClick = { scan.launch(ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE).setBeepEnabled(false).setOrientationLocked(false).setPrompt("Scan the QR from handsctl pair")) },
            ) { Text("Scan QR code") }
            OutlinedTextField(pasted, { pasted = it }, label = { Text("or paste the hands:// link") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
            OutlinedButton(onClick = { vm.pair(pasted, deviceName); pasted = "" }, enabled = ui.busy == null && pasted.isNotBlank()) { Text("Pair") }
        }
    }
}

@Composable
private fun RequestCard(r: RequestView, enrolled: Set<String>, enabled: Boolean, onUnlock: () -> Unit, onEnroll: () -> Unit) {
    val canUnlock = r.drives.any { it.luksUuid in enrolled }
    val needsEnroll = r.drives.any { it.luksUuid !in enrolled }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Unlock request", style = MaterialTheme.typography.titleMedium)
            r.drives.forEach {
                Text("${it.label}  (${it.size / 1_000_000_000} GB)" + if (it.luksUuid in enrolled) "" else "  passphrase not saved")
                Text(it.luksUuid, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (canUnlock) Button(onClick = onUnlock, enabled = enabled) { Text("Unlock") }
                if (needsEnroll) OutlinedButton(onClick = onEnroll, enabled = enabled) { Text("Save passphrases") }
            }
        }
    }
}

/** Passphrases live in secure text fields and are turned into byte arrays that are wiped after use. */
@Composable
private fun EnrollDialog(drives: List<DriveInfo>, onDismiss: () -> Unit, onSave: (Map<String, ByteArray>) -> Unit) {
    val fields = remember { drives.associate { it.luksUuid to TextFieldState() } }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Save passphrases") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Use the phone passphrase from: sudo handsctl add-phone-key <uuid>", style = MaterialTheme.typography.bodySmall)
                drives.forEach { d -> OutlinedSecureTextField(fields.getValue(d.luksUuid), label = { Text(d.label) }, modifier = Modifier.fillMaxWidth()) }
            }
        },
        confirmButton = {
            TextButton(onClick = { onSave(fields.mapNotNull { (u, s) -> s.takeBytes()?.let { u to it } }.toMap()) }) { Text("Save with biometric") }
        },
        dismissButton = { TextButton(onClick = { fields.values.forEach { it.clearText() }; onDismiss() }) { Text("Cancel") } },
    )
}

private fun TextFieldState.takeBytes(): ByteArray? {
    val t = text
    if (t.isEmpty()) return null
    val chars = CharArray(t.length) { t[it] }
    val buf = Charsets.UTF_8.encode(CharBuffer.wrap(chars))
    val out = ByteArray(buf.remaining()).also { buf.get(it) }
    chars.fill('\u0000')
    if (buf.hasArray()) buf.array().fill(0)
    clearText()
    return out
}
