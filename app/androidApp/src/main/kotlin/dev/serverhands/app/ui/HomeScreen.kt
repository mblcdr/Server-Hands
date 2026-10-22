package dev.serverhands.app.ui

import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedSecureTextField
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import dev.serverhands.app.AppViewModel
import dev.serverhands.app.UiState
import dev.serverhands.protocol.DriveInfo
import dev.serverhands.protocol.RequestView
import dev.serverhands.protocol.ScriptView
import java.nio.CharBuffer

@Composable
fun HomeScreen(vm: AppViewModel, activity: FragmentActivity) {
    val ui by vm.state.collectAsStateWithLifecycle()
    var enrolling by remember { mutableStateOf<RequestView?>(null) }
    var confirming by remember { mutableStateOf<ScriptView?>(null) }
    var tab by rememberSaveable { mutableIntStateOf(0) }

    // Reconnect (or confirm the connection) and keep the server status fresh while the app is in the foreground.
    LifecycleResumeEffect(Unit) {
        vm.onResume()
        onPauseOrDispose { vm.onPause() }
    }

    val pairing = ui.pairing
    Scaffold(
        bottomBar = {
            if (pairing != null) NavigationBar {
                NavigationBarItem(selected = tab == 0, onClick = { tab = 0 }, icon = { Icon(AppIcons.Server, null) }, label = { Text("Server") })
                NavigationBarItem(selected = tab == 1, onClick = { tab = 1 }, icon = { Icon(AppIcons.Terminal, null) }, label = { Text("Scripts") })
            }
        },
    ) { pad ->
        Column(Modifier.fillMaxSize().padding(pad)) {
            when {
                pairing == null -> LazyColumn(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    item { Header("Server Hands") }
                    item { StatusStrip(ui) }
                    item { PairCard(ui, vm) }
                }
                tab == 0 -> ServerTab(
                    ui, pairing,
                    onRefresh = vm::refresh,
                    onUnlock = { r -> vm.unlock(activity, r) },
                    onEnroll = { r -> enrolling = r },
                    onForget = vm::forget,
                )
                else -> ScriptsTab(
                    ui,
                    onCheck = vm::refresh,
                    onRun = { s ->
                        // With biometric protection the biometric prompt is the confirmation: no extra dialog.
                        if (s.requiresConfirmation && !s.biometricProtection) confirming = s else vm.runScript(activity, s)
                    },
                )
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
internal fun Header(title: String) = Text(title, style = MaterialTheme.typography.headlineMedium, modifier = Modifier.padding(top = 16.dp))

/** What is going on right now: progress, the pairing code, the last message. */
@Composable
internal fun StatusStrip(ui: UiState) = Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
    ui.busy?.let { Column { Text(it); LinearProgressIndicator(Modifier.fillMaxWidth()) } }
    ui.sas?.let { SasCard(it) }
    ui.message?.let { Text(it, color = MaterialTheme.colorScheme.primary) }
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
