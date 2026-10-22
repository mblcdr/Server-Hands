package dev.serverhands.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.serverhands.app.UiState
import dev.serverhands.protocol.ScriptView

@Composable
fun ScriptsTab(ui: UiState, onCheck: () -> Unit, onRun: (ScriptView) -> Unit) {
    val scripts = ui.scripts
    LazyColumn(
        Modifier.fillMaxSize().padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { Header("Scripts") }
        item { StatusStrip(ui) }
        if (scripts != null && !scripts.unlocked) {
            item {
                Panel {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Icon(AppIcons.Lock, null, tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(24.dp))
                        Text("Drives are locked. Scripts that need the data are refused until they are unlocked.", style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }
        if (scripts == null || scripts.scripts.isEmpty()) {
            item {
                Panel {
                    Text(if (scripts == null) "Not loaded yet." else "No scripts configured.", style = MaterialTheme.typography.titleSmall)
                    Text(
                        if (scripts == null) "Check the connection to load the server's scripts." else "Add [[script]] entries to /etc/server-hands/config.toml on the server.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    FilledTonalButton(onClick = onCheck, enabled = ui.busy == null) { Text("Check") }
                }
            }
        } else {
            items(scripts.scripts, key = { it.name }) { s -> ScriptItem(s, enabled = ui.busy == null, onRun = { onRun(s) }) }
        }
        item { Column(Modifier.padding(bottom = 16.dp)) {} }
    }
}

@Composable
private fun ScriptItem(s: ScriptView, enabled: Boolean, onRun: () -> Unit) = Panel {
    val tint = when (s.state) {
        "failed" -> MaterialTheme.colorScheme.error
        "running", "queued" -> MaterialTheme.colorScheme.tertiary
        else -> MaterialTheme.colorScheme.primary
    }
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        IconBadge(AppIcons.Terminal, tint, tint.copy(alpha = 0.12f))
        Column(Modifier.weight(1f)) {
            Text(s.label, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(
                (if (s.mode == "auto") "Runs automatically" else "Manual") + " · " + when (s.state) {
                    "idle" -> "not run yet"; "queued" -> "waiting"; "running" -> "running"
                    "ok" -> "finished"; else -> "failed"
                },
                style = MaterialTheme.typography.bodySmall,
                color = if (s.state == "failed") MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (s.biometricProtection || s.requiresConfirmation) {
                Row(Modifier.padding(top = 6.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    if (s.biometricProtection) Pill("Biometric", MaterialTheme.colorScheme.secondary)
                    else Pill("Asks first", MaterialTheme.colorScheme.outline)
                }
            }
        }
        FilledTonalButton(onClick = onRun, enabled = enabled && !s.busy) {
            Icon(AppIcons.Play, null, modifier = Modifier.size(18.dp))
            Text(if (s.state == "failed") "Retry" else "Run", modifier = Modifier.padding(start = 6.dp))
        }
    }
}
