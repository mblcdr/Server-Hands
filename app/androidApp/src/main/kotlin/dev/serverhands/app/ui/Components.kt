package dev.serverhands.app.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/** A bordered, softly rounded container; the basic building block of the screens. */
@Composable
fun Panel(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) = Card(
    modifier.fillMaxWidth(),
    shape = RoundedCornerShape(16.dp),
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
) {
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp), content = content)
}

/** A rounded tile with a tinted icon. */
@Composable
fun IconBadge(icon: ImageVector, tint: Color, container: Color, size: Dp = 44.dp) = Box(
    Modifier.size(size).clip(RoundedCornerShape(12.dp)).background(container),
    contentAlignment = Alignment.Center,
) {
    Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(size * 0.55f))
}

/** A small rounded label such as "Connected" or "Passphrase saved". */
@Composable
fun Pill(text: String, color: Color) = Surface(shape = CircleShape, color = color.copy(alpha = 0.14f)) {
    Text(text, color = color, style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp))
}

/** A thick rounded bar; turns to the error colour when nearly full. */
@Composable
fun UsageBar(fraction: Float, modifier: Modifier = Modifier) = LinearProgressIndicator(
    progress = { fraction.coerceIn(0f, 1f) },
    modifier = modifier.fillMaxWidth().height(10.dp).clip(RoundedCornerShape(5.dp)),
    color = if (fraction >= 0.9f) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
    trackColor = MaterialTheme.colorScheme.surfaceContainerHighest,
    strokeCap = StrokeCap.Round,
    gapSize = 0.dp,
    drawStopIndicator = {},
)

@Composable
fun SectionTitle(text: String, modifier: Modifier = Modifier) =
    Text(text, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = modifier.padding(top = 8.dp, start = 4.dp))
