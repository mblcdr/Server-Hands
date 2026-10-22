package dev.serverhands.app.ui

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.PathBuilder
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.unit.dp

/** Small outline icons drawn in code, so the app needs no icon library. All 24 x 24, tinted by the caller. */
object AppIcons {
    val Server: ImageVector by lazy {
        icon("Server") {
            rect(4f, 3.5f, 16f, 7f); rect(4f, 13.5f, 16f, 7f)
            dot(8f, 7f); dot(8f, 17f); line(12f, 7f, 16f, 7f); line(12f, 17f, 16f, 17f)
        }
    }
    val Terminal: ImageVector by lazy {
        icon("Terminal") {
            rect(3f, 4f, 18f, 16f)
            moveTo(7f, 9f); lineTo(10.5f, 12f); lineTo(7f, 15f)
            line(12.5f, 15f, 17f, 15f)
        }
    }
    val HardDrive: ImageVector by lazy {
        icon("HardDrive") {
            rect(3f, 6f, 18f, 12f)
            line(3f, 13f, 21f, 13f)
            dot(17f, 15.5f); line(6.5f, 15.5f, 11f, 15.5f)
            dot(7f, 9.5f)
        }
    }
    val Layers: ImageVector by lazy {
        icon("Layers") {
            moveTo(12f, 3f); lineTo(21f, 8f); lineTo(12f, 13f); lineTo(3f, 8f); close()
            moveTo(3f, 12f); lineTo(12f, 17f); lineTo(21f, 12f)
            moveTo(3f, 16f); lineTo(12f, 21f); lineTo(21f, 16f)
        }
    }
    val Play: ImageVector by lazy {
        icon("Play") { moveTo(8f, 5f); lineTo(19f, 12f); lineTo(8f, 19f); close() }
    }
    val Lock: ImageVector by lazy {
        icon("Lock") {
            rect(5f, 11f, 14f, 9f)
            moveTo(8f, 11f); verticalLineTo(8f); curveTo(8f, 5.5f, 16f, 5.5f, 16f, 8f); verticalLineTo(11f)
        }
    }

    private fun icon(name: String, block: PathBuilder.() -> Unit): ImageVector =
        ImageVector.Builder(name, 24.dp, 24.dp, 24f, 24f).path(
            stroke = SolidColor(Color.Black),
            strokeLineWidth = 1.8f,
            strokeLineCap = StrokeCap.Round,
            strokeLineJoin = StrokeJoin.Round,
            pathBuilder = block,
        ).build()

    private fun PathBuilder.rect(x: Float, y: Float, w: Float, h: Float) {
        moveTo(x, y); horizontalLineToRelative(w); verticalLineToRelative(h); horizontalLineToRelative(-w); close()
    }

    private fun PathBuilder.line(x1: Float, y1: Float, x2: Float, y2: Float) { moveTo(x1, y1); lineTo(x2, y2) }

    /** A zero-length stroke with round caps draws a dot. */
    private fun PathBuilder.dot(x: Float, y: Float) { moveTo(x, y); lineToRelative(0.01f, 0f) }
}
