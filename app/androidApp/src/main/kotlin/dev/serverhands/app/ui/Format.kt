package dev.serverhands.app.ui

import java.util.Locale

/** Decimal units, like drive makers and `df -H`: 4 TB means 4 * 10^12 bytes. */
fun formatBytes(bytes: Long): String {
    if (bytes <= 0) return "0 B"
    val units = listOf("B", "kB", "MB", "GB", "TB", "PB")
    var v = bytes.toDouble()
    var i = 0
    while (v >= 1000 && i < units.lastIndex) { v /= 1000; i++ }
    return if (i == 0) "${bytes} B" else String.format(Locale.US, if (v < 10) "%.1f %s" else "%.0f %s", v, units[i])
}

/** "3d 4h", "4h 12m", "12m", "45s". */
fun formatUptime(secs: Long): String {
    val d = secs / 86_400
    val h = secs % 86_400 / 3_600
    val m = secs % 3_600 / 60
    return when {
        d > 0 -> "${d}d ${h}h"
        h > 0 -> "${h}h ${m}m"
        m > 0 -> "${m}m"
        else -> "${secs.coerceAtLeast(0)}s"
    }
}

fun fraction(part: Long, whole: Long): Float = if (whole <= 0) 0f else (part.toDouble() / whole).toFloat().coerceIn(0f, 1f)

fun percent(f: Float): String = "${(f * 100).toInt()}%"
