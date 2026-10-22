package dev.serverhands.app.ui

import org.junit.Test
import kotlin.test.assertEquals

class FormatTest {
    @Test
    fun bytesUseDecimalUnits() {
        assertEquals("0 B", formatBytes(0))
        assertEquals("999 B", formatBytes(999))
        assertEquals("1.5 kB", formatBytes(1_500))
        assertEquals("4.0 TB", formatBytes(4_000_000_000_000))
        assertEquals("120 GB", formatBytes(120_000_000_000))
        assertEquals("16 GB", formatBytes(16_000_000_000))
    }

    @Test
    fun uptimePicksTheTwoLargestUnits() {
        assertEquals("45s", formatUptime(45))
        assertEquals("12m", formatUptime(12 * 60 + 5))
        assertEquals("4h 12m", formatUptime(4 * 3600 + 12 * 60))
        assertEquals("3d 4h", formatUptime(3 * 86_400 + 4 * 3600 + 59))
    }

    @Test
    fun fractionIsClampedAndSafeOnZero() {
        assertEquals(0f, fraction(5, 0))
        assertEquals(0.25f, fraction(1, 4))
        assertEquals(1f, fraction(9, 4))
        assertEquals("25%", percent(0.25f))
    }
}
