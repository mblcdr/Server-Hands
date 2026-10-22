package dev.serverhands.crypto

import kotlin.test.Test
import kotlin.test.assertEquals

/** Same bytes as `script_approve_message_layout_is_pinned` in hands-proto: both sides must build this identically. */
class ScriptApproveMessageTest {
    @Test
    fun layoutIsPinned() {
        val m = Signatures.scriptApproveMessage(ByteArray(32) { 1 }, ByteArray(16) { 2 }, "bio", ByteArray(32) { 3 })
        assertEquals(
            "68616e64732f76312f7363726970742d617070726f76650000000020010101010101010101010101010101010101010101010101010101010101010100000010020202020202020202020202020202020000000362696f000000200303030303030303030303030303030303030303030303030303030303030303",
            m.joinToString("") { "%02x".format(it) },
        )
    }
}
