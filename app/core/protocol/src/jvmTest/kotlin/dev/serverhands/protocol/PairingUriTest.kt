package dev.serverhands.protocol

import dev.serverhands.crypto.Codec
import dev.serverhands.crypto.ProtocolException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class PairingUriTest {
    private val b = Codec.b64e(ByteArray(32) { it.toByte() })
    private fun uri(host: String = "10.0.0.5", port: String = "7787", extra: String = "") =
        "hands://pair?v=1&host=$host&port=$port&spki=$b&sid=$b&tok=$b$extra"

    @Test
    fun parsesAValidUri() {
        val p = PairingUri.parse(uri())
        assertEquals("10.0.0.5", p.pin.host)
        assertEquals(7787, p.pin.port)
        assertContentEquals(ByteArray(32) { it.toByte() }, p.token)
        assertEquals(19, p.pin.fingerprint.length) // 16 hex chars + 3 spaces
    }

    @Test
    fun rejectsMalformedUris() {
        for (bad in listOf(
            "https://pair?x=1", uri(port = "0"), uri(port = "70000"), uri(port = "x"), uri(host = ""), uri(host = "a/b"),
            uri(host = "u@evil"), uri().replace("v=1", "v=2"), uri().replace("tok=$b", "tok=AAAA"), uri().replace("&sid=$b", ""),
        )) {
            assertFailsWith<ProtocolException>(bad) { PairingUri.parse(bad) }
        }
    }

    @Test
    fun uuidRoundTrip() {
        val s = "00000000-0000-4000-8000-000000000001"
        assertEquals(s, ServerClient.formatUuid(ServerClient.parseUuid(s)))
        assertFailsWith<ProtocolException> { ServerClient.parseUuid("00000000000040008000000000000001") }
    }
}
