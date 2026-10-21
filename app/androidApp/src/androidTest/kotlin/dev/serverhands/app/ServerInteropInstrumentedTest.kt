package dev.serverhands.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.serverhands.app.keys.KeystoreDeviceSigner
import dev.serverhands.crypto.Codec
import dev.serverhands.crypto.PasswordEntry
import dev.serverhands.protocol.Pin
import dev.serverhands.protocol.ServerClient
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertEquals

/**
 * Keystore-signed requests against the real Rust daemon. Needs the fixture running on the host:
 *   HANDS_FAKE_BIND=0.0.0.0 HANDS_FAKE_HOST=10.0.2.2 server/target/debug/examples/fake_server
 * and its JSON line passed base64-encoded as `-Pandroid.testInstrumentationRunnerArguments.pairing=<b64>` to the instrumentation.
 */
@RunWith(AndroidJUnit4::class)
class ServerInteropInstrumentedTest {
    @Test
    fun keystoreDevicePairsListsAndApproves() {
        val json = InstrumentationRegistry.getArguments().getString("pairing")
        assumeTrue("no fake server given", json != null)
        val j = Json.parseToJsonElement(String(java.util.Base64.getDecoder().decode(json!!))).jsonObject
        fun s(k: String) = j.getValue(k).jsonPrimitive.content
        val pin = Pin(s("host"), s("port").toInt(), Codec.b64d(s("spki")), Codec.b64d(s("sid")))
        val signer = KeystoreDeviceSigner.create("hands_test_interop", allowSoftware = true)
        try {
            val client = ServerClient(pin, signer)
            client.pair(Codec.b64d(s("token")), "emulator") {}
            val l = client.list()
            val req = l.requests.single()
            val uuid = ServerClient.parseUuid(req.drives[0].luksUuid)
            val r = client.approve(l, req, listOf(PasswordEntry(uuid, "correct horse battery staple".toByteArray())))
            assertEquals("ok", r.results.single().result)
        } finally {
            KeystoreDeviceSigner.delete("hands_test_interop")
        }
    }
}
