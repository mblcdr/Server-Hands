package dev.serverhands.protocol

import dev.serverhands.crypto.Codec
import dev.serverhands.crypto.PasswordEntry
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Software device key, same wire format as the Android Keystore one. */
class SoftSigner : DeviceSigner {
    private val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    override val spki: ByteArray = kp.public.encoded
    override fun sign(message: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").apply { initSign(kp.private); update(message) }.sign()
}

/**
 * Kotlin client against the real Rust daemon (TLS 1.3, SPKI pin, signed replies, HPKE) with a fake host.
 * Skipped unless `cargo build -p handsd --example fake_server` has been run.
 */
class InteropTest {
    private var proc: Process? = null
    private val uuid = "00000000-0000-4000-8000-000000000001"
    private val good = "correct horse battery staple".toByteArray()

    @AfterTest
    fun stop() { proc?.destroyForcibly() }

    private fun startServer(): Pair<Pin, ByteArray> {
        val exe = File(System.getProperty("fake.server"))
        assumeTrue(exe.canExecute(), "fake_server not built; skipping interop test")
        val p = ProcessBuilder(exe.absolutePath).redirectErrorStream(false).start().also { proc = it }
        val j = Json.parseToJsonElement(p.inputStream.bufferedReader().readLine()).jsonObject
        fun s(k: String) = j.getValue(k).jsonPrimitive.content
        val pin = Pin(s("host"), s("port").toInt(), Codec.b64d(s("spki")), Codec.b64d(s("sid")))
        return pin to Codec.b64d(s("token"))
    }

    private fun entry(pass: ByteArray) = PasswordEntry(ServerClient.parseUuid(uuid), pass.copyOf())

    @Test
    fun scriptsAreListedAndRunOnlyAfterUnlock() {
        val (pin, token) = startServer()
        val client = ServerClient(pin, SoftSigner())
        client.pair(token, "kotlin test") {}

        val before = client.scripts()
        assertTrue(!before.unlocked)
        val demo = before.scripts.single { it.name == "demo" }
        assertEquals(listOf("demo", "Demo containers", "manual", "idle"), listOf(demo.name, demo.label, demo.mode, demo.state))
        assertEquals(409, assertFailsWith<ServerException> { client.runScript("demo") }.status)
        assertEquals(404, assertFailsWith<ServerException> { client.runScript("nope") }.status)

        val listing = client.list()
        client.approve(listing, listing.requests.single(), listOf(entry(good)))
        assertTrue(client.scripts().unlocked)
        client.runScript("demo")
        repeat(100) {
            if (client.scripts().scripts.single { it.name == "demo" }.state == "ok") return
            Thread.sleep(50)
        }
        throw AssertionError("script never finished")
    }

    @Test
    fun biometricScriptNeedsRegisteredKeyAndServerChallenge() {
        val (pin, token) = startServer()
        val client = ServerClient(pin, SoftSigner())
        client.pair(token, "kotlin test") {}
        val secure = client.scripts().scripts.single { it.name == "secure" }
        assertTrue(secure.biometricProtection && secure.requiresConfirmation)

        // The app-side approval key stands in as a software key here; on Android it is biometric-bound.
        val approval = SoftSigner()
        assertEquals(403, assertFailsWith<ServerException> { client.scriptChallenge("secure") }.status)
        assertEquals(403, assertFailsWith<ServerException> { client.runScript("secure") }.status)

        client.registerApprovalKey(approval.spki)
        client.registerApprovalKey(approval.spki)
        assertEquals(409, assertFailsWith<ServerException> { client.registerApprovalKey(SoftSigner().spki) }.status)

        val challenge = client.scriptChallenge("secure")
        val sig = approval.sign(challenge.message)
        client.runScript("secure", challenge, sig)
        var tries = 0
        while (client.scripts().scripts.single { it.name == "secure" }.state != "ok" && tries++ < 100) Thread.sleep(50)
        assertEquals("ok", client.scripts().scripts.single { it.name == "secure" }.state)

        // single use
        assertEquals(403, assertFailsWith<ServerException> { client.runScript("secure", challenge, sig) }.status)
        // wrong key
        val c2 = client.scriptChallenge("secure")
        assertEquals(401, assertFailsWith<ServerException> { client.runScript("secure", c2, SoftSigner().sign(c2.message)) }.status)
    }

    @Test
    fun statusIsReadableAfterPairing() {
        val (pin, token) = startServer()
        val client = ServerClient(pin, SoftSigner())
        client.pair(token, "kotlin test") {}
        val s = client.status()
        assertEquals(3, s.load.size)
        assertTrue(s.cpuPercent in 0.0..100.0)
    }

    @Test
    fun pairListApproveRetry() {
        val (pin, token) = startServer()
        val client = ServerClient(pin, SoftSigner())
        var sas = ""
        client.pair(token, "kotlin test") { sas = it }
        assertEquals(6, sas.length)

        val first = client.list()
        assertEquals(1, first.requests.size)
        val req = first.requests[0]
        assertEquals(uuid, req.drives[0].luksUuid)
        assertEquals("Disk-1", req.drives[0].label)

        val bad = client.approve(first, req, listOf(entry("nope".toByteArray())))
        assertEquals("bad_passphrase", bad.results.single().result)

        val second = client.list()
        val retry = second.requests.single()
        assertTrue(retry.reqId != req.reqId && retry.ePub != req.ePub, "wrong passphrase must yield a fresh request and key")

        // the consumed request cannot be replayed
        assertFailsWith<ServerException> { client.approve(first, req, listOf(entry(good))) }

        assertEquals("ok", client.approve(second, retry, listOf(entry(good))).results.single().result)
        assertTrue(client.list().requests.isEmpty())
    }

    @Test
    fun approveWipesPassphrases() {
        val (pin, token) = startServer()
        val client = ServerClient(pin, SoftSigner())
        client.pair(token, "kotlin test") {}
        val l = client.list()
        val e = entry(good)
        client.approve(l, l.requests[0], listOf(e))
        assertContentEquals(ByteArray(good.size), e.passphrase)
    }

    @Test
    fun wrongPinUnpairedDeviceAndWrongServerKeyAreRefused() {
        val (pin, token) = startServer()
        val signer = SoftSigner()
        ServerClient(pin, signer).pair(token, "kotlin test") {}

        val badPin = Pin(pin.host, pin.port, ByteArray(32), pin.serverPub)
        assertFailsWith<javax.net.ssl.SSLException> { ServerClient(badPin, signer).list() }

        assertEquals(401, assertFailsWith<ServerException> { ServerClient(pin, SoftSigner()).list() }.status)

        // Right TLS key, paired device, but the client believes in a different server identity: the
        // (genuinely signed) reply must not be accepted.
        val wrongSid = Pin(pin.host, pin.port, pin.spkiSha256, ByteArray(32) { 1 })
        assertFailsWith<dev.serverhands.crypto.ProtocolException> { ServerClient(wrongSid, signer).list() }
    }
}
