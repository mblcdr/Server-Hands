package dev.serverhands.crypto

import kotlinx.serialization.json.*
import java.io.File
import kotlin.test.*

@OptIn(ExperimentalStdlibApi::class)
class VectorsTest {
    private val dir = File(System.getProperty("vectors.dir"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "v1.json").readText()).jsonObject

    private fun JsonElement.hex(): ByteArray = jsonPrimitive.content.hexToByteArray()
    private fun JsonElement.str() = jsonPrimitive.content
    private fun clamp(k: ByteArray) = k.copyOf().also {
        it[0] = (it[0].toInt() and 248).toByte()
        it[31] = ((it[31].toInt() and 127) or 64).toByte()
    }

    private fun domain(s: String) = when (s) {
        "hands/v1/server-reply" -> Domain.SERVER_REPLY
        "hands/v1/device-request" -> Domain.DEVICE_REQUEST
        "hands/v1/approve" -> Domain.APPROVE
        "hands/v1/pair" -> Domain.PAIR
        else -> error("unknown domain")
    }

    @Test
    fun positiveVectors() {
        val keys = v["keys"]!!.jsonObject
        val ids = v["ids"]!!.jsonObject
        val serverPub = keys["server_ed25519_pub"]!!.hex()
        val spki = keys["device_spki_der"]!!.hex()

        val envj = v["envelope"]!!.jsonObject
        val env = envj["envelope"]!!.jsonObject
        val body = Signatures.serverVerify(serverPub, domain(envj["domain"]!!.str()), env["body"]!!.str(), env["sig"]!!.str())
        assertContentEquals(envj["body_utf8"]!!.str().toByteArray(), body)

        assertContentEquals(keys["device_id"]!!.hex(), Signatures.deviceId(spki))

        val a = v["approve"]!!.jsonObject
        val reqId = ids["req_id"]!!.hex()
        val nonce = ids["client_nonce"]!!.hex()
        val devId = keys["device_id"]!!.hex()
        val info = Seal.info(serverPub, reqId, nonce, devId)
        assertContentEquals(a["info"]!!.hex(), info)
        val uuids = a["entries"]!!.jsonArray.map { it.jsonObject["uuid"]!!.hex() }
        val aad = Seal.aad(uuids)
        assertContentEquals(a["aad"]!!.hex(), aad)

        val (priv, pub) = Seal.deriveEphemeral(keys["eph_ikm"]!!.hex())
        // X25519 private keys are equivalent after clamping; implementations serialize raw vs clamped.
        assertContentEquals(clamp(keys["eph_priv"]!!.hex()), clamp(priv))
        assertContentEquals(keys["eph_pub"]!!.hex(), pub)

        // Open a ciphertext sealed by Rust.
        val pt = Seal.open(priv, pub, a["enc"]!!.hex(), info, aad, a["ct"]!!.hex())
        assertContentEquals(a["plaintext"]!!.hex(), pt)
        val decoded = Seal.decodePlaintext(pt)
        a["entries"]!!.jsonArray.zip(decoded).forEach { (e, d) ->
            assertContentEquals(e.jsonObject["uuid"]!!.hex(), d.uuid)
            assertContentEquals(e.jsonObject["passphrase_hex"]!!.hex(), d.passphrase)
        }
        // Re-encoding reproduces Rust's plaintext byte for byte.
        assertContentEquals(a["plaintext"]!!.hex(), Seal.encodePlaintext(decoded))

        val msg = Signatures.approveMessage(reqId, nonce, a["enc"]!!.hex(), a["ct"]!!.hex(), aad)
        assertContentEquals(a["signed_message"]!!.hex(), msg)
        Signatures.deviceVerify(spki, msg, a["device_sig_der"]!!.hex())

        val s = v["sas"]!!.jsonObject
        assertEquals(s["expected"]!!.str(), Seal.sas(serverPub, spki, s["token"]!!.hex()))
    }

    @Test
    fun negativeVectorsAreAllRejected() {
        val cases = v["negative"]!!.jsonArray
        assertTrue(cases.size >= 20)
        for (c in cases.map { it.jsonObject }) {
            val name = c["name"]!!.str()
            val threw = try {
                when (c["kind"]!!.str()) {
                    "envelope_verify" -> {
                        val e = c["envelope"]!!.jsonObject
                        Signatures.serverVerify(c["server_pub"]!!.hex(), domain(c["domain"]!!.str()), e["body"]!!.str(), e["sig"]!!.str())
                    }
                    "hpke_open" -> {
                        val priv = c["eph_priv"]!!.hex()
                        // public half is not part of the negative case; take it from the positive keys
                        Seal.open(priv, v["keys"]!!.jsonObject["eph_pub"]!!.hex(), c["enc"]!!.hex(), c["info"]!!.hex(), c["aad"]!!.hex(), c["ct"]!!.hex())
                    }
                    "device_verify" -> Signatures.deviceVerify(c["spki"]!!.hex(), c["message"]!!.hex(), c["sig"]!!.hex())
                    "plaintext_decode" -> Seal.decodePlaintext(c["bytes"]!!.hex())
                    else -> error("unknown kind")
                }
                false
            } catch (_: ProtocolException) {
                true
            }
            assertTrue(threw, "negative vector accepted: $name")
        }
    }

    /** Kotlin seals, Rust must open: writes protocol/vectors/v1-kotlin.json when WRITE_KOTLIN_VECTOR=1. */
    @Test
    fun kotlinSealedVectorOpensAndOptionallyExports() {
        val keys = v["keys"]!!.jsonObject
        val ids = v["ids"]!!.jsonObject
        val serverPub = keys["server_ed25519_pub"]!!.hex()
        val devId = keys["device_id"]!!.hex()
        val reqId = ids["req_id"]!!.hex()
        val nonce = ids["client_nonce"]!!.hex()
        val priv = keys["eph_priv"]!!.hex()
        val pub = keys["eph_pub"]!!.hex()

        val u1 = "00000000-0000-4000-8000-000000000001".replace("-", "").hexToByteArray()
        val u2 = "00000000-0000-4000-8000-000000000002".replace("-", "").hexToByteArray()
        val entries = listOf(
            PasswordEntry(u1, "FAKE-kotlin-sealed-one".toByteArray()),
            PasswordEntry(u2, "FAKE-kotlin-sealed-two".toByteArray()),
        )
        val pt = Seal.encodePlaintext(entries)
        val info = Seal.info(serverPub, reqId, nonce, devId)
        val aad = Seal.aad(listOf(u1, u2))
        val (enc, ct) = Seal.seal(pub, info, aad, pt)
        assertContentEquals(pt, Seal.open(priv, pub, enc, info, aad, ct))

        if (System.getenv("WRITE_KOTLIN_VECTOR") == "1") {
            val out = buildJsonObject {
                put("note", "FAKE test data sealed by the Kotlin implementation. Rust must open it.")
                put("info", info.toHexString()); put("aad", aad.toHexString())
                put("enc", enc.toHexString()); put("ct", ct.toHexString()); put("plaintext", pt.toHexString())
            }
            File(dir, "v1-kotlin.json").writeText(Json { prettyPrint = true }.encodeToString(JsonObject.serializer(), out) + "\n")
        }
    }
}
