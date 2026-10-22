package dev.serverhands.crypto

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

object Signatures {
    /**
     * Verifies a server envelope (Ed25519, raw 32-byte key, raw 64-byte signature) and only then returns
     * the body bytes. Throws [ProtocolException] on any failure.
     */
    fun serverVerify(serverPub: ByteArray, domain: ByteArray, bodyB64: String, sigB64: String): ByteArray {
        try {
            if (serverPub.size != 32) throw ProtocolException()
            val body = Codec.b64d(bodyB64)
            val sig = Codec.b64d(sigB64)
            if (sig.size != 64) throw ProtocolException()
            val v = Ed25519Signer()
            v.init(false, Ed25519PublicKeyParameters(serverPub, 0))
            val msg = Codec.signedBytes(domain, body)
            v.update(msg, 0, msg.size)
            if (!v.verifySignature(sig)) throw ProtocolException()
            return body
        } catch (e: ProtocolException) {
            throw e
        } catch (_: Exception) {
            throw ProtocolException()
        }
    }

    /** `SHA-256(spki)[0..16]` */
    fun deviceId(spkiDer: ByteArray): ByteArray = Codec.sha256(spkiDer).copyOfRange(0, 16)

    /** The bytes the device signs when approving a request. */
    fun approveMessage(reqId: ByteArray, clientNonce: ByteArray, enc: ByteArray, ct: ByteArray, aad: ByteArray): ByteArray =
        Codec.signedBytes(Domain.APPROVE, Codec.lp(reqId, clientNonce, enc, Codec.sha256(ct), aad))

    /** The bytes the biometric-bound approval key signs to authorise one run of [script]. */
    fun scriptApproveMessage(serverPub: ByteArray, deviceId: ByteArray, script: String, challenge: ByteArray): ByteArray =
        Codec.signedBytes(Domain.SCRIPT_APPROVE, Codec.lp(serverPub, deviceId, script.toByteArray(), challenge))

    /** ECDSA P-256 / SHA-256, DER signature, SPKI DER public key. Used for tests and the desktop client. */
    fun deviceVerify(spkiDer: ByteArray, message: ByteArray, sigDer: ByteArray) {
        try {
            val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spkiDer))
            val s = Signature.getInstance("SHA256withECDSA")
            s.initVerify(key)
            s.update(message)
            if (!s.verify(sigDer)) throw ProtocolException()
        } catch (e: ProtocolException) {
            throw e
        } catch (_: Exception) {
            throw ProtocolException()
        }
    }
}
