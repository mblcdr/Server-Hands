package dev.serverhands.app.keys

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import dev.serverhands.protocol.DeviceSigner
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class KeySecurityException(message: String) : Exception(message)

/** ECDSA P-256 device identity in the Android Keystore. Not auth-bound: approvals are gated by the vault biometric. */
class KeystoreDeviceSigner private constructor(private val key: PrivateKey, override val spki: ByteArray) : DeviceSigner {
    override fun sign(message: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run { initSign(key); update(message); sign() }

    companion object {
        private fun ks() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

        fun load(alias: String): KeystoreDeviceSigner? {
            val ks = ks()
            val key = ks.getKey(alias, null) as? PrivateKey ?: return null
            return KeystoreDeviceSigner(key, ks.getCertificate(alias).publicKey.encoded)
        }

        fun delete(alias: String) = ks().deleteEntry(alias)

        /** StrongBox if the device has it, otherwise the TEE. Software-only keys are refused unless [allowSoftware]. */
        fun create(alias: String, allowSoftware: Boolean): KeystoreDeviceSigner {
            delete(alias)
            val strong = try { generate(alias, true) } catch (_: StrongBoxUnavailableException) { null }
            strong ?: generate(alias, false)
            val signer = load(alias) ?: throw KeySecurityException("device key missing after creation")
            val info = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                .getKeySpec(ks().getKey(alias, null) as PrivateKey, KeyInfo::class.java)
            if (info.securityLevel == KeyProperties.SECURITY_LEVEL_SOFTWARE && !allowSoftware) {
                delete(alias)
                throw KeySecurityException("this device cannot keep the device key in secure hardware")
            }
            return signer
        }

        private fun generate(alias: String, strongBox: Boolean) {
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUnlockedDeviceRequired(true)
                .setIsStrongBoxBacked(strongBox)
                .build()
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run { initialize(spec); generateKeyPair() }
        }
    }
}
