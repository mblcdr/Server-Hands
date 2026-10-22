package dev.serverhands.app.keys

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * ECDSA P-256 key whose every signature needs a fresh Class 3 biometric (timeout 0, bound to a CryptoObject),
 * no device-credential fallback, dead if biometrics are re-enrolled. The server holds its public key and asks
 * for a signature over a challenge before it runs a `biometric_protection` script, so a signature is the proof
 * that a biometric happened. Separate from the device key, which signs without a prompt.
 */
object ApprovalKey {
    private const val ALIAS = "hands_approval_v1"

    private fun ks() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun delete() = ks().deleteEntry(ALIAS)

    /** SPKI DER of the public key, creating the key first if needed. */
    fun spki(allowSoftware: Boolean): ByteArray {
        if (!ks().containsAlias(ALIAS)) create(allowSoftware)
        return ks().getCertificate(ALIAS).publicKey.encoded
    }

    private fun create(allowSoftware: Boolean) {
        try { generate(true) } catch (_: StrongBoxUnavailableException) { generate(false) }
        val key = ks().getKey(ALIAS, null) as PrivateKey
        val info = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java)
        val hardware = info.securityLevel != KeyProperties.SECURITY_LEVEL_SOFTWARE && info.isUserAuthenticationRequirementEnforcedBySecureHardware
        if (!hardware && !allowSoftware) {
            delete()
            throw KeySecurityException("this device cannot enforce biometric key use in secure hardware")
        }
    }

    private fun generate(strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(true)
            .setUnlockedDeviceRequired(true)
            .setIsStrongBoxBacked(strongBox)
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run { initialize(spec); generateKeyPair() }
    }

    /** Throws KeyPermanentlyInvalidatedException if biometrics changed since the key was made. */
    fun signature(): Signature =
        Signature.getInstance("SHA256withECDSA").apply { initSign(ks().getKey(ALIAS, null) as PrivateKey) }
}
