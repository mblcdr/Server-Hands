package dev.serverhands.app.keys

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * The single AES-256-GCM vault key. Every use (encrypt or decrypt) needs a fresh Class 3 biometric
 * (timeout 0, bound to a CryptoObject), no device-credential fallback, and it dies if biometrics are re-enrolled.
 */
object VaultKey {
    private const val ALIAS = "hands_vault_v1"
    const val TAG_BITS = 128

    private fun ks() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun exists(): Boolean = ks().containsAlias(ALIAS)

    fun delete() = ks().deleteEntry(ALIAS)

    fun getOrCreate(allowSoftware: Boolean): SecretKey {
        (ks().getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val key = try { generate(true) } catch (_: StrongBoxUnavailableException) { generate(false) }
        val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
        val hardware = info.securityLevel != KeyProperties.SECURITY_LEVEL_SOFTWARE &&
            info.isUserAuthenticationRequirementEnforcedBySecureHardware
        if (!hardware && !allowSoftware) {
            delete()
            throw KeySecurityException("this device cannot enforce biometric key use in secure hardware")
        }
        return key
    }

    private fun generate(strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(true)
            .setUnlockedDeviceRequired(true)
            .setIsStrongBoxBacked(strongBox)
            .build()
        return javax.crypto.KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            .run { init(spec); generateKey() }
    }

    /** Throws KeyPermanentlyInvalidatedException if biometrics changed since the key was made. */
    fun encryptCipher(allowSoftware: Boolean): Cipher =
        Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, getOrCreate(allowSoftware)) }

    fun decryptCipher(iv: ByteArray): Cipher =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, ks().getKey(ALIAS, null) as SecretKey, GCMParameterSpec(TAG_BITS, iv))
        }
}
