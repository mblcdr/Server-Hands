package dev.serverhands.app

import android.content.pm.PackageManager
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.serverhands.app.keys.KeystoreDeviceSigner
import dev.serverhands.app.keys.VaultKey
import dev.serverhands.crypto.Signatures
import dev.serverhands.protocol.id
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import javax.crypto.SecretKeyFactory
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

@RunWith(AndroidJUnit4::class)
class KeystoreInstrumentedTest {
    private val ctx get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val alias = "hands_test_device"

    @Test
    fun deviceKeySignatureVerifiesWithTheProtocolVerifierAndIdMatchesSpki() {
        val signer = KeystoreDeviceSigner.create(alias, allowSoftware = true)
        try {
            val msg = "approve me".toByteArray()
            Signatures.deviceVerify(signer.spki, msg, signer.sign(msg)) // DER ECDSA over SPKI, as the server expects
            assertFailsWith<dev.serverhands.crypto.ProtocolException> {
                Signatures.deviceVerify(signer.spki, "other".toByteArray(), signer.sign(msg))
            }
            assertContentEquals(Signatures.deviceId(signer.spki), signer.id)
            assertEquals(16, signer.id.size)
            // Survives a reload from the keystore (what the app does after a restart)
            assertContentEquals(signer.spki, KeystoreDeviceSigner.load(alias)!!.spki)
        } finally {
            KeystoreDeviceSigner.delete(alias)
        }
    }

    @Test
    fun recreatingTheDeviceKeyChangesIdentity() {
        val a = KeystoreDeviceSigner.create(alias, true).spki
        val b = KeystoreDeviceSigner.create(alias, true).spki
        KeystoreDeviceSigner.delete(alias)
        assertTrue(!a.contentEquals(b))
    }

    /** Auth-bound keys can only be created once a strong biometric is enrolled; skip on bare emulators. */
    private fun assumeBiometricEnrolled() = assumeTrue(
        "no strong biometric enrolled",
        BiometricManager.from(ctx).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS,
    )

    @Test
    fun vaultKeyIsAuthBoundAndStrongBoxWhenAvailable() {
        assumeBiometricEnrolled()
        VaultKey.delete()
        val key = VaultKey.getOrCreate(allowSoftware = true)
        try {
            val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
            assertTrue(info.isUserAuthenticationRequired)
            assertTrue(info.isInvalidatedByBiometricEnrollment)
            assertTrue(info.isUnlockedDeviceRequired)
            assertEquals(0, info.userAuthenticationValidityDurationSeconds)
            assertEquals(256, info.keySize)
            // No device-credential fallback: only the biometric authenticator type is allowed.
            assertEquals(KeyProperties.AUTH_BIOMETRIC_STRONG, info.userAuthenticationType)
            if (ctx.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
                assertEquals(KeyProperties.SECURITY_LEVEL_STRONGBOX, info.securityLevel)
            }
        } finally {
            VaultKey.delete()
        }
    }

    @Test
    fun vaultKeyCannotBeUsedWithoutBiometricAuthentication() {
        assumeBiometricEnrolled()
        VaultKey.delete()
        try {
            val cipher = VaultKey.encryptCipher(allowSoftware = true)
            // init succeeds, but the keystore refuses the operation until a BiometricPrompt authorises it.
            assertFailsWith<java.security.GeneralSecurityException> { cipher.doFinal(ByteArray(16)) }
        } finally {
            VaultKey.delete()
        }
    }

    @Test
    fun strongBoxPathIsExercisedOnlyOnDevicesThatHaveIt() {
        assumeTrue(ctx.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE))
        val signer = KeystoreDeviceSigner.create(alias, allowSoftware = false) // must succeed without the software escape hatch
        KeystoreDeviceSigner.delete(alias)
        assertTrue(signer.spki.isNotEmpty())
    }
}
