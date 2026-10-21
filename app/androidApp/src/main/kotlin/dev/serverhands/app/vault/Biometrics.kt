package dev.serverhands.app.vault

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.suspendCancellableCoroutine
import javax.crypto.Cipher
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

class AuthCancelled : Exception("cancelled")
class AuthFailed(val reason: String) : Exception(reason)

object Biometrics {
    private const val STRONG = BiometricManager.Authenticators.BIOMETRIC_STRONG

    /** Null when a Class 3 biometric is ready, otherwise a message for the user. */
    fun unavailableReason(activity: FragmentActivity): String? = when (BiometricManager.from(activity).canAuthenticate(STRONG)) {
        BiometricManager.BIOMETRIC_SUCCESS -> null
        BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "Enrol a fingerprint or face (strong biometric) in system settings first."
        BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE, BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->
            "This device has no usable strong biometric sensor."
        else -> "Strong biometric authentication is not available."
    }

    /**
     * Shows the system prompt bound to [cipher] (no device-credential fallback). Returns the cipher the keystore
     * has authorised for exactly this one operation.
     */
    suspend fun authenticate(activity: FragmentActivity, cipher: Cipher, title: String, subtitle: String): Cipher =
        suspendCancellableCoroutine { cont ->
            val prompt = BiometricPrompt(
                activity,
                ContextCompat.getMainExecutor(activity),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val c = result.cryptoObject?.cipher
                        if (c != null) cont.resume(c) else cont.resumeWithException(AuthFailed("no cipher"))
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        val cancelled = errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                            errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON || errorCode == BiometricPrompt.ERROR_CANCELED
                        cont.resumeWithException(if (cancelled) AuthCancelled() else AuthFailed(errString.toString()))
                    }
                },
            )
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(subtitle)
                .setNegativeButtonText("Cancel")
                .setAllowedAuthenticators(STRONG)
                .setConfirmationRequired(true)
                .build()
            prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
            cont.invokeOnCancellation { prompt.cancelAuthentication() }
        }
}
