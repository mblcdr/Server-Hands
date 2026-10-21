# Phase 3: what is verified, and the on-device checklist

## Verified here

- `core:protocol` JVM tests (pairing URI parsing, UUID codecs) and **interop against the real Rust daemon** over TLS 1.3 with the SPKI pin (`InteropTest`): pair, list, wrong passphrase gives a fresh request/key, replay of a consumed request refused, wrong TLS pin refused, unpaired device refused, a genuinely signed reply refused when the client pins a different server key, passphrase arrays wiped after approve.
- `androidApp` unit tests: vault blob format (sorted, padded to a constant size, bound to the server key, tamper and wrong-server rejected, fresh IV each time) and the pairing store.
- On an API 35 emulator (software keystore): Keystore-signed pair, list and approve against the real daemon (`ServerInteropInstrumentedTest`); device-key signatures verify with the protocol verifier; the device id equals SHA-256(SPKI)[0..16].
- The debug APK builds; Gradle dependency verification is enabled.

## Not verified yet: needs a real phone (ideally with StrongBox)

The emulator had no enrolled biometric, so these ran as skipped and the UI was never driven:

| Item | How |
|---|---|
| Vault key properties (auth required every use, timeout 0, biometric-only, invalidated on new enrolment, unlocked-device required, StrongBox when present) | `./gradlew :androidApp:connectedDebugAndroidTest` with a phone attached and a fingerprint/face enrolled |
| `BiometricPrompt` + `CryptoObject` flow for save (encrypt) and unlock (decrypt) | manual, below |
| QR scanning | manual |
| Release-style hardware requirement: install a **release-like** build (`ALLOW_SOFTWARE_KEYS=false`) and confirm pairing still works | manual |

## Manual run on the phone

1. Rebuild and restart the daemon from this repo (the TLS certificate now has a subject; Java/Android refuse the old empty-DN one):
   `sudo systemctl stop handsd; sudo rm /var/lib/server-hands/tls-*.der; sudo systemctl start handsd`. This changes the pinned key, so every earlier pairing (hands-client) must be redone: `sudo handsctl revoke <id>`.
2. `adb install app/androidApp/build/outputs/apk/debug/androidApp-debug.apk`; open the app.
3. `sudo handsctl pair`, scan the QR in the app. The phone shows a 6-digit code; confirm it in `handsctl`.
4. Lock a drive (or use the loop test from `phase2-box-test.md`), tap "Check for unlock requests".
5. "Save passphrases": on the server `sudo handsctl add-phone-key <uuid>`, type the printed phone passphrase, confirm with the biometric (a first-time save asks once; adding a drive later asks twice: decrypt, then encrypt).
6. "Unlock", confirm with the biometric. Expect "unlocked"; check `ls /dev/mapper` and that `journalctl -u handsd` has no passphrase.
7. Negative checks: enrol a new fingerprint, then Unlock: the app must say the vault key was destroyed. Stop `handsd`: the app says it cannot reach the server.

## Known limits (accepted for the MVP)

- One server per app install.
- The device key is attested only via `KeyInfo.securityLevel` (hardware-backed or not); the certificate chain is not verified against Google roots.
- Passphrase text fields are Compose `TextFieldState`; the typed characters exist in its buffer until cleared, then are copied into a byte array that is wiped after use. A fully String-free input path would need a custom IME-less keypad.
- No push/notification: open the app to see a request.
