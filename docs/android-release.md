# Signing and releasing the Android app

The `app` workflow (`.github/workflows/app.yml`) tests the app and builds an APK on every push and pull request. On a tag `vX.Y.Z` it builds a **signed release APK** and attaches it, with `SHA256SUMS`, to the GitHub Release of that tag (created if missing). The same tag also drives the server package (`deb` workflow), so one tag releases both. The tag sets `versionName` (`v0.4.0` gives `0.4.0`) and `versionCode` (`major*10000 + minor*100 + patch`, e.g. 400).

Without the signing secrets the workflow still builds a **debug** APK as an artifact (fine for tests, not for release); a tag build without them fails on purpose.

## One-time: create the release key

Do this on your own machine and keep the file safe. **If you lose it, or the password, you can never publish an update that installs over the old app** (Android requires the same signing key; users would have to uninstall, which destroys their pairing and vault).

```sh
keytool -genkeypair -v -keystore server-hands-release.jks -alias serverhands \
  -keyalg RSA -keysize 4096 -validity 10000
```

`keytool` asks for a keystore password and certificate details (the name can be anything). Press Enter at "key password" to reuse the keystore password. Then record the SHA-256 fingerprint to compare later:

```sh
keytool -list -v -keystore server-hands-release.jks -alias serverhands | grep SHA256
```

Back the `.jks` file and the password up somewhere that is not this repository (password manager, encrypted backup). Never commit it.

## One-time: add the repository secrets

GitHub: repository, **Settings, Secrets and variables, Actions, New repository secret**. Add four secrets:

| Secret | Value |
|---|---|
| `ANDROID_KEYSTORE_BASE64` | the keystore file, base64 encoded: macOS `base64 -i server-hands-release.jks \| pbcopy`, Linux `base64 -w0 server-hands-release.jks` |
| `ANDROID_KEYSTORE_PASSWORD` | the keystore password |
| `ANDROID_KEY_ALIAS` | `serverhands` (or the alias you used) |
| `ANDROID_KEY_PASSWORD` | the key password; same as the keystore password if you pressed Enter |

With the GitHub CLI instead: `gh secret set ANDROID_KEYSTORE_BASE64 < <(base64 -i server-hands-release.jks)` and `gh secret set ANDROID_KEYSTORE_PASSWORD`, and so on.

Secrets are not passed to pull requests from forks, so those builds are debug APKs.

## Release

```sh
git tag v0.4.0 && git push origin v0.4.0
```

The workflow prints the signer certificate SHA-256; it must match the fingerprint you recorded. Download `server-hands_0.4.0.apk` from the release (check it against `SHA256SUMS`) and install it with `adb install -r`, or open it on the phone.

## Local release builds

```sh
cd app
export JAVA_HOME=/opt/homebrew/opt/openjdk@17
SERVERHANDS_KEYSTORE=/path/to/server-hands-release.jks SERVERHANDS_KEYSTORE_PASSWORD=... SERVERHANDS_KEY_ALIAS=serverhands \
  ./gradlew :androidApp:assembleRelease -PversionName=0.4.0 -PversionCode=400
```

Without those variables `assembleRelease` produces an unsigned APK that Android will not install.

## Code shrinking (R8)

Release builds are minified and resource-shrunk (about 31 MB before, 3.4 MB after); no keep rules are needed (`app/androidApp/proguard-rules.pro`). The app has no reflection of its own, BouncyCastle's lightweight API is called directly and kotlinx.serialization ships its own rules.

To check a change did not break that, run the instrumented tests against a shrunk and obfuscated debug build on an emulator (release builds refuse software keys, so they cannot run there):
```sh
cd app
./gradlew :androidApp:connectedDebugAndroidTest -PminifyDebug=true \
  -Pandroid.testInstrumentationRunnerArguments.pairing="$(head -1 /tmp/fake.out | base64 | tr -d '\n')"
```
(start the fake server as in `app/README.md`; its pairing token is single-use, so restart it for every run). `proguard-verify.pro` only applies to this mode: it keeps the Kotlin stdlib, kotlinx JSON and the crypto package that the test APK borrows from the app.

Not covered by those tests: the Compose screens, the QR scanner and the real biometric prompt. Check those on a phone with the signed release APK.

Builds are not reproducible yet (Phase 5).
