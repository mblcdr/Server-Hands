# App (Kotlin Multiplatform)

```
core/crypto     HPKE, Ed25519, P-256 verify, SAS, zeroing helpers (BouncyCastle lightweight API, bundled). Vectors tests.
core/protocol   Wire models, SPKI-pinned TLS 1.3 client (plain HttpsURLConnection + custom trust manager), ServerClient:
                pair / list / approve / scripts (list and run post-unlock scripts) with every reply verified against the pinned server key and bound to a fresh nonce.
androidApp      Compose UI (requests, "After unlock" scripts card), Keystore device key, biometric-gated vault, QR pairing. minSdk 31.
desktopApp      Phase 6 (Compose Desktop, reuses core:*).
```

Build (JDK 17, Android SDK; `local.properties` with `sdk.dir`):
```sh
export JAVA_HOME=/opt/homebrew/opt/openjdk@17
./gradlew :androidApp:assembleDebug          # app/androidApp/build/outputs/apk/debug/androidApp-debug.apk
./gradlew :core:crypto:jvmTest :core:protocol:jvmTest :androidApp:testDebugUnitTest
```

Interop (Kotlin client against the real Rust daemon with a fake host): build the fixture once,
`(cd ../server && cargo build -p handsd --example fake_server)`, then `:core:protocol:jvmTest` runs `InteropTest`
(it is skipped when the fixture is missing). On an emulator:
```sh
(cd ../server && HANDS_FAKE_BIND=0.0.0.0 HANDS_FAKE_HOST=10.0.2.2 target/debug/examples/fake_server > /tmp/fake.out) &
./gradlew :androidApp:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.pairing="$(head -1 /tmp/fake.out | base64 | tr -d '\n')"
```

Release builds are R8-minified; `-PminifyDebug=true` runs the instrumented tests against shrunk code (see `../docs/android-release.md`).

Gradle dependency verification is on (`gradle/verification-metadata.xml`, sha256). After changing dependencies:
`./gradlew --write-verification-metadata sha256 <the tasks you use>`, then review the diff.

Release APK: signed in CI from a `v*` tag (`../docs/android-release.md`); locally set `SERVERHANDS_KEYSTORE*` and run `:androidApp:assembleRelease -PversionName=X.Y.Z -PversionCode=N`.

Debug builds allow software-backed keys (emulators); release builds refuse them (`BuildConfig.ALLOW_SOFTWARE_KEYS`).
