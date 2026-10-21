# R8 rules for the release build. Verified by running the instrumented tests against a shrunk debug build:
#   ./gradlew :androidApp:connectedDebugAndroidTest -PminifyDebug=true ...   (see app/README.md)
#
# Nothing needs a keep rule today: the BouncyCastle lightweight API (HPKE, Ed25519) is called directly,
# kotlinx.serialization ships its own consumer rules, and the app uses no reflection of its own.
