# Only used with -PminifyDebug=true. The instrumented-test APK has no copy of the Kotlin stdlib and borrows it
# from the app under test, so it must not be shrunk away there. Release builds do not use this file.
-keep class kotlin.** { *; }
# Same for the JSON helper classes the interop test uses to read the fake server's pairing line.
-keep class kotlinx.serialization.json.** { *; }
# Test-only helper (Signatures.deviceVerify) that nothing in the app calls.
-keep class dev.serverhands.crypto.** { *; }
