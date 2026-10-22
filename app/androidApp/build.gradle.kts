plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.kotlin.compose)
}

// Release signing comes from the environment (CI secrets or your shell); without it the release APK is unsigned.
fun env(name: String): String? = providers.environmentVariable(name).orNull?.takeIf { it.isNotBlank() }
val keystorePath = env("SERVERHANDS_KEYSTORE")

android {
    namespace = "dev.serverhands.app"
    compileSdk = 37

    defaultConfig {
        applicationId = "dev.serverhands"
        minSdk = 31
        targetSdk = 36
        versionCode = (findProperty("versionCode") as String?)?.toInt() ?: 1
        versionName = (findProperty("versionName") as String?) ?: "0.4.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        testProguardFiles("proguard-test-rules.pro")
    }

    signingConfigs {
        if (keystorePath != null) {
            create("release") {
                storeFile = file(keystorePath)
                storePassword = env("SERVERHANDS_KEYSTORE_PASSWORD")
                keyAlias = env("SERVERHANDS_KEY_ALIAS")
                keyPassword = env("SERVERHANDS_KEY_PASSWORD") ?: env("SERVERHANDS_KEYSTORE_PASSWORD")
            }
        }
    }

    buildTypes {
        debug {
            // Emulators have no hardware-backed keystore. Never true in release builds.
            buildConfigField("boolean", "ALLOW_SOFTWARE_KEYS", "true")
            // -PminifyDebug=true runs the instrumented tests against R8-shrunk code on an emulator
            // (release builds refuse software keys, so they cannot run there).
            isMinifyEnabled = findProperty("minifyDebug") == "true"
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro", "proguard-verify.pro")
        }
        release {
            buildConfigField("boolean", "ALLOW_SOFTWARE_KEYS", "false")
            if (keystorePath != null) signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":core:protocol"))
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.foundation)
    implementation(libs.compose.material3)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.fragment)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.zxing.embedded)

    testImplementation(kotlin("test"))
    testImplementation(libs.junit)
    androidTestImplementation(kotlin("test"))
    androidTestImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.junit)
}
