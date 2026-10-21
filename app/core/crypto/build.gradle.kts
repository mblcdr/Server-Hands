plugins {
    alias(libs.plugins.kotlin.multiplatform)
}

kotlin {
    // Android and Desktop are both JVM; Phase 3 adds androidTarget() and shares this source set.
    jvm()
    jvmToolchain(17)

    sourceSets {
        jvmMain.dependencies {
            // Bundled BouncyCastle, used through the lightweight API (never registered as a JCA provider).
            implementation(libs.bouncycastle)
        }
        jvmTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.serialization.json)
        }
    }
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    // protocol/vectors lives at the repo root
    systemProperty("vectors.dir", rootProject.projectDir.parentFile.resolve("protocol/vectors").absolutePath)
}
