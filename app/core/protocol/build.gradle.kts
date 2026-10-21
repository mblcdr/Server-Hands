plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    // Android and Desktop are both JVM; the Android app consumes this jvm variant.
    jvm()
    jvmToolchain(17)

    sourceSets {
        jvmMain.dependencies {
            api(project(":core:crypto"))
            api(libs.kotlinx.serialization.json)
        }
        jvmTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    // Optional interop fixture: the Rust daemon with a fake host (cargo build -p handsd --example fake_server).
    systemProperty(
        "fake.server",
        rootProject.projectDir.parentFile.resolve("server/target/debug/examples/fake_server").absolutePath,
    )
}
