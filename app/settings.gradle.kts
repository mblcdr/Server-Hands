rootProject.name = "server-hands"

pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositories { google(); mavenCentral() }
}

include(":core:crypto")
include(":core:protocol")
include(":androidApp")
// Phase 6: :desktopApp
