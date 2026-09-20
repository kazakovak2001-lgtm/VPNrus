pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "poc-vpn"
include(":app")

// B46-2P physical validation harness - a separate, debug/research-only
// standalone Android application, deliberately independent of `:app` (see
// b46harness/build.gradle.kts's own header comment and
// docs/B46_2P_HYSTERIA2_ANDROID_PHYSICAL_VALIDATION.md).
include(":b46harness")
project(":b46harness").projectDir = file("../b46harness")
