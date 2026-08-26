plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "net.pocvpn.client"
    compileSdk = 35

    defaultConfig {
        applicationId = "net.pocvpn.client"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1-poc"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

// Pinned AmneziaWG :tunnel AAR, built reproducibly via third_party/build-tunnel-wsl.sh
// from amnezia-vpn/amneziawg-android @ v3.1.20260814 (5c16489e), AWG 3.1 generation.
// Not committed to git (build output); rebuild locally before first app build.
val awgTunnelAar = file("libs/amneziawg-tunnel-v3.1.20260814-debug.aar")

tasks.register("checkAwgTunnelAar") {
    doFirst {
        if (!awgTunnelAar.exists()) {
            throw GradleException(
                "\nAmneziaWG tunnel AAR is missing: ${awgTunnelAar.path}\n" +
                    "Run third_party/build-tunnel-wsl.sh from WSL2 to generate it,\n" +
                    "then copy the produced AAR into android/app/libs/.\n" +
                    "See docs/RUNBOOK.md.\n"
            )
        }
    }
}
tasks.matching { it.name.startsWith("pre") && it.name.endsWith("Build") }
    .configureEach { dependsOn("checkAwgTunnelAar") }

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation(files(awgTunnelAar))
    implementation("androidx.annotation:annotation:1.8.2")
    implementation("androidx.collection:collection:1.4.4")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}
