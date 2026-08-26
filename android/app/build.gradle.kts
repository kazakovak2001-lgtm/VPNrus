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

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    // Pinned AmneziaWG :tunnel AAR, built reproducibly via third_party/build-tunnel-wsl.sh
    // from amnezia-vpn/amneziawg-android @ v3.0.1 (f8290045). Not committed to git (build output);
    // rebuild locally before first app build. See docs/RUNBOOK.md.
    implementation(files("libs/amneziawg-tunnel-v3.0.1-debug.aar"))
    implementation("androidx.annotation:annotation:1.8.2")
    implementation("androidx.collection:collection:1.4.4")
}
