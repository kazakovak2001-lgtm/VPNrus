import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Optional, gitignored, developer-local gateway config for manual testing
// against a real VPS once one exists. Never committed - see .gitignore.
// All values default to "" (interpreted as GatewayConfiguration.Missing).
val gatewayDevProperties = Properties().apply {
    val f = file("gateway-dev.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}
fun gatewayDevProp(key: String): String = gatewayDevProperties.getProperty(key, "")

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

        buildConfigField("String", "GATEWAY_ENDPOINT_HOST", "\"${gatewayDevProp("endpointHost")}\"")
        buildConfigField("String", "GATEWAY_ENDPOINT_PORT", "\"${gatewayDevProp("endpointPort")}\"")
        buildConfigField("String", "GATEWAY_SERVER_PUBLIC_KEY", "\"${gatewayDevProp("serverPublicKey")}\"")
        buildConfigField("String", "GATEWAY_CLIENT_TUNNEL_IP", "\"${gatewayDevProp("clientTunnelIp")}\"")
        buildConfigField("String", "GATEWAY_TUNNEL_IP", "\"${gatewayDevProp("gatewayTunnelIp")}\"")
        buildConfigField("String", "GATEWAY_ALLOWED_IPS", "\"${gatewayDevProp("allowedIps")}\"")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    buildFeatures {
        buildConfig = true
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
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
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.8.7")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
    // B8B3A - ProvisioningClientTest exercises real org.json.JSONObject
    // parsing/serialization. Android's own org.json is a stub on the local
    // (non-instrumented) unit test classpath (returns default/empty values,
    // not real behavior) - this is the standard real implementation used to
    // get actual JSON behavior in JVM-only unit tests.
    testImplementation("org.json:json:20240303")
    androidTestImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}
