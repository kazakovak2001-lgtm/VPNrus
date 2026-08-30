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
        // B8E - Compose scoped to MainActivity's UI only (visual redesign
        // slice). No other module/architecture change - VpnController,
        // MainViewModel, and every non-UI class are untouched and remain
        // plain Kotlin with zero Compose dependency.
        compose = true
    }

    composeOptions {
        // Paired with the Kotlin 1.9.24 Gradle plugin above per the
        // AndroidX Compose Compiler <-> Kotlin compatibility map.
        kotlinCompilerExtensionVersion = "1.5.14"
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

// B8K1B - pinned AndroidLibXrayLite gomobile AAR, built reproducibly via
// third_party/xray/build-xray-wsl.sh from 2dust/AndroidLibXrayLite @
// c634d1baea97e94320c0bf6a9cf637369c4f11d4 (which pins xray-core v26.7.28 /
// 5ca6f4b7d4dc20a881d4330e498892697627ec0c transitively via its own go.sum -
// see third_party/xray/VERSION). Same convention as awgTunnelAar above: not
// committed to git (android/**/libs/ is gitignored), rebuild locally before
// first app build that touches NovaXrayVpnService/VlessRealityTransport.
// This is an isolated adapter shell (B8K1B) - XRAY_REALITY stays
// NOT_IMPLEMENTED in TransportRegistry regardless of this AAR's presence.
val xrayAar = file("libs/libv2ray-androidlibxraylite-c634d1b.aar")

tasks.register("checkXrayAar") {
    doFirst {
        if (!xrayAar.exists()) {
            throw GradleException(
                "\nXray (AndroidLibXrayLite) AAR is missing: ${xrayAar.path}\n" +
                    "Run third_party/xray/build-xray-wsl.sh from WSL2 to generate it,\n" +
                    "then copy the produced libv2ray.aar into android/app/libs/ as\n" +
                    "libv2ray-androidlibxraylite-c634d1b.aar.\n" +
                    "See third_party/xray/README.md and docs/B8K1A_TUN_SOCKET_PATH_AUDIT.md.\n"
            )
        }
    }
}
tasks.matching { it.name.startsWith("pre") && it.name.endsWith("Build") }
    .configureEach { dependsOn("checkXrayAar") }

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation(files(awgTunnelAar))
    implementation(files(xrayAar))
    implementation("androidx.annotation:annotation:1.8.2")
    implementation("androidx.collection:collection:1.4.4")
    // B11 - Ed25519 manifest-signature verification (EndpointManifestVerifier).
    // Low-level (non-JCA-provider) API used deliberately: no Provider
    // registration needed, works uniformly across minSdk 26..35 rather than
    // depending on platform Ed25519 support that only landed in AndroidKeyStore/
    // Conscrypt on API 33+.
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.8.7")
    // B8E - Compose, scoped to MainActivity's UI only (see buildFeatures.compose above).
    implementation(platform("androidx.compose:compose-bom:2024.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    debugImplementation("androidx.compose.ui:ui-tooling")
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
