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

// B17 - the real production Signed Offline Bootstrap manifest distribution
// endpoint (see docs/B12_MANIFEST_KEY_CEREMONY.md's "Production ceremony
// (B17)" section and docs/ROADMAP.md's Signed Offline Bootstrap row).
// Frankfurt is the sole configured primary - Stockholm serves the
// byte-identical artifact signed by the SAME production key (verified
// during B17's deployment pass), but HttpsRemoteManifestFetcher/
// ManifestDistributionClient (MainViewModel.Factory) only support ONE
// configured URL today; multi-origin manifest fetch/failover is
// deliberately out of scope for this slice, not an oversight - it is
// unrelated to AutoGatewaySelector's own gateway-level failover, which
// already spans both gateways once a manifest (from either URL) is
// trusted. No signing/private material of any kind lives in this file -
// this is a plain HTTPS GET endpoint for already-signed public bytes,
// the same trust level as any other URL literal already hardcoded in this
// codebase (e.g. ProvisioningClient's production gateway hosts).
val PRODUCTION_MANIFEST_URL = "https://152.70.43.1/v1/manifest"

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
        // B12/B17 - defaults to the real PRODUCTION_MANIFEST_URL above so a
        // normal build actually wires ManifestDistributionClient; a
        // developer's own gitignored gateway-dev.properties
        // (`manifestUrl=...`) can still override this for local testing
        // against a different server, same "explicit local override wins"
        // convention as every gatewayDevProp field above. Overridden
        // per-buildType immediately below for full reviewability of what
        // debug/release each actually ship with - both currently resolve to
        // the same production endpoint, on purpose (B17 does not yet
        // support a distinct staging manifest source).
        buildConfigField("String", "MANIFEST_URL", "\"${gatewayDevProp("manifestUrl").ifBlank { PRODUCTION_MANIFEST_URL }}\"")
    }

    buildTypes {
        debug {
            // B17 - explicit for reviewability: debug builds (including the
            // physical-device validation build) fetch the real production
            // manifest by default, same value release ships with, unless a
            // developer's local gateway-dev.properties overrides it.
            buildConfigField("String", "MANIFEST_URL", "\"${gatewayDevProp("manifestUrl").ifBlank { PRODUCTION_MANIFEST_URL }}\"")
        }
        release {
            isMinifyEnabled = false
            // B17 - explicit, not derived from any gitignored developer file -
            // a release build always points at the real production endpoint.
            buildConfigField("String", "MANIFEST_URL", "\"$PRODUCTION_MANIFEST_URL\"")
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
