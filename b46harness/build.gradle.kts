import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// B46-2P physical validation - a SEPARATE, standalone Android application
// module, deliberately independent of `:app` (see
// docs/B46_2P_HYSTERIA2_ANDROID_PHYSICAL_VALIDATION.md's "separate module"
// decision). `:app` links Xray's AndroidLibXrayLite AAR, which is ALSO
// gomobile-bound (go.Seq/go.Universe/go.error, native symbols tied to a
// single `libgojni.so`) - gomobile hardcodes that exact naming for every
// bind, so two independently gomobile-bound AARs (Xray's, and this
// module's own tun2socks bridge from
// research/b46-2p-android-physical/tun2socks-bridge/) cannot coexist in one
// app's classpath/native-library set. This module has ZERO dependency on
// `:app` - not even as a `debugImplementation` - so it never pulls Xray's
// AAR in. It is debug/research-only: never referenced by `:app`, never
// installed as part of a normal Nova release, and never wired into
// TransportRegistry/SmartConnectDecisionEngine/AutoGatewaySelector/
// TransportOrchestrator/production VpnController/MainViewModel.
//
// The physical validation this module proves is PHYSICAL ANDROID
// ARCHITECTURE FEASIBILITY for the B46-2C-selected permissive Hysteria2
// path (real VpnService TUN, real tun2socks AAR, real minimal Hysteria2
// child, real VpnService.protect(fd) via SCM_RIGHTS, real QUIC) - it is
// explicitly NOT YET INTEGRATED into the Nova `:app` process/classpath,
// which the AAR-coexistence issue above means requires separate follow-up
// engineering (e.g. relocating one AAR's gomobile runtime symbols) before
// any production integration could even be attempted.

// B46-2P - a SEPARATE, debug-only, gitignored local properties file
// carrying the temporary Hysteria2 test server's PUBLIC/non-secret
// endpoint values only (see
// docs/B46_2P_HYSTERIA2_ANDROID_PHYSICAL_VALIDATION.md). Never committed.
// Empty string defaults (never null); the config resolver fails closed
// with a typed error when these are blank.
//
// PRE-MERGE HARDENING CORRECTION (2026-09-20): this file - and the
// BuildConfig fields below - used to also carry `auth`, compiled directly
// into `BuildConfig.B46_HYSTERIA_AUTH` and therefore into the built debug
// APK. That is a real credential-delivery anti-pattern (secret material
// baked into a build artifact) and has been removed. `auth` (and any
// future obfuscation secret) is NEVER read from this properties file or
// exposed via BuildConfig - see B46HysteriaRuntimeCredential.kt for the
// real runtime-provisioned, app-private replacement.
val b46HysteriaDataPlaneProperties = Properties().apply {
    val f = file("b46-hysteria-dataplane.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}
fun b46HysteriaDataPlaneProp(key: String): String = b46HysteriaDataPlaneProperties.getProperty(key, "")

android {
    namespace = "net.pocvpn.b46harness"
    compileSdk = 35

    defaultConfig {
        applicationId = "net.pocvpn.b46harness"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1-b46-2p"

        // Public/non-secret test values ONLY - see the correction note
        // above. No `auth`/obfuscation-secret field exists here.
        buildConfigField("String", "B46_HYSTERIA_SERVER_HOST", "\"${b46HysteriaDataPlaneProp("serverHost")}\"")
        buildConfigField("String", "B46_HYSTERIA_SERVER_PORT", "\"${b46HysteriaDataPlaneProp("serverPort")}\"")
        buildConfigField("String", "B46_HYSTERIA_SNI", "\"${b46HysteriaDataPlaneProp("sni")}\"")
        buildConfigField("String", "B46_HYSTERIA_INSECURE", "\"${b46HysteriaDataPlaneProp("insecure").ifBlank { "true" }}\"")
        buildConfigField("String", "B46_HYSTERIA_EXPECTED_EXIT_IP", "\"${b46HysteriaDataPlaneProp("expectedExitIp")}\"")
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    // Same convention as `:app` (see its own build.gradle.kts) - plain JVM
    // unit tests never load the real Android framework, so any
    // `android.util.Log.*`/`org.json.*` call would otherwise throw
    // `RuntimeException("Stub!")`. Returning default (no-op/null) values
    // instead lets pure state-machine/orchestration logic be tested without
    // Robolectric.
    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

// PRE-MERGE HARDENING CORRECTION (2026-09-20, manual review, round 3):
// this whole module is documented everywhere as DEBUG/RESEARCH ONLY, but
// being a real `com.android.application` module it still had AGP's
// implicit `release` build type/variant by default - a standalone harness
// that could, in principle, be assembled and distributed as a release APK
// contradicts that stated boundary, even though nothing in this repository
// ever does so today. Disabled outright via the current AGP 8.7
// `androidComponents.beforeVariants` Variant API (`ApplicationVariantBuilder.enable`) -
// the release variant is never created, so `:b46harness:assembleRelease`
// produces no APK at all (not merely an empty/broken one). This is scoped
// to `b46harness` alone via `project(":b46harness")` at the Gradle level -
// it cannot affect `:app`'s own release variant, and this module is never
// added as a dependency of `:app` (see this file's own header comment) so
// there is no path by which a `b46harness` release artifact could ever
// reach a real Nova distribution.
androidComponents {
    beforeVariants(selector().withBuildType("release")) { variantBuilder ->
        variantBuilder.enable = false
    }
}

// The pinned tun2socks AAR (research/b46-2p-android-physical/tun2socks-bridge/README.md),
// gomobile-bound. Locally-built, gitignored - not committed. When absent,
// this module still compiles: B46Tun2SocksBridgeAdapter loads the real
// `bridge.Bridge` class via reflection at runtime, never a compile-time
// import, so a missing AAR fails closed at runtime with a typed error
// rather than failing compilation.
val b46Tun2SocksAar = file("local-libs/b46-tun2socks.aar")

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-ktx:1.9.3")
    if (b46Tun2SocksAar.exists()) {
        implementation(files(b46Tun2SocksAar))
    }
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
}
