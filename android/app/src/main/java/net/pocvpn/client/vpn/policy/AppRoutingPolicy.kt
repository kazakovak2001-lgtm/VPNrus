package net.pocvpn.client.vpn.policy

/**
 * B8H - the three per-app routing modes Nova VPN supports. This is a
 * DEVICE-LOCAL preference only - it never comes from /v1/activate and is
 * never persisted on the gateway/Oracle (see AppRoutingPolicyStore's own
 * docs). ALL_APPS is the only safe default: it reproduces the exact
 * pre-B8H full-tunnel behavior (see AppRoutingLists.AllApps), so existing
 * users who upgrade with no saved policy keep their current behavior.
 */
enum class AppRoutingMode { ALL_APPS, BYPASS_SELECTED, VPN_ONLY_SELECTED }

/**
 * The canonical policy value. [selectedPackageNames] is meaningless for
 * ALL_APPS (kept as whatever the user last picked, so switching back to
 * BYPASS_SELECTED/VPN_ONLY_SELECTED restores their prior selection) and is
 * the bypass-list or allow-list for the other two modes respectively - which
 * one it means is determined entirely by [mode], never by which field is
 * merely non-empty.
 */
data class AppRoutingPolicy(
    val mode: AppRoutingMode = AppRoutingMode.ALL_APPS,
    val selectedPackageNames: Set<String> = emptySet(),
) {
    companion object {
        /** No saved policy exists -> this. Also today's ONLY behavior, so upgrading users see no change. */
        val Default = AppRoutingPolicy(AppRoutingMode.ALL_APPS, emptySet())
    }
}

/**
 * The actual android.net.VpnService.Builder-level lists a resolved policy
 * produces - see GoBackend.setStateInternal's own bytecode (decompiled
 * against the pinned v3.1.20260814 AAR): it forwards
 * Config.Interface.getExcludedApplications()/getIncludedApplications()
 * verbatim into VpnService.Builder.addDisallowedApplication()/
 * addAllowedApplication(), with NO guard against both being populated at
 * once - that guard must live here instead. [includedApplications] and
 * [excludedApplications] can therefore never BOTH be non-empty: passing both
 * to VpnService.Builder is undefined/nonsensical, and every caller of this
 * class already receives a value that has already been decided to be one or
 * the other (or neither, for ALL_APPS).
 */
data class AppRoutingLists(
    val includedApplications: Set<String> = emptySet(),
    val excludedApplications: Set<String> = emptySet(),
) {
    init {
        require(includedApplications.isEmpty() || excludedApplications.isEmpty()) {
            "includedApplications and excludedApplications must never both be non-empty"
        }
    }

    companion object {
        /** ALL_APPS: no allowed/disallowed list at all - preserves the exact pre-B8H full-device VPN behavior. */
        val AllApps = AppRoutingLists()
    }
}

/** What resolving a saved [AppRoutingPolicy] against the device's currently-installed apps produced. */
sealed class EffectiveRoutingResult {
    data class Apply(val lists: AppRoutingLists) : EffectiveRoutingResult()

    /**
     * VPN_ONLY_SELECTED resolved to zero installed apps (none were ever
     * selected, or every selected package has since been uninstalled).
     * connect() MUST fail on this, never silently fall back to an empty
     * includedApplications list - GoBackend/VpnService.Builder treats "no
     * allowed-app list at all" as ALL_APPS (full tunnel), which would
     * silently defeat the user's explicit "only these apps" choice.
     */
    object NoAppsSelected : EffectiveRoutingResult()
}

/**
 * The one place [AppRoutingPolicy] becomes [AppRoutingLists]. [isInstalled]
 * is injected (not read from PackageManager directly) so this stays a pure,
 * JVM-testable function - VpnController supplies the real check via
 * InstalledPackageChecker.
 *
 * Stale/uninstalled packages are silently dropped here, never surfaced as a
 * crash or error - see this file's own "if an app is no longer installed"
 * requirement. BYPASS_SELECTED dropping down to zero installed apps is not
 * an error (nothing bypassed = full tunnel for that session, which is safe);
 * only VPN_ONLY_SELECTED must fail on zero, since an empty allow-list means
 * something different (and unsafe) to GoBackend than "select nothing".
 */
fun resolveAppRoutingLists(policy: AppRoutingPolicy, isInstalled: (String) -> Boolean): EffectiveRoutingResult {
    val installedSelected = policy.selectedPackageNames.filter(isInstalled).toSet()
    return when (policy.mode) {
        AppRoutingMode.ALL_APPS -> EffectiveRoutingResult.Apply(AppRoutingLists.AllApps)
        AppRoutingMode.BYPASS_SELECTED -> EffectiveRoutingResult.Apply(AppRoutingLists(excludedApplications = installedSelected))
        AppRoutingMode.VPN_ONLY_SELECTED ->
            if (installedSelected.isEmpty()) {
                EffectiveRoutingResult.NoAppsSelected
            } else {
                EffectiveRoutingResult.Apply(AppRoutingLists(includedApplications = installedSelected))
            }
    }
}

// Ordinary Android application-ID shape (Java package name: 2+ dot-separated
// segments, each starting with a letter). Deliberately used both when saving
// a policy from the app picker (which only ever offers real installed
// packages) and when loading a persisted file (a hand-edited/corrupted file
// can never smuggle a non-package-shaped string back into a selection set).
private val ANDROID_PACKAGE_NAME_REGEX = Regex("^[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)+$")

fun isValidAndroidPackageName(name: String): Boolean = ANDROID_PACKAGE_NAME_REGEX.matches(name)
