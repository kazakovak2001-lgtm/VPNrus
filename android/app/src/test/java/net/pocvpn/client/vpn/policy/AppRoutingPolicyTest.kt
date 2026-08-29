package net.pocvpn.client.vpn.policy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B8H - narrow tests for resolveAppRoutingLists, the one place an
 * AppRoutingPolicy becomes the actual VpnService.Builder-level allowed/
 * disallowed lists. Covers this feature's own required cases 1, 3, 4, 5, 6, 8.
 */
class AppRoutingPolicyTest {

    @Test
    fun `default policy is ALL_APPS with no selection`() {
        assertEquals(AppRoutingMode.ALL_APPS, AppRoutingPolicy.Default.mode)
        assertTrue(AppRoutingPolicy.Default.selectedPackageNames.isEmpty())
    }

    @Test
    fun `ALL_APPS resolves to no allowed or disallowed list, regardless of any stale selection`() {
        val policy = AppRoutingPolicy(AppRoutingMode.ALL_APPS, setOf("com.example.a", "com.example.b"))

        val result = resolveAppRoutingLists(policy) { true }

        assertTrue(result is EffectiveRoutingResult.Apply)
        val lists = (result as EffectiveRoutingResult.Apply).lists
        assertTrue(lists.includedApplications.isEmpty())
        assertTrue(lists.excludedApplications.isEmpty())
        assertEquals(AppRoutingLists.AllApps, lists)
    }

    @Test
    fun `BYPASS_SELECTED maps only to disallowed apps, included stays empty`() {
        val policy = AppRoutingPolicy(AppRoutingMode.BYPASS_SELECTED, setOf("com.bank.ru", "com.gov.ru"))

        val result = resolveAppRoutingLists(policy) { true }

        val lists = (result as EffectiveRoutingResult.Apply).lists
        assertEquals(setOf("com.bank.ru", "com.gov.ru"), lists.excludedApplications)
        assertTrue(lists.includedApplications.isEmpty())
    }

    @Test
    fun `VPN_ONLY_SELECTED maps only to allowed apps, excluded stays empty`() {
        val policy = AppRoutingPolicy(AppRoutingMode.VPN_ONLY_SELECTED, setOf("com.example.torrent"))

        val result = resolveAppRoutingLists(policy) { true }

        val lists = (result as EffectiveRoutingResult.Apply).lists
        assertEquals(setOf("com.example.torrent"), lists.includedApplications)
        assertTrue(lists.excludedApplications.isEmpty())
    }

    @Test
    fun `allowed and disallowed lists can never coexist`() {
        try {
            AppRoutingLists(includedApplications = setOf("a.b"), excludedApplications = setOf("c.d"))
            org.junit.Assert.fail("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun `VPN_ONLY_SELECTED with zero selected apps fails safely, never falls back to ALL_APPS`() {
        val policy = AppRoutingPolicy(AppRoutingMode.VPN_ONLY_SELECTED, emptySet())

        val result = resolveAppRoutingLists(policy) { true }

        assertTrue(result is EffectiveRoutingResult.NoAppsSelected)
    }

    @Test
    fun `VPN_ONLY_SELECTED where every selected app has since been uninstalled also fails safely`() {
        val policy = AppRoutingPolicy(AppRoutingMode.VPN_ONLY_SELECTED, setOf("com.deleted.app"))

        val result = resolveAppRoutingLists(policy) { installed -> installed != "com.deleted.app" }

        assertTrue(result is EffectiveRoutingResult.NoAppsSelected)
    }

    @Test
    fun `stale uninstalled package is dropped silently, not crashed on, for BYPASS_SELECTED`() {
        val policy = AppRoutingPolicy(AppRoutingMode.BYPASS_SELECTED, setOf("com.still.installed", "com.uninstalled.app"))

        val result = resolveAppRoutingLists(policy) { it != "com.uninstalled.app" }

        val lists = (result as EffectiveRoutingResult.Apply).lists
        assertEquals(setOf("com.still.installed"), lists.excludedApplications)
    }

    @Test
    fun `stale uninstalled package is dropped silently for VPN_ONLY_SELECTED as long as one real app remains`() {
        val policy = AppRoutingPolicy(AppRoutingMode.VPN_ONLY_SELECTED, setOf("com.still.installed", "com.uninstalled.app"))

        val result = resolveAppRoutingLists(policy) { it != "com.uninstalled.app" }

        val lists = (result as EffectiveRoutingResult.Apply).lists
        assertEquals(setOf("com.still.installed"), lists.includedApplications)
    }

    @Test
    fun `package name validation accepts real Android IDs and rejects malformed ones`() {
        assertTrue(isValidAndroidPackageName("com.example.app"))
        assertTrue(isValidAndroidPackageName("net.pocvpn.client"))
        assertFalse(isValidAndroidPackageName(""))
        assertFalse(isValidAndroidPackageName("nodots"))
        assertFalse(isValidAndroidPackageName("../../etc/passwd"))
        assertFalse(isValidAndroidPackageName("com.example..app"))
        assertFalse(isValidAndroidPackageName("1com.example.app"))
    }
}
