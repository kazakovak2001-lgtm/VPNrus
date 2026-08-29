package net.pocvpn.client.vpn.policy

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * B8H - narrow tests for FileAppRoutingPolicyStore: this feature's own
 * required cases 1 (no saved policy -> ALL_APPS) and 7 (persists/restores
 * across process death - simulated here by constructing a SECOND store
 * instance against the same directory, exactly like FileProfileStore's own
 * equivalent test would).
 */
class AppRoutingPolicyStoreTest {

    @Test
    fun `no saved policy file yields ALL_APPS`() {
        val dir = Files.createTempDirectory("app-routing-policy-test").toFile()
        val store = FileAppRoutingPolicyStore(dir)

        val policy = store.read()

        assertEquals(AppRoutingPolicy.Default, policy)
        assertEquals(AppRoutingMode.ALL_APPS, policy.mode)
    }

    @Test
    fun `a saved policy survives a fresh store instance against the same directory - process death, reboot, install -r`() {
        val dir = Files.createTempDirectory("app-routing-policy-test").toFile()
        val saved = AppRoutingPolicy(AppRoutingMode.VPN_ONLY_SELECTED, setOf("com.example.a", "com.example.b"))
        FileAppRoutingPolicyStore(dir).write(saved)

        // A brand-new instance - nothing in-memory carried over - simulates
        // the process (and the file's directory, i.e. the device) surviving
        // independently of this specific object's lifetime.
        val restored = FileAppRoutingPolicyStore(dir).read()

        assertEquals(saved, restored)
    }

    @Test
    fun `writing then reading BYPASS_SELECTED round-trips exactly`() {
        val dir = Files.createTempDirectory("app-routing-policy-test").toFile()
        val store = FileAppRoutingPolicyStore(dir)
        val saved = AppRoutingPolicy(AppRoutingMode.BYPASS_SELECTED, setOf("ru.bank.example"))

        store.write(saved)

        assertEquals(saved, store.read())
    }

    @Test
    fun `a corrupted policy file falls back to ALL_APPS, never crashes`() {
        val dir = Files.createTempDirectory("app-routing-policy-test").toFile()
        val file = java.io.File(dir, "app_routing_policy.bin")
        file.writeBytes(byteArrayOf(1, 2, 3)) // truncated/garbage, not a real record

        val policy = FileAppRoutingPolicyStore(dir).read()

        assertEquals(AppRoutingPolicy.Default, policy)
    }
}
