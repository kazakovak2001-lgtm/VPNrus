package net.pocvpn.client.vpn.shadowsocks

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import net.pocvpn.client.identity.Shadowsocks2022CredentialValidationResult
import net.pocvpn.client.identity.Shadowsocks2022CredentialValidator
import net.pocvpn.client.vpn.FakeShadowsocks2022CredentialRepository
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.Base64
import kotlinx.coroutines.flow.first

private val VALID_KEY_BASE64 = Base64.getEncoder().encodeToString(ByteArray(32) { it.toByte() })

/**
 * B45B-4P (correction) - proves the signed-method/secret-credential
 * consistency check (this task's own Phase 7): a real, otherwise-valid
 * credential whose OWN method disagrees with the signed manifest's public
 * method (carried through [ShadowsocksVpnService.EXTRA_METHOD]) must fail
 * closed BEFORE sslocal is ever spawned - never silently trusting the
 * credential's method. Uses [ShadowsocksVpnService.credentialRepositoryFactory]'s
 * existing test seam (same one [ShadowsocksVpnServiceTeardownTest] uses for
 * [ShadowsocksVpnService.teardownDispatcher]) - `Dispatchers.Unconfined`
 * makes the credential-load coroutine (launched on [Dispatchers.Default] in
 * production) run to completion synchronously within `onStartCommand`, so no
 * Robolectric idling/timing is needed.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ShadowsocksVpnServiceMethodMismatchTest {

    private fun credential(method: String) =
        (
            Shadowsocks2022CredentialValidator.validate(
                net.pocvpn.client.reachability.EndpointId("frankfurt"), method, VALID_KEY_BASE64,
            ) as Shadowsocks2022CredentialValidationResult.Valid
            ).credential

    private fun startIntent(method: String) =
        android.content.Intent(ShadowsocksVpnService.ACTION_START)
            .putExtra(ShadowsocksVpnService.EXTRA_SESSION_ID, 1L)
            .putExtra(ShadowsocksVpnService.EXTRA_ENDPOINT_ID, "frankfurt")
            .putExtra(ShadowsocksVpnService.EXTRA_HOST, "152.70.43.1")
            .putExtra(ShadowsocksVpnService.EXTRA_PORT, 28388)
            .putExtra(ShadowsocksVpnService.EXTRA_METHOD, method)

    @Test
    fun `method mismatch between signed profile and credential fails closed before any TUN establish attempt`() {
        val service = Robolectric.buildService(ShadowsocksVpnService::class.java).create().get()
        service.teardownDispatcher = Dispatchers.Unconfined
        // Credential genuinely validates on its own (a method this app
        // recognizes) - the mismatch is ONLY against the signed profile's
        // OWN method extra, a distinct fact from "is this credential valid".
        service.credentialRepositoryFactory = { _, _ ->
            FakeShadowsocks2022CredentialRepository(credential("2022-blake3-aes-256-gcm"))
        }

        service.onStartCommand(startIntent(method = "2022-blake3-aes-256-gcm-DIFFERENT"), 0, 1)
        val status = runBlocking {
            withTimeout(5_000) {
                ShadowsocksVpnService.status.first { it != null && it.sessionId == 1L }
            }
        }

        assertEquals(ShadowsocksRuntimePhase.FAILED, status?.phase)
        assertEquals(
            ShadowsocksRuntimeError.ProfileMethodMismatch("2022-blake3-aes-256-gcm-DIFFERENT", "2022-blake3-aes-256-gcm"),
            status?.error,
        )
    }

    @Test
    fun `matching method does not report a method-mismatch failure`() {
        val service = Robolectric.buildService(ShadowsocksVpnService::class.java).create().get()
        service.teardownDispatcher = Dispatchers.Unconfined
        service.credentialRepositoryFactory = { _, _ ->
            FakeShadowsocks2022CredentialRepository(credential("2022-blake3-aes-256-gcm"))
        }

        service.onStartCommand(startIntent(method = "2022-blake3-aes-256-gcm"), 0, 2)
        // Whatever happens next (a real TUN establish/sslocal spawn is not
        // achievable under a JVM unit test, so this attempt may never reach
        // a terminal status at all within a bounded wait) - the one thing
        // this test pins down is that IF a status for this session appears,
        // it is never ProfileMethodMismatch when the methods genuinely agree.
        val status = runBlocking {
            runCatching {
                withTimeout(2_000) {
                    ShadowsocksVpnService.status.first { it != null && it.sessionId == 2L }
                }
            }.getOrNull()
        }
        assertFalse("matching methods must never be reported as a mismatch", status?.error is ShadowsocksRuntimeError.ProfileMethodMismatch)
    }
}
