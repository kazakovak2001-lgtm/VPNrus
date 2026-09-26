package net.pocvpn.client.provisioning

import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import net.pocvpn.client.identity.FakeAesGcmKeyEncryptor
import net.pocvpn.client.identity.FileHysteria2CredentialStore
import net.pocvpn.client.identity.Hysteria2CredentialGetResult
import net.pocvpn.client.identity.SecureHysteria2CredentialRepository
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.Hysteria2Profile
import net.pocvpn.client.reachability.withHysteria2Profile
import net.pocvpn.client.transport.TransportKind

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B46-4A review fix (Finding 3/5) - proves the provisioner requires a real
 * trusted signed binding before ever dialing the network, and that the
 * server's response cannot override public routing/policy facts (host,
 * port, SNI, obfuscation mode) that the signed manifest already pinned -
 * only secret material (auth_secret) flows from the response into the
 * saved credential.
 */
class Hysteria2ProfileProvisionerTest {

    private val endpointId = EndpointId("edge-hy2")
    private val trustedProfile = Hysteria2Profile(sni = "hy2.example.com", obfuscationMode = "NONE")
    private val trustedBinding = EndpointTransportBinding(TransportKind.HYSTERIA2, "hy2.example", 443)
        .withHysteria2Profile(trustedProfile)

    private val validSuccess = Hysteria2ProfileResult.Success(
        serverAddress = "hy2.example",
        serverPort = 443,
        authSecret = "a".repeat(64),
        sni = "hy2.example.com",
        obfuscationMode = "NONE",
        obfuscationSecret = null,
        profileVersion = 1,
        issuedAtEpochSeconds = null,
        expiresAtEpochSeconds = null,
    )

    private fun newRepository() =
        SecureHysteria2CredentialRepository(endpointId, FileHysteria2CredentialStore(Files.createTempDirectory("hy2-provisioner-test").toFile(), endpointId), FakeAesGcmKeyEncryptor())

    @Test
    fun `successful fetch matching the trusted binding saves the credential`() = runBlocking {
        val repository = newRepository()
        val provisioner = Hysteria2ProfileProvisioner(repository) { _, _, _ -> validSuccess }

        val outcome = provisioner.provision(endpointId, trustedBinding, "pk", "activation-credential")

        assertEquals(Hysteria2ProvisioningOutcome.Saved, outcome)
        val saved = repository.getCredential()
        assertTrue(saved is Hysteria2CredentialGetResult.Present)
        assertEquals("a".repeat(64), (saved as Hysteria2CredentialGetResult.Present).credential.authSecret.value)
    }

    @Test
    fun `no trusted signed binding fails closed WITHOUT ever calling the network`() = runBlocking {
        var fetchCalled = false
        val legacyBinding = EndpointTransportBinding(TransportKind.HYSTERIA2, "hy2.example", 443) // no hysteria2Profile metadata -> Legacy
        val provisioner = Hysteria2ProfileProvisioner(newRepository()) { _, _, _ -> fetchCalled = true; validSuccess }

        val outcome = provisioner.provision(endpointId, legacyBinding, "pk", "activation-credential")

        assertTrue(outcome is Hysteria2ProvisioningOutcome.NoTrustedBinding)
        assertTrue("network must never be dialed without a trusted binding", !fetchCalled)
    }

    @Test
    fun `server address mismatch is rejected`() = runBlocking {
        val mismatched = validSuccess.copy(serverAddress = "attacker.example")
        val provisioner = Hysteria2ProfileProvisioner(newRepository()) { _, _, _ -> mismatched }

        val outcome = provisioner.provision(endpointId, trustedBinding, "pk", "activation-credential")

        assertTrue(outcome is Hysteria2ProvisioningOutcome.Mismatched)
    }

    @Test
    fun `server port mismatch is rejected`() = runBlocking {
        val mismatched = validSuccess.copy(serverPort = 9999)
        val provisioner = Hysteria2ProfileProvisioner(newRepository()) { _, _, _ -> mismatched }

        val outcome = provisioner.provision(endpointId, trustedBinding, "pk", "activation-credential")

        assertTrue(outcome is Hysteria2ProvisioningOutcome.Mismatched)
    }

    @Test
    fun `SNI mismatch against the trusted signed profile is rejected`() = runBlocking {
        val mismatched = validSuccess.copy(sni = "attacker.example.com")
        val provisioner = Hysteria2ProfileProvisioner(newRepository()) { _, _, _ -> mismatched }

        val outcome = provisioner.provision(endpointId, trustedBinding, "pk", "activation-credential")

        assertTrue("expected Mismatched, got $outcome", outcome is Hysteria2ProvisioningOutcome.Mismatched)
    }

    @Test
    fun `obfuscation mode mismatch against the trusted signed profile is rejected - response cannot override signed policy`() = runBlocking {
        // The response claims SALAMANDER even though the trusted signed profile says NONE.
        val mismatched = validSuccess.copy(obfuscationMode = "SALAMANDER", obfuscationSecret = "b".repeat(64))
        val provisioner = Hysteria2ProfileProvisioner(newRepository()) { _, _, _ -> mismatched }

        val outcome = provisioner.provision(endpointId, trustedBinding, "pk", "activation-credential")

        assertTrue("expected Mismatched, got $outcome", outcome is Hysteria2ProvisioningOutcome.Mismatched)
    }

    @Test
    fun `a credential whose obfuscation-secret presence disagrees with the trusted mode is never saved`() = runBlocking {
        // Same obfuscationMode as trusted (NONE), but the response smuggled an obfuscation secret anyway.
        val inconsistent = validSuccess.copy(obfuscationSecret = "c".repeat(64))
        val repository = newRepository()
        val provisioner = Hysteria2ProfileProvisioner(repository) { _, _, _ -> inconsistent }

        val outcome = provisioner.provision(endpointId, trustedBinding, "pk", "activation-credential")

        assertTrue("expected CredentialRejected, got $outcome", outcome is Hysteria2ProvisioningOutcome.CredentialRejected)
        assertEquals(Hysteria2CredentialGetResult.Absent, repository.getCredential())
    }

    @Test
    fun `activation credential is never persisted as the Hysteria auth secret`() = runBlocking {
        val repository = newRepository()
        val activationCredential = "the-activation-bearer-credential"
        val provisioner = Hysteria2ProfileProvisioner(repository) { _, _, _ -> validSuccess }

        provisioner.provision(endpointId, trustedBinding, "pk", activationCredential)

        val saved = repository.getCredential() as Hysteria2CredentialGetResult.Present
        assertTrue(saved.credential.authSecret.value != activationCredential)
        assertEquals(validSuccess.authSecret, saved.credential.authSecret.value)
    }

    @Test
    fun `unauthorized response never saves a credential`() = runBlocking {
        val repository = newRepository()
        val provisioner = Hysteria2ProfileProvisioner(repository) { _, _, _ -> Hysteria2ProfileResult.Unauthorized }

        val outcome = provisioner.provision(endpointId, trustedBinding, "pk", "activation-credential")

        assertEquals(Hysteria2ProvisioningOutcome.AuthorizationFailed, outcome)
        assertEquals(Hysteria2CredentialGetResult.Absent, repository.getCredential())
    }
}
