package net.pocvpn.client.provisioning

import kotlinx.coroutines.runBlocking
import net.pocvpn.client.identity.FakeAesGcmKeyEncryptor
import net.pocvpn.client.identity.FileXrayProfileStore
import net.pocvpn.client.identity.SecureXrayProfileRepository
import net.pocvpn.client.identity.XrayProfile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

/**
 * B8K4B - proves XrayProfileProvisioner's ONE safety rule: saveProfile() is
 * reached in exactly one branch (a validated Success), every other outcome
 * leaves a previously stored profile completely untouched.
 */
class XrayProfileProvisionerTest {

    private val validKey = "e2sIl+TFOY99CMiZqodvjKVS2UM1pY3H7wHfZuBChF0="
    private val validRealityPublicKey = "9WewKC/zyUPyPnKyzaI0bZrEN2c73PqjK7f+fRXHYRU="
    private val validUuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f"

    private val sampleSuccess = XrayProfileResult.Success(
        serverAddress = "152.70.43.1",
        serverPort = 443,
        uuid = validUuid,
        flow = "xtls-rprx-vision",
        serverName = "www.microsoft.com",
        fingerprint = "chrome",
        realityPublicKey = validRealityPublicKey,
        shortId = "a1b2c3d4",
    )

    private fun newRepository(): SecureXrayProfileRepository =
        SecureXrayProfileRepository(FileXrayProfileStore(Files.createTempDirectory("xray-provisioner-test").toFile()), FakeAesGcmKeyEncryptor())

    @Test
    fun `successful fetch saves exactly one validated profile mapped via the B8K4A mapper`() = runBlocking {
        val repository = newRepository()
        val provisioner = XrayProfileProvisioner(repository) { _, _ -> sampleSuccess }

        val outcome = provisioner.provision(validKey, "some-activation-credential")

        assertEquals(XrayProfileProvisioningOutcome.Saved, outcome)
        val saved = repository.getProfileOrNull()
        assertEquals(sampleSuccess.toXrayProfile(), saved)
    }

    @Test
    fun `same device public key and activation credential are forwarded to the fetch call`() = runBlocking {
        var capturedKey: String? = null
        var capturedCredential: String? = null
        val provisioner = XrayProfileProvisioner(newRepository()) { key, credential ->
            capturedKey = key
            capturedCredential = credential
            sampleSuccess
        }

        provisioner.provision(validKey, "my-activation-credential-123")

        assertEquals(validKey, capturedKey)
        assertEquals("my-activation-credential-123", capturedCredential)
    }

    @Test
    fun `network error does not delete or overwrite an existing stored profile`() = runBlocking {
        val repository = newRepository()
        val existing = XrayProfile(
            server = "existing.example.net", serverPort = 8443, uuid = validUuid,
            flow = "xtls-rprx-vision", serverName = "existing.example.net",
            fingerprint = "chrome", realityPublicKey = validRealityPublicKey, shortId = "deadbeef",
        )
        repository.saveProfile(existing)

        val provisioner = XrayProfileProvisioner(repository) { _, _ -> XrayProfileResult.NetworkError("timeout") }
        val outcome = provisioner.provision(validKey, "cred")

        assertEquals(XrayProfileProvisioningOutcome.Unavailable, outcome)
        assertEquals(existing, repository.getProfileOrNull())
    }

    @Test
    fun `503 does not delete or overwrite an existing stored profile`() = runBlocking {
        val repository = newRepository()
        val existing = sampleSuccess.toXrayProfile()
        repository.saveProfile(existing)

        val provisioner = XrayProfileProvisioner(repository) { _, _ -> XrayProfileResult.ServiceUnavailable }
        val outcome = provisioner.provision(validKey, "cred")

        assertEquals(XrayProfileProvisioningOutcome.Unavailable, outcome)
        assertEquals(existing, repository.getProfileOrNull())
    }

    @Test
    fun `401 does not delete or overwrite an existing stored profile and surfaces as AuthorizationFailed`() = runBlocking {
        val repository = newRepository()
        val existing = sampleSuccess.toXrayProfile()
        repository.saveProfile(existing)

        val provisioner = XrayProfileProvisioner(repository) { _, _ -> XrayProfileResult.Unauthorized }
        val outcome = provisioner.provision(validKey, "cred")

        assertEquals(XrayProfileProvisioningOutcome.AuthorizationFailed, outcome)
        assertEquals(existing, repository.getProfileOrNull())
    }

    @Test
    fun `revoked surfaces as AuthorizationFailed and does not touch the stored profile`() = runBlocking {
        val repository = newRepository()
        val existing = sampleSuccess.toXrayProfile()
        repository.saveProfile(existing)

        val provisioner = XrayProfileProvisioner(repository) { _, _ -> XrayProfileResult.Revoked }
        val outcome = provisioner.provision(validKey, "cred")

        assertEquals(XrayProfileProvisioningOutcome.AuthorizationFailed, outcome)
        assertEquals(existing, repository.getProfileOrNull())
    }

    @Test
    fun `device_not_bound surfaces as AuthorizationFailed and does not touch the stored profile`() = runBlocking {
        val repository = newRepository()
        val existing = sampleSuccess.toXrayProfile()
        repository.saveProfile(existing)

        val provisioner = XrayProfileProvisioner(repository) { _, _ -> XrayProfileResult.DeviceNotBound }
        val outcome = provisioner.provision(validKey, "cred")

        assertEquals(XrayProfileProvisioningOutcome.AuthorizationFailed, outcome)
        assertEquals(existing, repository.getProfileOrNull())
    }

    @Test
    fun `malformed response is never persisted and does not overwrite an existing stored profile`() = runBlocking {
        val repository = newRepository()
        val existing = sampleSuccess.toXrayProfile()
        repository.saveProfile(existing)

        val provisioner = XrayProfileProvisioner(repository) { _, _ -> XrayProfileResult.MalformedResponse("bad short_id") }
        val outcome = provisioner.provision(validKey, "cred")

        assertTrue(outcome is XrayProfileProvisioningOutcome.Malformed)
        assertEquals("bad short_id", (outcome as XrayProfileProvisioningOutcome.Malformed).reason)
        assertEquals(existing, repository.getProfileOrNull())
    }

    @Test
    fun `malformed response with no prior stored profile still saves nothing`() = runBlocking {
        val repository = newRepository()
        val provisioner = XrayProfileProvisioner(repository) { _, _ -> XrayProfileResult.MalformedResponse("bad uuid") }

        provisioner.provision(validKey, "cred")

        assertNull(repository.getProfileOrNull())
    }
}
