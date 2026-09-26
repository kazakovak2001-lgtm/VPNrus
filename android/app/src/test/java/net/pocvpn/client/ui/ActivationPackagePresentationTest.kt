package net.pocvpn.client.ui

import net.pocvpn.client.activation.ActivationPackageRejectionKind
import net.pocvpn.client.activation.ActivationPackageUiState
import net.pocvpn.client.activation.BootstrapStagingStatus
import net.pocvpn.client.activation.NovaActivationPackage
import net.pocvpn.client.provisioning.ProvisioningUiState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ActivationPackagePresentationTest {
    @Test fun `every rejection has fixed copy with no key, credential or internal detail`() {
        ActivationPackageRejectionKind.entries.forEach { kind ->
            val text = ActivationPackageUiState.Rejected(kind).toActivationPackageMessage()!!
            assertTrue(text, text.startsWith("Activation package") || text.startsWith("This activation package") || text.startsWith("Check your device"))
            listOf("key", "credential", "signature", "issuer", "=", "prod-").forEach { assertTrue("$kind: $text", !text.contains(it, ignoreCase = true)) }
        }
    }

    @Test fun `required user-facing categories`() {
        assertEquals("Activation package is invalid.", ActivationPackageUiState.Rejected(ActivationPackageRejectionKind.PACKAGE_MALFORMED).toActivationPackageMessage())
        assertEquals("Activation package has expired.", ActivationPackageUiState.Rejected(ActivationPackageRejectionKind.EXPIRED).toActivationPackageMessage())
        assertEquals("Activation package is not trusted.", ActivationPackageUiState.Rejected(ActivationPackageRejectionKind.ISSUER_UNKNOWN).toActivationPackageMessage())
        assertEquals("Activation package was already used.", ActivationPackageUiState.Rejected(ActivationPackageRejectionKind.ALREADY_REDEEMED).toActivationPackageMessage())
        assertTrue(ActivationPackageUiState.NetworkRequired(BootstrapStagingStatus.STAGED).toActivationPackageMessage()!!.contains("Network connection is required"))
    }

    @Test fun `in-progress and success states show nothing`() {
        listOf(
            ActivationPackageUiState.Idle,
            ActivationPackageUiState.Verifying,
            ActivationPackageUiState.Activating(BootstrapStagingStatus.NOT_INCLUDED),
            ActivationPackageUiState.Succeeded(BootstrapStagingStatus.NOT_INCLUDED),
        ).forEach { assertNull(it.toActivationPackageMessage()) }
    }

    @Test fun `a stale package error never masks a raw-credential attempt`() {
        val stale = ActivationPackageUiState.Rejected(ActivationPackageRejectionKind.EXPIRED)
        assertEquals(ProvisioningUiState.Revoked.toActivationErrorText(), activationErrorText("raw-credential", stale, ProvisioningUiState.Revoked))
        assertEquals("Activation package has expired.", activationErrorText(NovaActivationPackage.TEXT_PREFIX + "AAAA", stale, ProvisioningUiState.Idle))
    }

    @Test fun `server-side refusal of a verified package falls through to the existing activation copy`() {
        assertEquals(
            ProvisioningUiState.Revoked.toActivationErrorText(),
            activationErrorText(NovaActivationPackage.TEXT_PREFIX + "AAAA", ActivationPackageUiState.ActivationFailed, ProvisioningUiState.Revoked),
        )
    }
}
