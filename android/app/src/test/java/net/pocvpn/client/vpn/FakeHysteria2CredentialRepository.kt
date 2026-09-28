package net.pocvpn.client.vpn

import net.pocvpn.client.identity.Hysteria2Credential
import net.pocvpn.client.identity.Hysteria2CredentialGetResult
import net.pocvpn.client.identity.Hysteria2CredentialRepository

/**
 * B46-4A - plain in-memory JVM test double for [Hysteria2CredentialRepository],
 * mirrors [FakeShadowsocks2022CredentialRepository]'s own shape exactly -
 * only for proving Smart Connect selection wiring, never for exercising the
 * real encrypted persistence path.
 */
class FakeHysteria2CredentialRepository(
    private var credential: Hysteria2Credential? = null,
    private val corrupted: Boolean = false,
) : Hysteria2CredentialRepository {
    override suspend fun getCredential(): Hysteria2CredentialGetResult = when {
        corrupted -> Hysteria2CredentialGetResult.Corrupted("simulated corruption")
        credential != null -> Hysteria2CredentialGetResult.Present(credential!!)
        else -> Hysteria2CredentialGetResult.Absent
    }

    override suspend fun storeCredential(credential: Hysteria2Credential) {
        this.credential = credential
    }

    override suspend fun deleteCredential() {
        credential = null
    }

    override suspend fun credentialExists(): Boolean = credential != null
}
