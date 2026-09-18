package net.pocvpn.client.vpn

import net.pocvpn.client.identity.Shadowsocks2022Credential
import net.pocvpn.client.identity.Shadowsocks2022CredentialGetResult
import net.pocvpn.client.identity.Shadowsocks2022CredentialRepository

/**
 * B45B-4 - plain in-memory JVM test double for [Shadowsocks2022CredentialRepository],
 * the same "not encrypted, not file-backed" shape [FakeXrayProfileRepository]
 * already uses - only for proving Smart Connect selection wiring, never for
 * exercising the real B45B-2 persistence/crypto path.
 */
class FakeShadowsocks2022CredentialRepository(
    private var credential: Shadowsocks2022Credential? = null,
    private val corrupted: Boolean = false,
) : Shadowsocks2022CredentialRepository {
    override suspend fun getCredential(): Shadowsocks2022CredentialGetResult = when {
        corrupted -> Shadowsocks2022CredentialGetResult.Corrupted("simulated corruption")
        credential != null -> Shadowsocks2022CredentialGetResult.Present(credential!!)
        else -> Shadowsocks2022CredentialGetResult.Absent
    }

    override suspend fun storeCredential(credential: Shadowsocks2022Credential) {
        this.credential = credential
    }

    override suspend fun deleteCredential() {
        credential = null
    }

    override suspend fun credentialExists(): Boolean = credential != null
}
