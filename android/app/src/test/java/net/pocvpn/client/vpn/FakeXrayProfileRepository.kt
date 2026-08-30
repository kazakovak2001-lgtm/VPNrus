package net.pocvpn.client.vpn

import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.identity.XrayProfileRepository

/**
 * B8I6 - plain in-memory JVM test double for [XrayProfileRepository]. Not
 * encrypted, not file-backed - unlike SecureXrayProfileRepository, this is
 * only for proving VpnController's buildTransportConfig(XRAY_REALITY, ...)
 * wiring, never for exercising the real persistence/crypto path (that's
 * XrayProfileRepositoryTest's job).
 */
class FakeXrayProfileRepository(private var profile: XrayProfile? = null) : XrayProfileRepository {
    override suspend fun getProfileOrNull(): XrayProfile? = profile
    override suspend fun saveProfile(profile: XrayProfile) {
        this.profile = profile
    }
    override suspend fun clearProfile() {
        profile = null
    }
}
