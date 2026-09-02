package net.pocvpn.client.vpn

import net.pocvpn.client.identity.XrayQuicProfile
import net.pocvpn.client.identity.XrayQuicProfileRepository

/** B21 - the QUIC counterpart of [FakeXrayTlsProfileRepository]: same plain in-memory JVM test double shape. */
class FakeXrayQuicProfileRepository(private var profile: XrayQuicProfile? = null) : XrayQuicProfileRepository {
    override suspend fun getProfileOrNull(): XrayQuicProfile? = profile
    override suspend fun saveProfile(profile: XrayQuicProfile) {
        this.profile = profile
    }
    override suspend fun clearProfile() {
        profile = null
    }
}
