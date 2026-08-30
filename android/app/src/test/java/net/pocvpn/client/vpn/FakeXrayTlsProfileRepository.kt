package net.pocvpn.client.vpn

import net.pocvpn.client.identity.XrayTlsProfile
import net.pocvpn.client.identity.XrayTlsProfileRepository

/** B8O2 - the TLS/TCP counterpart of [FakeXrayProfileRepository]: same plain in-memory JVM test double shape. */
class FakeXrayTlsProfileRepository(private var profile: XrayTlsProfile? = null) : XrayTlsProfileRepository {
    override suspend fun getProfileOrNull(): XrayTlsProfile? = profile
    override suspend fun saveProfile(profile: XrayTlsProfile) {
        this.profile = profile
    }
    override suspend fun clearProfile() {
        profile = null
    }
}
