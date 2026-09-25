package net.pocvpn.client.vpn

import net.pocvpn.client.identity.XrayXhttpProfile
import net.pocvpn.client.identity.XrayXhttpProfileRepository

/** B61 - the XHTTP (EXIT-role, B60) counterpart of [FakeXrayTlsProfileRepository]: same plain in-memory JVM test double shape. */
class FakeXrayXhttpProfileRepository(private var profile: XrayXhttpProfile? = null) : XrayXhttpProfileRepository {
    override suspend fun getProfileOrNull(): XrayXhttpProfile? = profile
    override suspend fun saveProfile(profile: XrayXhttpProfile) {
        this.profile = profile
    }
    override suspend fun clearProfile() {
        profile = null
    }
}
