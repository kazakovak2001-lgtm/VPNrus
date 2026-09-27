package net.pocvpn.client.vpn.config

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * B47 F1 - the gateway provisioning source of truth
 * (`gateway/config/awg-profile.env`, rendered into a NEW gateway's awg0.conf
 * by `gateway/provision.sh`) must carry the same AmneziaWG S1-S4/H1-H4 as the
 * profile the app ships ([ProductionGatewayCatalog], [PocAwgProfile]).
 * The repo file had kept its original B5 values while the current app and
 * both live gateways use the values it now carries (read-only verified
 * 2026-09-27). Historical project evidence (B8B3B, see [PocAwgProfile])
 * indicates such a mismatch has caused AWG compatibility problems; no live
 * handshake regression test was run for this check.
 *
 * Deliberately NOT compared here: Jc/Jmin/Jmax/RandomTrailers/DisableCookies
 * - live Frankfurt differs from the repo/app/Stockholm on those
 * (unresolved configuration drift, not part of F1), and this test must not
 * implicitly declare that configuration wrong.
 */
class AwgProvisioningProfileConsistencyTest {

    private fun repoEnvFile(): File {
        // Gradle runs unit tests with user.dir = the module dir; walk up to the repo root.
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            val candidate = File(dir, "gateway/config/awg-profile.env")
            if (candidate.isFile) return candidate
            dir = dir.parentFile
        }
        error("gateway/config/awg-profile.env not found from ${System.getProperty("user.dir")}")
    }

    private fun repoEnv(): Map<String, String> =
        repoEnvFile().readLines()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") && it.contains('=') }
            .associate { it.substringBefore('=').trim() to it.substringAfter('=').trim() }

    private fun headerAndPaddingFields(p: AwgProfile): Map<String, String?> = mapOf(
        "AWG_S1" to p.initPacketJunkSize?.toString(),
        "AWG_S2" to p.responsePacketJunkSize?.toString(),
        "AWG_S3" to p.cookieReplyPacketJunkSize?.toString(),
        "AWG_S4" to p.transportPacketJunkSize?.toString(),
        "AWG_H1" to p.initPacketMagicHeader,
        "AWG_H2" to p.responsePacketMagicHeader,
        "AWG_H3" to p.underloadPacketMagicHeader,
        "AWG_H4" to p.transportPacketMagicHeader,
    )

    @Test
    fun `repo provisioning env carries every S1-S4 and H1-H4 key`() {
        val env = repoEnv()
        for (key in listOf("AWG_S1", "AWG_S2", "AWG_S3", "AWG_S4", "AWG_H1", "AWG_H2", "AWG_H3", "AWG_H4")) {
            assertTrue("$key missing from awg-profile.env", !env[key].isNullOrEmpty())
        }
    }

    @Test
    fun `repo provisioning env S1-S4 and H1-H4 equal every production gateway profile`() {
        val env = repoEnv()
        for (gateway in ProductionGatewayCatalog.all) {
            for ((key, appValue) in headerAndPaddingFields(gateway.awgProfile)) {
                assertEquals("${gateway.id} $key", appValue, env[key])
            }
        }
    }

    @Test
    fun `repo provisioning env S1-S4 and H1-H4 equal the POC default profile`() {
        val env = repoEnv()
        for ((key, appValue) in headerAndPaddingFields(PocAwgProfile.value)) {
            assertEquals("PocAwgProfile $key", appValue, env[key])
        }
    }
}
