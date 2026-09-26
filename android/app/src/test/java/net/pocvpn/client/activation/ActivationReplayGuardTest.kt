package net.pocvpn.client.activation

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class ActivationReplayGuardTest {
    @get:Rule val tmp = TemporaryFolder()
    private lateinit var f: ActivationPackageFixtures
    private lateinit var dir: File

    @Before fun setUp() {
        f = ActivationPackageFixtures(tmp.newFolder())
        dir = tmp.newFolder()
    }

    @Test fun `redeemed state persists across instances`() {
        val env = f.envelope()
        FileActivationReplayGuard(dir).markRedeemed(env, f.now)
        assertTrue(FileActivationReplayGuard(dir).isRedeemed(env))
        assertFalse(FileActivationReplayGuard(dir).isRedeemed(f.envelope(nonceSeed = 99)))
    }

    @Test fun `stored file contains no credential, no nonce, no activation id`() {
        val env = f.envelope()
        FileActivationReplayGuard(dir).markRedeemed(env, f.now)
        val stored = File(dir, FileActivationReplayGuard.FILE_NAME).readText()
        assertFalse(stored.contains(f.credential))
        assertFalse(stored.contains(env.activationId.value))
        assertFalse(stored.contains(env.nonce.joinToString("") { "%02x".format(it) }))
    }

    @Test fun `expired entries are pruned on the next write`() {
        val short = f.envelope(expiresAt = f.now + 1_000L)
        val guard = FileActivationReplayGuard(dir)
        guard.markRedeemed(short, f.now)
        guard.markRedeemed(f.envelope(nonceSeed = 50), f.now + 2_000L)
        assertFalse(guard.isRedeemed(short))
    }

    @Test fun `corrupt lines are ignored, never trusted as entries`() {
        File(dir, FileActivationReplayGuard.FILE_NAME).writeText("garbage\n${"z".repeat(64)} 5\n")
        assertFalse(FileActivationReplayGuard(dir).isRedeemed(f.envelope()))
    }
}
