package net.pocvpn.b46harness

import java.io.File
import kotlin.io.path.createTempDirectory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B46-2P - PRE-MERGE HARDENING CORRECTION regression tests. Proves the
 * `auth` secret is never compiled into `BuildConfig`, and that the runtime
 * app-private credential file fails closed on every bad input and is
 * genuinely deleted on cleanup. See `B46HysteriaRuntimeCredential.kt` and
 * `docs/B46_2P_HYSTERIA2_ANDROID_PHYSICAL_VALIDATION.md`'s own correction
 * note for the full before/after.
 */
class B46HysteriaRuntimeCredentialTest {

    private fun tempFilesDir(): File = createTempDirectory("b46-cred-test").toFile().apply { deleteOnExit() }

    private fun writeCredential(filesDir: File, contents: String): File {
        val file = B46HysteriaRuntimeCredential.credentialFile(filesDir)
        file.parentFile?.mkdirs()
        file.writeText(contents)
        return file
    }

    // 1. no B46_HYSTERIA_AUTH (or any other secret-shaped) BuildConfig field exists
    @Test
    fun `BuildConfig has no auth or obfuscation-secret field - the secret must never be compiled in`() {
        val fieldNames = BuildConfig::class.java.declaredFields.map { it.name }
        assertFalse(
            "BuildConfig must never carry a secret field: $fieldNames",
            fieldNames.any { it.contains("AUTH", ignoreCase = true) || it.contains("OBFS", ignoreCase = true) || it.contains("SECRET", ignoreCase = true) },
        )
        // Public/non-secret fields are still expected to exist.
        assertTrue(fieldNames.contains("B46_HYSTERIA_SERVER_HOST"))
        assertTrue(fieldNames.contains("B46_HYSTERIA_SERVER_PORT"))
        assertTrue(fieldNames.contains("B46_HYSTERIA_SNI"))
        assertTrue(fieldNames.contains("B46_HYSTERIA_EXPECTED_EXIT_IP"))
    }

    // 2. missing runtime credential fails closed
    @Test
    fun `missing runtime credential file fails closed with a typed error`() {
        val filesDir = tempFilesDir() // nothing provisioned

        val result = B46HysteriaRuntimeCredential.resolve(filesDir)

        assertTrue(result is B46HysteriaRuntimeCredential.Result.Invalid)
        assertTrue((result as B46HysteriaRuntimeCredential.Result.Invalid).reason.contains("missing"))
    }

    // 3. malformed config fails closed (present but unusable, two shapes)
    @Test
    fun `credential file present but missing 'auth' key fails closed`() {
        val filesDir = tempFilesDir()
        writeCredential(filesDir, "obfsSalamander=whatever\n")

        val result = B46HysteriaRuntimeCredential.resolve(filesDir)

        assertTrue(result is B46HysteriaRuntimeCredential.Result.Invalid)
    }

    @Test
    fun `credential file with blank auth value fails closed`() {
        val filesDir = tempFilesDir()
        writeCredential(filesDir, "auth=\n")

        val result = B46HysteriaRuntimeCredential.resolve(filesDir)

        assertTrue(result is B46HysteriaRuntimeCredential.Result.Invalid)
    }

    @Test
    fun `a directory where the credential file should be is rejected, not treated as a regular file`() {
        val filesDir = tempFilesDir()
        B46HysteriaRuntimeCredential.credentialFile(filesDir).apply {
            parentFile?.mkdirs()
            mkdirs()
        }

        val result = B46HysteriaRuntimeCredential.resolve(filesDir)

        assertTrue(result is B46HysteriaRuntimeCredential.Result.Invalid)
    }

    @Test
    fun `valid credential file with only auth resolves with empty obfsSalamander`() {
        val filesDir = tempFilesDir()
        writeCredential(filesDir, "auth=real-secret-value\n")

        val result = B46HysteriaRuntimeCredential.resolve(filesDir)

        assertTrue(result is B46HysteriaRuntimeCredential.Result.Valid)
        val valid = result as B46HysteriaRuntimeCredential.Result.Valid
        assertEquals("real-secret-value", valid.auth)
        assertEquals("", valid.obfsSalamander)
    }

    @Test
    fun `valid credential file with auth and obfsSalamander resolves both`() {
        val filesDir = tempFilesDir()
        writeCredential(filesDir, "auth=real-secret-value\nobfsSalamander=obfs-secret\n")

        val result = B46HysteriaRuntimeCredential.resolve(filesDir)

        assertTrue(result is B46HysteriaRuntimeCredential.Result.Valid)
        val valid = result as B46HysteriaRuntimeCredential.Result.Valid
        assertEquals("real-secret-value", valid.auth)
        assertEquals("obfs-secret", valid.obfsSalamander)
    }

    // 5. cleanup deletes the runtime secret file
    @Test
    fun `delete removes the runtime credential file`() {
        val filesDir = tempFilesDir()
        val file = writeCredential(filesDir, "auth=real-secret-value\n")
        assertTrue(file.exists())

        B46HysteriaRuntimeCredential.delete(filesDir)

        assertFalse(file.exists())
    }

    @Test
    fun `delete is idempotent and never throws when nothing was provisioned`() {
        val filesDir = tempFilesDir()

        B46HysteriaRuntimeCredential.delete(filesDir) // must not throw
        B46HysteriaRuntimeCredential.delete(filesDir) // second call, still must not throw

        assertFalse(B46HysteriaRuntimeCredential.credentialFile(filesDir).exists())
    }

    // 8. successful credential consume requires ACTUAL (verified) deletion
    @Test
    fun `consumeDelete with the real deleter reports Ok only when the file is actually gone`() {
        val filesDir = tempFilesDir()
        val file = writeCredential(filesDir, "auth=real-secret-value\n")
        assertTrue(file.exists())

        val result = B46HysteriaRuntimeCredential.consumeDelete(filesDir)

        assertTrue(result is B46HysteriaRuntimeCredential.ConsumeResult.Ok)
        assertFalse(file.exists())
    }

    @Test
    fun `consumeDelete on an already-absent file reports Ok - nothing left to verify`() {
        val filesDir = tempFilesDir() // nothing provisioned

        val result = B46HysteriaRuntimeCredential.consumeDelete(filesDir)

        assertTrue(result is B46HysteriaRuntimeCredential.ConsumeResult.Ok)
    }

    // 9. simulated delete failure fails closed
    @Test
    fun `consumeDelete with a deleter that does not actually remove the file fails closed`() {
        val filesDir = tempFilesDir()
        val file = writeCredential(filesDir, "auth=real-secret-value\n")
        // A fake deleter that CLAIMS success (returns true) without
        // actually touching the filesystem - simulates the exact failure
        // mode a real filesystem could produce (delete() returns true but
        // the file is still there for some other reason) without relying
        // on host-filesystem permission quirks (unreliable across OSes,
        // as this project already found with chmod - see
        // B46HysteriaChildConfig.kt's own history).
        val noOpDeleter = B46HysteriaRuntimeCredential.Deleter { true }

        val result = B46HysteriaRuntimeCredential.consumeDelete(filesDir, deleter = noOpDeleter)

        assertTrue(result is B46HysteriaRuntimeCredential.ConsumeResult.Failed)
        assertTrue(file.exists()) // still there - the fail-closed report is honest
        // The reason must never contain the secret value.
        assertFalse((result as B46HysteriaRuntimeCredential.ConsumeResult.Failed).reason.contains("real-secret-value"))
    }

    @Test
    fun `consumeDelete with a deleter that throws still fails closed rather than crashing`() {
        val filesDir = tempFilesDir()
        writeCredential(filesDir, "auth=real-secret-value\n")
        val throwingDeleter = B46HysteriaRuntimeCredential.Deleter { throw java.io.IOException("simulated I/O failure") }

        val result = B46HysteriaRuntimeCredential.consumeDelete(filesDir, deleter = throwingDeleter)

        assertTrue(result is B46HysteriaRuntimeCredential.ConsumeResult.Failed)
    }
}
