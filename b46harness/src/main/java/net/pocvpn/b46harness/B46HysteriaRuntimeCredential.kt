package net.pocvpn.b46harness

import java.io.File
import java.util.Properties

/** `<filesDir>/b46-secret/credential.properties` - see [B46HysteriaRuntimeCredential]'s own doc. */
internal const val B46_RUNTIME_CREDENTIAL_DIR = "b46-secret"
internal const val B46_RUNTIME_CREDENTIAL_FILENAME = "credential.properties"

/**
 * B46-2P - PRE-MERGE HARDENING CORRECTION (2026-09-20): the temporary
 * Hysteria2 test server's `auth` password used to be compiled into
 * `BuildConfig.B46_HYSTERIA_AUTH` (via `b46-hysteria-dataplane.properties`
 * at build time) - a real credential-delivery anti-pattern, since that
 * bakes the secret into the built debug APK regardless of whether the
 * disposable temporary server it authenticates against still exists. This
 * object replaces that: the secret is read at RUNTIME from a single
 * app-private file the operator provisions AFTER install (never compiled
 * in, never in Git, never in a build artifact).
 *
 * Provisioning path (see docs/B46_2P_HYSTERIA2_ANDROID_PHYSICAL_VALIDATION.md):
 *
 * 1. `adb push <local-file> /data/local/tmp/b46-credential.properties`
 * 2. `adb shell run-as net.pocvpn.b46harness sh -c 'mkdir -p files/b46-secret && cat /data/local/tmp/b46-credential.properties > files/b46-secret/credential.properties && chmod 600 files/b46-secret/credential.properties'`
 * 3. `adb shell rm /data/local/tmp/b46-credential.properties` (delete the
 *    world-readable staging copy immediately - `/data/local/tmp` has no
 *    per-app protection)
 * 4. Delete the plaintext copy on the PC once staged.
 *
 * File format: Java `Properties` text, at minimum `auth=<password>`,
 * optionally `obfsSalamander=<password>` - the same two secret fields
 * [B46HysteriaChildConfig] carries. Never printed, never logged - only the
 * parsed values are held in memory, and only long enough to build the
 * child's own `--config-file` payload.
 *
 * [delete] is called on every stop path (normal AND failure) by
 * [B46HysteriaVpnService], mirroring the same "provisioned once per
 * session, deleted on cleanup" discipline the per-session child
 * `--config-file`/protect-socket already follow (`B46HysteriaRuntime.stop()`) -
 * this file is never left at rest longer than one test session.
 */
internal object B46HysteriaRuntimeCredential {

    sealed interface Result {
        data class Valid(val auth: String, val obfsSalamander: String) : Result
        data class Invalid(val reason: String) : Result
    }

    /**
     * PRE-MERGE HARDENING CORRECTION (2026-09-20, manual review, round 3):
     * the outcome of [consumeDelete] - the deletion that follows a
     * SUCCESSFUL parse. Distinct from the plain best-effort [delete] below:
     * this one is VERIFIED (checks the file is actually gone afterward, not
     * merely that `File.delete()` claimed success) and typed, because the
     * caller (`B46HysteriaDataPlaneConfig.resolve`) must fail closed rather
     * than silently continuing to TUN/bridge/child startup if the secret
     * material is still sitting on disk after it was supposed to have been
     * consumed.
     */
    sealed interface ConsumeResult {
        object Ok : ConsumeResult
        data class Failed(val reason: String) : ConsumeResult
    }

    /**
     * Narrow, injectable delete seam - real Android/JVM file deletion can't
     * be reliably forced to fail on every host filesystem (Windows dev
     * machines in particular don't reject `File.delete()` the same way a
     * real device's filesystem might), so tests substitute a fake deleter
     * that reports success without actually removing the file, to
     * physically exercise the "deletion claimed success but the file is
     * still there" fail-closed path - never a Robolectric/real-filesystem
     * hack.
     */
    internal fun interface Deleter {
        fun delete(file: File): Boolean
    }

    private val realDeleter = Deleter { it.delete() }

    fun credentialFile(filesDir: File): File = File(File(filesDir, B46_RUNTIME_CREDENTIAL_DIR), B46_RUNTIME_CREDENTIAL_FILENAME)

    /** Fails closed (typed [Result.Invalid]) on a missing or malformed file - never falls back to any hardcoded/fake credential. Never deletes the file itself - see [consumeDelete] for that. */
    fun resolve(filesDir: File): Result {
        val file = credentialFile(filesDir)
        if (!file.exists() || !file.isFile) {
            return Result.Invalid(
                "runtime credential file missing at ${file.absolutePath} - provision it via " +
                    "adb push + run-as before starting (see docs/B46_2P_HYSTERIA2_ANDROID_PHYSICAL_VALIDATION.md)",
            )
        }

        val props = Properties()
        try {
            file.inputStream().use { props.load(it) }
        } catch (t: Throwable) {
            return Result.Invalid("runtime credential file at ${file.absolutePath} is malformed: ${t.javaClass.simpleName}")
        }

        val auth = props.getProperty("auth", "")
        if (auth.isBlank()) {
            return Result.Invalid("runtime credential file at ${file.absolutePath} is malformed or missing a non-blank 'auth' value")
        }
        val obfsSalamander = props.getProperty("obfsSalamander", "")
        return Result.Valid(auth = auth, obfsSalamander = obfsSalamander)
    }

    /**
     * Called ONLY after [resolve] returned [Result.Valid] and its secret
     * values have already been copied into an in-memory config - attempts
     * deletion, then VERIFIES the file no longer exists on disk before
     * reporting [ConsumeResult.Ok]. If the file is still present afterward
     * (deletion silently failed, or something re-created it), returns
     * [ConsumeResult.Failed] with a typed, non-secret reason (never the
     * file's contents, only its path) - the caller must treat this as
     * fail-closed and not proceed to TUN/bridge/child startup.
     */
    fun consumeDelete(filesDir: File, deleter: Deleter = realDeleter): ConsumeResult {
        val file = credentialFile(filesDir)
        runCatching { deleter.delete(file) }
        return if (!file.exists()) {
            ConsumeResult.Ok
        } else {
            ConsumeResult.Failed(
                "runtime credential file still exists at ${file.absolutePath} after a verified-delete attempt - " +
                    "refusing to continue with the consumed secret still at rest on disk",
            )
        }
    }

    /**
     * Best-effort, idempotent cleanup for the OTHER call sites (a
     * missing/malformed credential's own failure path, and the service's
     * normal/failure stop paths, where by then either nothing was ever
     * provisioned or [consumeDelete] has already succeeded) - deliberately
     * NOT verified, since those callers don't need to fail the whole
     * session over a redundant delete of a file that may already be gone.
     * Safe to call even when nothing was ever provisioned. Never throws.
     */
    fun delete(filesDir: File) {
        runCatching { credentialFile(filesDir).delete() }
    }
}
