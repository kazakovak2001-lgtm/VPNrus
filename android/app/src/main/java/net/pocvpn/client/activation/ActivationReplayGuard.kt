package net.pocvpn.client.activation

import java.io.File
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest

/**
 * B56-5 - LOCAL replay/import dedupe for [ActivationEnvelope]s
 * (architecture section 7/14: the envelope nonce is "LOCAL replay/import
 * dedupe only, not a security boundary").
 *
 * What actually bounds replay is SERVER-side and unchanged: the activation
 * store's per-credential `max_devices`, race-free device binding
 * (`decide_and_bind`), expiry and revocation. A copied package redeemed on
 * a second device hits that device limit; this guard cannot see other
 * devices and does not pretend to. What this guard adds on THIS device: an
 * envelope that has already been successfully redeemed here is refused
 * locally ("already used") instead of silently re-running activation, and
 * that refusal survives process restarts (file-backed).
 *
 * Stored per entry: a SHA-256 over (issuerKeyId, activationId, nonce) and
 * the envelope's own expiry - never the credential, never the nonce itself.
 * Entries are pruned once the envelope has expired (an expired envelope is
 * already rejected by the verifier, so its entry is no longer needed).
 */
interface ActivationReplayGuard {
    fun isRedeemed(envelope: ActivationEnvelope): Boolean
    fun markRedeemed(envelope: ActivationEnvelope, nowEpochMillis: Long)
}

internal fun activationReplayKey(envelope: ActivationEnvelope): String {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(envelope.issuerKeyId.value.toByteArray(Charsets.UTF_8))
    digest.update(0)
    digest.update(envelope.activationId.value.toByteArray(Charsets.UTF_8))
    digest.update(0)
    digest.update(envelope.nonce)
    return digest.digest().joinToString("") { "%02x".format(it) }
}

class InMemoryActivationReplayGuard : ActivationReplayGuard {
    private val redeemed = mutableMapOf<String, Long>()

    @Synchronized
    override fun isRedeemed(envelope: ActivationEnvelope): Boolean = redeemed.containsKey(activationReplayKey(envelope))

    @Synchronized
    override fun markRedeemed(envelope: ActivationEnvelope, nowEpochMillis: Long) {
        redeemed.entries.removeAll { it.value <= nowEpochMillis }
        redeemed[activationReplayKey(envelope)] = envelope.expiresAtEpochMillis
    }
}

/**
 * File-backed guard (one small text file, `<64-hex key> <expiresAtMillis>`
 * per line, atomic temp-file + rename replace). Malformed lines are
 * ignored and an unreadable file reads as empty: losing this LOCAL dedupe
 * state only removes a convenience refusal - the server-side binding and
 * device limit (the real replay bound) are unaffected.
 */
class FileActivationReplayGuard(private val directory: File) : ActivationReplayGuard {
    private val file get() = File(directory, FILE_NAME)

    @Synchronized
    override fun isRedeemed(envelope: ActivationEnvelope): Boolean = read().containsKey(activationReplayKey(envelope))

    @Synchronized
    override fun markRedeemed(envelope: ActivationEnvelope, nowEpochMillis: Long) {
        val entries = read().filterValues { it > nowEpochMillis }.toMutableMap()
        entries[activationReplayKey(envelope)] = envelope.expiresAtEpochMillis
        directory.mkdirs()
        val tmp = File(directory, "$FILE_NAME.tmp")
        tmp.writeText(entries.entries.joinToString("") { "${it.key} ${it.value}\n" })
        try {
            try {
                Files.move(
                    tmp.toPath(),
                    file.toPath(),
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE,
                )
            } catch (e: AtomicMoveNotSupportedException) {
                Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING)
            }
        } catch (e: java.io.IOException) {
            tmp.delete()
            throw java.io.IOException("failed to persist activation replay guard", e)
        }
    }

    private fun read(): Map<String, Long> {
        val f = file
        if (!f.isFile) return emptyMap()
        return try {
            f.readLines().mapNotNull { line ->
                val parts = line.split(' ')
                val expires = parts.getOrNull(1)?.toLongOrNull()
                if (parts.size == 2 && KEY_FORMAT.matches(parts[0]) && expires != null) parts[0] to expires else null
            }.toMap()
        } catch (e: java.io.IOException) {
            emptyMap()
        }
    }

    companion object {
        const val FILE_NAME = "redeemed-activation-envelopes"
        private val KEY_FORMAT = Regex("^[0-9a-f]{64}$")
    }
}
