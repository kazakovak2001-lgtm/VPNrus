package net.pocvpn.client.vpn.shadowsocks

import java.io.File
import org.json.JSONObject

/**
 * B45B-3 (Phase 7) - the narrowest safe path from a decrypted credential to
 * sslocal's runtime input: a process-private JSON config file, written only
 * immediately before spawn, never the `-k <secret>` CLI flag B45A's own
 * argv-only design used (proven unacceptable for production - see this
 * class's own package docs / the B45B-3 task's Phase 7).
 *
 * Upstream behavior this design relies on (verified directly against the
 * pinned shadowsocks-rust v1.25.0 source, `src/service/local.rs::create()`
 * and `ServerReloader`, not guessed): sslocal reads the full JSON config
 * exactly ONCE at startup, via `Config::load_from_file` inside `create()`.
 * Its only reload mechanism is `ServerReloader::launch_reload_server_task`,
 * which on Unix only re-reads the file in response to an explicit `SIGUSR1`
 * signal (`sigusr1.recv().await`) - this production runtime never sends
 * that signal, so the file is genuinely never reopened after startup. It is
 * therefore safe to delete the plaintext file as soon as startup is
 * confirmed (see [ShadowsocksRuntime]'s own delete-after-handoff timing),
 * not merely "at stop".
 *
 * The JSON schema (top-level `server`/`server_port`/`method`/`password`) is
 * the plain single-server schema documented in the same pinned source's
 * module doc comment (`crates/shadowsocks-service/src/config.rs`), the exact
 * counterpart of the `-s`/`-m`/`-k` CLI flags B45A already proved work for
 * this same AEAD-2022 method. `password` holds the base64 raw key, matching
 * `-k`'s own accepted format for AEAD-2022 methods (never a KDF password).
 */
internal object ShadowsocksRuntimeConfigWriter {

    /**
     * Writes the config file at `<directory>/<fileName>`, app-private
     * storage only (caller passes a directory already scoped that way - see
     * [ShadowsocksRuntime]). Never logs [host]/[method]/[keyBase64].
     */
    fun write(directory: File, fileName: String, host: String, port: Int, method: String, keyBase64: String): File {
        directory.mkdirs()
        val json = JSONObject().apply {
            put("server", host)
            put("server_port", port)
            put("method", method)
            put("password", keyBase64)
        }
        val file = File(directory, fileName)
        file.writeText(json.toString())
        return file
    }

    /** Best-effort delete - never throws, since this always runs on a cleanup path. */
    fun delete(file: File) {
        runCatching { file.delete() }
    }
}
