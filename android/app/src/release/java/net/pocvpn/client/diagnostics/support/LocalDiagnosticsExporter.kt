package net.pocvpn.client.diagnostics.support

import java.io.File

/**
 * SG-002 evidence-closure - the `release` build type's own counterpart to
 * the debug-only local diagnostics exporter (see the `debug` source
 * set's own [LocalDiagnosticsExporter] - same package, same class name -
 * for the real implementation's own docs). AGP's per-build-type source-
 * set merging compiles exactly ONE of these two files into any given
 * build, never both, so a release build's compiled classes/dex contain
 * ONLY this stub's body: no `File.mkdirs`/`writeText` call, no directory
 * name, nothing - a release build genuinely cannot produce a local
 * support-diagnostics export through this symbol; it always does nothing
 * and returns `null`.
 */
object LocalDiagnosticsExporter {
    fun exportLatest(filesDir: File, json: String): File? = null
}
