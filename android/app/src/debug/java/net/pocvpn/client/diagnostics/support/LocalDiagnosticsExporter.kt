package net.pocvpn.client.diagnostics.support

import java.io.File

/**
 * SG-002 evidence-closure - debug-build-only local export of the EXACT
 * JSON [net.pocvpn.client.MainViewModel.exportSupportBundleJson] already
 * produces for the real "Export diagnostics" share-sheet button
 * (AppRoot.kt) - never re-serializes, mutates, sanitizes, or re-derives a
 * single field; writes the given [json] string VERBATIM to app-private
 * storage. Lives in the `debug` Gradle source set - the SAME scoping
 * discipline as [net.pocvpn.client.debug.XrayDiagnosticsActivity] - so
 * this real, functioning implementation is genuinely absent from a
 * release APK's compiled classes/dex.
 *
 * The `release` build type's own source set provides a same-named, same-
 * signature no-op stub (see that file's own docs) so main-source UI code
 * (AppRoot.kt) can call this ONE symbol regardless of build type, without
 * ever holding a compile-time reference that would only resolve for one
 * variant - AGP's per-build-type source-set merging picks exactly one of
 * these two files per build, never both.
 *
 * Reachable ONLY from the debug-only Diagnostics dialog's "Save
 * diagnostics locally" button (AppRoot.kt, inside the `isDebugBuild &&
 * showDiagnostics` gate, itself `BuildConfig.DEBUG`-driven per build type
 * - see MainActivity.kt) - the identical runtime-gating discipline this
 * codebase already uses for every other debug-only capability in that
 * same dialog. Never invokes ACTION_SEND or any share sheet, never
 * touches the network, never writes outside app-private storage, never
 * makes anything world-readable.
 */
object LocalDiagnosticsExporter {
    const val RELATIVE_DIR = "support-diagnostics"
    const val FILE_NAME = "latest.json"

    /**
     * Writes [json] verbatim to <[filesDir]>/[RELATIVE_DIR]/[FILE_NAME]
     * (app-private storage - the file inherits the app's own default,
     * non-world-readable permissions), overwriting any prior "latest"
     * export, and returns the written [File].
     */
    fun exportLatest(filesDir: File, json: String): File? {
        val dir = File(filesDir, RELATIVE_DIR)
        dir.mkdirs()
        val file = File(dir, FILE_NAME)
        file.writeText(json)
        return file
    }
}
