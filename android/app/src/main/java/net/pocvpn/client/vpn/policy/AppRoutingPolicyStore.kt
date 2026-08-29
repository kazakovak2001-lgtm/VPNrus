package net.pocvpn.client.vpn.policy

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.charset.StandardCharsets

/**
 * B8H - the one canonical, DEVICE-LOCAL store for AppRoutingPolicy. Kept
 * deliberately separate from ProvisionedProfileStore/PersistedProfile (see
 * that class's own docs): split-tunneling is a local device preference, not
 * a server-issued fact - it must never come from /v1/activate and must
 * never be written back to Oracle. Nothing here is secret (package names
 * only), but it is still device-specific the same way PersistedProfile is,
 * so it uses the exact same atomic tmp-file-then-rename, length-prefixed,
 * versioned-format pattern as that store and identity/IdentityFileStore.kt -
 * reused deliberately rather than introducing a database/DataStore/new
 * framework for a handful of strings.
 *
 * read() NEVER throws and NEVER returns a partially-parsed policy: any
 * missing file, corrupt/truncated data, or unrecognized mode ordinal falls
 * back to AppRoutingPolicy.Default (ALL_APPS) - fail-safe, and also exactly
 * this file's own "no saved policy -> ALL_APPS" / "existing users keep
 * current behavior" requirement. Individual malformed package-name entries
 * are dropped rather than corrupting the whole read (see
 * isValidAndroidPackageName) - defense in depth against a hand-edited file,
 * on top of the installed-app filter VpnController applies at connect time.
 */
interface AppRoutingPolicyStore {
    fun read(): AppRoutingPolicy
    fun write(policy: AppRoutingPolicy)

    companion object {
        /** Always reads AppRoutingPolicy.Default and ignores writes - the safe default for call sites with no real persistence wired (tests, additive constructor params). */
        fun allApps(): AppRoutingPolicyStore = object : AppRoutingPolicyStore {
            override fun read() = AppRoutingPolicy.Default
            override fun write(policy: AppRoutingPolicy) = Unit
        }
    }
}

class FileAppRoutingPolicyStore(
    private val directory: File,
    private val fileName: String = "app_routing_policy.bin",
) : AppRoutingPolicyStore {

    private val file: File get() = File(directory, fileName)

    private companion object {
        const val FORMAT_VERSION = 1
        const val MAX_STRING_LEN = 512
        const val MAX_PACKAGE_COUNT = 4096
    }

    override fun read(): AppRoutingPolicy {
        if (!file.exists()) return AppRoutingPolicy.Default
        return try {
            DataInputStream(file.inputStream().buffered()).use { input ->
                val version = input.readInt()
                if (version != FORMAT_VERSION) return AppRoutingPolicy.Default

                val modeOrdinal = input.readInt()
                val mode = AppRoutingMode.entries.getOrNull(modeOrdinal) ?: return AppRoutingPolicy.Default

                val count = input.readInt()
                require(count in 0..MAX_PACKAGE_COUNT) { "implausible package count: $count" }
                val packages = buildSet {
                    repeat(count) {
                        val name = readString(input)
                        if (isValidAndroidPackageName(name)) add(name)
                    }
                }
                AppRoutingPolicy(mode = mode, selectedPackageNames = packages)
            }
        } catch (e: java.io.IOException) {
            AppRoutingPolicy.Default
        } catch (e: IllegalArgumentException) {
            AppRoutingPolicy.Default
        }
    }

    override fun write(policy: AppRoutingPolicy) {
        directory.mkdirs()
        val validPackages = policy.selectedPackageNames.filter(::isValidAndroidPackageName)
        val tmp = File(directory, "$fileName.tmp")
        val bytes = ByteArrayOutputStream().also { buffer ->
            DataOutputStream(buffer).use { out ->
                out.writeInt(FORMAT_VERSION)
                out.writeInt(policy.mode.ordinal)
                out.writeInt(validPackages.size)
                validPackages.forEach { writeString(out, it) }
            }
        }.toByteArray()
        tmp.writeBytes(bytes)
        if (!tmp.renameTo(file)) {
            tmp.delete()
            throw java.io.IOException("failed to atomically replace app routing policy file")
        }
    }

    private fun writeString(out: DataOutputStream, s: String) {
        val bytes = s.toByteArray(StandardCharsets.UTF_8)
        out.writeInt(bytes.size)
        out.write(bytes)
    }

    private fun readString(input: DataInputStream): String {
        val len = input.readInt()
        require(len in 0..MAX_STRING_LEN) { "implausible length-prefixed field: $len" }
        val bytes = ByteArray(len)
        input.readFully(bytes)
        return String(bytes, StandardCharsets.UTF_8)
    }
}
