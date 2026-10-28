package net.pocvpn.client.diagnostics.fieldtest

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Source-level guarantees about the stage/DNS probes (reviewed conditions): no trust-all, no coupling to the transports, one entry point. */
class ProbeIsolationTest {
    private val main = File("src/main/java")
    private val probeSources = listOf("StageProbe.kt", "DnsDirectProbe.kt", "ProbeTargets.kt")
        .map { File(main, "net/pocvpn/client/diagnostics/fieldtest/$it") }

    private fun kotlinAndJava(dir: File) = dir.walkTo { it.extension == "kt" || it.extension == "java" }

    private fun File.walkTo(filter: (File) -> Boolean): List<File> = walkTopDown().filter { it.isFile && filter(it) }.toList()

    /** Source without // line comments and block comments, so prose that names a forbidden thing does not count. */
    private fun code(f: File): String = f.readText()
        .replace(Regex("""/\*[\s\S]*?\*/"""), "")
        .lines().joinToString("\n") { it.substringBefore("//") }

    @Test fun the_probe_sources_exist() {
        probeSources.forEach { assertTrue("missing ${it.path}", it.isFile) }
    }

    @Test fun the_probes_use_no_tls_library_trust_manager_or_hostname_verifier() {
        val forbidden = listOf("TrustManager", "HostnameVerifier", "SSLContext", "SSLSocketFactory", "SSLSocket", "javax.net.ssl", "setHostnameVerifier", "allowInsecure")
        for (f in probeSources) {
            val c = code(f)
            forbidden.forEach { assertTrue("${f.name} mentions $it", it !in c) }
        }
    }

    @Test fun no_production_source_defines_a_trust_all_manager_or_a_permissive_verifier() {
        val offenders = kotlinAndJava(main).filter { f ->
            val c = code(f)
            "X509TrustManager" in c || Regex("""HostnameVerifier\s*\{""").containsMatchIn(c) || "ALLOW_ALL_HOSTNAME_VERIFIER" in c || "trustAllCerts" in c
        }.map { it.path }
        assertTrue("trust-all / permissive verifier in: $offenders", offenders.isEmpty())
    }

    @Test fun the_probes_do_not_depend_on_the_transports() {
        val forbiddenImports = listOf("net.pocvpn.client.vpn.", "net.pocvpn.client.smartconnect.")
        for (f in probeSources) {
            val imports = f.readLines().filter { it.startsWith("import ") }
            forbiddenImports.forEach { p -> assertTrue("${f.name} imports $p", imports.none { p in it }) }
        }
    }

    @Test fun the_probes_never_touch_vpnservice_protect_or_bind_a_process_network() {
        for (f in probeSources) {
            val c = code(f)
            assertTrue(f.name, "protect(" !in c && "bindProcessToNetwork" !in c && "VpnService" !in c)
        }
    }

    @Test fun the_field_test_runner_is_constructed_in_exactly_one_place() {
        val sites = kotlinAndJava(main).filter { f ->
            f.name != "FieldTestRunner.kt" && Regex("""\bFieldTestRunner\(""").containsMatchIn(code(f))
        }.map { it.name }
        assertEquals(listOf("MainViewModel.kt"), sites)
    }

    @Test fun nothing_outside_the_runner_calls_the_new_probes() {
        val callers = kotlinAndJava(main).filter { f ->
            f.name !in setOf("FieldTestRunner.kt", "StageProbe.kt", "DnsDirectProbe.kt") &&
                Regex("""\b(StageProbe|DnsDirectProbe)\(""").containsMatchIn(code(f))
        }.map { it.name }
        assertTrue("unexpected callers: $callers", callers.isEmpty())
    }

    @Test fun the_consent_text_mentions_the_test_packets() {
        val strings = File("src/main/res/values/strings.xml").readText()
        val line = strings.lines().first { "settings_diagnostics_explanation" in it }
        assertTrue(line, "TLS and DNS packets" in line && "own servers" in line)
    }
}
