package net.pocvpn.client.activation

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

private const val VALID_TOKEN = "abcdefghij0123456789ABCDEFGHIJ"
private const val PROD_HOST = ActivationInputResolver.PRODUCTION_ACTIVATION_HOST

/** [ActivationPackageInput.Text] is a plain (non-data) class - assert on its `.text` field, never on wrapper identity. */
private fun assertReadyText(expectedText: String, result: ActivationInputResolution) {
    val ready = result as? ActivationInputResolution.Ready
        ?: throw AssertionError("expected Ready, got $result")
    val text = ready.input as? ActivationPackageInput.Text
        ?: throw AssertionError("expected ActivationPackageInput.Text, got ${ready.input}")
    assertEquals(expectedText, text.text)
}

class ActivationInputResolverFileTests {
    @Test
    fun `valid package text is passed through unchanged`() {
        val text = "nova-activation:1:abcXYZ_-123"
        val result = ActivationInputResolver.resolveFile(text)
        assertReadyText(text, result)
    }

    @Test
    fun `malformed content is still passed through unchanged - shape checking is the importer's job, not the file adapter's`() {
        val text = "not a real package at all"
        val result = ActivationInputResolver.resolveFile(text)
        assertReadyText(text, result)
    }

    @Test
    fun `empty file is rejected before reaching the importer`() {
        val result = ActivationInputResolver.resolveFile("")
        assertEquals(ActivationInputResolution.Rejected(ActivationInputRejectionReason.FILE_EMPTY), result)
    }

    @Test
    fun `blank (whitespace-only) file is rejected`() {
        val result = ActivationInputResolver.resolveFile("   \n\t  ")
        assertEquals(ActivationInputResolution.Rejected(ActivationInputRejectionReason.FILE_EMPTY), result)
    }

    @Test
    fun `UTF-8 multi-byte characters survive unchanged`() {
        val text = "nova-activation:1:abc_ünïcödé-ЮНИКОД-😀"
        val result = ActivationInputResolver.resolveFile(text)
        assertReadyText(text, result)
    }

    @Test
    fun `Base64URL payload characters are never altered - no character substitution, no re-encoding`() {
        val payload = "nova-activation:1:AbCdEf012789_-AbCdEf012789_-AbCdEf012789_-"
        val result = ActivationInputResolver.resolveFile(payload) as ActivationInputResolution.Ready
        val text = (result.input as ActivationPackageInput.Text).text
        assertEquals(payload, text)
    }
}

class ActivationInputResolverFileStreamTests {
    @Test
    fun `file limit is derived from the existing parser text limit`() {
        assertEquals(ActivationPackageParser.MAX_TEXT_LENGTH, ActivationInputResolver.MAX_FILE_BYTES)
    }

    @Test
    fun `file exactly at the limit is accepted`() {
        val text = "nova-activation:1:" + "A".repeat(ActivationInputResolver.MAX_FILE_BYTES - "nova-activation:1:".length)
        val result = ActivationInputResolver.resolveFileStream(java.io.ByteArrayInputStream(text.toByteArray(Charsets.UTF_8)))
        assertReadyText(text, result)
    }

    @Test
    fun `file one byte over the limit is rejected as too large`() {
        val bytes = ByteArray(ActivationInputResolver.MAX_FILE_BYTES + 1) { 'A'.code.toByte() }
        val result = ActivationInputResolver.resolveFileStream(java.io.ByteArrayInputStream(bytes))
        assertEquals(ActivationInputResolution.Rejected(ActivationInputRejectionReason.FILE_TOO_LARGE), result)
    }

    @Test
    fun `oversized stream is never read past limit plus one byte`() {
        var bytesServed = 0L
        val endless = object : java.io.InputStream() {
            override fun read(): Int { bytesServed++; return 'A'.code }
        }
        val result = ActivationInputResolver.resolveFileStream(endless)
        assertEquals(ActivationInputResolution.Rejected(ActivationInputRejectionReason.FILE_TOO_LARGE), result)
        assertEquals((ActivationInputResolver.MAX_FILE_BYTES + 1).toLong(), bytesServed)
    }

    @Test
    fun `empty stream is rejected as empty`() {
        val result = ActivationInputResolver.resolveFileStream(java.io.ByteArrayInputStream(ByteArray(0)))
        assertEquals(ActivationInputResolution.Rejected(ActivationInputRejectionReason.FILE_EMPTY), result)
    }

    @Test
    fun `stream result matches string-based file resolution`() {
        val text = "nova-activation:1:abcXYZ_-123\n"
        val fromStream = ActivationInputResolver.resolveFileStream(java.io.ByteArrayInputStream(text.toByteArray(Charsets.UTF_8)))
        assertReadyText(text, fromStream)
        assertReadyText(text, ActivationInputResolver.resolveFile(text))
    }
}

class ActivationInputResolverQrTests {
    @Test
    fun `valid HTTPS activation link is recognized and produces a handoff token`() {
        val url = "https://$PROD_HOST/a/$VALID_TOKEN"
        val result = ActivationInputResolver.resolveQr(url)
        assertEquals(ActivationInputResolution.NeedsHandoff(VALID_TOKEN), result)
    }

    @Test
    fun `valid offline package payload is recognized`() {
        val payload = "nova-activation:1:abcXYZ_-123"
        val result = ActivationInputResolver.resolveQr(payload)
        assertReadyText(payload, result)
    }

    @Test
    fun `malformed URL is rejected as unrecognized, never crashes`() {
        val result = ActivationInputResolver.resolveQr("https://")
        assertTrue(result is ActivationInputResolution.Rejected)
    }

    @Test
    fun `unsupported host is rejected`() {
        val result = ActivationInputResolver.resolveQr("https://evil.example.com/a/$VALID_TOKEN")
        assertEquals(ActivationInputResolution.Rejected(ActivationInputRejectionReason.APPLINK_WRONG_HOST), result)
    }

    @Test
    fun `unsupported path is rejected`() {
        val result = ActivationInputResolver.resolveQr("https://$PROD_HOST/other/$VALID_TOKEN")
        assertEquals(ActivationInputResolution.Rejected(ActivationInputRejectionReason.APPLINK_WRONG_PATH), result)
    }

    @Test
    fun `empty payload is rejected`() {
        val result = ActivationInputResolver.resolveQr("")
        assertEquals(ActivationInputResolution.Rejected(ActivationInputRejectionReason.QR_EMPTY), result)
    }

    @Test
    fun `unrecognized non-URL non-package payload is rejected`() {
        val result = ActivationInputResolver.resolveQr("just some random text")
        assertEquals(ActivationInputResolution.Rejected(ActivationInputRejectionReason.QR_UNRECOGNIZED), result)
    }
}

class ActivationInputResolverAppLinkTests {
    @Test
    fun `valid production host and path yields a handoff token, never a Ready result`() {
        val result = ActivationInputResolver.resolveAppLinkUrl("https://$PROD_HOST/a/$VALID_TOKEN")
        assertEquals(ActivationInputResolution.NeedsHandoff(VALID_TOKEN), result)
    }

    @Test
    fun `wrong host is rejected even with a correct path and scheme`() {
        val result = ActivationInputResolver.resolveAppLinkUrl("https://not-$PROD_HOST/a/$VALID_TOKEN")
        assertEquals(ActivationInputResolution.Rejected(ActivationInputRejectionReason.APPLINK_WRONG_HOST), result)
    }

    @Test
    fun `wrong scheme is rejected even with a correct host and path`() {
        val result = ActivationInputResolver.resolveAppLinkUrl("http://$PROD_HOST/a/$VALID_TOKEN")
        assertEquals(ActivationInputResolution.Rejected(ActivationInputRejectionReason.APPLINK_WRONG_SCHEME), result)
    }

    @Test
    fun `custom URI scheme is rejected - https only, never a custom scheme`() {
        val result = ActivationInputResolver.resolveAppLinkUrl("novavpn://activate/a/$VALID_TOKEN")
        assertEquals(ActivationInputResolution.Rejected(ActivationInputRejectionReason.APPLINK_WRONG_SCHEME), result)
    }

    @Test
    fun `wrong path is rejected even with a correct host and scheme`() {
        val result = ActivationInputResolver.resolveAppLinkUrl("https://$PROD_HOST/wrong/$VALID_TOKEN")
        assertEquals(ActivationInputResolution.Rejected(ActivationInputRejectionReason.APPLINK_WRONG_PATH), result)
    }

    @Test
    fun `malformed token (too short) is rejected`() {
        val result = ActivationInputResolver.resolveAppLinkUrl("https://$PROD_HOST/a/short")
        assertEquals(ActivationInputResolution.Rejected(ActivationInputRejectionReason.APPLINK_MALFORMED_TOKEN), result)
    }

    @Test
    fun `malformed token (illegal characters) is rejected`() {
        val result = ActivationInputResolver.resolveAppLinkUrl("https://$PROD_HOST/a/has spaces and stuff!!")
        assertTrue(result is ActivationInputResolution.Rejected)
    }

    @Test
    fun `bare root path with no token is rejected as wrong path`() {
        val result = ActivationInputResolver.resolveAppLinkUrl("https://$PROD_HOST/")
        assertEquals(ActivationInputResolution.Rejected(ActivationInputRejectionReason.APPLINK_WRONG_PATH), result)
    }

    @Test
    fun `unparseable URL never throws - fails closed as rejected`() {
        val result = ActivationInputResolver.resolveAppLinkUrl("not a url at all ://???")
        assertTrue(result is ActivationInputResolution.Rejected)
    }
}

/**
 * Security invariants this whole layer exists to preserve - see
 * docs/ACTIVATION_HANDOFF_CONTRACT.md. These tests exercise the EXISTING,
 * unmodified pipeline exactly as the pre-existing test suites already do;
 * they are here only to make explicit that adding [ActivationInputResolver]
 * changes NOTHING about that pipeline's own guarantees - it is a pure router
 * in front of the same [ActivationPackageImporter].
 */
class ActivationInputSecurityInvariantTests {
    @Test
    fun `a NeedsHandoff token is never itself treated as a Ready package - no implicit trust`() {
        val result = ActivationInputResolver.resolveAppLinkUrl("https://$PROD_HOST/a/$VALID_TOKEN")
        assertTrue("resolving an App Link must never itself produce a Ready(package)", result !is ActivationInputResolution.Ready)
    }

    @Test
    fun `resolver never mutates a valid text payload - byte-identical Ready result for Text input`() {
        val text = "nova-activation:1:AbCdEf012789_-"
        val result = ActivationInputResolver.resolve(ActivationInput.Text(text))
        assertReadyText(text, result)
    }
}
