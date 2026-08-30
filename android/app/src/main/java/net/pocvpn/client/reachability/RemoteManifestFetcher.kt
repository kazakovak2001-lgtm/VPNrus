package net.pocvpn.client.reachability

import java.io.IOException
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/** Outcome of one bounded attempt to download the current signed manifest. Never itself a trust decision - see [ManifestDistributionClient]. */
sealed class ManifestFetchResult {
    data class Fetched(val signed: SignedManifest) : ManifestFetchResult()
    data class Failed(val reason: String) : ManifestFetchResult()
}

/**
 * B12 - ONE bounded HTTPS GET against the control-plane's manifest
 * distribution endpoint. Deliberately dumb: fetching bytes over HTTPS is
 * NOT itself a trust decision - "client never trusts the transport merely
 * because it came from HTTPS" (task requirement) - the fetched bytes are
 * handed to [ManifestDistributionClient], which routes them through
 * [EndpointManifestRepository.offer] for the SAME signature/expiry/rollback
 * verification any other candidate manifest gets. This class has no
 * knowledge of trust anchors, LKG, or the bootstrap at all.
 */
fun interface RemoteManifestFetcher {
    suspend fun fetch(): ManifestFetchResult
}

/**
 * Real implementation: normal platform CA validation only (same discipline
 * as HttpsGatewayReachabilityProbe - never pinned/bypassed, never a
 * trust-all TrustManager), no credentials, no request body. Bounded by
 * [timeoutMs] for the WHOLE fetch (connect+read+body), same
 * withTimeoutOrNull pattern as HttpsGatewayReachabilityProbe so a hung
 * control plane can never block a caller indefinitely.
 */
class HttpsRemoteManifestFetcher(
    private val urlString: String,
    private val timeoutMs: Long = DEFAULT_TIMEOUT_MS,
) : RemoteManifestFetcher {

    override suspend fun fetch(): ManifestFetchResult =
        withTimeoutOrNull(timeoutMs) { performFetch() } ?: ManifestFetchResult.Failed("timed out")

    private suspend fun performFetch(): ManifestFetchResult = withContext(Dispatchers.IO) {
        try {
            val connection = URL(urlString).openConnection() as HttpsURLConnection
            connection.requestMethod = "GET"
            connection.connectTimeout = timeoutMs.toInt()
            connection.readTimeout = timeoutMs.toInt()
            connection.instanceFollowRedirects = false
            try {
                val code = connection.responseCode
                if (code != 200) return@withContext ManifestFetchResult.Failed("unexpected HTTP status $code")

                val contentLength = connection.contentLengthLong
                if (contentLength > MAX_RESPONSE_BYTES) {
                    return@withContext ManifestFetchResult.Failed("declared response size exceeds bound")
                }

                val bytes = connection.inputStream.use { readBounded(it, MAX_RESPONSE_BYTES) }
                    ?: return@withContext ManifestFetchResult.Failed("response body exceeds bound")

                val signed = SignedManifestCodec.decode(bytes)
                ManifestFetchResult.Fetched(signed)
            } finally {
                connection.disconnect()
            }
        } catch (e: SSLException) {
            ManifestFetchResult.Failed("TLS error: ${e.javaClass.simpleName}")
        } catch (e: IOException) {
            ManifestFetchResult.Failed("network error: ${e.javaClass.simpleName}")
        } catch (e: IllegalArgumentException) {
            ManifestFetchResult.Failed("malformed manifest container: ${e.message}")
        }
    }

    /** Reads at most [maxBytes]+1 bytes to detect an over-bound stream without buffering an unbounded amount first; returns null if the bound was exceeded. */
    private fun readBounded(input: java.io.InputStream, maxBytes: Int): ByteArray? {
        val buffer = java.io.ByteArrayOutputStream()
        val chunk = ByteArray(8192)
        var total = 0
        while (true) {
            val read = input.read(chunk)
            if (read == -1) break
            total += read
            if (total > maxBytes) return null
            buffer.write(chunk, 0, read)
        }
        return buffer.toByteArray()
    }

    companion object {
        const val DEFAULT_TIMEOUT_MS = 8_000L

        /** Generously larger than any real manifest this fabric produces (MAX_ENDPOINTS/MAX_TRANSPORTS caps in ManifestCanonicalizer keep real payloads far smaller) - bounds a malicious/misconfigured control plane's response, nothing more. */
        const val MAX_RESPONSE_BYTES = 1_000_000
    }
}

/**
 * B12 - ties [RemoteManifestFetcher] to [EndpointManifestRepository.offer]:
 * the ONE place a downloaded manifest is actually offered for adoption.
 * A fetch failure (network, TLS, malformed bytes, non-200) is reported as a
 * [ManifestUpdateResult.Rejected] WITHOUT ever calling [EndpointManifestRepository.offer] -
 * repository state (LKG) is untouched either way, matching "unavailable
 * control plane must fall back to valid LKG/bootstrap" (trustedState()
 * already does this automatically - refresh() never needs to know about
 * that fallback itself).
 */
class ManifestDistributionClient(
    private val fetcher: RemoteManifestFetcher,
    private val repository: EndpointManifestRepository,
) {
    suspend fun refresh(): ManifestUpdateResult = when (val result = fetcher.fetch()) {
        is ManifestFetchResult.Fetched -> repository.offer(result.signed)
        is ManifestFetchResult.Failed -> ManifestUpdateResult.Rejected(result.reason)
    }
}
