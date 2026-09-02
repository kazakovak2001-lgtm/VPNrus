package net.pocvpn.client.relay

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.charset.StandardCharsets
import net.pocvpn.client.identity.AesGcmKeyEncryptor
import net.pocvpn.client.identity.EncryptedPayload
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.identity.XrayTlsProfile
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.transport.TransportKind
import org.json.JSONObject

/**
 * B25 (task E) - the real, typed, PERSISTED ingress client profile: what
 * this device's control-plane activation against ONE ingress endpoint
 * issued it. Deliberately reuses the EXISTING [XrayProfile]/[XrayTlsProfile]
 * shapes for the client-facing credential (never a third, parallel
 * REALITY/TLS field set) - task requirement 4/7's "reuse the existing
 * Xray/client credential handling" - but wraps them with the facts unique
 * to an ingress profile: which endpoint/binding/transport this credential
 * is scoped to (so [RelayIngressResolverImpl] can refuse a profile that
 * does not match the pinned attempt - task requirement F.3), a version/
 * validity window, and the real end-to-end proof coordinates the
 * control-plane issued alongside the credential (task requirement C - never
 * fabricated locally).
 *
 * Exactly one of [realityProfile]/[tlsProfile] is non-null, matching
 * [transport] - enforced by [validate], never merely assumed.
 *
 * Deliberately NEVER carries: the ingress's own REALITY private key, the
 * upstream ingress->exit relay UUID, or any other device's credential (task
 * requirement E's own exclusion list) - none of those fields exist on this
 * type at all, so a future accidental serialization of it cannot leak them.
 */
data class IngressClientProfile(
    val ingressEndpointId: EndpointId,
    val ingressBinding: EndpointTransportBinding,
    val transport: TransportKind,
    val realityProfile: XrayProfile? = null,
    val tlsProfile: XrayTlsProfile? = null,
    val profileVersion: Int,
    val issuedAtEpochMillis: Long,
    val expiresAtEpochMillis: Long? = null,
    /**
     * Task requirement C - the real end-to-end data-plane proof endpoint
     * the control-plane issued for THIS device/session, reachable only via
     * client -> ingress -> exit (never a public, generally-reachable URL -
     * see [RelayEndToEndProbe]'s own docs). null means this profile carries
     * no real proof channel yet (a device provisioned before this endpoint
     * existed, or a control-plane build that hasn't wired it) - resolved to
     * a typed [RelayFailureCategory.EXECUTION_NOT_IMPLEMENTED] by
     * [NotConfiguredRelayEndToEndProbe], never a fabricated success.
     */
    val endToEndProbeUrl: String? = null,
    /** Opaque per-device bearer credential for [endToEndProbeUrl] - never logged, never the device's Xray uuid reused for a second purpose. */
    val endToEndProbeToken: String? = null,
) {
    /** Never expose credential material via an accidental log/toString call. */
    override fun toString(): String = "IngressClientProfile(ingressEndpointId=$ingressEndpointId, transport=$transport, " +
        "profileVersion=$profileVersion, issuedAtEpochMillis=$issuedAtEpochMillis, expiresAtEpochMillis=$expiresAtEpochMillis, " +
        "realityProfile=${if (realityProfile != null) "<redacted>" else "null"}, tlsProfile=${if (tlsProfile != null) "<redacted>" else "null"}, " +
        "endToEndProbeUrl=$endToEndProbeUrl, endToEndProbeToken=${if (endToEndProbeToken != null) "<redacted>" else "null"})"

    /**
     * Task requirement F.3 - the exact match [RelayIngressResolverImpl]
     * requires before ever using this profile: the SAME ingress endpoint,
     * binding, and transport the pinned [RelayedExecutionPlan] carries -
     * never merely "some profile exists for this endpoint id".
     */
    fun matches(plan: RelayedExecutionPlan): Boolean =
        ingressEndpointId == plan.ingressEndpointId &&
            ingressBinding == plan.ingressBinding &&
            transport == plan.ingressTransport

    fun isExpired(nowEpochMillis: Long): Boolean {
        val expiry = expiresAtEpochMillis ?: return false
        return nowEpochMillis >= expiry
    }

    private fun structurallyValid(): Boolean = when (transport) {
        TransportKind.XRAY_REALITY -> realityProfile != null && tlsProfile == null
        TransportKind.TLS_TCP -> tlsProfile != null && realityProfile == null
        else -> false
    }

    fun toJson(): String {
        require(structurallyValid()) { "IngressClientProfile.transport ($transport) must match exactly one of realityProfile/tlsProfile" }
        val obj = JSONObject()
            .put(KEY_INGRESS_ENDPOINT_ID, ingressEndpointId.value)
            .put(KEY_TRANSPORT, transport.name)
            .put(KEY_PROFILE_VERSION, profileVersion)
            .put(KEY_ISSUED_AT, issuedAtEpochMillis)
            .put(KEY_EXPIRES_AT, expiresAtEpochMillis ?: JSONObject.NULL)
            .put(KEY_PROBE_URL, endToEndProbeUrl ?: JSONObject.NULL)
            .put(KEY_PROBE_TOKEN, endToEndProbeToken ?: JSONObject.NULL)
            .put(KEY_BINDING, EndpointTransportBindingJson.toJson(ingressBinding))
        realityProfile?.let { obj.put(KEY_REALITY_PROFILE, JSONObject(it.toJson())) }
        tlsProfile?.let { obj.put(KEY_TLS_PROFILE, JSONObject(it.toJson())) }
        return obj.toString()
    }

    companion object {
        private const val KEY_INGRESS_ENDPOINT_ID = "ingressEndpointId"
        private const val KEY_TRANSPORT = "transport"
        private const val KEY_PROFILE_VERSION = "profileVersion"
        private const val KEY_ISSUED_AT = "issuedAt"
        private const val KEY_EXPIRES_AT = "expiresAt"
        private const val KEY_PROBE_URL = "probeUrl"
        private const val KEY_PROBE_TOKEN = "probeToken"
        private const val KEY_BINDING = "binding"
        private const val KEY_REALITY_PROFILE = "realityProfile"
        private const val KEY_TLS_PROFILE = "tlsProfile"

        /** @throws org.json.JSONException on malformed/corrupted stored JSON. */
        fun fromJson(json: String): IngressClientProfile {
            val obj = JSONObject(json)
            val transport = TransportKind.valueOf(obj.getString(KEY_TRANSPORT))
            return IngressClientProfile(
                ingressEndpointId = EndpointId(obj.getString(KEY_INGRESS_ENDPOINT_ID)),
                ingressBinding = EndpointTransportBindingJson.fromJson(obj.getJSONObject(KEY_BINDING)),
                transport = transport,
                realityProfile = if (obj.has(KEY_REALITY_PROFILE) && !obj.isNull(KEY_REALITY_PROFILE)) {
                    XrayProfile.fromJson(obj.getJSONObject(KEY_REALITY_PROFILE).toString())
                } else {
                    null
                },
                tlsProfile = if (obj.has(KEY_TLS_PROFILE) && !obj.isNull(KEY_TLS_PROFILE)) {
                    XrayTlsProfile.fromJson(obj.getJSONObject(KEY_TLS_PROFILE).toString())
                } else {
                    null
                },
                profileVersion = obj.getInt(KEY_PROFILE_VERSION),
                issuedAtEpochMillis = obj.getLong(KEY_ISSUED_AT),
                expiresAtEpochMillis = if (obj.isNull(KEY_EXPIRES_AT)) null else obj.getLong(KEY_EXPIRES_AT),
                endToEndProbeUrl = if (obj.isNull(KEY_PROBE_URL)) null else obj.getString(KEY_PROBE_URL),
                endToEndProbeToken = if (obj.isNull(KEY_PROBE_TOKEN)) null else obj.getString(KEY_PROBE_TOKEN),
            )
        }
    }
}

/** Minimal, lossless JSON round-trip for [EndpointTransportBinding] - reused only by this file's persistence format, never a general-purpose manifest codec. */
internal object EndpointTransportBindingJson {
    private const val KEY_KIND = "kind"
    private const val KEY_HOST = "host"
    private const val KEY_PORT = "port"
    private const val KEY_METADATA = "metadata"

    fun toJson(binding: EndpointTransportBinding): JSONObject {
        val metadataObj = JSONObject()
        binding.metadata.forEach { (k, v) -> metadataObj.put(k, v) }
        return JSONObject()
            .put(KEY_KIND, binding.kind.name)
            .put(KEY_HOST, binding.host)
            .put(KEY_PORT, binding.port)
            .put(KEY_METADATA, metadataObj)
    }

    fun fromJson(obj: JSONObject): EndpointTransportBinding {
        val metadataObj = obj.optJSONObject(KEY_METADATA)
        val metadata = buildMap {
            metadataObj?.keys()?.forEach { key -> put(key, metadataObj.getString(key)) }
        }
        return EndpointTransportBinding(
            kind = TransportKind.valueOf(obj.getString(KEY_KIND)),
            host = obj.getString(KEY_HOST),
            port = obj.getInt(KEY_PORT),
            metadata = metadata,
        )
    }
}

sealed class IngressProfileLoadResult {
    object NotFound : IngressProfileLoadResult()
    data class Found(val profile: IngressClientProfile) : IngressProfileLoadResult()
    data class Corrupted(val reason: String) : IngressProfileLoadResult()
}

/**
 * B25 (task E/G) - the per-device, per-ingress-endpoint-scoped store a real
 * control-plane activation writes into (task G's `/v1/ingress-profile`
 * response), and [RelayIngressResolverImpl] reads from. Endpoint-scoped by
 * construction (task requirement E's own "never reuse one ingress
 * credential across unrelated ingress endpoints" - a distinct file per
 * [EndpointId], same discipline [net.pocvpn.client.identity.FileXrayProfileStore]
 * already uses for regular gateway profiles).
 */
interface IngressProfileStore {
    suspend fun getProfileOrNull(endpointId: EndpointId): IngressClientProfile?
    suspend fun saveProfile(profile: IngressClientProfile)
    suspend fun clearProfile(endpointId: EndpointId)
}

class IngressProfileCorruptedException(message: String) : Exception(message)

/**
 * Encrypted-at-rest file store, one file per ingress [EndpointId] - the
 * SAME AndroidKeystoreAesGcmEncryptor discipline [net.pocvpn.client.identity.SecureXrayProfileRepository]
 * already uses (task requirement E's "encrypted/Keystore-backed storage
 * equivalent to existing Xray/client credential handling"), with its own
 * key alias so an ingress credential is never encrypted under the same key
 * material as the managed-network Xray profile it is otherwise unrelated to.
 */
class FileIngressProfileStore(
    private val directory: File,
    private val encryptor: AesGcmKeyEncryptor,
) : IngressProfileStore {
    private companion object {
        const val FORMAT_VERSION = 1
        const val MAX_CIPHERTEXT_LEN = 16384
        const val MAX_IV_LEN = 64
    }

    private fun fileFor(endpointId: EndpointId): File =
        File(directory, "ingress_profile_${net.pocvpn.client.identity.sanitizeForFileName(endpointId)}.bin")

    override suspend fun getProfileOrNull(endpointId: EndpointId): IngressClientProfile? {
        val file = fileFor(endpointId)
        if (!file.exists()) return null
        val encrypted = try {
            DataInputStream(file.inputStream().buffered()).use { input ->
                val version = input.readInt()
                if (version != FORMAT_VERSION) throw IngressProfileCorruptedException("unsupported format version $version")
                val iv = readLengthPrefixed(input, MAX_IV_LEN)
                val ciphertext = readLengthPrefixed(input, MAX_CIPHERTEXT_LEN)
                EncryptedPayload(iv, ciphertext)
            }
        } catch (e: java.io.EOFException) {
            throw IngressProfileCorruptedException("truncated ingress profile file")
        } catch (e: java.io.IOException) {
            throw IngressProfileCorruptedException("unreadable ingress profile file: ${e.javaClass.simpleName}")
        }
        val plaintext = encryptor.decrypt(encrypted)
        return try {
            IngressClientProfile.fromJson(String(plaintext, StandardCharsets.UTF_8))
        } catch (e: org.json.JSONException) {
            throw IngressProfileCorruptedException(e.message ?: "malformed ingress profile file")
        }
    }

    override suspend fun saveProfile(profile: IngressClientProfile) {
        directory.mkdirs()
        val file = fileFor(profile.ingressEndpointId)
        val tmp = File(directory, "${file.name}.tmp")
        val encrypted = encryptor.encrypt(profile.toJson().toByteArray(StandardCharsets.UTF_8))
        val bytes = ByteArrayOutputStream().also { buffer ->
            DataOutputStream(buffer).use { out ->
                out.writeInt(FORMAT_VERSION)
                writeLengthPrefixed(out, encrypted.iv)
                writeLengthPrefixed(out, encrypted.ciphertext)
            }
        }.toByteArray()
        tmp.writeBytes(bytes)
        if (!tmp.renameTo(file)) {
            tmp.delete()
            throw java.io.IOException("failed to atomically replace ingress profile file")
        }
    }

    override suspend fun clearProfile(endpointId: EndpointId) {
        fileFor(endpointId).delete()
    }

    private fun writeLengthPrefixed(out: DataOutputStream, bytes: ByteArray) {
        out.writeInt(bytes.size)
        out.write(bytes)
    }

    private fun readLengthPrefixed(input: DataInputStream, maxLen: Int): ByteArray {
        val len = input.readInt()
        require(len in 0..maxLen) { "implausible length-prefixed field: $len" }
        val bytes = ByteArray(len)
        input.readFully(bytes)
        return bytes
    }
}

/** In-memory store for tests/unwired defaults - never used in production (see [FileIngressProfileStore]). */
class InMemoryIngressProfileStore : IngressProfileStore {
    private val profiles = mutableMapOf<EndpointId, IngressClientProfile>()
    override suspend fun getProfileOrNull(endpointId: EndpointId): IngressClientProfile? = profiles[endpointId]
    override suspend fun saveProfile(profile: IngressClientProfile) { profiles[profile.ingressEndpointId] = profile }
    override suspend fun clearProfile(endpointId: EndpointId) { profiles.remove(endpointId) }
}
