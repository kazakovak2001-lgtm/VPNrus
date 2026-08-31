package net.pocvpn.client.vpn.config

/** Raw, unvalidated strings for gateway config - lets tests supply values without touching Android's BuildConfig. */
interface GatewayConfigSource {
    fun endpointHost(): String
    fun endpointPort(): String
    fun serverPublicKey(): String
    fun clientTunnelIp(): String
    fun gatewayTunnelIp(): String

    /**
     * Comma-separated AllowedIPs override (e.g. "10.77.0.0/24" for a narrow
     * local-test route, instead of the full-tunnel default). Blank means
     * "not specified" - DefaultGatewayConfigurationRepository falls back to
     * the full-tunnel default in that case.
     */
    fun allowedIps(): String = ""

    /**
     * B13 - the AWG obfuscation/timing profile for THIS source's gateway.
     * Defaults to [PocAwgProfile.value] (Germany's own values, historically
     * the only ones that existed) so every pre-B13 implementation
     * ([BuildConfigGatewaySource], every test fake) is byte-for-byte
     * unaffected. [SelectedProductionGatewaySource] is the one real
     * implementation that overrides this per-gateway - see its own docs for
     * why a single global profile was a real bug, not a simplification.
     */
    fun profile(): AwgProfile = PocAwgProfile.value

    /**
     * B13 THIRD consolidated review fix (finding 6) - ONE atomic snapshot of
     * every field above, resolved TOGETHER. The default implementation here
     * simply calls each individual getter in turn, in the SAME order
     * DefaultGatewayConfigurationRepository.get() always has - byte-for-byte
     * unchanged behavior for every source with no concurrent-mutation
     * concern (BuildConfigGatewaySource's values are compile-time constants;
     * every plain test fake returns fixed strings).
     *
     * A source whose underlying selection CAN change between two calls
     * (today: [SelectedProductionGatewaySource], selection changes via
     * MainViewModel.selectGateway() on a different coroutine/thread than
     * whatever is mid-`get()`) MUST override this to resolve its
     * selection/descriptor EXACTLY ONCE and derive every field from that
     * SAME resolved value - never six independent re-reads a concurrent
     * selection change could interleave, which could otherwise combine one
     * gateway's host with a DIFFERENT gateway's key/clientTunnelIp/profile
     * into one nonsensical GatewayConfiguration.Configured.
     */
    fun snapshot(): GatewayConfigSnapshot = GatewayConfigSnapshot(
        endpointHost = endpointHost(),
        endpointPort = endpointPort(),
        serverPublicKey = serverPublicKey(),
        clientTunnelIp = clientTunnelIp(),
        gatewayTunnelIp = gatewayTunnelIp(),
        allowedIps = allowedIps(),
        profile = profile(),
    )
}

/** B13 THIRD consolidated review fix (finding 6) - see [GatewayConfigSource.snapshot]'s own docs. */
data class GatewayConfigSnapshot(
    val endpointHost: String,
    val endpointPort: String,
    val serverPublicKey: String,
    val clientTunnelIp: String,
    val gatewayTunnelIp: String,
    val allowedIps: String,
    val profile: AwgProfile,
)

interface GatewayConfigurationRepository {
    fun get(): GatewayConfiguration
}

/**
 * Validates raw config strings into a GatewayConfiguration. All fields blank
 * -> Missing (no gateway configured at all - the expected POC-01 state until
 * B6 exists). Any field present but structurally wrong -> Invalid(reason),
 * never silently ignored and never a crash.
 */
class DefaultGatewayConfigurationRepository(
    private val source: GatewayConfigSource,
) : GatewayConfigurationRepository {

    override fun get(): GatewayConfiguration =
        // B13 THIRD consolidated review fix (finding 6) - ONE snapshot()
        // call, not six independent getter calls: every field below is
        // guaranteed to describe the SAME resolved gateway, even if the
        // underlying selection changes concurrently the instant after this
        // call returns - see GatewayConfigSource.snapshot()'s own docs.
        GatewayConfigSnapshotValidator.validate(source.snapshot())
}

/**
 * B16 - the ONE place a raw [GatewayConfigSnapshot] is validated into a
 * [GatewayConfiguration]. Extracted out of [DefaultGatewayConfigurationRepository.get]
 * (which still calls this, unchanged, for a freshly re-read snapshot) so
 * [VpnController] can ALSO validate an already-resolved, PINNED snapshot -
 * e.g. an automatic-gateway-selection candidate's own
 * `GatewayAttemptCandidate.configSnapshot` (see AutoGatewaySelector's own
 * docs) - through the EXACT SAME validation rules, never a second/duplicated
 * copy that could silently drift out of agreement with what a manual
 * gateway's own config validation accepts or rejects.
 */
object GatewayConfigSnapshotValidator {
    fun validate(snapshot: GatewayConfigSnapshot): GatewayConfiguration {
        val host = snapshot.endpointHost.trim()
        val portRaw = snapshot.endpointPort.trim()
        val serverPublicKey = snapshot.serverPublicKey.trim()
        val clientTunnelIp = snapshot.clientTunnelIp.trim()
        val gatewayTunnelIp = snapshot.gatewayTunnelIp.trim()

        if (host.isEmpty() && portRaw.isEmpty() && serverPublicKey.isEmpty() &&
            clientTunnelIp.isEmpty() && gatewayTunnelIp.isEmpty()
        ) {
            return GatewayConfiguration.Missing
        }

        if (host.isEmpty()) return GatewayConfiguration.Invalid("endpoint host is blank")

        val port = portRaw.toIntOrNull()
            ?: return GatewayConfiguration.Invalid("endpoint port is not a number: '$portRaw'")
        if (port !in 1..65535) return GatewayConfiguration.Invalid("endpoint port out of range: $port")

        if (!WgKeyFormat.isValid(serverPublicKey)) {
            return GatewayConfiguration.Invalid("server public key is not a valid AmneziaWG/WireGuard key")
        }
        if (!Ipv4Format.isValid(clientTunnelIp)) {
            return GatewayConfiguration.Invalid("client tunnel IP is not a valid IPv4 address: '$clientTunnelIp'")
        }
        if (!Ipv4Format.isValid(gatewayTunnelIp)) {
            return GatewayConfiguration.Invalid("gateway tunnel IP is not a valid IPv4 address: '$gatewayTunnelIp'")
        }

        return GatewayConfiguration.Configured(
            endpointHost = host,
            endpointPort = port,
            serverPublicKeyBase64 = serverPublicKey,
            clientTunnelIp = clientTunnelIp,
            gatewayTunnelIp = gatewayTunnelIp,
            allowedIps = resolveAllowedIps(snapshot),
            // B8F - a local client policy, not a server-issued/persisted
            // fact (see VpnDnsPolicy's own docs) - applied here so every
            // profile source converges on the same DNS servers.
            dnsServers = VpnDnsPolicy.servers,
            // B13 - read fresh from the SAME snapshot as every other field
            // above (no caching across separate get() calls, but never a
            // second, independent read within THIS one) - see
            // GatewayConfigSource.profile()/snapshot()'s own docs.
            profile = snapshot.profile,
        )
    }

    /** Full-tunnel default, unless the source overrides it (e.g. a narrow route for local testing). */
    private fun resolveAllowedIps(snapshot: GatewayConfigSnapshot): List<String> {
        val override = snapshot.allowedIps.split(",").map { it.trim() }.filter { it.isNotEmpty() }
        return override.ifEmpty { listOf("0.0.0.0/0", "::/0") }
    }
}
