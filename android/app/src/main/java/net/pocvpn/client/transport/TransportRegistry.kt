package net.pocvpn.client.transport

import net.pocvpn.client.vpn.VpnTransport

/**
 * The one authoritative place describing which transports exist and which
 * are actually available at runtime. VpnController/TransportOrchestrator
 * consult this instead of containing protocol-specific if/else chains.
 */
class TransportRegistry private constructor(
    private val descriptorsByKind: Map<TransportKind, TransportDescriptor>,
) {
    fun descriptorFor(kind: TransportKind): TransportDescriptor? = descriptorsByKind[kind]

    fun all(): List<TransportDescriptor> = descriptorsByKind.values.toList()

    fun available(): List<TransportDescriptor> = descriptorsByKind.values.filter { it.status == TransportStatus.AVAILABLE }

    /** Only valid to call for an AVAILABLE descriptor - see TransportDescriptor's own invariant. */
    fun createTransport(kind: TransportKind): VpnTransport? = descriptorFor(kind)?.factory?.invoke()

    companion object {
        /** Builds a registry from explicit descriptors, rejecting a duplicate registration for the same kind. */
        fun build(descriptors: List<TransportDescriptor>): TransportRegistry {
            val byKind = LinkedHashMap<TransportKind, TransportDescriptor>()
            for (descriptor in descriptors) {
                require(byKind.put(descriptor.kind, descriptor) == null) {
                    "duplicate transport registration for ${descriptor.kind}"
                }
            }
            return TransportRegistry(byKind)
        }

        /**
         * Default registry state as of Phase 2A: only AmneziaWG is real.
         * [amneziaWgFactory] is supplied by the caller (needs an Android
         * Context) so this class stays pure/testable and has no Android
         * dependency of its own.
         */
        fun defaults(amneziaWgFactory: () -> VpnTransport): TransportRegistry = build(
            listOf(
                TransportDescriptor(
                    kind = TransportKind.AMNEZIA_WG,
                    status = TransportStatus.AVAILABLE,
                    capabilities = TransportCapabilities.amneziaWg(),
                    factory = amneziaWgFactory,
                ),
                TransportDescriptor(
                    kind = TransportKind.XRAY_REALITY,
                    status = TransportStatus.NOT_IMPLEMENTED,
                    capabilities = TransportCapabilities.notImplemented(),
                ),
                TransportDescriptor(
                    kind = TransportKind.QUIC,
                    status = TransportStatus.NOT_IMPLEMENTED,
                    capabilities = TransportCapabilities.notImplemented(),
                ),
                TransportDescriptor(
                    kind = TransportKind.TLS_TCP,
                    status = TransportStatus.NOT_IMPLEMENTED,
                    capabilities = TransportCapabilities.notImplemented(),
                ),
            ),
        )
    }
}
