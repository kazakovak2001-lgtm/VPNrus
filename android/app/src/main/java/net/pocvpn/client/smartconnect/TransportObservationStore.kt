package net.pocvpn.client.smartconnect

/**
 * B-WL-R1 - process-local, bounded memory of recent [TransportAttemptObservation]s,
 * scoped to an opaque network key (the same HMAC NetworkFingerprinter output
 * PathHistoryStore is keyed by - never raw SSID/BSSID/IP). Reading for one
 * network never returns another network's evidence, so a UDP-blocking
 * mobile network cannot leak its classification onto home Wi-Fi.
 *
 * Deliberately in-memory only: behavior evidence is short-lived by design
 * (RestrictionClassifier already ignores anything older than
 * DEFAULT_STALE_AFTER_MILLIS), and nothing here needs to survive process death.
 * [capacity] bounds the whole store (oldest evicted first), not each network.
 */
class TransportObservationStore(private val capacity: Int = DEFAULT_CAPACITY) {

    init {
        require(capacity > 0) { "capacity must be positive" }
    }

    private data class Entry(val networkKey: String, val observation: TransportAttemptObservation)

    private val entries = ArrayDeque<Entry>()

    @Synchronized
    fun record(networkKey: String, observation: TransportAttemptObservation) {
        entries.addLast(Entry(networkKey, observation))
        while (entries.size > capacity) entries.removeFirst()
    }

    /** Oldest first, only observations recorded under [networkKey]. */
    @Synchronized
    fun recent(networkKey: String): List<TransportAttemptObservation> =
        entries.filter { it.networkKey == networkKey }.map { it.observation }

    @Synchronized
    fun clear() {
        entries.clear()
    }

    companion object {
        const val DEFAULT_CAPACITY: Int = 32

        /** Used when no network fingerprint can be computed; evidence is still kept, never mixed with a fingerprinted network. */
        const val UNSCOPED_NETWORK_KEY: String = "unscoped"
    }
}
