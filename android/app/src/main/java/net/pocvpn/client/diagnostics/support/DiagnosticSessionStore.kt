package net.pocvpn.client.diagnostics.support

/**
 * B29 (task D) - the bounded local ring buffer of recent
 * [DiagnosticSession]s. Deliberately NEVER unlimited logging: every real
 * implementation must cap retention by count (see [MAX_RETAINED_SESSIONS])
 * with oldest-first eviction (task's own explicit retention policy).
 */
interface DiagnosticSessionStore {
    /** Most recent first. Never more than [MAX_RETAINED_SESSIONS] entries. */
    fun recent(): List<DiagnosticSession>

    /** Appends [session], evicting the OLDEST retained session first once [MAX_RETAINED_SESSIONS] would be exceeded. */
    fun append(session: DiagnosticSession)

    /** Removes every retained session (task J - an explicit user action, "Clear diagnostics"). */
    fun clear()

    companion object {
        /** Task D's own suggested retention ("last 5-10 sessions") - the middle of that range. */
        const val MAX_RETAINED_SESSIONS = 8
    }
}

/**
 * B29 - the default, thread-safe, in-memory ring buffer. Bounded strictly by
 * [DiagnosticSessionStore.MAX_RETAINED_SESSIONS] - `synchronized` because a
 * real session can be appended from [net.pocvpn.client.MainViewModel]'s
 * `viewModelScope` collectors while [recent]/[clear] may be read from the UI
 * thread via a Compose recomposition.
 */
class InMemoryDiagnosticSessionStore : DiagnosticSessionStore {
    private val lock = Any()

    // Newest LAST internally (append-friendly); [recent] reverses on read.
    private val sessions = ArrayDeque<DiagnosticSession>()

    override fun recent(): List<DiagnosticSession> = synchronized(lock) { sessions.asReversed().toList() }

    override fun append(session: DiagnosticSession) {
        synchronized(lock) {
            sessions.addLast(session)
            while (sessions.size > DiagnosticSessionStore.MAX_RETAINED_SESSIONS) {
                sessions.removeFirst()
            }
        }
    }

    override fun clear() {
        synchronized(lock) { sessions.clear() }
    }
}
