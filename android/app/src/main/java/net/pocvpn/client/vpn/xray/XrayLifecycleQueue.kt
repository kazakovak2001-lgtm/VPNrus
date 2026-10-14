package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch

/**
 * Runs `:xray` lifecycle commands (START, STOP, revoke) one at a time, in
 * the order they were enqueued. Separate `scope.launch` calls on
 * Dispatchers.IO can reach [NovaXrayServiceLifecycleCoordinator]'s mutex in
 * either order, so STOP(N) could run after START(N+1). A failing command is
 * reported to [onFailure] and does not stop later ones.
 */
internal class XrayLifecycleQueue(scope: CoroutineScope, private val onFailure: (Throwable) -> Unit = {}) {
    private val commands = Channel<suspend () -> Unit>(Channel.UNLIMITED)

    init {
        scope.launch {
            for (command in commands) {
                try {
                    command()
                } catch (e: CancellationException) {
                    throw e
                } catch (t: Throwable) {
                    onFailure(t)
                }
            }
        }
    }

    fun enqueue(command: suspend () -> Unit) {
        commands.trySend(command)
    }
}
