package net.pocvpn.client.vpn.hysteria

/**
 * B46-3A - debug-only, research-scoped JNI boundary onto the Nova native
 * tun2socks bridge (see `research/b46-3a-hysteria-native-bridge/` and
 * `docs/B46_3A_HYSTERIA_NATIVE_BRIDGE_COEXISTENCE.md`).
 *
 * Unlike B46-2P's `bridge.Bridge` (a gomobile-bound class reached only via
 * reflection - see `B46Tun2SocksBridgeAdapter`), this is a PLAIN JNI
 * boundary: `external fun` declarations compile unconditionally (no
 * reflection needed), and only the runtime `System.loadLibrary` call can
 * fail when the locally-built `.so`s are absent - caught below and mapped
 * to a typed [NativeBridgeResult.Failed], never a raw crash.
 *
 * Native libraries loaded (in dependency order, see
 * `research/b46-3a-hysteria-native-bridge/scripts/build-jni-shim.sh`):
 *  - `libnovatun2socks.so` - Go `-buildmode=c-shared` artifact wrapping the
 *    real pinned `xjasonlyu/tun2socks` engine. NOT gomobile-bound: no
 *    `go.Seq`/`go.Universe`/`go.error`, no second `libgojni.so`.
 *  - `libnovatun2socks_jni.so` - the JNI shim itself (links against the
 *    above), the only library this class ever `dlopen()`s directly.
 *
 * FD OWNERSHIP CONTRACT (reused verbatim from B46-2P/B46-2C, load-bearing):
 * [fd] must already be a DUPLICATE of the VpnService-owned TUN
 * fd (`ParcelFileDescriptor.dup(original.fileDescriptor).detachFd()`).
 * [start] takes ownership of exactly that fd number on success; the native
 * engine closes it on [stop]. The caller must never pass the original
 * VpnService fd, and must never close the duplicate itself after a
 * successful [start].
 */
/** Result of a native bridge lifecycle call - never a raw exception/crash. */
internal sealed interface NativeBridgeResult {
    object Ok : NativeBridgeResult
    data class Failed(val reason: String) : NativeBridgeResult
}

internal object NativeTun2SocksBridge {

    // novaErr* codes mirrored from research/b46-3a-hysteria-native-bridge/native/main.go.
    private const val NOVA_OK = 0
    private const val NOVA_ERR_ALREADY_STARTED = -1
    private const val NOVA_ERR_INVALID_FD = -2
    private const val NOVA_ERR_INVALID_MTU = -3
    private const val NOVA_ERR_EMPTY_SOCKS_ADDR = -4
    private const val NOVA_ERR_ENGINE_START_FAIL = -5
    private const val NOVA_ERR_ENGINE_STOP_FAIL = -6

    private val libraryLoadError: Throwable? = runCatching {
        // Load order matters: the JNI shim's NEEDED entry is
        // libnovatun2socks.so, so it must already be resident before the
        // shim itself is dlopen()'d, or the second load fails with
        // UnsatisfiedLinkError even though both files are present.
        System.loadLibrary("novatun2socks")
        System.loadLibrary("novatun2socks_jni")
    }.exceptionOrNull()

    private val isLibraryLoaded: Boolean get() = libraryLoadError == null

    @JvmStatic
    private external fun nativeStart(fd: Int, mtu: Int, socksAddr: String): Int

    @JvmStatic
    private external fun nativeStop(): Int

    @JvmStatic
    private external fun nativeIsStarted(): Boolean

    /**
     * Starts the native tun2socks bridge. [fd] must already be a duplicate
     * of the VpnService's TUN fd (see the ownership contract above). Never
     * throws: a missing native library, an invalid argument, or an engine
     * failure all come back as [NativeBridgeResult.Failed].
     */
    fun start(fd: Int, mtu: Int, socksAddr: String): NativeBridgeResult {
        libraryLoadError?.let {
            return NativeBridgeResult.Failed("native library not loaded: ${it.javaClass.simpleName}: ${it.message}")
        }
        return try {
            mapCode(nativeStart(fd, mtu, socksAddr))
        } catch (t: Throwable) {
            // UnsatisfiedLinkError for a symbol mismatch, or any other
            // unexpected JNI-boundary throwable - fail closed, never crash
            // the host process.
            NativeBridgeResult.Failed("${t.javaClass.simpleName}: ${t.message}")
        }
    }

    /** Idempotent: safe to call when not started, or after a failed [start]. */
    fun stop(): NativeBridgeResult {
        if (!isLibraryLoaded) {
            // Nothing was ever started if the library never loaded.
            return NativeBridgeResult.Ok
        }
        return try {
            mapCode(nativeStop())
        } catch (t: Throwable) {
            NativeBridgeResult.Failed("${t.javaClass.simpleName}: ${t.message}")
        }
    }

    /** Diagnostic only - never used to gate a production decision. */
    fun isStarted(): Boolean {
        if (!isLibraryLoaded) return false
        return try {
            nativeIsStarted()
        } catch (t: Throwable) {
            false
        }
    }

    private fun mapCode(code: Int): NativeBridgeResult = when (code) {
        NOVA_OK -> NativeBridgeResult.Ok
        NOVA_ERR_ALREADY_STARTED -> NativeBridgeResult.Failed("bridge already started")
        NOVA_ERR_INVALID_FD -> NativeBridgeResult.Failed("invalid fd")
        NOVA_ERR_INVALID_MTU -> NativeBridgeResult.Failed("invalid mtu")
        NOVA_ERR_EMPTY_SOCKS_ADDR -> NativeBridgeResult.Failed("empty socks address")
        NOVA_ERR_ENGINE_START_FAIL -> NativeBridgeResult.Failed("engine start failed")
        NOVA_ERR_ENGINE_STOP_FAIL -> NativeBridgeResult.Failed("engine stop failed")
        else -> NativeBridgeResult.Failed("unknown native error code $code")
    }
}
