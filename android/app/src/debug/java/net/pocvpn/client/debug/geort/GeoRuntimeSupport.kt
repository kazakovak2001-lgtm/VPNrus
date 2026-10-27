package net.pocvpn.client.debug.geort

import android.content.Context
import android.os.Build
import android.os.Process
import android.os.SystemClock
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest

/**
 * GEO-RUNTIME-EXPERIMENT E0-E6 - TEST ONLY helpers (debug source set, never committed).
 * Fixed blackhole-only Xray configs; nothing here can carry user traffic.
 */
object GeoRt {
    const val TAG = "GeoRt"
    const val SOCKS_PORT = 18080
    const val HIT_TAG = "geort-hit"
    const val MISS_TAG = "geort-miss"

    // Inputs verified on the host against the exact bundled databases (see the report):
    // 77.88.8.8 is in geoip RU only; 8.8.8.8 is in US/GOOGLE, not RU; www.yandex.org matches the
    // YANDEX suffix entry "yandex.org"; www.example.invalid is in no geosite list.
    const val IP_HIT = "77.88.8.8"
    const val IP_MISS = "8.8.8.8"
    const val DOMAIN_HIT = "www.yandex.org"
    const val DOMAIN_MISS = "www.example.invalid"
    const val UNKNOWN_CODE = "NOSUCHCODEZZ"

    fun sha256(file: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { i ->
            val b = ByteArray(64 * 1024)
            while (true) { val n = i.read(b); if (n < 0) break; md.update(b, 0, n) }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    fun sha256Asset(context: Context, name: String): Pair<Long, String> {
        val md = MessageDigest.getInstance("SHA-256")
        var total = 0L
        context.assets.open(name).use { i ->
            val b = ByteArray(64 * 1024)
            while (true) { val n = i.read(b); if (n < 0) break; md.update(b, 0, n); total += n }
        }
        return total to md.digest().joinToString("") { "%02x".format(it) }
    }

    /** rule = "geoip:ru" / "geosite:yandex" / null. withSocks: loopback-only evaluation probe. */
    fun config(rule: String?, withSocks: Boolean, withTun: Boolean): String {
        val root = JSONObject()
        root.put("log", JSONObject().put("loglevel", "warning").put("access", "none"))
        root.put("stats", JSONObject())
        val inbounds = JSONArray()
        if (withSocks) {
            inbounds.put(
                JSONObject().put("tag", "geort-socks-in").put("listen", "127.0.0.1").put("port", SOCKS_PORT)
                    .put("protocol", "socks").put("settings", JSONObject().put("auth", "noauth").put("udp", false)),
            )
        }
        if (withTun) {
            inbounds.put(
                JSONObject().put("tag", "geort-tun-in").put("protocol", "tun").put("port", 0)
                    .put("settings", JSONObject().put("name", "geort-tun").put("desc", "GeoRt").put("mtu", 1500)),
            )
        }
        if (inbounds.length() > 0) root.put("inbounds", inbounds)
        // First outbound is the default route: "miss" closes the connection with no bytes,
        // "hit" answers with a canned HTTP 403. Neither dials anything.
        root.put(
            "outbounds",
            JSONArray()
                .put(JSONObject().put("tag", MISS_TAG).put("protocol", "blackhole"))
                .put(
                    JSONObject().put("tag", HIT_TAG).put("protocol", "blackhole")
                        .put("settings", JSONObject().put("response", JSONObject().put("type", "http"))),
                ),
        )
        if (rule != null) {
            val key = if (rule.startsWith("geoip:")) "ip" else "domain"
            root.put(
                "routing",
                JSONObject().put("domainStrategy", "AsIs").put(
                    "rules",
                    JSONArray().put(JSONObject().put("type", "field").put(key, JSONArray().put(rule)).put("outboundTag", HIT_TAG)),
                ),
            )
        }
        return root.toString()
    }

    /** Loopback SOCKS5 CONNECT to [target] through the core's own inbound; result HIT / MISS / INCONCLUSIVE:<why>. */
    fun socksProbe(target: String): JSONObject {
        val out = JSONObject().put("target", target)
        try {
            Socket().use { s ->
                s.soTimeout = 4000
                s.connect(InetSocketAddress("127.0.0.1", SOCKS_PORT), 2000)
                val o = s.getOutputStream()
                val i = s.getInputStream()
                o.write(byteArrayOf(5, 1, 0)); o.flush()
                val greet = ByteArray(2); readFully(i, greet)
                if (greet[0].toInt() != 5 || greet[1].toInt() != 0) return out.put("result", "INCONCLUSIVE:socks-greeting")
                val req = java.io.ByteArrayOutputStream()
                req.write(byteArrayOf(5, 1, 0))
                val ip = Regex("""^\d+\.\d+\.\d+\.\d+$""").matches(target)
                if (ip) { req.write(1); target.split('.').forEach { req.write(it.toInt()) } }
                else { req.write(3); req.write(target.length); req.write(target.toByteArray()) }
                req.write(0); req.write(80)
                o.write(req.toByteArray()); o.flush()
                val head = ByteArray(4); readFully(i, head)
                if (head[1].toInt() != 0) return out.put("result", "INCONCLUSIVE:socks-reply-${head[1]}")
                val rest = when (head[3].toInt()) { 1 -> 6; 4 -> 18; else -> 0 }
                readFully(i, ByteArray(rest))
                o.write("GET / HTTP/1.0\r\nHost: $target\r\n\r\n".toByteArray()); o.flush()
                val buf = ByteArray(256)
                val n = try { i.read(buf) } catch (e: java.net.SocketTimeoutException) { return out.put("result", "INCONCLUSIVE:timeout") }
                val text = if (n > 0) String(buf, 0, n, Charsets.ISO_8859_1).lineSequence().first().take(60) else ""
                out.put("firstLine", text)
                out.put("result", if (n > 0 && text.startsWith("HTTP/1.1 403")) "HIT" else if (n <= 0) "MISS" else "INCONCLUSIVE:unexpected-bytes")
            }
        } catch (t: Throwable) {
            out.put("result", "INCONCLUSIVE:${t.javaClass.simpleName}:${t.message}")
        }
        return out
    }

    private fun readFully(i: java.io.InputStream, b: ByteArray) {
        var off = 0
        while (off < b.size) { val n = i.read(b, off, b.size - off); if (n < 0) throw java.io.EOFException(); off += n }
    }

    /** Plain HTTP GET to a public IP literal, from this app. A real HTTP status line == the packet left the device. */
    fun leakProbe(timeoutMs: Int = 1500, context: Context? = null): JSONObject {
        val out = JSONObject().put("startNs", SystemClock.elapsedRealtimeNanos())
        var localAddress: java.net.InetAddress? = null
        try {
            Socket().use { s ->
                s.soTimeout = timeoutMs
                s.connect(InetSocketAddress("1.1.1.1", 80), timeoutMs)
                out.put("connected", true).put("connectedNs", SystemClock.elapsedRealtimeNanos())
                localAddress = recordSocketAddresses(s, out)
                s.getOutputStream().write("GET / HTTP/1.0\r\nHost: 1.1.1.1\r\n\r\n".toByteArray())
                val buf = ByteArray(64)
                val n = try { s.getInputStream().read(buf) } catch (e: java.net.SocketTimeoutException) { -2 }
                if (n > 0) out.put("firstDataNs", SystemClock.elapsedRealtimeNanos())
                val line = if (n > 0) String(buf, 0, n, Charsets.ISO_8859_1).lineSequence().first() else ""
                out.put("outcome", if (line.startsWith("HTTP/")) "REAL_RESPONSE" else if (n == -2) "NO_RESPONSE" else "CLOSED_NO_DATA")
                out.put("firstLine", line)
            }
        } catch (t: Throwable) {
            out.put("connected", false)
            out.put("outcome", "CONNECT_FAIL:${t.javaClass.simpleName}")
        }
        out.put("endNs", SystemClock.elapsedRealtimeNanos())
        // Diagnostics run strictly AFTER endNs (so endNs/durationMs keep their original meaning) and can
        // only ever add the "diag" key: any failure is contained here and never touches outcome/connected/times.
        val diagAddress = localAddress
        if (diagAddress != null) {
            try {
                recordPathDiagnostics(diagAddress, context, out)
            } catch (t: Throwable) {
                try { diagOf(out).put("diagError", t.javaClass.simpleName) } catch (_: Throwable) {}
            }
        }
        return out
    }

    // ---- path diagnostics (read-only; no protect(), no bind, no routing/network change) ----------
    // Field semantics - the four facts below are NOT interchangeable and none of them is a packet capture:
    //  1. diag.srcIp / srcPort / dstIp / dstPort  - srcIp/srcPort: socket local side (getsockname); dst*: requested target. The kernel
    //     picked srcIp from the route lookup at connect() time, so it is evidence about the route chosen for
    //     the SYN, not about where later packets went.
    //  2. diag.srcIpOwnerIface.*                  - the interface that currently OWNS srcIp
    //     (NetworkInterface.getByInetAddress). It says which interface holds the address, not which one
    //     transmitted the packet.
    //  3. diag.defaultNetwork.* / diag.vpnNetworks - ConnectivityManager's view for this UID at queriedAtNs
    //     (policy level, queried AFTER the response was read AND after endNs, so it can differ from the moment of connect()).
    //  4. diag.claims.*                           - always false here: this probe cannot prove the real egress
    //     interface or that a packet traversed the TUN. That needs an independent capture.

    /** Returns the socket's local address (null on any failure); never throws, writes only the "diag" key. */
    private fun recordSocketAddresses(s: Socket, out: JSONObject): java.net.InetAddress? {
        var local: java.net.InetAddress? = null
        try {
            local = s.localAddress
            val d = JSONObject()
            d.put("srcIp", local?.hostAddress ?: JSONObject.NULL)
            d.put("srcPort", s.localPort)
            // dstIp/dstPort are the destination the Socket object was asked to connect to, not a getpeername() result.
            d.put("dstIp", s.inetAddress?.hostAddress ?: JSONObject.NULL)
            d.put("dstPort", s.port)
            d.put("addressesReadNs", SystemClock.elapsedRealtimeNanos())
            out.put("diag", d)
        } catch (t: Throwable) {
            try { out.put("diag", JSONObject().put("addressError", t.javaClass.simpleName)) } catch (_: Throwable) {}
        }
        return local
    }

    private fun diagOf(out: JSONObject): JSONObject =
        out.optJSONObject("diag") ?: JSONObject().also { out.put("diag", it) }

    @Suppress("DEPRECATION")
    private fun recordPathDiagnostics(localAddress: java.net.InetAddress, context: Context?, out: JSONObject) {
        val d = diagOf(out)
        d.put("queriedAtNs", SystemClock.elapsedRealtimeNanos())
        d.put(
            "claims",
            JSONObject().put("egressInterfaceProven", false).put("tunTraversalProven", false)
                .put("note", "srcIp is a route-lookup result at connect(); not a capture"),
        )
        try {
            val owner = JSONObject()
            val ni = java.net.NetworkInterface.getByInetAddress(localAddress)
            if (ni == null) {
                owner.put("found", false)
            } else {
                owner.put("found", true).put("name", ni.name).put("index", ni.index).put("isUp", ni.isUp)
                    .put("isPointToPoint", ni.isPointToPoint).put("mtu", ni.mtu)
                    .put("addresses", JSONArray(ni.interfaceAddresses.map { it.address.hostAddress }))
            }
            d.put("srcIpOwnerIface", owner)
        } catch (t: Throwable) {
            d.put("srcIpOwnerIface", JSONObject().put("error", t.javaClass.simpleName))
        }
        if (context == null) {
            d.put("defaultNetwork", JSONObject().put("error", "no context"))
            return
        }
        try {
            val cm = context.getSystemService(android.net.ConnectivityManager::class.java)
            fun describe(n: android.net.Network?): JSONObject {
                val o = JSONObject()
                if (n == null) return o.put("network", JSONObject.NULL)
                o.put("network", n.toString())
                val caps = cm.getNetworkCapabilities(n)
                if (caps != null) {
                    val names = listOf(
                        android.net.NetworkCapabilities.TRANSPORT_CELLULAR to "CELLULAR", android.net.NetworkCapabilities.TRANSPORT_WIFI to "WIFI",
                        android.net.NetworkCapabilities.TRANSPORT_VPN to "VPN", android.net.NetworkCapabilities.TRANSPORT_ETHERNET to "ETHERNET",
                    )
                    o.put("transports", JSONArray(names.filter { caps.hasTransport(it.first) }.map { it.second }))
                    o.put("notVpnCapability", caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN))
                }
                o.put("linkInterfaceName", cm.getLinkProperties(n)?.interfaceName ?: JSONObject.NULL)
                return o
            }
            d.put("defaultNetwork", describe(cm.activeNetwork))
            val vpns = JSONArray()
            cm.allNetworks.forEach { n ->
                if (cm.getNetworkCapabilities(n)?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) == true) vpns.put(describe(n))
            }
            d.put("vpnNetworks", vpns)
        } catch (t: Throwable) {
            d.put("defaultNetwork", JSONObject().put("error", t.javaClass.simpleName))
        }
    }

    fun listDir(dir: File): JSONArray {
        val a = JSONArray()
        dir.listFiles()?.sortedBy { it.name }?.forEach {
            a.put(JSONObject().put("name", it.name).put("dir", it.isDirectory).put("size", if (it.isFile) it.length() else -1L).put("mtime", it.lastModified()))
        }
        return a
    }

    fun deviceInfo(): JSONObject = JSONObject()
        .put("model", Build.MODEL).put("device", Build.DEVICE).put("release", Build.VERSION.RELEASE)
        .put("sdk", Build.VERSION.SDK_INT).put("fingerprint", Build.FINGERPRINT)
        .put("pid", Process.myPid()).put("uid", Process.myUid())
        .put("processStartElapsedMs", Process.getStartElapsedRealtime())
        .put("nowElapsedMs", SystemClock.elapsedRealtime())

    fun processName(): String = try {
        File("/proc/self/cmdline").readBytes().takeWhile { it != 0.toByte() }.toByteArray().toString(Charsets.UTF_8)
    } catch (t: Throwable) { "unknown" }

    /** Atomic write of the case result into noBackupFilesDir/geort/. Never deletes anything. */
    fun writeResult(context: Context, name: String, json: JSONObject): File {
        val dir = File(context.noBackupFilesDir, "geort").apply { mkdirs() }
        var f = File(dir, "$name.json")
        var n = 1
        while (f.exists()) { f = File(dir, "$name-$n.json"); n++ }
        val tmp = File(dir, f.name + ".tmp")
        FileOutputStream(tmp).use { it.write(json.toString(2).toByteArray()); it.fd.sync() }
        Files.move(tmp.toPath(), f.toPath(), StandardCopyOption.ATOMIC_MOVE)
        Log.i(TAG, "GEORT|result-file=${f.name}")
        return f
    }

    fun ms(a: Long, b: Long): Double = (b - a) / 1_000_000.0
}
