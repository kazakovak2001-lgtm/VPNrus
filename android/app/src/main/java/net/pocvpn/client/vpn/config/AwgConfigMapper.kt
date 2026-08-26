package net.pocvpn.client.vpn.config

import org.amnezia.awg.config.Config
import org.amnezia.awg.config.InetEndpoint
import org.amnezia.awg.config.InetNetwork
import org.amnezia.awg.config.Interface
import org.amnezia.awg.config.Peer
import org.amnezia.awg.crypto.Key
import org.amnezia.awg.crypto.KeyPair
import java.net.InetAddress

/**
 * Maps our local AwgConfig/AwgProfile model onto the official AmneziaWG
 * backend's org.amnezia.awg.config.Config. This is the only file allowed to
 * import org.amnezia.awg.config.* outside AmneziaWgTransport itself - keeps
 * AWG-specific field names from leaking into the rest of the app.
 */
object AwgConfigMapper {

    fun toBackendConfig(awg: AwgConfig): Config {
        val iface = Interface.Builder()
        iface.setKeyPair(KeyPair(Key.fromBase64(awg.privateKeyBase64)))
        awg.localAddresses.forEach { iface.addAddress(InetNetwork.parse(it)) }
        awg.dnsServers.forEach { iface.addDnsServer(InetAddress.getByName(it)) }
        awg.listenPort?.let { iface.setListenPort(it) }
        awg.mtu?.let { iface.setMtu(it) }
        applyProfile(iface, awg.profile)

        val peer = Peer.Builder()
        peer.setPublicKey(Key.fromBase64(awg.peer.publicKeyBase64))
        peer.setEndpoint(InetEndpoint.parse("${awg.peer.endpointHost}:${awg.peer.endpointPort}"))
        awg.peer.allowedIps.forEach { peer.addAllowedIp(InetNetwork.parse(it)) }
        awg.peer.persistentKeepaliveSeconds?.let { peer.setPersistentKeepalive(it) }

        return Config.Builder()
            .setInterface(iface.build())
            .addPeer(peer.build())
            .build()
    }

    private fun applyProfile(iface: Interface.Builder, p: AwgProfile) {
        p.junkPacketCount?.let { iface.setJunkPacketCount(it) }
        p.junkPacketMinSize?.let { iface.setJunkPacketMinSize(it) }
        p.junkPacketMaxSize?.let { iface.setJunkPacketMaxSize(it) }
        p.initPacketJunkSize?.let { iface.setInitPacketJunkSize(it) }
        p.responsePacketJunkSize?.let { iface.setResponsePacketJunkSize(it) }
        p.cookieReplyPacketJunkSize?.let { iface.setCookieReplyPacketJunkSize(it) }
        p.transportPacketJunkSize?.let { iface.setTransportPacketJunkSize(it) }
        p.initPacketMagicHeader?.let { iface.setInitPacketMagicHeader(it) }
        p.responsePacketMagicHeader?.let { iface.setResponsePacketMagicHeader(it) }
        p.underloadPacketMagicHeader?.let { iface.setUnderloadPacketMagicHeader(it) }
        p.transportPacketMagicHeader?.let { iface.setTransportPacketMagicHeader(it) }
        p.specialJunkI1?.let { iface.setSpecialJunkI1(it) }
        p.specialJunkI2?.let { iface.setSpecialJunkI2(it) }
        p.specialJunkI3?.let { iface.setSpecialJunkI3(it) }
        p.specialJunkI4?.let { iface.setSpecialJunkI4(it) }
        p.specialJunkI5?.let { iface.setSpecialJunkI5(it) }
        p.headerProtectionKeyBase64?.let { iface.setHeaderProtectionKey(Key.fromBase64(it)) }
        p.contentPaddingAddition?.let { iface.setContentPaddingAddition(it) }
        p.randomTrailers?.let { iface.setRandomTrailers(if (it) "on" else "off") }
        p.disableCookies?.let { iface.setDisableCookies(if (it) "on" else "off") }
        p.rekeyAfterTime?.let { iface.setRekeyAfterTime(it) }
        p.rekeyTimeout?.let { iface.setRekeyTimeout(it) }
        p.rejectAfterTime?.let { iface.setRejectAfterTime(it) }
        p.keepaliveTimeout?.let { iface.setKeepaliveTimeout(it) }
        p.maxHandshakeAttempts?.let { iface.setMaxHandshakeAttempts(it) }
    }
}
