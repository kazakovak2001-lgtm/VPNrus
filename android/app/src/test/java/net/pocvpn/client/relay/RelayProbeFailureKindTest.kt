package net.pocvpn.client.relay

import java.io.IOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLHandshakeException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RelayProbeFailureKindTest {
    @Test fun `HTTPS probe classifies authoritative exception types without reading messages`() {
        assertEquals(RelayProbeFailureKind.DNS_RESOLUTION_FAILED, relayProbeFailureKindFor(UnknownHostException("tls timeout")))
        assertEquals(RelayProbeFailureKind.TLS_HANDSHAKE_FAILED, relayProbeFailureKindFor(SSLHandshakeException("dns failure")))
        assertEquals(RelayProbeFailureKind.REQUEST_TIMED_OUT, relayProbeFailureKindFor(SocketTimeoutException("irrelevant")))
        assertNull(relayProbeFailureKindFor(IOException("dns tls timeout")))
    }
}
