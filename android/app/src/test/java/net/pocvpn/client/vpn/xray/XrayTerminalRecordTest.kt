package net.pocvpn.client.vpn.xray

import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/** The `:xray` -> main terminal-event record the death watch reads when the broadcast is late. */
class XrayTerminalRecordTest {

    @get:Rule val tmp = TemporaryFolder()

    private fun record() = XrayTerminalRecord(File(tmp.root, "xray-terminal-event"))

    @Test
    fun `Stopped and a typed Failed round-trip`() {
        val r = record()
        r.write(XrayRuntimeEvent.Stopped(42L))
        assertEquals(XrayRuntimeEvent.Stopped(42L), r.read())

        val relayLost = XrayRuntimeState.relayHealthLostEvent(43L, TransportKind.XRAY_XHTTP)
        r.write(relayLost)
        assertEquals(relayLost, r.read())
    }

    @Test
    fun `Started is never recorded`() {
        val r = record()
        r.write(XrayRuntimeEvent.Stopped(1L))
        r.write(XrayRuntimeEvent.Started(2L))
        assertEquals(XrayRuntimeEvent.Stopped(1L), r.read())
    }

    @Test
    fun `missing or malformed files read as no record`() {
        val r = record()
        assertNull(r.read())
        File(tmp.root, "xray-terminal-event").writeText("garbage")
        assertNull(r.read())
        File(tmp.root, "xray-terminal-event").writeText("failed\nnot-a-number\n\nx")
        assertNull(r.read())
    }

    @Test
    fun `a newline in the reason cannot break the format`() {
        val r = record()
        r.write(XrayRuntimeEvent.Failed(7L, "line one\nline two"))
        assertEquals(XrayRuntimeEvent.Failed(7L, "line one line two"), r.read())
    }
}
