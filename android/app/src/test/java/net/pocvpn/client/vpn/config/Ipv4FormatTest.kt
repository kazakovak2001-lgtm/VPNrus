package net.pocvpn.client.vpn.config

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** B13 consolidated review fix (finding 7) - the ONE strict IPv4 validator every store/repository defers to. */
class Ipv4FormatTest {

    @Test
    fun `accepts well-formed addresses with every octet in range`() {
        assertTrue(Ipv4Format.isValid("10.77.0.5"))
        assertTrue(Ipv4Format.isValid("0.0.0.0"))
        assertTrue(Ipv4Format.isValid("255.255.255.255"))
        assertTrue(Ipv4Format.isValid("152.70.43.1"))
    }

    @Test
    fun `rejects an out-of-range octet even though the shape looks right`() {
        assertFalse(Ipv4Format.isValid("999.999.999.999"))
        assertFalse(Ipv4Format.isValid("256.0.0.1"))
        assertFalse(Ipv4Format.isValid("10.77.0.256"))
    }

    @Test
    fun `rejects malformed shapes`() {
        assertFalse(Ipv4Format.isValid("not-an-ip"))
        assertFalse(Ipv4Format.isValid("10.77.0"))
        assertFalse(Ipv4Format.isValid("10.77.0.5.6"))
        assertFalse(Ipv4Format.isValid(""))
    }
}
