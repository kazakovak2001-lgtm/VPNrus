package net.pocvpn.client.vpn.xray

import java.io.File
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class XraySessionIdsTest {

    private class Ceiling(var value: Long? = null, var writable: Boolean = true) {
        var writes = 0
        fun read(): Long? = value
        fun write(v: Long): Boolean {
            writes++
            if (writable) value = v
            return writable
        }
    }

    private fun allocator(ceiling: Ceiling, clock: () -> Long, floor: Long = 0L, reserve: Long = 10L) =
        XraySessionIdAllocator(ceiling::read, ceiling::write, clock, reserve, floor)

    @Test
    fun `ids keep growing across a restart even when the clock moved back`() {
        val ceiling = Ceiling()
        val firstRun = allocator(ceiling, { 1_000_000L })
        val issued = List(25) { firstRun.nextId() }

        // Process restart with the wall clock an hour earlier.
        val secondRun = allocator(ceiling, { 1_000_000L - 3_600_000L })
        val next = secondRun.nextId()

        assertTrue("$next must exceed every earlier id", next > issued.max())
    }

    @Test
    fun `a repeated or frozen timestamp never repeats an id`() {
        val run = allocator(Ceiling(), { 42L })
        val ids = List(100) { run.nextId() }
        assertEquals(ids.size, ids.toSet().size)
        assertEquals(ids.sorted(), ids)
    }

    @Test
    fun `every handed-out id is covered by the persisted ceiling first`() {
        val ceiling = Ceiling()
        val run = allocator(ceiling, { 0L }, reserve = 3L)
        repeat(20) {
            val id = run.nextId()
            assertTrue(id <= ceiling.value!!)
        }
        assertTrue("reserve keeps writes rare: ${ceiling.writes}", ceiling.writes <= 20 / 3 + 1)
    }

    @Test
    fun `a failed ceiling write keeps ids monotonic and is retried`() {
        val ceiling = Ceiling(writable = false)
        val run = allocator(ceiling, { 5L })
        val a = run.nextId()
        val b = run.nextId()
        assertTrue(b > a)
        assertEquals(2, ceiling.writes) // retried, not given up

        ceiling.writable = true
        val c = run.nextId()
        assertTrue(c > b)
        assertTrue(c <= ceiling.value!!)
    }

    @Test
    fun `reinitialising in the same process never goes below an issued id`() {
        val inMemory = allocator(Ceiling(writable = false), { 9_000L })
        val early = inMemory.nextId()

        val installed = allocator(Ceiling(), { 1L }, floor = inMemory.lastIssued())

        assertTrue(installed.nextId() > early)
    }

    @Test
    fun `ceiling file round-trips and treats missing, malformed and negative values as none`() {
        val dir = Files.createTempDirectory("xray-ids").toFile()
        val file = File(dir, "xray-session-id-ceiling")
        val ceiling = XraySessionIdCeilingFile(file)

        assertNull(ceiling.read())
        assertTrue(ceiling.write(123_456L))
        assertEquals(123_456L, XraySessionIdCeilingFile(file).read())

        file.writeText("garbage")
        assertNull(ceiling.read())
        file.writeText("-5")
        assertNull(ceiling.read())
        assertEquals(listOf(file.name), dir.list()!!.toList()) // no temp files left behind
        dir.deleteRecursively()
    }

    @Test
    fun `an unwritable ceiling location fails the write`() {
        val dir = Files.createTempDirectory("xray-ids").toFile()
        val blocker = File(dir, "not-a-dir").apply { writeText("x") }
        assertEquals(false, XraySessionIdCeilingFile(File(blocker, "ceiling")).write(1L))
        dir.deleteRecursively()
    }
}
