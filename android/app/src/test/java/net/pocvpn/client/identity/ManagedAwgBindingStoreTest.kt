package net.pocvpn.client.identity

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import net.pocvpn.client.vpn.config.ProductionGatewayId
import org.amnezia.awg.crypto.KeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.Base64

class ManagedAwgBindingStoreTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val k0 = KeyPair().publicKey.toBase64()
    private val k1 = KeyPair().publicKey.toBase64()
    private val fp0 = ManagedAwgKeyFingerprint.of(k0)
    private val fp1 = ManagedAwgKeyFingerprint.of(k1)

    private fun store(dir: File = tempFolder.root) = FileManagedAwgBindingStore(dir)
    private fun bindingFile(dir: File = tempFolder.root) = File(dir, "managed_awg_binding.bin")
    private fun key(publicKey: String): suspend () -> ManagedKeyPeek = { ManagedKeyPeek.Present(publicKey) }

    private fun valid(result: ManagedAwgBindingLoadResult) = (result as ManagedAwgBindingLoadResult.Valid).bindings
    private fun assertUnreadable(result: ManagedAwgBindingLoadResult) =
        assertTrue("expected Unreadable, was $result", result is ManagedAwgBindingLoadResult.Unreadable)

    // --- fingerprint ---

    @Test
    fun `fingerprint is deterministic, 16 lowercase hex, and distinct per key`() {
        assertEquals(fp0, ManagedAwgKeyFingerprint.of(k0))
        assertEquals(fp0, ManagedAwgKeyFingerprint.of("  $k0\n"))
        assertTrue(Regex("^[0-9a-f]{16}$").matches(fp0))
        assertNotEquals(fp0, fp1)
    }

    @Test
    fun `fingerprint rejects non-base64 and wrong-length keys`() {
        assertThrows(IllegalArgumentException::class.java) { ManagedAwgKeyFingerprint.of("not base64 !!") }
        assertThrows(IllegalArgumentException::class.java) {
            ManagedAwgKeyFingerprint.of(Base64.getEncoder().encodeToString(ByteArray(31)))
        }
    }

    // --- persistence ---

    @Test
    fun `missing file reads Absent`() = runBlocking {
        assertEquals(ManagedAwgBindingLoadResult.Absent, store().read())
    }

    @Test
    fun `round trip of multiple gateways survives a fresh instance`() = runBlocking {
        val s = store()
        assertEquals(ManagedAwgBindingUpdateResult.Updated, s.updateGateway(ProductionGatewayId.GERMANY, fp1, key(k1)))
        assertEquals(ManagedAwgBindingUpdateResult.Updated, s.updateGateway(ProductionGatewayId.STOCKHOLM, fp1, key(k1)))

        assertEquals(
            mapOf(ProductionGatewayId.GERMANY to fp1, ProductionGatewayId.STOCKHOLM to fp1),
            valid(store().read()),
        )
    }

    @Test
    fun `updating one gateway keeps the other valid binding`() = runBlocking {
        val s = store()
        s.updateGateway(ProductionGatewayId.STOCKHOLM, fp0, key(k0))
        s.updateGateway(ProductionGatewayId.GERMANY, fp1, key(k1))

        assertEquals(
            mapOf(ProductionGatewayId.STOCKHOLM to fp0, ProductionGatewayId.GERMANY to fp1),
            valid(s.read()),
        )
    }

    @Test
    fun `truncated file fails closed`() = runBlocking {
        store().updateGateway(ProductionGatewayId.GERMANY, fp0, key(k0))
        val bytes = bindingFile().readBytes()
        bindingFile().writeBytes(bytes.copyOf(bytes.size - 5))
        assertUnreadable(store().read())
        bindingFile().writeBytes(bytes.copyOf(3))
        assertUnreadable(store().read())
    }

    @Test
    fun `bad magic fails closed`() = runBlocking {
        store().updateGateway(ProductionGatewayId.GERMANY, fp0, key(k0))
        val bytes = bindingFile().readBytes()
        bytes[0] = 'X'.code.toByte()
        bindingFile().writeBytes(bytes)
        assertUnreadable(store().read())
    }

    @Test
    fun `bad checksum fails closed`() = runBlocking {
        store().updateGateway(ProductionGatewayId.GERMANY, fp0, key(k0))
        val bytes = bindingFile().readBytes()
        bytes[bytes.size - 9] = (bytes[bytes.size - 9] + 1).toByte() // last fingerprint char, CRC unchanged
        bindingFile().writeBytes(bytes)
        assertUnreadable(store().read())
    }

    @Test
    fun `unsupported version fails closed even with a valid checksum`() = runBlocking {
        val bytes = FileManagedAwgBindingStore.encode(mapOf(ProductionGatewayId.GERMANY to fp0))
        bytes[7] = 2 // FORMAT_VERSION low byte (after 4 magic bytes)
        val body = bytes.copyOf(bytes.size - 8)
        val crc = java.util.zip.CRC32().apply { update(body) }.value
        val out = java.io.ByteArrayOutputStream().also { b ->
            java.io.DataOutputStream(b).use { it.write(body); it.writeLong(crc) }
        }.toByteArray()
        bindingFile().writeBytes(out)
        val result = store().read()
        assertUnreadable(result)
        assertTrue((result as ManagedAwgBindingLoadResult.Unreadable).reason.contains("version"))
    }

    @Test
    fun `malformed entries fail closed`() = runBlocking {
        fun withValidCrc(body: ByteArray): ByteArray {
            val crc = java.util.zip.CRC32().apply { update(body) }.value
            return java.io.ByteArrayOutputStream().also { b ->
                java.io.DataOutputStream(b).use { it.write(body); it.writeLong(crc) }
            }.toByteArray()
        }
        fun body(name: String, fingerprint: String, count: Int = 1, duplicate: Boolean = false): ByteArray =
            java.io.ByteArrayOutputStream().also { b ->
                java.io.DataOutputStream(b).use { out ->
                    out.write(FileManagedAwgBindingStore.MAGIC)
                    out.writeInt(FileManagedAwgBindingStore.FORMAT_VERSION)
                    out.writeInt(if (duplicate) 2 else count)
                    repeat(if (duplicate) 2 else 1) {
                        out.writeShort(name.length)
                        out.write(name.toByteArray())
                        out.write(fingerprint.toByteArray())
                    }
                }
            }.toByteArray()

        // unknown gateway id
        bindingFile().writeBytes(withValidCrc(body("ATLANTIS", fp0)))
        assertUnreadable(store().read())
        // fingerprint not lowercase hex
        bindingFile().writeBytes(withValidCrc(body("GERMANY", "ZZZZZZZZZZZZZZZZ")))
        assertUnreadable(store().read())
        // duplicate gateway id
        bindingFile().writeBytes(withValidCrc(body("GERMANY", fp0, duplicate = true)))
        assertUnreadable(store().read())
        // implausible count
        bindingFile().writeBytes(withValidCrc(body("GERMANY", fp0, count = 9999)))
        assertUnreadable(store().read())
    }

    @Test
    fun `leftover temp file without a committed target creates no binding`() = runBlocking {
        val tmp = File(tempFolder.root, "managed_awg_binding.bin.tmp")
        tmp.writeBytes(FileManagedAwgBindingStore.encode(mapOf(ProductionGatewayId.GERMANY to fp0)))
        assertEquals(ManagedAwgBindingLoadResult.Absent, store().read())
    }

    @Test
    fun `leftover temp file never overrides a committed target`() = runBlocking {
        store().updateGateway(ProductionGatewayId.GERMANY, fp0, key(k0))
        File(tempFolder.root, "managed_awg_binding.bin.tmp")
            .writeBytes(FileManagedAwgBindingStore.encode(mapOf(ProductionGatewayId.GERMANY to fp1)))
        assertEquals(mapOf(ProductionGatewayId.GERMANY to fp0), valid(store().read()))
    }

    @Test
    fun `failed write is reported and the previous valid target is preserved`() = runBlocking {
        val s = store()
        s.updateGateway(ProductionGatewayId.GERMANY, fp0, key(k0))
        // A directory squatting on the temp path makes the temp write fail.
        File(tempFolder.root, "managed_awg_binding.bin.tmp").mkdir()

        val result = s.updateGateway(ProductionGatewayId.STOCKHOLM, fp0, key(k0))

        assertTrue("expected WriteFailed, was $result", result is ManagedAwgBindingUpdateResult.WriteFailed)
        assertEquals(mapOf(ProductionGatewayId.GERMANY to fp0), valid(store().read()))
    }

    @Test
    fun `uncreatable directory is reported as a write failure`() = runBlocking {
        val notADir = tempFolder.newFile("occupied")
        val result = store(notADir).updateGateway(ProductionGatewayId.GERMANY, fp0, key(k0))
        assertTrue("expected WriteFailed, was $result", result is ManagedAwgBindingUpdateResult.WriteFailed)
    }

    @Test
    fun `unreadable file is not silently overwritten by a per-gateway update`() = runBlocking {
        bindingFile().writeBytes(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20))
        val before = bindingFile().readBytes()

        val result = store().updateGateway(ProductionGatewayId.GERMANY, fp0, key(k0))

        assertTrue("expected StoreUnreadable, was $result", result is ManagedAwgBindingUpdateResult.StoreUnreadable)
        assertTrue(before.contentEquals(bindingFile().readBytes()))
    }

    @Test
    fun `deleteAll removes committed and temp files`() = runBlocking {
        val s = store()
        s.updateGateway(ProductionGatewayId.GERMANY, fp0, key(k0))
        File(tempFolder.root, "managed_awg_binding.bin.tmp").writeText("x")

        assertEquals(ManagedAwgBindingDeleteResult.Deleted, s.deleteAll())
        assertEquals(ManagedAwgBindingLoadResult.Absent, s.read())
        assertFalse(File(tempFolder.root, "managed_awg_binding.bin.tmp").exists())
    }

    // --- guarded update / concurrency ---

    @Test
    fun `stale activation fingerprint never creates a binding after the key changed`() = runBlocking {
        var current = k0
        val activationFingerprint = ManagedAwgKeyFingerprint.of(current) // activation request used K0
        current = k1 // managed key changed before the guarded update

        val result = store().updateGateway(ProductionGatewayId.GERMANY, activationFingerprint) { ManagedKeyPeek.Present(current) }

        assertEquals(ManagedAwgBindingUpdateResult.FingerprintMismatch, result)
        assertEquals(ManagedAwgBindingLoadResult.Absent, store().read())
    }

    @Test
    fun `missing or unavailable current key never creates a binding`() = runBlocking {
        val s = store()
        assertTrue(s.updateGateway(ProductionGatewayId.GERMANY, fp0) { ManagedKeyPeek.Absent } is ManagedAwgBindingUpdateResult.IdentityUnavailable)
        assertTrue(s.updateGateway(ProductionGatewayId.GERMANY, fp0) { ManagedKeyPeek.Unavailable("corrupt") } is ManagedAwgBindingUpdateResult.IdentityUnavailable)
        assertEquals(ManagedAwgBindingLoadResult.Absent, s.read())
    }

    @Test
    fun `malformed activation fingerprint is rejected`() = runBlocking {
        assertEquals(
            ManagedAwgBindingUpdateResult.FingerprintMismatch,
            store().updateGateway(ProductionGatewayId.GERMANY, "nothex", key(k0)),
        )
    }

    @Test
    fun `concurrent updates for different gateways are serialized and both survive`() = runBlocking {
        val s = store()
        val gate = CompletableDeferred<Unit>()
        val germanyEnteredCheck = CompletableDeferred<Unit>()

        val germany = async {
            s.updateGateway(ProductionGatewayId.GERMANY, fp0) {
                germanyEnteredCheck.complete(Unit)
                gate.await() // holds the store lock mid check-then-write
                ManagedKeyPeek.Present(k0)
            }
        }
        germanyEnteredCheck.await()
        val stockholm = async { s.updateGateway(ProductionGatewayId.STOCKHOLM, fp0, key(k0)) }
        yield()
        assertFalse("Stockholm must wait for the lock held by Germany", stockholm.isCompleted)

        gate.complete(Unit)
        assertEquals(ManagedAwgBindingUpdateResult.Updated, germany.await())
        assertEquals(ManagedAwgBindingUpdateResult.Updated, stockholm.await())
        assertEquals(
            mapOf(ProductionGatewayId.GERMANY to fp0, ProductionGatewayId.STOCKHOLM to fp0),
            valid(s.read()),
        )
    }

    // --- removeGateway (A-1) ---

    @Test
    fun `removeGateway unbinds only the target gateway`() = runBlocking {
        val s = store()
        s.updateGateway(ProductionGatewayId.GERMANY, fp0, key(k0))
        s.updateGateway(ProductionGatewayId.STOCKHOLM, fp0, key(k0))

        assertEquals(ManagedAwgBindingRemoveResult.Removed, s.removeGateway(ProductionGatewayId.GERMANY))

        assertEquals(mapOf(ProductionGatewayId.STOCKHOLM to fp0), valid(store().read()))
    }

    @Test
    fun `removing the last binding leaves a valid empty store, never an absent or unreadable one`() = runBlocking {
        val s = store()
        s.updateGateway(ProductionGatewayId.GERMANY, fp0, key(k0))

        assertEquals(ManagedAwgBindingRemoveResult.Removed, s.removeGateway(ProductionGatewayId.GERMANY))

        assertEquals(ManagedAwgBindingLoadResult.Valid(emptyMap()), store().read())
    }

    @Test
    fun `removeGateway on an absent store or unbound gateway is Removed and writes nothing`() = runBlocking {
        assertEquals(ManagedAwgBindingRemoveResult.Removed, store().removeGateway(ProductionGatewayId.GERMANY))
        assertFalse(bindingFile().exists())

        store().updateGateway(ProductionGatewayId.STOCKHOLM, fp0, key(k0))
        val before = bindingFile().readBytes()
        assertEquals(ManagedAwgBindingRemoveResult.Removed, store().removeGateway(ProductionGatewayId.GERMANY))
        assertTrue(before.contentEquals(bindingFile().readBytes()))
    }

    @Test
    fun `removeGateway on an unreadable store fails closed and leaves the file untouched`() = runBlocking {
        bindingFile().writeBytes(ByteArray(20) { 9 })
        val before = bindingFile().readBytes()

        val result = store().removeGateway(ProductionGatewayId.GERMANY)

        assertTrue("expected StoreUnreadable, was $result", result is ManagedAwgBindingRemoveResult.StoreUnreadable)
        assertTrue(before.contentEquals(bindingFile().readBytes()))
    }

    @Test
    fun `removeGateway write failure is reported and the previous binding is preserved`() = runBlocking {
        val s = store()
        s.updateGateway(ProductionGatewayId.GERMANY, fp0, key(k0))
        File(tempFolder.root, "managed_awg_binding.bin.tmp").mkdir()

        val result = s.removeGateway(ProductionGatewayId.GERMANY)

        assertTrue("expected WriteFailed, was $result", result is ManagedAwgBindingRemoveResult.WriteFailed)
        assertEquals(mapOf(ProductionGatewayId.GERMANY to fp0), valid(store().read()))
    }
}
