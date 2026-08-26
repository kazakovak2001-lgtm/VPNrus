package net.pocvpn.client

import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import net.pocvpn.client.identity.ClientKeyRepository
import net.pocvpn.client.identity.ClientKeyRepositoryFactory

/**
 * B6A developer-only screen: shows the client's AWG public key so it can be
 * copied into gateway provisioning. Deliberately not the real Connect/
 * Disconnect UI (that's B7) - this exists only to get a real public key out
 * of a real device/emulator without ever surfacing the private key.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var repository: ClientKeyRepository
    private lateinit var publicKeyView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        repository = ClientKeyRepositoryFactory.create(applicationContext)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 96, 48, 48)
        }

        root.addView(TextView(this).apply { text = "VPN PoC" })
        root.addView(TextView(this).apply { text = "Transport: AWG 3.1" })

        publicKeyView = TextView(this).apply { text = "Client public key: (loading...)" }
        root.addView(publicKeyView)

        val copyButton = Button(this).apply {
            text = "Copy public key"
            setOnClickListener { copyPublicKeyToClipboard() }
        }
        root.addView(copyButton)

        if (BuildConfig.DEBUG) {
            val regenerateButton = Button(this).apply {
                text = "Regenerate identity (debug only)"
                setOnClickListener { regenerateIdentity() }
            }
            root.addView(regenerateButton)
        }

        setContentView(root)
        loadIdentity()
    }

    private fun loadIdentity() {
        lifecycleScope.launch {
            val identity = repository.getOrCreateIdentity()
            publicKeyView.text = "Client public key: ${identity.publicKeyBase64}"
        }
    }

    private fun regenerateIdentity() {
        lifecycleScope.launch {
            repository.clearIdentity()
            val identity = repository.getOrCreateIdentity()
            publicKeyView.text = "Client public key: ${identity.publicKeyBase64}"
        }
    }

    private fun copyPublicKeyToClipboard() {
        lifecycleScope.launch {
            val publicKey = repository.getPublicKey()
            val clipboard = getSystemService(ClipboardManager::class.java)
            clipboard.setPrimaryClip(ClipData.newPlainText("AWG public key", publicKey))
            Toast.makeText(this@MainActivity, "Public key copied", Toast.LENGTH_SHORT).show()
        }
    }
}
