package net.pocvpn.client.debug.b46_3b

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.widget.TextView

private const val TAG = "B46_3B_Consent"
private const val REQUEST_VPN_CONSENT = 4001

/**
 * B46-3B - DEBUG/RESEARCH ONLY. Manual entry point to trigger the real
 * Android `VpnService.prepare()` consent dialog and record whether it was
 * shown/accepted - purely a device-diagnostic tool for the physical
 * process-isolation pass (see docs/B46_3B_HYSTERIA_PROCESS_ISOLATION.md
 * Part 9), never wired into any production flow. Never fabricates consent -
 * only reports the real `Activity.RESULT_OK`/`RESULT_CANCELED` this
 * activity itself receives back from the real system dialog.
 */
class Tun2SocksIsolatedConsentActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val tv = TextView(this)
        tv.text = "B46-3B VPN consent probe"
        setContentView(tv)

        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent == null) {
            Log.i(TAG, "B46_3B_CONSENT_ALREADY_PREPARED")
            finish()
        } else {
            Log.i(TAG, "B46_3B_CONSENT_INTENT_REQUIRED")
            startActivityForResult(prepareIntent, REQUEST_VPN_CONSENT)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN_CONSENT) {
            if (resultCode == RESULT_OK) {
                Log.i(TAG, "B46_3B_CONSENT_GRANTED")
            } else {
                Log.w(TAG, "B46_3B_CONSENT_DENIED_OR_CANCELED: resultCode=$resultCode")
            }
        }
        finish()
    }
}
