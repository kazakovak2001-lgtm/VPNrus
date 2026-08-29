package net.pocvpn.client.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import net.pocvpn.client.ui.HomeVisualState

/**
 * B8E - the large circular VPN control. Visually communicates connection
 * state (per HomeVisualState) rather than just being a generic button:
 * solid accent fill + steady power glyph when connected, outlined/neutral
 * when disconnected, a rotating progress ring while in flight, and an
 * error-tinted ring with the same power glyph when failed (tapping it
 * retries, same onClick as connect).
 */
@Composable
fun VpnPowerButton(
    state: HomeVisualState,
    onClick: () -> Unit,
    contentDescription: String,
    modifier: Modifier = Modifier,
) {
    val colors = MaterialTheme.colorScheme
    val ringColor = when (state) {
        HomeVisualState.CONNECTED -> colors.primary
        HomeVisualState.FAILED -> colors.error
        HomeVisualState.IN_PROGRESS -> colors.primary
        HomeVisualState.DISCONNECTED -> colors.onSurfaceVariant
    }
    val fillColor = if (state == HomeVisualState.CONNECTED) colors.primary else Color.Transparent

    Box(
        contentAlignment = Alignment.Center,
        modifier = modifier
            .size(148.dp)
            .semantics { this.contentDescription = contentDescription }
            .clickable(onClick = onClick),
    ) {
        when (state) {
            HomeVisualState.IN_PROGRESS -> {
                val transition = rememberInfiniteTransition(label = "vpn-power-spin")
                val angle by transition.animateFloat(
                    initialValue = 0f,
                    targetValue = 360f,
                    animationSpec = infiniteRepeatable(tween(1400, easing = LinearEasing)),
                    label = "vpn-power-spin-angle",
                )
                CircularProgressIndicator(
                    modifier = Modifier.size(148.dp).rotate(angle),
                    color = ringColor,
                    strokeWidth = 4.dp,
                )
            }
            else -> {
                Box(
                    modifier = Modifier
                        .size(148.dp)
                        .background(color = fillColor, shape = CircleShape),
                )
            }
        }

        PowerGlyph(
            tint = if (state == HomeVisualState.CONNECTED) colors.onPrimary else ringColor,
            modifier = Modifier.size(56.dp),
        )
    }
}
