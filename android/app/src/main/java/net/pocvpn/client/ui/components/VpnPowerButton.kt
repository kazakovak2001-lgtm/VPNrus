package net.pocvpn.client.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import net.pocvpn.client.ui.HomeVisualState
import kotlin.math.cos
import kotlin.math.sin

/**
 * Secure Orbit - the large circular VPN control. State is drawn, not just
 * tinted: a faint outer orbit with a slowly travelling satellite and a solid
 * accent ring when protected, a rotating sweep arc while in flight, a muted
 * ring when disconnected and an error ring when failed (tap retries, same
 * onClick as connect). The "protected" look is only ever drawn for
 * [HomeVisualState.CONNECTED], which the caller derives from VpnSessionHealth.
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
        HomeVisualState.CONNECTED, HomeVisualState.IN_PROGRESS -> colors.primary
        HomeVisualState.FAILED -> colors.error
        HomeVisualState.DISCONNECTED -> colors.onSurfaceVariant
    }
    val orbitColor = colors.outlineVariant

    // One transition, only advanced by the states that need it.
    val transition = rememberInfiniteTransition(label = "vpn-orbit")
    val sweep by transition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(tween(1400, easing = LinearEasing), RepeatMode.Restart),
        label = "vpn-orbit-sweep",
    )
    val drift by transition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(tween(14_000, easing = LinearEasing), RepeatMode.Restart),
        label = "vpn-orbit-drift",
    )

    Box(
        contentAlignment = Alignment.Center,
        modifier = modifier
            .size(188.dp)
            .semantics {
                this.contentDescription = contentDescription
                role = Role.Button
            }
            .clickable(onClick = onClick),
    ) {
        Canvas(modifier = Modifier.size(188.dp)) {
            val center = Offset(size.width / 2f, size.height / 2f)
            val orbitRadius = size.minDimension / 2f - 4.dp.toPx()
            val ringRadius = orbitRadius - 18.dp.toPx()
            val discRadius = ringRadius - 10.dp.toPx()

            // Outer orbit.
            drawCircle(color = orbitColor, radius = orbitRadius, center = center, style = Stroke(width = 1.5.dp.toPx()))

            // Soft glow + inner disc.
            val glowAlpha = if (state == HomeVisualState.CONNECTED) 0.30f else 0.10f
            drawCircle(
                brush = Brush.radialGradient(
                    colors = listOf(ringColor.copy(alpha = glowAlpha), ringColor.copy(alpha = 0f)),
                    center = center,
                    radius = ringRadius + 14.dp.toPx(),
                ),
                radius = ringRadius + 14.dp.toPx(),
                center = center,
            )
            drawCircle(
                color = ringColor.copy(alpha = if (state == HomeVisualState.CONNECTED) 0.16f else 0.06f),
                radius = discRadius,
                center = center,
            )

            val ringStroke = Stroke(width = 4.dp.toPx(), cap = StrokeCap.Round)
            val arcTopLeft = Offset(center.x - ringRadius, center.y - ringRadius)
            val arcSize = Size(ringRadius * 2, ringRadius * 2)
            when (state) {
                HomeVisualState.IN_PROGRESS -> {
                    drawCircle(color = ringColor.copy(alpha = 0.25f), radius = ringRadius, center = center, style = ringStroke)
                    drawArc(
                        color = ringColor,
                        startAngle = sweep,
                        sweepAngle = 100f,
                        useCenter = false,
                        topLeft = arcTopLeft,
                        size = arcSize,
                        style = ringStroke,
                    )
                }
                else -> drawCircle(color = ringColor, radius = ringRadius, center = center, style = ringStroke)
            }

            // Satellite on the outer orbit - drifts only while protected.
            if (state == HomeVisualState.CONNECTED) {
                val angle = Math.toRadians(drift.toDouble())
                val dot = Offset(
                    center.x + orbitRadius * cos(angle).toFloat(),
                    center.y + orbitRadius * sin(angle).toFloat(),
                )
                drawCircle(color = ringColor, radius = 4.dp.toPx(), center = dot)
            }
        }

        PowerGlyph(tint = ringColor, modifier = Modifier.size(52.dp))
    }
}
