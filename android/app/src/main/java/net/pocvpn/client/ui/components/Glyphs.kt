package net.pocvpn.client.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke

/**
 * B8E - small hand-drawn glyphs (power / location pin / chevron / settings
 * gear / bug) instead of pulling in the much larger material-icons-extended
 * artifact for four simple shapes. Every glyph is a plain Canvas draw, no
 * new dependency, no design-system framework.
 */

@Composable
fun PowerGlyph(tint: Color, modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val strokeWidth = size.minDimension * 0.12f
        drawArc(
            color = tint,
            startAngle = -230f,
            sweepAngle = 280f,
            useCenter = false,
            style = Stroke(width = strokeWidth, cap = StrokeCap.Round),
        )
        drawLine(
            color = tint,
            start = Offset(size.width / 2f, 0f),
            end = Offset(size.width / 2f, size.height * 0.45f),
            strokeWidth = strokeWidth,
            cap = StrokeCap.Round,
        )
    }
}

@Composable
fun LocationPinGlyph(tint: Color, modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        val path = Path().apply {
            moveTo(w / 2f, h)
            cubicTo(w * 0.1f, h * 0.55f, w * 0.15f, 0f, w / 2f, 0f)
            cubicTo(w * 0.85f, 0f, w * 0.9f, h * 0.55f, w / 2f, h)
            close()
        }
        drawPath(path, color = tint)
        drawCircle(color = Color.White.copy(alpha = 0.85f), radius = w * 0.16f, center = Offset(w / 2f, h * 0.36f))
    }
}

@Composable
fun ChevronRightGlyph(tint: Color, modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        val strokeWidth = size.minDimension * 0.16f
        val path = Path().apply {
            moveTo(w * 0.32f, h * 0.12f)
            lineTo(w * 0.72f, h * 0.5f)
            lineTo(w * 0.32f, h * 0.88f)
        }
        drawPath(path, color = tint, style = Stroke(width = strokeWidth, cap = StrokeCap.Round))
    }
}

@Composable
fun SettingsGlyph(tint: Color, modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val strokeWidth = size.minDimension * 0.1f
        drawCircle(color = tint, radius = size.minDimension * 0.32f, style = Stroke(width = strokeWidth))
        drawCircle(color = tint, radius = size.minDimension * 0.1f)
    }
}

@Composable
fun BugGlyph(tint: Color, modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawOval(
            color = tint,
            topLeft = Offset(w * 0.2f, h * 0.28f),
            size = androidx.compose.ui.geometry.Size(w * 0.6f, h * 0.6f),
        )
        val strokeWidth = size.minDimension * 0.08f
        drawLine(tint, Offset(w * 0.5f, h * 0.28f), Offset(w * 0.5f, h * 0.12f), strokeWidth, cap = StrokeCap.Round)
        drawLine(tint, Offset(w * 0.22f, h * 0.4f), Offset(w * 0.05f, h * 0.3f), strokeWidth, cap = StrokeCap.Round)
        drawLine(tint, Offset(w * 0.78f, h * 0.4f), Offset(w * 0.95f, h * 0.3f), strokeWidth, cap = StrokeCap.Round)
        drawLine(tint, Offset(w * 0.22f, h * 0.7f), Offset(w * 0.05f, h * 0.8f), strokeWidth, cap = StrokeCap.Round)
        drawLine(tint, Offset(w * 0.78f, h * 0.7f), Offset(w * 0.95f, h * 0.8f), strokeWidth, cap = StrokeCap.Round)
    }
}
