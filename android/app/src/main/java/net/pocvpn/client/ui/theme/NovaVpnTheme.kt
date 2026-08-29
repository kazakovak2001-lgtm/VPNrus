package net.pocvpn.client.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/**
 * B8E - one accent color, a dark-navy scheme and a light-neutral scheme.
 * Not a design-system framework - just the two ColorSchemes Material3
 * itself already models, switched by the system light/dark setting.
 */

// Single strong accent - used for the power button, the primary Activate
// button, and small highlight touches. Same hue in both schemes so the
// brand reads consistently regardless of theme.
private val Accent = Color(0xFF3DDC97)
private val AccentOnDark = Color(0xFF0B1220)

private val NavyBackground = Color(0xFF0B1220)
private val NavySurface = Color(0xFF141B2E)
private val NavySurfaceVariant = Color(0xFF1E2740)
private val NavyOnBackground = Color(0xFFE7ECF7)
private val NavyOnSurfaceVariant = Color(0xFFA9B2C7)

private val NeutralBackground = Color(0xFFF7F8FB)
private val NeutralSurface = Color(0xFFFFFFFF)
private val NeutralSurfaceVariant = Color(0xFFEDEFF5)
private val NeutralOnBackground = Color(0xFF14182B)
private val NeutralOnSurfaceVariant = Color(0xFF5C6478)

private val NovaDarkColorScheme = darkColorScheme(
    primary = Accent,
    onPrimary = AccentOnDark,
    background = NavyBackground,
    onBackground = NavyOnBackground,
    surface = NavySurface,
    onSurface = NavyOnBackground,
    surfaceVariant = NavySurfaceVariant,
    onSurfaceVariant = NavyOnSurfaceVariant,
    error = Color(0xFFFF6B6B),
)

private val NovaLightColorScheme = lightColorScheme(
    primary = Accent,
    onPrimary = AccentOnDark,
    background = NeutralBackground,
    onBackground = NeutralOnBackground,
    surface = NeutralSurface,
    onSurface = NeutralOnBackground,
    surfaceVariant = NeutralSurfaceVariant,
    onSurfaceVariant = NeutralOnSurfaceVariant,
    error = Color(0xFFD1372E),
)

@Composable
fun NovaVpnTheme(content: @Composable () -> Unit) {
    val colorScheme = if (isSystemInDarkTheme()) NovaDarkColorScheme else NovaLightColorScheme
    MaterialTheme(colorScheme = colorScheme, content = content)
}
