package net.pocvpn.client.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import net.pocvpn.client.R

/**
 * B13 - real, clickable gateway-location card: [country]/[city] reflect
 * whichever gateway is ACTUALLY currently selected (see
 * MainViewModel.selectedGateway/ProductionGatewayCatalog), never the
 * static "Germany / Frankfurt" placeholder text this card used to render
 * unconditionally (B8E's own "server selection is explicitly out of scope"
 * note no longer applies - see [onClick]).
 */
@Composable
fun LocationCard(country: String, city: String, onClick: () -> Unit, modifier: Modifier = Modifier) {
    val locationDescription = stringResource(R.string.home_location_content_description)
    val chevronDescription = stringResource(R.string.home_location_chevron_content_description)

    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
        modifier = modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(20.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 20.dp, vertical = 18.dp)
            .semantics { contentDescription = locationDescription },
    ) {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .size(36.dp)
                .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.18f), CircleShape),
        ) {
            LocationPinGlyph(tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(20.dp))
        }

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = country,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = city,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        ChevronRightGlyph(
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(20.dp).semantics { contentDescription = chevronDescription },
        )
    }
}
