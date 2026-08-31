package net.pocvpn.client.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import net.pocvpn.client.R

/**
 * B8E - redesigned first-run activation screen. Shown when no provisioned
 * profile exists at all (see AppRoot / net.pocvpn.client.ui.screenFor), and
 * (B15) reused, unchanged, for activating an ADDITIONAL gateway on an
 * already-provisioned device (AppRoot's activatingGatewayId path, reached
 * from GatewayPickerDialog's "Activate" action on an unprovisioned row).
 * credential/onCredentialChange are hoisted, not remembered here - the
 * caller (MainActivity's Compose host) owns the field's value so it can be
 * cleared from a single place on success (see MainActivity's own comment).
 *
 * [onCancel] is null for the mandatory first-run path (there is nothing to
 * cancel back to) and non-null only for the B15 additional-gateway path,
 * where the user reached this screen from a dismissible dialog and must be
 * able to back out of it the same way.
 */
@Composable
fun ActivationScreen(
    credential: String,
    onCredentialChange: (String) -> Unit,
    onActivateClick: () -> Unit,
    errorText: String?,
    isSubmitting: Boolean,
    modifier: Modifier = Modifier,
    onCancel: (() -> Unit)? = null,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 32.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = stringResource(R.string.app_name),
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onBackground,
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = stringResource(R.string.activation_title),
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onBackground,
        )
        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = stringResource(R.string.activation_helper_text),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(28.dp))

        OutlinedTextField(
            value = credential,
            onValueChange = onCredentialChange,
            label = { Text(stringResource(R.string.activation_credential_label)) },
            singleLine = true,
            enabled = !isSubmitting,
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = MaterialTheme.colorScheme.primary,
                cursorColor = MaterialTheme.colorScheme.primary,
            ),
            modifier = Modifier.fillMaxWidth(),
        )

        errorText?.let {
            Spacer(modifier = Modifier.height(8.dp))
            Text(text = it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }

        Spacer(modifier = Modifier.height(20.dp))

        Button(
            onClick = onActivateClick,
            enabled = !isSubmitting && credential.isNotBlank(),
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = MaterialTheme.colorScheme.onPrimary,
            ),
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
        ) {
            Text(stringResource(R.string.activation_button))
        }

        if (onCancel != null) {
            Spacer(modifier = Modifier.height(8.dp))
            TextButton(
                onClick = onCancel,
                enabled = !isSubmitting,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.activation_cancel_button))
            }
        }
    }
}
