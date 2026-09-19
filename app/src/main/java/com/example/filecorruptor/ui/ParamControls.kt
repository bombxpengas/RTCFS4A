package com.example.filecorruptor.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.filecorruptor.engine.ParamType
import com.example.filecorruptor.engine.ParamValue
import com.example.filecorruptor.engine.ParameterDef

/**
 * Renders the right control for a [ParameterDef] and reports changes back via
 * [onValueChange]. Sliders also get a compact exact-value text field next to
 * them — a plain slider alone can't be set to a precise number, which was the
 * whole reason this generic parameter system replaced the old one-slider UI.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ParameterControl(
    def: ParameterDef,
    value: ParamValue,
    onValueChange: (ParamValue) -> Unit,
    modifier: Modifier = Modifier
) {
    when (def.type) {
        ParamType.SLIDER -> SliderWithField(def, value, onValueChange, modifier)
        ParamType.NUMBER -> NumberField(def, value, onValueChange, modifier)
        ParamType.SWITCH -> SwitchRow(def, value, onValueChange, modifier)
        ParamType.DROPDOWN -> DropdownField(def, value, onValueChange, modifier)
        ParamType.TEXT -> FreeTextField(def, value, onValueChange, modifier)
    }
}

@Composable
private fun ParamLabel(def: ParameterDef) {
    Text(def.label, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Medium)
    if (def.description.isNotBlank()) {
        Text(
            def.description,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun SliderWithField(
    def: ParameterDef,
    value: ParamValue,
    onValueChange: (ParamValue) -> Unit,
    modifier: Modifier = Modifier
) {
    // Local text buffer so the user can type freely (including transiently
    // invalid states like "" or "-") without the slider fighting them. Keyed
    // on the value's own text too (not just def.id) so an externally-applied
    // change — e.g. importing a config — resyncs this field; mid-typing it
    // won't reset, since invalid intermediate text never updates `value`.
    var text by remember(def.id, value.raw) { mutableStateOf(formatNumber(value.asDouble())) }
    val current = value.asDouble().toFloat()

    Column(modifier) {
        ParamLabel(def)
        Spacer(Modifier.height(4.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Slider(
                value = current.coerceIn(def.min.toFloat(), def.max.toFloat()),
                onValueChange = {
                    val stepped = snapToStep(it.toDouble(), def.step, def.min)
                    text = formatNumber(stepped)
                    onValueChange(ParamValue.of(stepped))
                },
                valueRange = def.min.toFloat()..def.max.toFloat(),
                modifier = Modifier.weight(1f)
            )
            Spacer(Modifier.width(8.dp))
            OutlinedTextField(
                value = text,
                onValueChange = { input ->
                    text = input
                    input.toDoubleOrNull()?.let { parsed ->
                        val clamped = parsed.coerceIn(def.min, def.max)
                        onValueChange(ParamValue.of(clamped))
                    }
                },
                singleLine = true,
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.Decimal),
                suffix = if (def.unit.isNotBlank()) { { Text(def.unit, fontSize = 12.sp) } } else null,
                modifier = Modifier.width(96.dp)
            )
        }
    }
}

@Composable
private fun NumberField(
    def: ParameterDef,
    value: ParamValue,
    onValueChange: (ParamValue) -> Unit,
    modifier: Modifier = Modifier
) {
    var text by remember(def.id, value.raw) { mutableStateOf(formatNumber(value.asDouble())) }
    Column(modifier) {
        ParamLabel(def)
        Spacer(Modifier.height(4.dp))
        OutlinedTextField(
            value = text,
            onValueChange = { input ->
                text = input
                input.toDoubleOrNull()?.let { parsed ->
                    val clamped = parsed.coerceIn(def.min, def.max)
                    onValueChange(ParamValue.of(clamped))
                }
            },
            singleLine = true,
            keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.Decimal),
            suffix = if (def.unit.isNotBlank()) { { Text(def.unit, fontSize = 12.sp) } } else null,
            modifier = Modifier.fillMaxWidth()
        )
    }
}

@Composable
private fun SwitchRow(
    def: ParameterDef,
    value: ParamValue,
    onValueChange: (ParamValue) -> Unit,
    modifier: Modifier = Modifier
) {
    Row(
        modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) { ParamLabel(def) }
        Switch(checked = value.asBoolean(), onCheckedChange = { onValueChange(ParamValue.of(it)) })
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DropdownField(
    def: ParameterDef,
    value: ParamValue,
    onValueChange: (ParamValue) -> Unit,
    modifier: Modifier = Modifier
) {
    var expanded by remember { mutableStateOf(false) }
    Column(modifier) {
        ParamLabel(def)
        Spacer(Modifier.height(4.dp))
        ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
            OutlinedTextField(
                value = value.asString(),
                onValueChange = {},
                readOnly = true,
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                modifier = Modifier.menuAnchor().fillMaxWidth()
            )
            ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                def.options.forEach { option ->
                    DropdownMenuItem(
                        text = { Text(option) },
                        onClick = { onValueChange(ParamValue.of(option)); expanded = false }
                    )
                }
            }
        }
    }
}

@Composable
private fun FreeTextField(
    def: ParameterDef,
    value: ParamValue,
    onValueChange: (ParamValue) -> Unit,
    modifier: Modifier = Modifier
) {
    Column(modifier) {
        ParamLabel(def)
        Spacer(Modifier.height(4.dp))
        OutlinedTextField(
            value = value.asString(),
            onValueChange = { onValueChange(ParamValue.of(it)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
    }
}

private fun snapToStep(value: Double, step: Double, min: Double): Double {
    if (step <= 0.0) return value
    val steps = ((value - min) / step).let { kotlin.math.round(it) }
    return min + steps * step
}

private fun formatNumber(d: Double): String =
    if (d == d.toLong().toDouble()) d.toLong().toString() else d.toString()
