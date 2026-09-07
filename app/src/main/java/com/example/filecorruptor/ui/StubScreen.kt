package com.example.filecorruptor.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Save
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.example.filecorruptor.stub.FileStubGenerator
import com.example.filecorruptor.stub.FillPattern
import com.example.filecorruptor.stub.StubSettings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun StubScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var fileNameInput by remember { mutableStateOf("dummy_file") }
    var extension by remember { mutableStateOf("bin") }
    var sizeText by remember { mutableStateOf("10") }
    var unit by remember { mutableStateOf(SizeUnit.MB) }
    var pattern by remember { mutableStateOf(FillPattern.ZEROS) }
    var repeatingText by remember { mutableStateOf("STUB") }
    var isGenerating by remember { mutableStateOf(false) }
    var statusMessage by remember { mutableStateOf<String?>(null) }
    var pendingSettings by remember { mutableStateOf<StubSettings?>(null) }

    val createDocumentLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("*/*")
    ) { uri: Uri? ->
        val settings = pendingSettings
        if (uri == null || settings == null) return@rememberLauncherForActivityResult
        isGenerating = true
        scope.launch {
            withContext(Dispatchers.IO) {
                context.contentResolver.openOutputStream(uri)?.use { out ->
                    FileStubGenerator.generate(out, settings)
                }
            }
            isGenerating = false
            statusMessage = "Generated stub file."
        }
    }

    val sizeBytes: Long? = sizeText.toDoubleOrNull()?.let { (it * unit.multiplier).toLong() }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text("File Stub Generator", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Create placeholder files of an exact size and extension — for testing upload limits, filling storage, or generating junk data.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        OutlinedTextField(
            value = fileNameInput,
            onValueChange = { fileNameInput = it },
            label = { Text("File name") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true
        )

        OutlinedTextField(
            value = extension,
            onValueChange = { extension = it.trimStart('.') },
            label = { Text("Extension (e.g. mp4, jpg, pdf, bin)") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true
        )

        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedTextField(
                value = sizeText,
                onValueChange = { sizeText = it },
                label = { Text("Size") },
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.Decimal),
                modifier = Modifier.weight(1f),
                singleLine = true
            )
            SizeUnitDropdown(unit, onSelect = { unit = it }, modifier = Modifier.weight(1f))
        }

        Text("Quick presets", style = MaterialTheme.typography.titleMedium)
        LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            items(FileStubGenerator.presetSizes()) { (label, bytes) ->
                AssistChip(
                    onClick = {
                        val (value, u) = bestUnitFor(bytes)
                        sizeText = value
                        unit = u
                    },
                    label = { Text(label) }
                )
            }
        }

        Text("Fill pattern", style = MaterialTheme.typography.titleMedium)
        Column {
            FillPattern.entries.forEach { p ->
                Row(
                    Modifier.fillMaxWidth(),
                    verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
                ) {
                    RadioButton(selected = pattern == p, onClick = { pattern = p })
                    Text(p.label, modifier = Modifier.padding(start = 4.dp))
                }
            }
        }

        if (pattern == FillPattern.REPEATING_TEXT) {
            OutlinedTextField(
                value = repeatingText,
                onValueChange = { repeatingText = it },
                label = { Text("Repeating text") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
        }

        sizeBytes?.let {
            Text(
                "Output size: ${formatBytesLong(it)}",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        Button(
            onClick = {
                val bytes = sizeBytes ?: return@Button
                val settings = StubSettings(
                    sizeBytes = bytes,
                    fillPattern = pattern,
                    repeatingText = repeatingText
                )
                pendingSettings = settings
                val ext = extension.trim()
                val suggested = if (ext.isNotEmpty()) "$fileNameInput.$ext" else fileNameInput
                createDocumentLauncher.launch(suggested)
            },
            enabled = sizeBytes != null && sizeBytes > 0 && !isGenerating,
            modifier = Modifier.fillMaxWidth()
        ) {
            if (isGenerating) {
                CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
                Text("Generating...")
            } else {
                Icon(Icons.Filled.Save, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Generate stub file")
            }
        }

        statusMessage?.let {
            AssistChip(onClick = { statusMessage = null }, label = { Text(it) })
        }
    }
}

private enum class SizeUnit(val label: String, val multiplier: Double) {
    KB("KB", 1024.0),
    MB("MB", 1024.0 * 1024.0),
    GB("GB", 1024.0 * 1024.0 * 1024.0)
}

private fun bestUnitFor(bytes: Long): Pair<String, SizeUnit> {
    return when {
        bytes >= SizeUnit.GB.multiplier -> (bytes / SizeUnit.GB.multiplier).toString() to SizeUnit.GB
        bytes >= SizeUnit.MB.multiplier -> (bytes / SizeUnit.MB.multiplier).toString() to SizeUnit.MB
        else -> (bytes / SizeUnit.KB.multiplier).toString() to SizeUnit.KB
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SizeUnitDropdown(selected: SizeUnit, onSelect: (SizeUnit) -> Unit, modifier: Modifier = Modifier) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }, modifier = modifier) {
        OutlinedTextField(
            value = selected.label,
            onValueChange = {},
            readOnly = true,
            label = { Text("Unit") },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier.menuAnchor().fillMaxWidth()
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            SizeUnit.entries.forEach { u ->
                DropdownMenuItem(text = { Text(u.label) }, onClick = { onSelect(u); expanded = false })
            }
        }
    }
}

private fun formatBytesLong(size: Long): String {
    if (size < 1024) return "$size B"
    val kb = size / 1024.0
    if (kb < 1024) return String.format("%.1f KB", kb)
    val mb = kb / 1024.0
    if (mb < 1024) return String.format("%.1f MB", mb)
    return String.format("%.2f GB", mb / 1024.0)
}
