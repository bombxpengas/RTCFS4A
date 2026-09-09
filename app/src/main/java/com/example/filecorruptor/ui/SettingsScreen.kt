package com.example.filecorruptor.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.UploadFile
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.filecorruptor.engine.EngineViewModel

@Composable
fun SettingsScreen(engineViewModel: EngineViewModel = viewModel()) {
    val context = LocalContext.current
    val engines by engineViewModel.engines.collectAsState()
    val selectedEngineId by engineViewModel.selectedEngineId.collectAsState()
    val status = engineViewModel.statusMessage.value
    val error = engineViewModel.errorMessage.value
    var showFormatHelp by remember { mutableStateOf(false) }

    val importEngineLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? -> uri?.let { engineViewModel.importEngine(context, it) } }

    val importConfigLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? -> uri?.let { engineViewModel.importConfig(context, it) } }

    val exportConfigLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri: Uri? -> uri?.let { engineViewModel.exportConfig(context, it) } }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text("Settings", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Manage corruption engines. Import a new one as JSON, or export/import your current parameter values as a shareable config.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        status?.let {
            AssistChip(onClick = { engineViewModel.statusMessage.value = null }, label = { Text(it) })
        }
        error?.let {
            AssistChip(
                onClick = { engineViewModel.errorMessage.value = null },
                label = { Text(it) },
                colors = AssistChipDefaults.assistChipColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer,
                    labelColor = MaterialTheme.colorScheme.onErrorContainer
                )
            )
        }

        Text("Engines", style = MaterialTheme.typography.titleMedium)
        engines.forEach { engine ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = if (engine.id == selectedEngineId)
                        MaterialTheme.colorScheme.primaryContainer
                    else
                        MaterialTheme.colorScheme.surfaceVariant
                )
            ) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(engine.name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Medium)
                    if (engine.description.isNotBlank()) {
                        Text(engine.description, style = MaterialTheme.typography.bodyMedium)
                    }
                    Text(
                        buildString {
                            append("v${engine.version}")
                            if (engine.author.isNotBlank()) append(" • ${engine.author}")
                            append(" • ${engine.parameters.size} parameter${if (engine.parameters.size == 1) "" else "s"}")
                        },
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        HorizontalDivider()

        Text("Import & Export", style = MaterialTheme.typography.titleMedium)

        OutlinedButton(
            onClick = { importEngineLauncher.launch(arrayOf("application/json", "*/*")) },
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Filled.UploadFile, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("Import custom engine (JSON)")
        }

        OutlinedButton(
            onClick = {
                val engineId = selectedEngineId ?: return@OutlinedButton
                exportConfigLauncher.launch("${engineId}_config.json")
            },
            enabled = selectedEngineId != null,
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Filled.Download, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("Export current config")
        }

        OutlinedButton(
            onClick = { importConfigLauncher.launch(arrayOf("application/json", "*/*")) },
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Filled.UploadFile, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("Import config")
        }

        HorizontalDivider()

        TextButton(onClick = { showFormatHelp = !showFormatHelp }) {
            Text(if (showFormatHelp) "Hide engine JSON format" else "Show engine JSON format")
        }
        if (showFormatHelp) {
            EngineFormatHelp()
        }
    }
}

@Composable
private fun EngineFormatHelp() {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Engine JSON format", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Medium)
            Text(
                "An engine is \"id\", \"name\", \"description\", \"author\", \"version\", a \"parameters\" array, " +
                    "and an \"operations\" array.",
                style = MaterialTheme.typography.bodyMedium
            )
            Text(
                "Each parameter needs: id, label, type (slider / number / switch / dropdown / text), " +
                    "default, and for slider/number: min, max, step, unit. Dropdown adds an \"options\" " +
                    "array of strings. Set \"hidden\": true to keep a value out of the UI, or " +
                    "\"visibleWhenParam\"/\"visibleWhenValues\" to only show it while another parameter " +
                    "(e.g. a mode dropdown) currently holds certain values.",
                style = MaterialTheme.typography.bodyMedium
            )
            Text(
                "Each operation needs: type (random_bytes, bit_flip, chunk_shuffle, chunk_reverse, " +
                    "byte_shift, zero_out, duplicate_block, random_block_overwrite, byte_corrupt, " +
                    "text_replace_literal, vector_engine, nightmare_engine, hellgenie_engine, " +
                    "pipe_engine, or " +
                    "cluster_engine) and a \"params\" object mapping that operation's argument names to " +
                    "one of your parameter ids. An optional \"enabledParam\" names a switch parameter that " +
                    "turns the whole operation on/off.",
                style = MaterialTheme.typography.bodyMedium
            )
            Text(
                "A parameter named \"seed\" (number, min -1) makes an engine's output reproducible: " +
                    "-1 means random (a fresh seed every run), any value 0 or above is used as a fixed " +
                    "seed instead — no separate on/off switch needed. Multiple operations run in order, " +
                    "each mutating the same bytes.",
                style = MaterialTheme.typography.bodyMedium
            )
            Text(
                "{\n" +
                    "  \"id\": \"my_engine\",\n" +
                    "  \"name\": \"My Engine\",\n" +
                    "  \"parameters\": [\n" +
                    "    {\"id\": \"intensity\", \"label\": \"Intensity\", \"type\": \"slider\",\n" +
                    "     \"min\": 1, \"max\": 100, \"default\": \"20\", \"unit\": \"%\"}\n" +
                    "  ],\n" +
                    "  \"operations\": [\n" +
                    "    {\"type\": \"random_bytes\", \"params\": {\"intensity\": \"intensity\"}}\n" +
                    "  ]\n" +
                    "}",
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            )
        }
    }
}
