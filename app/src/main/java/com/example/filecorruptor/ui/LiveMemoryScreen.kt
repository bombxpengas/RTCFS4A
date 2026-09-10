package com.example.filecorruptor.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.filecorruptor.engine.CorruptionEngineExecutor
import com.example.filecorruptor.engine.EngineViewModel
import com.example.filecorruptor.engine.ParamValue
import com.example.filecorruptor.engine.isVisible
import com.example.filecorruptor.livemem.LiveProcess
import com.example.filecorruptor.livemem.MemoryRegion
import com.example.filecorruptor.livemem.RootMemoryHelper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private fun formatSize(bytes: Long): String = when {
    bytes >= 1_048_576 -> "%.1f MB".format(bytes / 1_048_576.0)
    bytes >= 1024 -> "%.1f KB".format(bytes / 1024.0)
    else -> "$bytes B"
}

@Composable
fun LiveMemoryScreen(engineViewModel: EngineViewModel = viewModel()) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val engines by engineViewModel.engines.collectAsState()
    val selectedEngineId by engineViewModel.selectedEngineId.collectAsState()
    val engine = engines.firstOrNull { it.id == selectedEngineId }

    var rootChecked by remember { mutableStateOf(false) }
    var rootAvailable by remember { mutableStateOf(false) }

    var processes by remember { mutableStateOf<List<LiveProcess>>(emptyList()) }
    var processLoading by remember { mutableStateOf(false) }
    var selectedProcess by remember { mutableStateOf<LiveProcess?>(null) }

    var regions by remember { mutableStateOf<List<MemoryRegion>>(emptyList()) }
    var regionLoading by remember { mutableStateOf(false) }
    var selectedRegion by remember { mutableStateOf<MemoryRegion?>(null) }

    var isBusy by remember { mutableStateOf(false) }
    var statusMessage by remember { mutableStateOf<String?>(null) }
    var isErrorStatus by remember { mutableStateOf(false) }

    var liveRunning by remember { mutableStateOf(false) }
    var tickIntervalMs by remember { mutableStateOf(250f) }
    var tickCount by remember { mutableStateOf(0) }

    LaunchedEffect(Unit) {
        rootAvailable = withContext(Dispatchers.IO) { RootMemoryHelper.hasRoot() }
        rootChecked = true
    }

    // Stop any live-corrupt loop the moment you leave this tab, rather than
    // letting it keep running against a screen you can no longer see or stop.
    DisposableEffect(Unit) {
        onDispose { liveRunning = false }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text("Live RAM", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Corrupts another running app's real memory in place — an emulator's " +
                "emulated console RAM, for example — instead of a file. This needs root, " +
                "there's no undo, and it can freeze or crash the target app; that's inherent " +
                "to poking live memory, not a bug here.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        if (!rootChecked) {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        } else if (!rootAvailable) {
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Filled.Warning, contentDescription = null, tint = MaterialTheme.colorScheme.onErrorContainer)
                        Spacer(Modifier.width(8.dp))
                        Text(
                            "No root access detected",
                            fontWeight = FontWeight.Medium,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                    }
                    Text(
                        "This screen needs a rooted device with su available, and you'll need to grant this app root when prompted the first time it runs a command.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer
                    )
                    TextButton(onClick = {
                        scope.launch {
                            rootChecked = false
                            rootAvailable = withContext(Dispatchers.IO) { RootMemoryHelper.hasRoot() }
                            rootChecked = true
                        }
                    }) { Text("Check again") }
                }
            }
        } else {
            // --- Engine picker (same engines/parameters as file corruption) ---
            Text("Engine", style = MaterialTheme.typography.titleMedium)
            if (engines.isEmpty()) {
                Text(
                    "No engines installed yet.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(engines) { e ->
                        FilterChip(
                            selected = e.id == selectedEngineId,
                            onClick = { engineViewModel.selectEngine(e.id) },
                            label = { Text(e.name) }
                        )
                    }
                }
            }

            // --- Process picker ---
            FilledTonalButton(
                onClick = {
                    processLoading = true
                    scope.launch {
                        processes = withContext(Dispatchers.IO) { RootMemoryHelper.listProcesses(context) }
                        processLoading = false
                    }
                },
                enabled = !processLoading,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Filled.Refresh, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Refresh running processes")
            }
            if (processLoading) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())

            if (processes.isNotEmpty()) {
                Card {
                    LazyColumn(Modifier.heightIn(max = 260.dp)) {
                        items(processes) { p ->
                            ListItem(
                                headlineContent = { Text(p.name, maxLines = 1) },
                                supportingContent = { Text("pid ${p.pid}") },
                                trailingContent = {
                                    if (selectedProcess?.pid == p.pid) {
                                        Icon(Icons.Filled.Memory, contentDescription = "Selected")
                                    }
                                },
                                modifier = Modifier.clickable {
                                    selectedProcess = p
                                    regions = emptyList()
                                    selectedRegion = null
                                }
                            )
                            HorizontalDivider()
                        }
                    }
                }
            }

            // --- Memory region picker ---
            selectedProcess?.let { proc ->
                Text("Target: ${proc.name} (pid ${proc.pid})", style = MaterialTheme.typography.titleMedium)

                FilledTonalButton(
                    onClick = {
                        regionLoading = true
                        scope.launch {
                            val all = withContext(Dispatchers.IO) { RootMemoryHelper.listMemoryMaps(context, proc.pid) }
                            // Only regions actually worth corrupting: writable,
                            // and at least 4KB (anything smaller is very unlikely
                            // to be a console's whole RAM).
                            regions = all.filter { it.isWritable && it.size >= 4096 }
                                .sortedByDescending { it.size }
                            regionLoading = false
                        }
                    },
                    enabled = !regionLoading,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Filled.Memory, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("Scan memory regions")
                }
                if (regionLoading) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())

                if (regions.isNotEmpty()) {
                    Text(
                        "Pick the region whose size matches the console you're emulating — " +
                            "e.g. ~2KB NES, ~128KB SNES WRAM, ~2MB PS1, ~4-8MB N64, ~24MB DS. " +
                            "There's no reliable way to know for certain without trying it.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Card {
                        LazyColumn(Modifier.heightIn(max = 320.dp)) {
                            items(regions) { region ->
                                ListItem(
                                    headlineContent = { Text(formatSize(region.size)) },
                                    supportingContent = {
                                        Text(
                                            "0x${region.start.toString(16)} - 0x${region.end.toString(16)}  ${region.perms}" +
                                                if (region.path.isNotBlank()) "  ${region.path}" else "  [anonymous]"
                                        )
                                    },
                                    trailingContent = {
                                        if (selectedRegion == region) {
                                            Icon(Icons.Filled.Memory, contentDescription = "Selected")
                                        }
                                    },
                                    modifier = Modifier.clickable { selectedRegion = region }
                                )
                                HorizontalDivider()
                            }
                        }
                    }
                }
            }

            // --- Parameters + corruption controls ---
            val region = selectedRegion
            if (engine != null && region != null) {
                val engineValues = engineViewModel.valuesFor(engine.id)
                val currentValues = engineValues.toMap()

                Text("Parameters", style = MaterialTheme.typography.titleMedium)
                engine.parameters.filterNot { it.hidden }.forEach { def ->
                    AnimatedVisibility(
                        visible = def.isVisible(currentValues),
                        enter = fadeIn() + expandVertically(),
                        exit = fadeOut() + shrinkVertically()
                    ) {
                        ParameterControl(
                            def = def,
                            value = engineValues[def.id] ?: ParamValue(def.default),
                            onValueChange = { engineValues[def.id] = it }
                        )
                    }
                }

                fun runOneCycle(onDone: (Boolean) -> Unit) {
                    val proc = selectedProcess
                    if (proc == null) {
                        onDone(false)
                        return
                    }
                    scope.launch {
                        val ok = withContext(Dispatchers.IO) {
                            val bytes = RootMemoryHelper.readMemory(context, proc.pid, region.start, region.size.toInt())
                                ?: return@withContext false
                            val result = CorruptionEngineExecutor.runWithSeed(bytes, engine, currentValues)
                            if (engineValues.containsKey("lastSeedUsed")) {
                                engineValues["lastSeedUsed"] = ParamValue.of(result.seedUsed.toString())
                            }
                            RootMemoryHelper.writeMemory(context, proc.pid, region.start, result.bytes)
                        }
                        onDone(ok)
                    }
                }

                Button(
                    onClick = {
                        isBusy = true
                        runOneCycle { ok ->
                            isBusy = false
                            isErrorStatus = !ok
                            statusMessage = if (ok) "Corrupted ${formatSize(region.size)} once." else "Read/write failed — process may have exited or region is no longer valid."
                        }
                    },
                    enabled = !isBusy && !liveRunning,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Filled.Bolt, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("Corrupt Once")
                }

                HorizontalDivider()

                Row(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(Modifier.weight(1f)) {
                        Text("Live Corrupting", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Medium)
                        Text(
                            "Repeatedly re-corrupts this region until you turn it off.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(
                        checked = liveRunning,
                        onCheckedChange = {
                            liveRunning = it
                            if (it) tickCount = 0
                        }
                    )
                }

                Column {
                    Text(
                        "Tick every ${tickIntervalMs.toInt()} ms",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Slider(
                        value = tickIntervalMs,
                        onValueChange = { tickIntervalMs = it },
                        valueRange = 50f..2000f,
                        enabled = !liveRunning
                    )
                }

                if (liveRunning) {
                    LaunchedEffect(liveRunning, region, engine.id, tickIntervalMs) {
                        while (liveRunning) {
                            val proc = selectedProcess
                            if (proc == null) {
                                liveRunning = false
                                break
                            }
                            val ok = withContext(Dispatchers.IO) {
                                val bytes = RootMemoryHelper.readMemory(context, proc.pid, region.start, region.size.toInt())
                                    ?: return@withContext false
                                val result = CorruptionEngineExecutor.runWithSeed(bytes, engine, engineValues.toMap())
                                RootMemoryHelper.writeMemory(context, proc.pid, region.start, result.bytes)
                            }
                            if (!ok) {
                                liveRunning = false
                                isErrorStatus = true
                                statusMessage = "Live corrupting stopped — the process may have exited."
                                break
                            }
                            tickCount++
                            delay(tickIntervalMs.toLong())
                        }
                    }
                    Text(
                        "Ticks: $tickCount",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
            }

            statusMessage?.let { msg ->
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = if (isErrorStatus) MaterialTheme.colorScheme.errorContainer
                        else MaterialTheme.colorScheme.surfaceVariant
                    )
                ) {
                    Text(
                        msg,
                        modifier = Modifier.padding(16.dp),
                        color = if (isErrorStatus) MaterialTheme.colorScheme.onErrorContainer
                        else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}
