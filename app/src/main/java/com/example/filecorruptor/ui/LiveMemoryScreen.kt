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
import androidx.compose.material.icons.filled.Eco
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

/** Denylist of path substrings that mark a region as Android-runtime/system
 *  plumbing rather than anything belonging to the target app's own game
 *  state — corrupting these just crashes the process almost every time.
 *  This already catches ART/Dalvik heap spaces by their "dalvik" label
 *  regardless of size, which used to also be covered by a separate hard
 *  size cap on top of this — dropped, since it hid perfectly legitimate
 *  large regions in apps with no fixed, known RAM size (a modern game
 *  engine's world/chunk data, unlike a fixed-hardware console's RAM). */
private val NOISY_PATH_MARKERS = listOf(
    "dalvik", "/apex/", "/system/", "/vendor/", ".so", ".dex", ".vdex", ".odex", ".oat", ".art",
    "/dev/", "[vdso]", "[vvar]", "[vsyscall]", "[stack", "jit-cache", "/data/dalvik-cache", "/linker"
)

private fun looksLikeNoise(region: MemoryRegion): Boolean {
    val p = region.path.lowercase()
    return NOISY_PATH_MARKERS.any { marker -> p.contains(marker) }
}

private data class CorruptionTarget(val process: LiveProcess, val region: MemoryRegion)

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
    var processFilter by remember { mutableStateOf("") }

    var regions by remember { mutableStateOf<List<MemoryRegion>>(emptyList()) }
    var regionLoading by remember { mutableStateOf(false) }
    // Tracks the previous scan's results so a re-scan can flag regions that
    // weren't there before — e.g. scan, load a ROM, scan again, and whatever
    // just appeared is a strong candidate for the console RAM the emulator
    // only just allocated. scanCount starts fresh whenever you switch process,
    // since comparing across two different processes' scans is meaningless.
    var previousRegions by remember { mutableStateOf<Set<MemoryRegion>>(emptySet()) }
    var scanCount by remember { mutableStateOf(0) }

    // Accumulated across possibly several processes — pick a process, scan
    // it, add one or more regions, then switch process and add more. Every
    // added target gets corrupted together each cycle.
    var targets by remember { mutableStateOf<List<CorruptionTarget>>(emptyList()) }

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
            var showDiagnostics by remember { mutableStateOf(false) }
            var diagnosticText by remember { mutableStateOf<String?>(null) }
            val helperExists = remember { RootMemoryHelper.helperExists(context) }

            Card(
                colors = CardDefaults.cardColors(
                    containerColor = if (helperExists) MaterialTheme.colorScheme.surfaceVariant
                    else MaterialTheme.colorScheme.errorContainer
                )
            ) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            if (helperExists) "Native helper found on disk" else "Native helper missing on disk",
                            fontWeight = FontWeight.Medium,
                            modifier = Modifier.weight(1f),
                            color = if (helperExists) MaterialTheme.colorScheme.onSurfaceVariant
                            else MaterialTheme.colorScheme.onErrorContainer
                        )
                        TextButton(onClick = { showDiagnostics = !showDiagnostics }) {
                            Text(if (showDiagnostics) "Hide" else "Diagnostics")
                        }
                    }
                    if (!helperExists) {
                        Text(
                            "This means every command below will silently fail, not just process " +
                                "listing — there's no file to run yet. Reinstall the app with the " +
                                "latest build (packaging.jniLibs.useLegacyPackaging must be on so this " +
                                "gets extracted to disk at install time) and check again.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                    }
                    if (showDiagnostics) {
                        Text(
                            "Expected path:\n${RootMemoryHelper.helperPath(context)}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        TextButton(onClick = {
                            scope.launch {
                                diagnosticText = "Running…"
                                diagnosticText = withContext(Dispatchers.IO) {
                                    RootMemoryHelper.runRawDiagnostic(context, "list_processes")
                                }
                            }
                        }) { Text("Run list_processes raw") }
                        diagnosticText?.let {
                            Text(
                                it,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .heightIn(max = 220.dp)
                                    .verticalScroll(rememberScrollState())
                            )
                        }
                    }
                }
            }

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
                OutlinedTextField(
                    value = processFilter,
                    onValueChange = { processFilter = it },
                    label = { Text("Filter by name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                // Same package before the ':' means Android spawned it as a
                // separate process for the same app (a WebView renderer, an
                // isolated service, an SDK's own process, etc.) — that's a
                // real, distinct process with its own /proc/pid/maps, worth
                // checking separately from the main one. This is genuinely
                // different from a single process's map entries multiplying
                // as it allocates more — this is checking whether an app
                // that *looks* like one process actually spawned several.
                val filtered = remember(processes, processFilter) {
                    if (processFilter.isBlank()) processes
                    else processes.filter { it.name.contains(processFilter, ignoreCase = true) }
                }
                val groupCounts = remember(processes) {
                    processes.groupingBy { it.name.substringBefore(':') }.eachCount()
                }

                Card {
                    LazyColumn(Modifier.heightIn(max = 260.dp)) {
                        items(filtered) { p ->
                            val base = p.name.substringBefore(':')
                            val isChildProcess = p.name.contains(':')
                            val siblingCount = groupCounts[base] ?: 1
                            ListItem(
                                headlineContent = { Text(p.name, maxLines = 1) },
                                supportingContent = {
                                    Text(
                                        "pid ${p.pid}" +
                                            if (isChildProcess) "  •  separate process of $base" else "",
                                    )
                                },
                                trailingContent = {
                                    when {
                                        selectedProcess?.pid == p.pid -> Icon(Icons.Filled.Memory, contentDescription = "Selected")
                                        siblingCount > 1 -> Text("${siblingCount}×", style = MaterialTheme.typography.labelMedium)
                                    }
                                },
                                modifier = Modifier.clickable {
                                    selectedProcess = p
                                    regions = emptyList()
                                    previousRegions = emptySet()
                                    scanCount = 0
                                    // targets deliberately NOT cleared here —
                                    // switching process is how you add a
                                    // second process's region to the same
                                    // multi-target corruption set.
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

                var showAllRegions by remember { mutableStateOf(false) }

                FilledTonalButton(
                    onClick = {
                        regionLoading = true
                        scope.launch {
                            val all = withContext(Dispatchers.IO) { RootMemoryHelper.listMemoryMaps(context, proc.pid) }
                            previousRegions = regions.toSet() // snapshot before overwriting, for the "new" comparison below
                            regions = all
                            scanCount++
                            regionLoading = false
                        }
                    },
                    enabled = !regionLoading,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Filled.Memory, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text(if (scanCount == 0) "Scan memory regions" else "Re-scan (highlight new regions)")
                }
                if (regionLoading) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())

                val isNewRegion: (MemoryRegion) -> Boolean = { scanCount > 1 && it !in previousRegions }

                val visibleRegions = remember(regions, showAllRegions, previousRegions, scanCount) {
                    val filtered = if (showAllRegions) regions.filter { it.isWritable && it.size >= 4096 }
                        else regions.filter { it.isWritable && it.size >= 4096 && !looksLikeNoise(it) }
                    // New-since-last-scan regions float to the top — after a
                    // re-scan (e.g. right after loading a ROM), whatever just
                    // appeared is a much stronger candidate than sorting by
                    // size alone ever was.
                    filtered.sortedWith(
                        compareByDescending<MemoryRegion> { isNewRegion(it) }.thenByDescending { it.size }
                    )
                }

                if (regions.isNotEmpty()) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = showAllRegions, onCheckedChange = { showAllRegions = it })
                        Text(
                            "Show everything (including Dalvik/ART and mapped system libraries)",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                    Text(
                        "Hiding ${regions.size - visibleRegions.size} of ${regions.size} regions by default — " +
                            "an app's own process also contains the Android runtime's Dalvik/ART heap spaces " +
                            "and mapped system libraries, which aren't the app's own game state and will " +
                            "almost always just crash the target if corrupted. Regions of any size are shown " +
                            "now, though — a fixed-hardware console has one known RAM size to look for, but a " +
                            "modern game engine's own memory (world/chunk data, asset caches) doesn't, so " +
                            "filtering by size the way an emulator's console RAM can be doesn't apply here.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (scanCount > 1) {
                        Text(
                            "🌱 marks regions that appeared since your last scan of this process — e.g. " +
                                "scan once, load a ROM in the emulator, then re-scan: whatever's newly " +
                                "marked is very likely the RAM that just got allocated for it.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }

                if (visibleRegions.isNotEmpty()) {
                    Text(
                        "For a fixed-hardware emulator, pick the region whose size matches the console's " +
                            "own RAM — e.g. ~2KB NES, ~128KB SNES WRAM, ~2MB PS1, ~4-8MB N64, ~24MB DS. " +
                            "For a modern game with no fixed RAM size (like Minecraft), that trick doesn't " +
                            "apply — favor unlabeled anonymous regions instead (marked below), since a " +
                            "native engine's own heap allocations usually show up that way with no file " +
                            "path at all. Tap a region to add or remove it from the target list below — " +
                            "add several at once (even from a different process) to widen the net.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Card {
                        LazyColumn(Modifier.heightIn(max = 320.dp)) {
                            items(visibleRegions) { region ->
                                val isTargeted = targets.any { it.process.pid == proc.pid && it.region == region }
                                val isNew = isNewRegion(region)
                                ListItem(
                                    headlineContent = { Text(formatSize(region.size)) },
                                    supportingContent = {
                                        Text(
                                            "0x${region.start.toString(16)} - 0x${region.end.toString(16)}  ${region.perms}" +
                                                if (region.path.isNotBlank()) "  ${region.path}" else "  [anonymous — likely candidate]"
                                        )
                                    },
                                    leadingContent = {
                                        if (isNew) {
                                            Icon(
                                                Icons.Filled.Eco,
                                                contentDescription = "New since last scan",
                                                tint = MaterialTheme.colorScheme.primary
                                            )
                                        }
                                    },
                                    trailingContent = {
                                        if (isTargeted) {
                                            Icon(Icons.Filled.Memory, contentDescription = "Targeted")
                                        }
                                    },
                                    modifier = Modifier.clickable {
                                        targets = if (isTargeted) {
                                            targets.filterNot { it.process.pid == proc.pid && it.region == region }
                                        } else {
                                            targets + CorruptionTarget(proc, region)
                                        }
                                    }
                                )
                                HorizontalDivider()
                            }
                        }
                    }
                }
            }

            if (targets.isNotEmpty()) {
                Text("Targets (${targets.size})", style = MaterialTheme.typography.titleMedium)
                Card {
                    Column(Modifier.padding(8.dp)) {
                        targets.forEach { t ->
                            ListItem(
                                headlineContent = { Text("${t.process.name} — ${formatSize(t.region.size)}", maxLines = 1) },
                                supportingContent = { Text("pid ${t.process.pid} @ 0x${t.region.start.toString(16)}") },
                                trailingContent = {
                                    TextButton(onClick = { targets = targets - t }) { Text("Remove") }
                                }
                            )
                        }
                    }
                }
            }

            // --- Parameters + corruption controls ---
            if (engine != null && targets.isNotEmpty()) {
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

                // One target's failure (OOM on a huge region, process exited,
                // etc.) never stops the others — each is fully independent,
                // same as batch file corruption tallies successes/failures
                // instead of aborting the whole run on the first problem.
                suspend fun corruptOneTarget(target: CorruptionTarget, values: Map<String, ParamValue>): Result<Long> =
                    runCatching {
                        val bytes = RootMemoryHelper.readMemory(context, target.process.pid, target.region.start, target.region.size.toInt())
                            ?: error("could not read ${target.process.name}'s region — it may have moved or the process may be gone")
                        val result = CorruptionEngineExecutor.runWithSeed(bytes, engine, values)
                        if (!RootMemoryHelper.writeMemory(context, target.process.pid, target.region.start, result.bytes)) {
                            error("write failed for ${target.process.name}")
                        }
                        result.seedUsed
                    }

                fun runOneCycle(onDone: (succeeded: Int, failed: Int, lastError: String?) -> Unit) {
                    val currentTargets = targets
                    scope.launch {
                        var succeeded = 0
                        var failed = 0
                        var lastError: String? = null
                        var lastSeed: Long? = null
                        withContext(Dispatchers.IO) {
                            for (target in currentTargets) {
                                corruptOneTarget(target, currentValues)
                                    .onSuccess { seed -> succeeded++; lastSeed = seed }
                                    .onFailure { e ->
                                        failed++
                                        lastError = if (e is OutOfMemoryError) {
                                            "Out of memory on ${target.process.name} (${formatSize(target.region.size)}) — too large to hold twice at once."
                                        } else {
                                            e.message
                                        }
                                    }
                            }
                        }
                        lastSeed?.let { seed ->
                            if (engineValues.containsKey("lastSeedUsed")) {
                                engineValues["lastSeedUsed"] = ParamValue.of(seed.toString())
                            }
                        }
                        onDone(succeeded, failed, lastError)
                    }
                }

                Button(
                    onClick = {
                        isBusy = true
                        runOneCycle { succeeded, failed, lastError ->
                            isBusy = false
                            isErrorStatus = failed > 0
                            statusMessage = when {
                                failed == 0 -> "Corrupted all $succeeded target(s) once."
                                succeeded == 0 -> lastError ?: "All $failed target(s) failed."
                                else -> "Corrupted $succeeded, failed $failed" + (lastError?.let { " — $it" } ?: "")
                            }
                        }
                    },
                    enabled = !isBusy && !liveRunning,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Filled.Bolt, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("Corrupt Once (${targets.size} target${if (targets.size == 1) "" else "s"})")
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
                            "Repeatedly re-corrupts every target until you turn it off.",
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
                    LaunchedEffect(liveRunning, targets, engine.id, tickIntervalMs) {
                        while (liveRunning) {
                            if (targets.isEmpty()) {
                                liveRunning = false
                                break
                            }
                            var anySucceeded = false
                            var anyFailed = false
                            var lastError: String? = null
                            withContext(Dispatchers.IO) {
                                for (target in targets) {
                                    // Same OOM-safety reasoning as Corrupt Once —
                                    // one bad target must not crash the loop or
                                    // stop the other targets from still ticking.
                                    corruptOneTarget(target, engineValues.toMap())
                                        .onSuccess { anySucceeded = true }
                                        .onFailure { e ->
                                            anyFailed = true
                                            lastError = if (e is OutOfMemoryError) {
                                                "out of memory on ${target.process.name} (${formatSize(target.region.size)})"
                                            } else {
                                                e.message
                                            }
                                        }
                                }
                            }
                            if (!anySucceeded && anyFailed) {
                                liveRunning = false
                                isErrorStatus = true
                                statusMessage = "Live corrupting stopped — $lastError"
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
