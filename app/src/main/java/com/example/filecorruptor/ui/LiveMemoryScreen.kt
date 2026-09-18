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
import androidx.compose.material.icons.filled.Insights
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import java.io.File
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
 *  engine's world/chunk data, unlike a fixed-hardware console's RAM).
 *
 *  NOTE: ".so" is deliberately NOT in this list, even though it used to
 *  be. Source-confirmed with FCEUmm (the NES core Lemuroid uses): a
 *  loaded library maps as two separate regions — an executable r-xp code
 *  segment (still excluded, by isSafeToCorrupt's non-executable check
 *  below) and a much smaller, non-executable rw-p data/bss segment,
 *  which is exactly where a core's static globals live — FCEUmm's real
 *  NES RAM, nametable RAM, and palette RAM are literal top-level C
 *  arrays (uint8_t RAM[0x800], NTARAM[0x800], PALRAM[0x20], ...), not
 *  malloc'd heap buffers, so they physically live inside the .so's own
 *  mapping. Blanket-excluding every ".so" path was hiding exactly the
 *  region that mattered for a core built this way. */
private val NOISY_PATH_MARKERS = listOf(
    "dalvik", "/apex/", "/system/", "/vendor/", ".dex", ".vdex", ".odex", ".oat", ".art",
    "/dev/", "[vdso]", "[vvar]", "[vsyscall]", "[stack", "jit-cache", "/data/dalvik-cache", "/linker"
)

private fun looksLikeNoise(region: MemoryRegion): Boolean {
    val p = region.path.lowercase()
    return NOISY_PATH_MARKERS.any { marker -> p.contains(marker) }
}

/** Source-confirmed with Lemuroid: it declares android:process=":game" on its
 *  GameActivity specifically so a crashing libretro core takes down only
 *  that process, not the whole app — the real emulation core and its RAM
 *  live there, not in the main package process. Generalized to other
 *  common naming conventions other emulator/game frontends use for the
 *  same isolation pattern, since this isn't a Lemuroid-only trick. */
private val LIKELY_EMULATION_PROCESS_SUFFIXES = listOf("game", "emu", "emulator", "core", "libretro")

private fun looksLikeEmulationProcess(processName: String): Boolean {
    val suffix = processName.substringAfter(':', missingDelimiterValue = "").lowercase()
    return suffix.isNotEmpty() && LIKELY_EMULATION_PROCESS_SUFFIXES.any { suffix.contains(it) }
}

/** A contiguous-ish (small gaps allowed) span of a region where bytes were
 *  observed to actually change value across repeated samples — a real,
 *  measured signal instead of guessing by region label or size. [changeScore]
 *  is the total number of byte-level changes observed within the window,
 *  summed across all sampled offsets in it (not just a count of offsets). */
private data class HotWindow(val offsetStart: Int, val offsetEnd: Int, val changeScore: Int) {
    val size: Int get() = offsetEnd - offsetStart
}

/** Result of analyzing one region: its hot windows (ranked) and the total
 *  activity score across the whole region — the latter is what lets
 *  regions be ranked against *each other*, not just windows within one. */
private data class RegionActivity(val windows: List<HotWindow>, val totalScore: Int)

/** Clusters a finished per-byte change-count array into a short, rankable
 *  list of windows (small gaps between changed bytes tolerated) instead of
 *  a raw per-byte dump. Shared by both the single-region and batch paths. */
private fun windowsFromChangeCounts(changeCounts: IntArray): RegionActivity {
    val size = changeCounts.size
    val maxGapBytes = 16
    val windows = mutableListOf<HotWindow>()
    var i = 0
    while (i < size) {
        if (changeCounts[i] > 0) {
            val windowStart = i
            var lastActive = i
            var score = changeCounts[i]
            var j = i + 1
            while (j < size && (j - lastActive) <= maxGapBytes) {
                if (changeCounts[j] > 0) {
                    score += changeCounts[j]
                    lastActive = j
                }
                j++
            }
            windows.add(HotWindow(windowStart, lastActive + 1, score))
            i = lastActive + 1
        } else {
            i++
        }
    }
    val totalScore = changeCounts.sum()
    return RegionActivity(windows.sortedByDescending { it.changeScore }.take(25), totalScore)
}

/**
 * Reads [region] repeatedly (with a short delay between reads, so real
 * gameplay has a chance to actually change something), diffing each new
 * read against only the *previous* one and then discarding it — this is
 * the fix for a real crash: the first version kept every sample's full
 * byte array in memory until the very end, so memory scaled with
 * samples × region size. With the sample cap raised to 300, that could
 * mean holding hundreds of copies of a multi-MB region at once — an easy
 * OutOfMemoryError. A running per-byte change-count array is all that's
 * actually needed, so memory here no longer depends on sample count at all.
 */
private suspend fun analyzeRegionActivity(
    context: android.content.Context,
    pid: Int,
    region: MemoryRegion,
    samples: Int,
    intervalMs: Long,
    onProgress: (done: Int, total: Int) -> Unit
): RegionActivity {
    val size = region.size.toInt()
    if (size <= 0) return RegionActivity(emptyList(), 0)

    val changeCounts = IntArray(size)
    var previous: ByteArray? = null
    repeat(samples) { i ->
        val bytes = RootMemoryHelper.readMemory(context, pid, region.start, size)
        if (bytes != null) {
            val prev = previous
            if (prev != null && prev.size == size && bytes.size == size) {
                for (j in 0 until size) {
                    if (prev[j] != bytes[j]) changeCounts[j]++
                }
            }
            previous = bytes // replaces the old array, which is now free to be collected
        }
        onProgress(i + 1, samples)
        if (i < samples - 1) delay(intervalMs)
    }
    return windowsFromChangeCounts(changeCounts)
}

/**
 * Same idea as [analyzeRegionActivity], but across every region at once —
 * and, crucially, *interleaved*: each round reads every region once before
 * moving to the next round, rather than fully sampling region A and then
 * fully sampling region B. That means every region gets compared at the
 * same moments in time (fairer — a burst of activity between two rounds
 * shows up for all of them at once), and the whole scan still only takes
 * samples × interval, not that multiplied by the number of regions.
 *
 * Each region's *previous* sample lives in its own small temp file rather
 * than an in-memory map — read the old one, compare, overwrite it with the
 * new one, move on. That keeps only one region's snapshot in RAM at a time
 * no matter how many regions are being batch-analyzed, instead of holding
 * every region's previous snapshot simultaneously (which is what could
 * still add up with "Analyze All" across many/large regions even after the
 * streaming fix above). The running per-byte change-count arrays still
 * live in memory for the whole scan — an unavoidable minimum, since a
 * cumulative count has to accumulate somewhere — but that's the much
 * smaller of the two costs.
 */
private suspend fun analyzeAllRegionsActivity(
    context: android.content.Context,
    pid: Int,
    regions: List<MemoryRegion>,
    samples: Int,
    intervalMs: Long,
    onProgress: (done: Int, total: Int) -> Unit
): Map<MemoryRegion, RegionActivity> {
    if (regions.isEmpty()) return emptyMap()
    val changeCountsByRegion = regions.associateWith { IntArray(it.size.toInt()) }
    val tempFiles = regions.associateWith { region ->
        File(context.cacheDir, "rtmem_activity_${region.start.toString(16)}_${System.nanoTime()}.tmp")
    }

    try {
        repeat(samples) { i ->
            for (region in regions) {
                val size = region.size.toInt()
                if (size <= 0) continue
                val bytes = RootMemoryHelper.readMemory(context, pid, region.start, size) ?: continue
                val tempFile = tempFiles.getValue(region)
                if (tempFile.exists() && tempFile.length() == size.toLong()) {
                    val prev = tempFile.readBytes()
                    val counts = changeCountsByRegion.getValue(region)
                    for (j in 0 until size) {
                        if (prev[j] != bytes[j]) counts[j]++
                    }
                }
                tempFile.writeBytes(bytes) // overwrites for the next round's comparison
            }
            onProgress(i + 1, samples)
            if (i < samples - 1) delay(intervalMs)
        }
    } finally {
        tempFiles.values.forEach { it.delete() } // always clean up, even on failure/cancellation
    }

    return regions.associateWith { region -> windowsFromChangeCounts(changeCountsByRegion.getValue(region)) }
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

    // Activity-scan state, shared by both the per-region and "analyze
    // everything" flows — every measured region's result lands in the same
    // map, so the region list can rank by it regardless of which flow ran.
    var regionActivity by remember { mutableStateOf<Map<MemoryRegion, RegionActivity>>(emptyMap()) }
    var expandedActivityRegion by remember { mutableStateOf<MemoryRegion?>(null) }
    var analysisRunning by remember { mutableStateOf(false) }
    var analysisProgress by remember { mutableStateOf(0 to 0) }
    var analysisSamples by remember { mutableStateOf(8f) }

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
                    val matched = if (processFilter.isBlank()) processes
                        else processes.filter { it.name.contains(processFilter, ignoreCase = true) }
                    // Likely emulation-core child processes (":game", ":emu",
                    // etc.) float to the top — source-confirmed with Lemuroid
                    // that this is genuinely where the interesting memory is,
                    // not the main package process most people would guess.
                    matched.sortedByDescending { looksLikeEmulationProcess(it.name) }
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
                            val looksLikeEmuCore = isChildProcess && looksLikeEmulationProcess(p.name)
                            ListItem(
                                headlineContent = { Text(p.name, maxLines = 1) },
                                supportingContent = {
                                    Text(
                                        "pid ${p.pid}" +
                                            when {
                                                looksLikeEmuCore -> "  •  likely holds the actual emulation core (isolated from $base)"
                                                isChildProcess -> "  •  separate process of $base"
                                                else -> ""
                                            },
                                    )
                                },
                                leadingContent = {
                                    if (looksLikeEmuCore) {
                                        Icon(Icons.Filled.Star, contentDescription = "Likely emulation core process", tint = MaterialTheme.colorScheme.primary)
                                    }
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
                                    regionActivity = emptyMap()
                                    expandedActivityRegion = null
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

                var regionPathFilter by remember { mutableStateOf("") }
                val isNewRegion: (MemoryRegion) -> Boolean = { scanCount > 1 && it !in previousRegions }

                val visibleRegions = remember(regions, showAllRegions, previousRegions, scanCount, regionPathFilter, regionActivity) {
                    val filtered = if (showAllRegions) regions.filter { it.isWritable && it.size >= 4096 }
                        else regions.filter { it.isSafeToCorrupt && it.size >= 4096 && !looksLikeNoise(it) }
                    val pathMatched = if (regionPathFilter.isBlank()) filtered
                        else filtered.filter { it.path.contains(regionPathFilter, ignoreCase = true) }
                    // Measured activity (from an activity scan) is the strongest
                    // signal there is — it's an actual measurement, not a
                    // guess, so it takes priority over everything else.
                    // Below that, new-since-scan and size are just tie-breakers
                    // among not-yet-measured regions. Label-based "this kind of
                    // region tends to be good" heuristics were tried and
                    // deliberately removed — which region matters turned out to
                    // vary too much per emulator/core to be a reliable signal,
                    // and a false "recommended" label is worse than no label.
                    pathMatched.sortedWith(
                        compareByDescending<MemoryRegion> { regionActivity[it]?.totalScore ?: -1 }
                            .thenByDescending { isNewRegion(it) }
                            .thenByDescending { it.size }
                    )
                }

                if (visibleRegions.isNotEmpty()) {
                    Button(
                        onClick = {
                            val toScan = visibleRegions
                            analysisRunning = true
                            analysisProgress = 0 to analysisSamples.toInt()
                            scope.launch {
                                val outcome = withContext(Dispatchers.IO) {
                                    runCatching {
                                        analyzeAllRegionsActivity(
                                            context, proc.pid, toScan,
                                            samples = analysisSamples.toInt().coerceAtLeast(2),
                                            intervalMs = 150L
                                        ) { done, total -> analysisProgress = done to total }
                                    }
                                }
                                analysisRunning = false
                                outcome.onSuccess { result ->
                                    regionActivity = regionActivity + result
                                    expandedActivityRegion = result.maxByOrNull { it.value.totalScore }?.key
                                }.onFailure { e ->
                                    isErrorStatus = true
                                    statusMessage = if (e is OutOfMemoryError) {
                                        "Ran out of memory analyzing ${toScan.size} region(s) at once — try fewer " +
                                            "samples, or narrow the list first (the path filter or unchecking " +
                                            "\"Show everything\") before analyzing everything."
                                    } else {
                                        "Analysis failed: ${e.message}"
                                    }
                                }
                            }
                        },
                        enabled = !analysisRunning,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Filled.Insights, contentDescription = null)
                        Spacer(Modifier.width(8.dp))
                        Text("Analyze All ${visibleRegions.size} Visible Regions")
                    }
                    Text(
                        "Estimated time: ~${(analysisSamples.toInt() * 150L / 1000.0).let { "%.1f".format(it) }}s for the scan itself, " +
                            "plus overhead per region per sample — the more regions and samples, the longer, " +
                            "but every region is sampled at the same moments either way.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                if (regions.isNotEmpty()) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = showAllRegions, onCheckedChange = { showAllRegions = it })
                        Text(
                            "Show everything (including executable, Dalvik/ART, and system library regions)",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                    OutlinedTextField(
                        value = regionPathFilter,
                        onValueChange = { regionPathFilter = it },
                        label = { Text("Filter by mapped file/library name (optional)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Text(
                        "Hiding ${regions.size - visibleRegions.size} of ${regions.size} regions by default — " +
                            "besides Dalvik/ART heap spaces and mapped system libraries, this now also excludes " +
                            "executable (rwx) regions, matching what RTCV's own real process-corruption mode " +
                            "does by default: an executable page is far more likely to be JIT-compiled code or " +
                            "similar machinery than plain game data, and corrupting it tends to just crash the " +
                            "process outright rather than glitch it. Regions of any size are shown, though — a " +
                            "fixed-hardware console has one known RAM size to look for, but a modern game " +
                            "engine's own memory (world/chunk data, asset caches) doesn't.",
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
                        "Which region actually matters varies a lot by emulator/core — there's no reliable " +
                            "label or size rule that predicts it, so trial and error (or the Analyze button " +
                            "below) is the honest way to find out, not a recommendation. A 🌱 just means a " +
                            "region appeared since your last scan of this process — a real, factual signal, " +
                            "not a guess about whether it's worth targeting. Tap a region to add or remove " +
                            "it from the target list below — add several at once (even from a different " +
                            "process) to widen the net.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        "If a region glitches the target before crashing it, that region is promising but " +
                            "still shared with a lot of other live heap data — narrow the blast radius with " +
                            "the engine's own Start Byte / End Byte (relative to the region, not the whole " +
                            "process) and a much smaller Blast Count, then widen gradually from whatever " +
                            "slice survives. That's how you turn \"glitches, then crashes\" into \"just glitches.\"",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Card {
                        LazyColumn(Modifier.heightIn(max = 320.dp)) {
                            items(visibleRegions) { region ->
                                val isTargeted = targets.any { it.process.pid == proc.pid && it.region == region }
                                val isNew = isNewRegion(region)
                                ListItem(
                                    headlineContent = {
                                        val score = regionActivity[region]?.totalScore
                                        Text(
                                            formatSize(region.size) +
                                                if (score != null) "   •   activity: $score" else ""
                                        )
                                    },
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
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            if (isTargeted) {
                                                Icon(Icons.Filled.Memory, contentDescription = "Targeted")
                                            }
                                            IconButton(
                                                onClick = {
                                                    expandedActivityRegion = region
                                                    analysisRunning = true
                                                    analysisProgress = 0 to analysisSamples.toInt()
                                                    scope.launch {
                                                        val outcome = withContext(Dispatchers.IO) {
                                                            runCatching {
                                                                analyzeRegionActivity(
                                                                    context, proc.pid, region,
                                                                    samples = analysisSamples.toInt().coerceAtLeast(2),
                                                                    intervalMs = 150L
                                                                ) { done, total -> analysisProgress = done to total }
                                                            }
                                                        }
                                                        analysisRunning = false
                                                        outcome.onSuccess { result ->
                                                            regionActivity = regionActivity + (region to result)
                                                        }.onFailure { e ->
                                                            isErrorStatus = true
                                                            statusMessage = if (e is OutOfMemoryError) {
                                                                "Ran out of memory analyzing this ${formatSize(region.size)} region — try fewer samples."
                                                            } else {
                                                                "Analysis failed: ${e.message}"
                                                            }
                                                        }
                                                    }
                                                },
                                                enabled = !analysisRunning
                                            ) {
                                                Icon(Icons.Filled.Insights, contentDescription = "Analyze activity in this region")
                                            }
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

                Column {
                    Text(
                        "Activity scan samples: ${analysisSamples.toInt()}  (~${(analysisSamples.toInt() * 150L / 1000.0).let { "%.1f".format(it) }}s)",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Slider(
                        value = analysisSamples,
                        onValueChange = { analysisSamples = it },
                        valueRange = 4f..300f,
                        enabled = !analysisRunning
                    )
                    Text(
                        "Analyze one region with the 🔍 next to it, or every visible region at once with " +
                            "the button above, to find bytes that are actually changing — a real measurement " +
                            "instead of a guess. Do this while something is happening in the target (moving, " +
                            "taking damage, a HUD counter ticking) so there's something to detect. More " +
                            "samples take longer but catch slower-changing state too, and cost the same " +
                            "either way whether you're scanning one region or all of them at once.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                if (analysisRunning) {
                    val (done, total) = analysisProgress
                    LinearProgressIndicator(
                        progress = { if (total == 0) 0f else done / total.toFloat() },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Text(
                        "Sampling… ($done/$total rounds)",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                val expandedRegion = expandedActivityRegion
                if (!analysisRunning && expandedRegion != null) {
                    val activity = regionActivity[expandedRegion]
                    Text("Activity in ${formatSize(expandedRegion.size)} region", style = MaterialTheme.typography.titleMedium)
                    if (activity == null || activity.windows.isEmpty()) {
                        Text(
                            "Nothing changed across the sampled window. Either nothing was happening in " +
                                "the target during the scan, or this region really is static — try again " +
                                "while something is actively occurring, or pick a different region.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    } else {
                        Card {
                            Column(Modifier.padding(8.dp)) {
                                activity.windows.forEach { w ->
                                    ListItem(
                                        headlineContent = {
                                            Text("0x${w.offsetStart.toString(16)} - 0x${w.offsetEnd.toString(16)}  (${w.size} bytes)")
                                        },
                                        supportingContent = { Text("Changed ${w.changeScore} time(s) across the samples") },
                                        trailingContent = {
                                            TextButton(onClick = {
                                                val target = CorruptionTarget(proc, expandedRegion)
                                                if (targets.none { it.process.pid == proc.pid && it.region == expandedRegion }) {
                                                    targets = targets + target
                                                }
                                                val eng = engine
                                                if (eng != null) {
                                                    val values = engineViewModel.valuesFor(eng.id)
                                                    if (values.containsKey("rangeStart") && values.containsKey("rangeEnd")) {
                                                        values["rangeStart"] = ParamValue.of(w.offsetStart.toString())
                                                        values["rangeEnd"] = ParamValue.of(w.offsetEnd.toString())
                                                    }
                                                }
                                            }) { Text("Use range") }
                                        }
                                    )
                                }
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
