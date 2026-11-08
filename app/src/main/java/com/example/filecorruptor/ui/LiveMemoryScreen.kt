package com.example.filecorruptor.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.material.icons.filled.PictureInPictureAlt
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import java.io.File
import com.example.filecorruptor.engine.CorruptionEngineExecutor
import com.example.filecorruptor.engine.EngineViewModel
import com.example.filecorruptor.engine.ParamValue
import com.example.filecorruptor.engine.isVisible
import com.example.filecorruptor.livemem.LiveSession
import com.example.filecorruptor.livemem.LiveTarget
import com.example.filecorruptor.livemem.LiveProcess
import com.example.filecorruptor.livemem.MemoryGovernor
import com.example.filecorruptor.livemem.MemoryRegion
import com.example.filecorruptor.log.RtcLog
import com.example.filecorruptor.overlay.OverlayService
import com.example.filecorruptor.livemem.NesAnchorHit
import com.example.filecorruptor.livemem.NesAnchorKind
import com.example.filecorruptor.livemem.RootMemoryHelper
import com.example.filecorruptor.livemem.findOamAnchors
import com.example.filecorruptor.livemem.findPaletteRamAnchors
import com.example.filecorruptor.livemem.proposeRamStartsFromOamShadow
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
    "/dev/", "[vdso]", "[vvar]", "[vsyscall]", "[stack", "jit-cache", "/data/dalvik-cache", "/linker",
    // Anti-crash additions: runtime/allocator/loader bookkeeping that is never
    // "game data" and aborts the process the moment it is corrupted
    // (bionic's stack+TLS blocks, the CFI shadow, the linker's own allocator,
    // GWP-ASan guard pages, system-property and atexit tables, signal stacks).
    "[anon:stack_and_tls", "[anon:cfi", "[anon:linker_alloc", "[anon:gwp", "[anon:system property",
    "[anon:atexit", "[anon:thread signal stack", "[anon:bionic_alloc", "[anon:art"
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

/** Common console RAM/VRAM sizes, as quick-fill presets for the activity
 *  scanner's target-size search — saves typing out well-known byte counts. */
private val COMMON_MEMORY_SIZE_PRESETS = listOf(
    "2KB (NES RAM)" to 2 * 1024,
    "8KB (Game Boy RAM)" to 8 * 1024,
    "16KB (SMS RAM)" to 16 * 1024,
    "64KB (Genesis RAM)" to 64 * 1024,
    "128KB (SNES WRAM)" to 128 * 1024,
    "256KB (GBA EWRAM)" to 256 * 1024,
    "2MB (PS1 RAM)" to 2 * 1024 * 1024,
    "4MB (N64 RAM)" to 4 * 1024 * 1024,
    "24MB (DS RAM)" to 24 * 1024 * 1024
)

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

/** Result of analyzing one region: its hot windows (ranked), the total
 *  activity score across the whole region (for ranking regions against
 *  each other), and the raw change counters — kept so a fixed-size search can
 *  be re-run instantly against already-collected data. The counters are one
 *  unsigned byte per [granule] bytes of the region (granule 1 = byte-exact;
 *  big regions use coarser granules so a scan always fits its memory budget
 *  instead of needing 4+ bytes of counter per byte scanned). */
private data class RegionActivity(
    val windows: List<HotWindow>,
    val totalScore: Int,
    val counts: ByteArray,
    val granule: Int
)

/** Clusters a finished change-counter array into a short, rankable list of
 *  windows (small gaps between changed granules tolerated) instead of a raw
 *  dump. Offsets are reported in bytes of the region. */
private fun windowsFromCounts(counts: ByteArray, granule: Int): RegionActivity {
    val size = counts.size
    val maxGap = maxOf(1, 16 / granule)
    val windows = mutableListOf<HotWindow>()
    var total = 0L
    var i = 0
    while (i < size) {
        val c = counts[i].toInt() and 0xFF
        if (c > 0) {
            val windowStart = i
            var lastActive = i
            var score = c.toLong()
            var j = i + 1
            while (j < size && (j - lastActive) <= maxGap) {
                val cj = counts[j].toInt() and 0xFF
                if (cj > 0) {
                    score += cj
                    lastActive = j
                }
                j++
            }
            total += score
            windows.add(
                HotWindow(
                    (windowStart.toLong() * granule).coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
                    ((lastActive + 1).toLong() * granule).coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
                    score.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
                )
            )
            i = lastActive + 1
        } else {
            i++
        }
    }
    return RegionActivity(
        windows.sortedByDescending { it.changeScore }.take(25),
        total.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
        counts,
        granule
    )
}

/** Keeps the cached scan results from growing without bound: past the cap, the oldest unrelated
 *  entries are dropped (their lists simply show as "not analyzed" again). */
private const val ACTIVITY_CACHE_MAX_BYTES = 64L * 1024 * 1024

private fun trimActivity(
    map: Map<MemoryRegion, RegionActivity>,
    keep: Collection<MemoryRegion>
): Map<MemoryRegion, RegionActivity> {
    var total = map.values.sumOf { it.counts.size.toLong() }
    if (total <= ACTIVITY_CACHE_MAX_BYTES) return map
    val out = LinkedHashMap(map)
    val it = out.entries.iterator()
    while (total > ACTIVITY_CACHE_MAX_BYTES && it.hasNext()) {
        val e = it.next()
        if (e.key in keep) continue
        total -= e.value.counts.size
        it.remove()
    }
    return out
}

/**
 * Instead of letting window size fall out of however far apart changed
 * bytes happen to be (windowsFromChangeCounts above), this slides a window
 * of exactly [targetSize] bytes across the region and finds where the
 * *sum* of activity inside that exact span is highest — e.g. "is there a
 * contiguous 2048-byte block that's unusually active", which is a much
 * more direct way to go looking for something like a NES's RAM or a
 * known-size VRAM/palette buffer than eyeballing gap-clustered windows of
 * whatever size they happened to form. Uses a prefix-sum so every
 * candidate position is an O(1) lookup rather than re-summing each time.
 * Non-max suppression avoids returning a dozen near-identical windows
 * that are really just the same hot spot shifted by a few bytes.
 */
private fun findBestFixedSizeWindows(counts: ByteArray, granule: Int, targetBytes: Int, topN: Int = 10): List<HotWindow> {
    val size = counts.size
    // Work in counter units; the reported span keeps the exact byte size that was asked for.
    val targetSize = ((targetBytes.toLong() + granule - 1) / granule).toInt().coerceAtLeast(1)
    if (targetBytes <= 0 || targetSize > size) return emptyList()

    // Memory-safe version. The old one built a boxed Pair<Int, Long> for EVERY offset of the region
    // (tens of bytes each) plus an 8-byte prefix sum per byte, and ran on every recomposition —
    // on a big scudo region that is what threw OutOfMemoryError (log: "Integer.valueOf ... giving
    // up on allocation because <1% of heap free"). Now: one sliding-window pass with primitives,
    // keeping only the best window start per block of candidates.
    val blockLen = maxOf(targetSize, size / 100_000 + 1)
    val nBlocks = (size - targetSize) / blockLen + 1
    val bestStart = IntArray(nBlocks)
    val bestScore = LongArray(nBlocks) { -1L }

    var sum = 0L
    for (i in 0 until targetSize) sum += counts[i].toInt() and 0xFF
    var start = 0
    var totalScore = 0L
    var positives = 0L
    while (true) {
        val b = start / blockLen
        if (sum > bestScore[b]) { bestScore[b] = sum; bestStart[b] = start }
        if (sum > 0) { totalScore += sum; positives++ }
        if (start + targetSize >= size) break
        sum += (counts[start + targetSize].toInt() and 0xFF) - (counts[start].toInt() and 0xFF)
        start++
    }
    if (positives == 0L) return emptyList()

    // In a region that's busy almost everywhere (a shared Scudo primary arena), keep only spans
    // meaningfully above the region's own average; fall back to everything rather than nothing.
    val threshold = (totalScore.toDouble() / positives) * 1.5
    var pool = (0 until nBlocks).filter { bestScore[it] > 0 && bestScore[it] >= threshold }
    if (pool.isEmpty()) pool = (0 until nBlocks).filter { bestScore[it] > 0 }
    val ordered = pool.sortedByDescending { bestScore[it] }

    val picked = mutableListOf<HotWindow>()
    for (blk in ordered) {
        if (picked.size >= topN) break
        val st = (bestStart[blk].toLong() * granule).coerceAtMost(Int.MAX_VALUE.toLong() - targetBytes).toInt()
        val end = st + targetBytes
        val overlapsExisting = picked.any { w -> st < w.offsetEnd && end > w.offsetStart }
        if (!overlapsExisting) picked.add(HotWindow(st, end, bestScore[blk].coerceAtMost(Int.MAX_VALUE.toLong()).toInt()))
    }
    return picked
}

/**
 * Activity scan, done natively (see `activity` in rtmem_helper.c): the helper samples the regions
 * itself and keeps only a hash + counter per *granule*, sized so the whole scan fits a fixed memory
 * budget. That replaced a Java version that held two full copies of the region per sample plus a
 * 4-byte counter per byte (an 80 MB region needed ~500 MB — more than the app's heap) and wrote the
 * region to storage on every sample. It also no longer stops the target while reading, runs at
 * background priority and pauses between chunks, so other apps keep running smoothly.
 */
private suspend fun runActivityScan(
    context: android.content.Context,
    pid: Int,
    regions: List<MemoryRegion>,
    samples: Int,
    intervalMs: Long,
    onProgress: (done: Int, total: Int) -> Unit
): Map<MemoryRegion, RegionActivity> {
    val job = kotlinx.coroutines.currentCoroutineContext()[kotlinx.coroutines.Job]
    val eligible = regions.filter { it.size in 1..Int.MAX_VALUE.toLong() }
    if (eligible.isEmpty()) return emptyMap()
    val outcome = RootMemoryHelper.activityScan(
        context, pid, eligible, samples, intervalMs,
        MemoryGovernor.analysisBudgetMb(context), onProgress
    ) { job?.isActive == false }
    if (outcome.cancelled) return emptyMap()
    val out = HashMap<MemoryRegion, RegionActivity>()
    var skipped = 0
    for (r in outcome.results) {
        val c = r.counts
        if (c == null) { skipped++; continue }
        out[r.region] = windowsFromCounts(c, r.granule)
    }
    if (skipped > 0) {
        RtcLog.w("Analyze", "$skipped region(s) skipped: too big for the scan's memory budget even at the coarsest resolution — analyze them on their own")
    }
    return out
}

private suspend fun analyzeRegionActivity(
    context: android.content.Context,
    pid: Int,
    region: MemoryRegion,
    samples: Int,
    intervalMs: Long,
    onProgress: (done: Int, total: Int) -> Unit
): RegionActivity {
    if (region.size <= 0) return RegionActivity(emptyList(), 0, ByteArray(0), 1)
    return runActivityScan(context, pid, listOf(region), samples, intervalMs, onProgress)[region]
        ?: throw IllegalStateException(
            "${formatSize(region.size)} is too big to analyze within the memory budget, even at the coarsest resolution " +
                "(or the scan was cancelled)"
        )
}

private suspend fun analyzeAllRegionsActivity(
    context: android.content.Context,
    pid: Int,
    regions: List<MemoryRegion>,
    samples: Int,
    intervalMs: Long,
    onProgress: (done: Int, total: Int) -> Unit
): Map<MemoryRegion, RegionActivity> {
    if (regions.isEmpty()) return emptyMap()
    return runActivityScan(context, pid, regions, samples, intervalMs, onProgress)
}

private const val NES_SCAN_CHUNK = 2 * 1024 * 1024
private const val NES_SCAN_OVERLAP = 512
private const val NES_SCAN_MAX_PER_REGION = 256L * 1024 * 1024

/**
 * Looks for NES palette/OAM-shaped bytes in [region] a chunk at a time (with an overlap so a pattern
 * straddling a boundary is still seen once), instead of reading up to 16 MB in one go and silently
 * ignoring the rest of a bigger region. Memory use is one chunk, whatever the region size.
 */
private fun scanRegionForNesAnchors(
    context: android.content.Context,
    pid: Int,
    region: MemoryRegion
): List<NesAnchorHit> {
    val total = minOf(region.size, NES_SCAN_MAX_PER_REGION)
    val out = ArrayList<NesAnchorHit>()
    val lastEnd = HashMap<String, Long>()
    var off = 0L
    while (off < total) {
        val len = minOf(NES_SCAN_CHUNK.toLong() + NES_SCAN_OVERLAP, region.size - off).toInt()
        val bytes = RootMemoryHelper.readMemory(context, pid, region.start + off, len)
        if (bytes != null) {
            val lastChunk = off + NES_SCAN_CHUNK >= total
            val hits = (findPaletteRamAnchors(bytes) + findOamAnchors(bytes)).sortedBy { it.offset }
            for (h in hits) {
                if (!lastChunk && h.offset >= NES_SCAN_CHUNK) continue // belongs to the next chunk
                val abs = off + h.offset
                if (abs < (lastEnd[h.kind.name] ?: -1L)) continue // already reported by the previous chunk
                lastEnd[h.kind.name] = abs + h.size
                out += h.copy(offset = abs.toInt())
            }
        }
        off += NES_SCAN_CHUNK
        try { Thread.sleep(2) } catch (_: InterruptedException) { break } // breathing room for other apps
    }
    return out
}

// Shared with the floating overlay (see LiveSession): the targets live in the session, not in this screen.
private typealias CorruptionTarget = LiveTarget

private tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}

private fun formatSize(bytes: Long): String = when {
    bytes >= 1_048_576 -> "%.1f MB".format(bytes / 1_048_576.0)
    bytes >= 1024 -> "%.1f KB".format(bytes / 1024.0)
    else -> "$bytes B"
}

/**
 * Classic hex-editor-style dump: offset, hex bytes, and a printable-ASCII
 * column side by side — the point being to actually look at what's in a
 * candidate region or window before committing to it. Real console memory
 * often gives itself away this way: NES/SNES-era tile and nametable data
 * (plain arrays like uint8_t vram[2048] in most cores, not malloc'd) tends
 * to show visibly repeating small values, where a pointer-heavy structure
 * would look comparatively patternless, and readable strings show up as
 * plain text in the ASCII column if there are any nearby (level names,
 * debug strings, etc). Capped in length since this is for a quick look,
 * not a full binary export.
 */
private fun hexDump(bytes: ByteArray, baseOffset: Int = 0, maxBytes: Int = 512): String {
    val shown = bytes.take(maxBytes)
    val bytesPerLine = 16
    val sb = StringBuilder()
    var i = 0
    while (i < shown.size) {
        val line = shown.subList(i, minOf(i + bytesPerLine, shown.size))
        val hex = line.joinToString(" ") { "%02X".format(it) }
        val ascii = line.joinToString("") { b ->
            val c = b.toInt() and 0xFF
            if (c in 32..126) c.toChar().toString() else "."
        }
        sb.append("%06X".format(baseOffset + i))
            .append("  ")
            .append(hex.padEnd(bytesPerLine * 3 - 1))
            .append("  |")
            .append(ascii)
            .append("|\n")
        i += bytesPerLine
    }
    if (bytes.size > maxBytes) sb.append("… (${bytes.size - maxBytes} more bytes not shown)")
    return sb.toString().trimEnd()
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
    var targets by remember { mutableStateOf<List<CorruptionTarget>>(LiveSession.targets) }

    // Activity-scan state, shared by both the per-region and "analyze
    // everything" flows — every measured region's result lands in the same
    // map, so the region list can rank by it regardless of which flow ran.
    var regionActivity by remember { mutableStateOf<Map<MemoryRegion, RegionActivity>>(emptyMap()) }
    var expandedActivityRegion by remember { mutableStateOf<MemoryRegion?>(null) }
    var analysisRunning by remember { mutableStateOf(false) }
    var analysisProgress by remember { mutableStateOf(0 to 0) }
    var analysisSamples by remember { mutableStateOf(8f) }
    var targetSizeText by remember { mutableStateOf("") }

    // NES palette/OAM signature scan — content-based anchors (see
    // NesRamSignatures.kt) that don't need any activity sampling to be
    // useful, since they're derived from what real NES palette/OAM RAM
    // always looks like rather than from watching for change over time.
    var nesAnchorResults by remember { mutableStateOf<Map<MemoryRegion, List<NesAnchorHit>>>(emptyMap()) }
    var nesAnchorScanRunning by remember { mutableStateOf(false) }

    var previewLabel by remember { mutableStateOf<String?>(null) }
    var previewText by remember { mutableStateOf<String?>(null) }
    var previewLoading by remember { mutableStateOf(false) }

    var statusMessage by remember { mutableStateOf<String?>(null) }
    var isErrorStatus by remember { mutableStateOf(false) }

    // The live loop, tick speed and Corrupt-Once live in LiveSession so the floating
    // overlay can drive them while this screen is hidden; this screen is just one view of it.
    val session by LiveSession.state.collectAsState()
    val liveRunning = session.running
    val tickCount = session.ticks
    val sessionTargets by LiveSession.targetsFlow.collectAsState()
    var overlayNotice by remember { mutableStateOf<String?>(null) }

    // targets: screen -> session when the user edits them; session -> screen when it drops a dead one.
    LaunchedEffect(targets) { LiveSession.setTargets(targets) }
    LaunchedEffect(sessionTargets) { if (sessionTargets != targets) targets = sessionTargets }
    SideEffect {
        LiveSession.setEngine(context, engine, engine?.let { engineViewModel.valuesFor(it.id) })
    }
    // Results coming from the session (also when triggered from the overlay) show up in the status card.
    LaunchedEffect(session.messageSeq) {
        session.message?.let {
            statusMessage = it
            isErrorStatus = session.isError
        }
    }

    LaunchedEffect(Unit) {
        rootAvailable = withContext(Dispatchers.IO) { RootMemoryHelper.hasRoot() }
        rootChecked = true
    }

    // Stop any live-corrupt loop the moment you leave this tab, rather than
    // letting it keep running against a screen you can no longer see or stop —
    // unless the floating overlay is up, which *is* a way to see and stop it.
    DisposableEffect(Unit) {
        onDispose { if (!OverlayService.isRunning) LiveSession.stop() }
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

        // Minimized mode: shrink the app into a floating control window over the emulator,
        // so no split-screen / freeform window is needed.
        OutlinedButton(
            onClick = {
                scope.launch {
                    val allowed = withContext(Dispatchers.IO) { OverlayService.ensurePermission(context) }
                    if (allowed) {
                        overlayNotice = null
                        OverlayService.start(context)
                        context.findActivity()?.moveTaskToBack(true)
                    } else {
                        overlayNotice = "Allow \"Display over other apps\" for this app in the screen that just opened, " +
                            "then tap Minimize again."
                        context.startActivity(OverlayService.permissionSettingsIntent(context))
                    }
                }
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Filled.PictureInPictureAlt, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("Minimize to floating overlay")
        }
        overlayNotice?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }

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
                                    nesAnchorResults = emptyMap()
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

                val visibleRegions = remember(regions, showAllRegions, previousRegions, scanCount, regionPathFilter, regionActivity, nesAnchorResults) {
                    val filtered = if (showAllRegions) regions.filter { it.isWritable && it.size >= 4096 }
                        else regions.filter { it.isSafeToCorrupt && it.size >= 4096 && !looksLikeNoise(it) }
                    val pathMatched = if (regionPathFilter.isBlank()) filtered
                        else filtered.filter { it.path.contains(regionPathFilter, ignoreCase = true) }
                    // A NES palette/OAM content match outranks everything else —
                    // it's a static signature almost nothing produces by
                    // accident (see NesRamSignatures.kt), stronger than a mere
                    // activity score because activity alone can't tell "NES RAM"
                    // apart from any other same-sized buffer that happens to be
                    // changing. Measured activity is still the next-strongest
                    // signal — an actual measurement, not a guess — with
                    // new-since-scan and size as tie-breakers among regions
                    // neither scan has said anything about yet. Label-based
                    // "this kind of region tends to be good" heuristics were
                    // tried and deliberately removed — which region matters
                    // turned out to vary too much per emulator/core to be a
                    // reliable signal, and a false "recommended" label is worse
                    // than no label.
                    pathMatched.sortedWith(
                        compareByDescending<MemoryRegion> { nesAnchorResults[it]?.maxOfOrNull { h -> h.confidence } ?: -1.0 }
                            .thenByDescending { regionActivity[it]?.totalScore ?: -1 }
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
                            LiveSession.setProgress("Activity scan", 0, analysisSamples.toInt())
                            scope.launch {
                                val outcome = withContext(Dispatchers.IO) {
                                    runCatching {
                                        analyzeAllRegionsActivity(
                                            context, proc.pid, toScan,
                                            samples = analysisSamples.toInt().coerceAtLeast(2),
                                            intervalMs = 150L
                                        ) { done, total ->
                                            analysisProgress = done to total
                                            LiveSession.setProgress("Activity scan", done, total)
                                        }
                                    }
                                }
                                analysisRunning = false
                                LiveSession.clearProgress()
                                outcome.onSuccess { result ->
                                    regionActivity = trimActivity(regionActivity + result, result.keys)
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

                    Button(
                        onClick = {
                            val toScan = visibleRegions
                            nesAnchorScanRunning = true
                            LiveSession.setProgress("NES signature scan", 0, 0)
                            scope.launch {
                                val results = withContext(Dispatchers.IO) {
                                    val out = mutableMapOf<MemoryRegion, List<NesAnchorHit>>()
                                    for (region in toScan) {
                                        val hits = scanRegionForNesAnchors(context, proc.pid, region)
                                        if (hits.isNotEmpty()) out[region] = hits
                                    }
                                    out
                                }
                                nesAnchorScanRunning = false
                                LiveSession.clearProgress()
                                nesAnchorResults = results
                                if (results.isEmpty()) {
                                    isErrorStatus = false
                                    statusMessage = "No palette/OAM-shaped bytes found in any visible region right " +
                                        "now — a title screen or a paused/idle moment can leave the palette " +
                                        "flatter than usual, so try again during active gameplay, or widen the " +
                                        "list with \"Show everything\" first."
                                } else {
                                    isErrorStatus = false
                                    statusMessage = "Found NES palette/OAM-shaped bytes in ${results.size} of " +
                                        "${toScan.size} region(s) — sorted to the top of the list below."
                                    expandedActivityRegion = results.entries
                                        .maxByOrNull { (_, hits) -> hits.maxOf { it.confidence } }
                                        ?.key
                                }
                            }
                        },
                        enabled = !nesAnchorScanRunning,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Filled.Radar, contentDescription = null)
                        Spacer(Modifier.width(8.dp))
                        Text("Scan for NES RAM Signatures (palette/OAM)")
                    }
                    Text(
                        "Looks for the byte-level shape of real NES sprite/OAM RAM (a long run of " +
                            "one repeated, off-screen-parked sprite entry, excluding solid fills like " +
                            "0xFF — that's an allocator poison pattern, not a game) and, as a much " +
                            "weaker secondary signal, palette RAM (32 bytes all <= 0x3F). Sprite/OAM " +
                            "hits are the strong lead here; palette hits are common in ordinary memory " +
                            "too (real memory is full of small numbers — counters, flags, indices — " +
                            "so \"32 bytes <= 0x3F\" isn't the rare event it sounds like) and should be " +
                            "read as \"possible\", not \"likely\", on their own. Either way, confirm with " +
                            "an activity scan before trusting it. Works on a paused frame — doesn't need " +
                            "gameplay happening.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (nesAnchorScanRunning) {
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    }
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
                                val nesHits = nesAnchorResults[region]
                                ListItem(
                                    headlineContent = {
                                        val score = regionActivity[region]?.totalScore
                                        val bestNesConf = nesHits?.maxOfOrNull { it.confidence }
                                        Text(
                                            buildString {
                                                append(formatSize(region.size))
                                                if (score != null) append("   •   activity: $score")
                                                if (bestNesConf != null) append("   •   NES-shaped: %.0f%%".format(bestNesConf * 100))
                                            }
                                        )
                                    },
                                    supportingContent = {
                                        Text(
                                            "0x${region.start.toString(16)} - 0x${region.end.toString(16)}  ${region.perms}" +
                                                if (region.path.isNotBlank()) "  ${region.path}" else "  [anonymous — likely candidate]"
                                        )
                                    },
                                    leadingContent = {
                                        Row {
                                            if (nesHits != null) {
                                                Icon(
                                                    Icons.Filled.Radar,
                                                    contentDescription = "Matches NES palette/OAM RAM shape",
                                                    tint = MaterialTheme.colorScheme.primary
                                                )
                                            }
                                            if (isNew) {
                                                Icon(
                                                    Icons.Filled.Eco,
                                                    contentDescription = "New since last scan",
                                                    tint = MaterialTheme.colorScheme.primary
                                                )
                                            }
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
                                                    LiveSession.setProgress("Activity scan", 0, analysisSamples.toInt())
                                                    scope.launch {
                                                        val outcome = withContext(Dispatchers.IO) {
                                                            runCatching {
                                                                analyzeRegionActivity(
                                                                    context, proc.pid, region,
                                                                    samples = analysisSamples.toInt().coerceAtLeast(2),
                                                                    intervalMs = 150L
                                                                ) { done, total ->
                                                                    analysisProgress = done to total
                                                                    LiveSession.setProgress("Activity scan", done, total)
                                                                }
                                                            }
                                                        }
                                                        analysisRunning = false
                                                        LiveSession.clearProgress()
                                                        outcome.onSuccess { result ->
                                                            regionActivity = trimActivity(regionActivity + (region to result), listOf(region))
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
                                            IconButton(
                                                onClick = {
                                                    previewLabel = "First bytes of ${formatSize(region.size)} region at 0x${region.start.toString(16)}"
                                                    previewText = null
                                                    previewLoading = true
                                                    scope.launch {
                                                        val bytes = withContext(Dispatchers.IO) {
                                                            RootMemoryHelper.readMemory(context, proc.pid, region.start, minOf(region.size, 512).toInt())
                                                        }
                                                        previewLoading = false
                                                        previewText = if (bytes != null) hexDump(bytes) else "Could not read this region — it may have moved or the process may be gone."
                                                    }
                                                },
                                                enabled = !previewLoading
                                            ) {
                                                Icon(Icons.Filled.Visibility, contentDescription = "Preview bytes as hex/ASCII")
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

                    OutlinedTextField(
                        value = targetSizeText,
                        onValueChange = { targetSizeText = it.filter { c -> c.isDigit() } },
                        label = { Text("Target size in bytes (optional)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Text(
                        "Leave blank to see activity windows as they naturally cluster. Set a size to " +
                            "instead search for exactly that many contiguous bytes with the most combined " +
                            "activity — useful for spotting a known-size buffer (a console's RAM, VRAM, or " +
                            "similar) hiding inside a much larger region. Re-runs instantly against data " +
                            "you've already scanned, no need to scan again after changing it.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        items(COMMON_MEMORY_SIZE_PRESETS) { (label, bytes) ->
                            AssistChip(
                                onClick = { targetSizeText = bytes.toString() },
                                label = { Text(label) }
                            )
                        }
                    }
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
                if (expandedRegion != null) {
                    val nesHits = nesAnchorResults[expandedRegion]
                    if (!nesHits.isNullOrEmpty()) {
                        Text(
                            "NES Signature Matches in ${formatSize(expandedRegion.size)} region",
                            style = MaterialTheme.typography.titleMedium
                        )
                        Text(
                            "Static content matches, not activity — safe to use even on a paused/title-" +
                                "screen frame. \"RAM start guess\" only appears for a sprite/OAM match, and " +
                                "assumes this game keeps its sprite table at the usual CPU RAM page ($0200); " +
                                "confirm with a preview or an activity scan before relying on it.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Card {
                            Column(Modifier.padding(8.dp)) {
                                nesHits.sortedByDescending { it.confidence }.forEach { hit ->
                                    val kindLabel = when (hit.kind) {
                                        NesAnchorKind.PALETTE_RAM -> "Palette RAM shape (weak signal)"
                                        NesAnchorKind.SPRITE_OAM -> "Sprite/OAM shape (strong signal)"
                                    }
                                    ListItem(
                                        headlineContent = {
                                            Text("$kindLabel — 0x${hit.offset.toString(16)}  (${hit.size} bytes)")
                                        },
                                        supportingContent = {
                                            Text("Confidence: %.0f%%".format(hit.confidence * 100))
                                        },
                                        trailingContent = {
                                            IconButton(onClick = {
                                                previewLabel = "$kindLabel at 0x${hit.offset.toString(16)} in ${formatSize(expandedRegion.size)} region"
                                                previewText = null
                                                previewLoading = true
                                                scope.launch {
                                                    val bytes = withContext(Dispatchers.IO) {
                                                        RootMemoryHelper.readMemory(
                                                            context, proc.pid,
                                                            expandedRegion.start + hit.offset,
                                                            hit.size
                                                        )
                                                    }
                                                    previewLoading = false
                                                    previewText = if (bytes != null) hexDump(bytes, baseOffset = hit.offset)
                                                    else "Could not read this span — it may have moved or the process may be gone."
                                                }
                                            }) {
                                                Icon(Icons.Filled.Visibility, contentDescription = "Preview bytes as hex/ASCII")
                                            }
                                        }
                                    )
                                    if (hit.kind == NesAnchorKind.SPRITE_OAM) {
                                        val ramGuesses = proposeRamStartsFromOamShadow(listOf(hit), expandedRegion.size.toInt())
                                        ramGuesses.take(4).forEach { (ramStart, confidence) ->
                                            ListItem(
                                                headlineContent = {
                                                    Text("  RAM start guess — 0x${ramStart.toString(16)}  (2048 bytes)")
                                                },
                                                supportingContent = {
                                                    Text("Confidence: %.0f%%  (offset - 0x${(hit.offset - ramStart).toString(16)})".format(confidence * 100))
                                                },
                                                trailingContent = {
                                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                                        IconButton(onClick = {
                                                            previewLabel = "Guessed RAM (0x${ramStart.toString(16)}) in ${formatSize(expandedRegion.size)} region"
                                                            previewText = null
                                                            previewLoading = true
                                                            scope.launch {
                                                                val bytes = withContext(Dispatchers.IO) {
                                                                    RootMemoryHelper.readMemory(
                                                                        context, proc.pid,
                                                                        expandedRegion.start + ramStart,
                                                                        0x800
                                                                    )
                                                                }
                                                                previewLoading = false
                                                                previewText = if (bytes != null) hexDump(bytes, baseOffset = ramStart)
                                                                else "Could not read this span — it may have moved or the process may be gone."
                                                            }
                                                        }) {
                                                            Icon(Icons.Filled.Visibility, contentDescription = "Preview bytes as hex/ASCII")
                                                        }
                                                        TextButton(onClick = {
                                                            targetSizeText = "2048"
                                                            val target = CorruptionTarget(proc, expandedRegion)
                                                            if (targets.none { it.process.pid == proc.pid && it.region == expandedRegion }) {
                                                                targets = targets + target
                                                            }
                                                            val eng = engine
                                                            if (eng != null) {
                                                                val values = engineViewModel.valuesFor(eng.id)
                                                                if (values.containsKey("rangeStart") && values.containsKey("rangeEnd")) {
                                                                    values["rangeStart"] = ParamValue.of(ramStart.toString())
                                                                    values["rangeEnd"] = ParamValue.of((ramStart + 0x800).toString())
                                                                }
                                                            }
                                                        }) { Text("Use range") }
                                                    }
                                                }
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if (!analysisRunning && expandedRegion != null) {
                    val activity = regionActivity[expandedRegion]
                    val targetSize = targetSizeText.toIntOrNull()?.takeIf { it > 0 }
                    // Computed off the main thread and only when the inputs change (it used to run on every recomposition).
                    val fixedWindows by produceState<List<HotWindow>?>(null, activity, targetSize) {
                        value = if (activity != null && targetSize != null) {
                            withContext(Dispatchers.Default) { findBestFixedSizeWindows(activity.counts, activity.granule, targetSize) }
                        } else null
                    }
                    val displayWindows = when {
                        activity == null -> emptyList()
                        targetSize != null -> fixedWindows ?: emptyList()
                        else -> activity.windows
                    }
                    Text(
                        if (targetSize != null) "Best ${targetSize}-byte spans in ${formatSize(expandedRegion.size)} region"
                        else "Activity in ${formatSize(expandedRegion.size)} region",
                        style = MaterialTheme.typography.titleMedium
                    )
                    if (activity == null || displayWindows.isEmpty()) {
                        Text(
                            if (targetSize != null && activity != null && activity.windows.isNotEmpty())
                                "No $targetSize-byte span in this region had any activity — try a different size, " +
                                    "or clear it to see the naturally-clustered windows instead."
                            else "Nothing changed across the sampled window. Either nothing was happening in " +
                                "the target during the scan, or this region really is static — try again " +
                                "while something is actively occurring, or pick a different region.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    } else {
                        Card {
                            Column(Modifier.padding(8.dp)) {
                                displayWindows.forEach { w ->
                                    ListItem(
                                        headlineContent = {
                                            Text("0x${w.offsetStart.toString(16)} - 0x${w.offsetEnd.toString(16)}  (${w.size} bytes)")
                                        },
                                        supportingContent = { Text("Changed ${w.changeScore} time(s) across the samples") },
                                        trailingContent = {
                                            Row(verticalAlignment = Alignment.CenterVertically) {
                                                IconButton(onClick = {
                                                    previewLabel = "0x${w.offsetStart.toString(16)} - 0x${w.offsetEnd.toString(16)} in ${formatSize(expandedRegion.size)} region"
                                                    previewText = null
                                                    previewLoading = true
                                                    scope.launch {
                                                        val bytes = withContext(Dispatchers.IO) {
                                                            RootMemoryHelper.readMemory(
                                                                context, proc.pid,
                                                                expandedRegion.start + w.offsetStart,
                                                                minOf(w.size, 512)
                                                            )
                                                        }
                                                        previewLoading = false
                                                        previewText = if (bytes != null) hexDump(bytes, baseOffset = w.offsetStart)
                                                        else "Could not read this span — it may have moved or the process may be gone."
                                                    }
                                                }) {
                                                    Icon(Icons.Filled.Visibility, contentDescription = "Preview bytes as hex/ASCII")
                                                }
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
                                        }
                                    )
                                }
                            }
                        }
                    }
                }

                if (previewLoading || previewText != null) {
                    Text("Byte Preview", style = MaterialTheme.typography.titleMedium)
                    previewLabel?.let {
                        Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    if (previewLoading) {
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    } else {
                        Card {
                            Text(
                                previewText.orEmpty(),
                                modifier = Modifier
                                    .padding(12.dp)
                                    .fillMaxWidth()
                                    .horizontalScroll(rememberScrollState()),
                                fontFamily = FontFamily.Monospace,
                                fontSize = 12.sp,
                                softWrap = false
                            )
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

                // The read -> corrupt -> guard -> write pipeline, the live loop, crash
                // detection and logging all live in LiveSession / LiveCorruptor, so the
                // floating overlay can run exactly the same thing.
                Button(
                    onClick = { LiveSession.corruptOnce() },
                    enabled = !session.busy && !liveRunning,
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
                        onCheckedChange = { if (it) LiveSession.start() else LiveSession.stop() }
                    )
                }

                Column {
                    Text(
                        "Tick every ${session.tickIntervalMs} ms",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Slider(
                        value = session.tickIntervalMs.toFloat(),
                        onValueChange = { LiveSession.setTickInterval(it.toInt()) },
                        valueRange = 50f..2000f
                    )
                }

                if (liveRunning) {
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
