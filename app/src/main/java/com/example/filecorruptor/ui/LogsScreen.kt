package com.example.filecorruptor.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.filecorruptor.log.CrashReporter
import com.example.filecorruptor.log.RtcLog
import com.example.filecorruptor.livemem.MemoryGovernor
import com.example.filecorruptor.safety.AntiCrash
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val MAX_LINES_SHOWN = 300

@Composable
fun LogsScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current

    val config by AntiCrash.config.collectAsState()
    val stats by AntiCrash.stats.collectAsState()
    val windowMb by MemoryGovernor.windowMb.collectAsState()
    LaunchedEffect(Unit) { MemoryGovernor.init(context) }
    val entries by RtcLog.entries.collectAsState()

    var minLevel by remember { mutableStateOf(RtcLog.Level.INFO) }
    var verbose by remember { mutableStateOf(AntiCrash.verboseLog) }
    var quarantined by remember { mutableStateOf(AntiCrash.quarantinedAreaCount()) }
    var collecting by remember { mutableStateOf(false) }
    var crashLog by remember { mutableStateOf<String?>(null) }
    var notice by remember { mutableStateOf<String?>(null) }

    // Refresh the quarantine counter whenever new log lines arrive (a crash adds one).
    LaunchedEffect(entries.size) { quarantined = AntiCrash.quarantinedAreaCount() }

    val shown = remember(entries, minLevel) {
        entries.filter { it.level.ordinal >= minLevel.ordinal }.takeLast(MAX_LINES_SHOWN)
    }
    val logText = shown.joinToString("\n") { it.format() }

    val saveLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain")
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val ok = withContext(Dispatchers.IO) {
                runCatching {
                    val text = RtcLog.readPersistedText().ifBlank { entries.joinToString("\n") { it.format() } }
                    context.contentResolver.openOutputStream(uri, "wt")?.use { it.write(text.toByteArray()) }
                        ?: error("could not open output")
                }.isSuccess
            }
            notice = if (ok) "Saved the log." else "Couldn't save the log."
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text("Logs & Anti-Crash", style = MaterialTheme.typography.headlineMedium)

        // ---------------- Anti-crash ----------------
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Anti-crash", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Medium)
                Text(
                    "Avoids the patterns that most often crash the target (or make a ROM unloadable) " +
                        "instead of producing a glitch. It can't make corruption perfectly safe — " +
                        "some crashes are inherent — but it removes the avoidable ones.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                ToggleRow(
                    "Anti-crash (master switch)",
                    "Off = the original unguarded behavior everywhere.",
                    config.enabled
                ) { AntiCrash.update(config.copy(enabled = it)) }

                ToggleRow(
                    "Protect ROM/file headers",
                    "Files: puts back iNES, GB/GBC, GBA, NDS, N64, Genesis, ELF and ZIP headers so the file still loads.",
                    config.protectFileHeaders,
                    enabled = config.enabled
                ) { AntiCrash.update(config.copy(protectFileHeaders = it)) }

                ToggleRow(
                    "Block executable regions",
                    "Live RAM: refuses code regions (rwx). Corrupting code is an instant crash.",
                    config.blockExecutable,
                    enabled = config.enabled
                ) { AntiCrash.update(config.copy(blockExecutable = it)) }

                ToggleRow(
                    "Block system regions",
                    "Live RAM: refuses stacks/TLS, vDSO, linker bookkeeping and the system-property area — always a crash, never a glitch.",
                    config.blockSystemRegions,
                    enabled = config.enabled
                ) { AntiCrash.update(config.copy(blockSystemRegions = it)) }

                ToggleRow(
                    "Heap guard (Scudo headers)",
                    "Live RAM: never overwrites the allocator's chunk headers in scudo heap regions. Every crash in the logs was " +
                        "\"Scudo ERROR: corrupted chunk header\" (SIGABRT) — it fires later, when the app frees the block.",
                    config.heapGuard,
                    enabled = config.enabled
                ) { AntiCrash.update(config.copy(heapGuard = it)) }

                ToggleRow(
                    "Pointer shield",
                    "Live RAM: never overwrites a value that points into the app's own memory — the #1 cause of SIGSEGV.",
                    config.pointerShield,
                    enabled = config.enabled
                ) { AntiCrash.update(config.copy(pointerShield = it)) }

                ToggleRow(
                    "Minimal patches",
                    "Live RAM: writes only the bytes that changed (one validated attach) instead of rewriting the whole " +
                        "region, so it can't revert what the app changed meanwhile or write into a freed region.",
                    config.minimalPatches,
                    enabled = config.enabled
                ) { AntiCrash.update(config.copy(minimalPatches = it)) }

                ToggleRow(
                    "Verify before write (freeze + compare)",
                    "Live RAM: freezes every thread of the target while writing, and skips any patch whose memory the app " +
                        "changed since the snapshot (freed, re-allocated, rewritten). Brief hitch per tick.",
                    config.verifyBeforeWrite,
                    enabled = config.enabled && config.minimalPatches
                ) { AntiCrash.update(config.copy(verifyBeforeWrite = it)) }

                ToggleRow(
                    "Learn from crashes (quarantine)",
                    "Live RAM: for file-backed memory only (libraries/assets), an area touched right before two separate " +
                        "crashes is left alone. Heap memory is never learned from — its layout changes every launch.",
                    config.quarantine,
                    enabled = config.enabled
                ) { AntiCrash.update(config.copy(quarantine = it)) }

                ToggleRow(
                    "Stop live corrupting when the target dies",
                    "Otherwise the loop keeps going for any other targets.",
                    config.stopOnCrash,
                    enabled = config.enabled
                ) { AntiCrash.update(config.copy(stopOnCrash = it)) }

                Text(
                    "Heap headers protected: ${stats.headersProtected}   ·   stale patches skipped: ${stats.stalePatchesSkipped}" +
                        "   ·   allocator aborts: ${stats.heapAborts}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Row(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "Quarantined areas: $quarantined",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.weight(1f)
                    )
                    TextButton(
                        onClick = {
                            AntiCrash.clearQuarantine()
                            quarantined = 0
                        },
                        enabled = quarantined > 0
                    ) { Text("Clear") }
                }
            }
        }

        // ---------------- Memory ----------------
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Memory", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Medium)
                Text(
                    "Big regions are never loaded whole. Live corrupting works on one window of the region per tick " +
                        "(sweeping through it, or staying inside your range), and activity scans run in the native helper " +
                        "with a fixed memory budget at a lower priority. A smaller window = lighter on the phone and " +
                        "other apps; a bigger one = more of a large region corrupted per tick. It also shrinks by itself " +
                        "when Android is low on memory.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                val choices = MemoryGovernor.WINDOW_CHOICES_MB
                val index = choices.indexOf(windowMb).coerceAtLeast(0)
                Text("Live RAM window: $windowMb MB per tick", style = MaterialTheme.typography.bodyMedium)
                Slider(
                    value = index.toFloat(),
                    onValueChange = { MemoryGovernor.setWindowMb(context, choices[it.toInt().coerceIn(0, choices.lastIndex)]) },
                    valueRange = 0f..choices.lastIndex.toFloat(),
                    steps = choices.size - 2
                )
            }
        }

        // ---------------- Log viewer ----------------
        Text("Log", style = MaterialTheme.typography.titleMedium)
        Text(
            "Also in logcat as RTCFS4A/*." +
                (RtcLog.logDirPath()?.let { "\nFiles: $it" } ?: ""),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            RtcLog.Level.values().forEach { level ->
                FilterChip(
                    selected = minLevel == level,
                    onClick = { minLevel = level },
                    label = { Text(level.letter.toString() + "+") }
                )
            }
        }

        ToggleRow(
            "Verbose (per-tick) lines in the log file",
            "Debug lines are always in logcat; this also writes them to the file. The file fills up fast.",
            verbose
        ) {
            verbose = it
            AntiCrash.verboseLog = it
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = {
                clipboard.setText(AnnotatedString(logText))
                notice = "Copied ${shown.size} line(s)."
            }) { Text("Copy") }
            OutlinedButton(onClick = { saveLauncher.launch("rtcfs4a_log.txt") }) { Text("Save…") }
            OutlinedButton(onClick = {
                RtcLog.clear()
                notice = "Log cleared."
            }) { Text("Clear") }
        }

        OutlinedButton(
            onClick = {
                collecting = true
                scope.launch {
                    crashLog = withContext(Dispatchers.IO) { CrashReporter.collectRecent() }
                    collecting = false
                }
            },
            enabled = !collecting,
            modifier = Modifier.fillMaxWidth()
        ) { Text(if (collecting) "Collecting…" else "Collect device crash log (needs root)") }
        if (collecting) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())

        notice?.let {
            AssistChip(onClick = { notice = null }, label = { Text(it) })
        }

        crashLog?.let { text ->
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Device crash log", fontWeight = FontWeight.Medium)
                    SelectionContainer {
                        Text(
                            text.take(12_000),
                            style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace, fontSize = 10.sp)
                        )
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextButton(onClick = {
                            clipboard.setText(AnnotatedString(text))
                            notice = "Copied the crash log."
                        }) { Text("Copy") }
                        TextButton(onClick = { crashLog = null }) { Text("Dismiss") }
                    }
                }
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            SelectionContainer {
                Text(
                    if (logText.isBlank()) "(nothing logged yet at this level)" else logText,
                    modifier = Modifier.padding(12.dp),
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace, fontSize = 10.sp)
                )
            }
        }
    }
}

@Composable
private fun ToggleRow(
    title: String,
    description: String,
    checked: Boolean,
    enabled: Boolean = true,
    onChange: (Boolean) -> Unit
) {
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f).padding(end = 12.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(
                description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Switch(checked = checked, onCheckedChange = onChange, enabled = enabled)
    }
}
