package com.example.filecorruptor.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.example.filecorruptor.livemem.EmulatorRam
import com.example.filecorruptor.livemem.EmulatorRamCandidate
import com.example.filecorruptor.livemem.EmulatorRamResult
import com.example.filecorruptor.livemem.LiveSession
import com.example.filecorruptor.livemem.MemoryRegion
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean

/**
 * "Find emulator RAM": detects where an emulated N64's RAM lives in the selected process, with proof.
 * Auto-detects by default and shows a confidence tier; only a certain/high, unambiguous result gets the
 * one-tap "Target the RAM" button — anything weaker is shown as a suggestion to confirm, and the manual
 * region list below always stays available. The ROM file path is optional (adds ROM-copy evidence and shows
 * where the cartridge image sits relative to RAM).
 */
@Composable
fun EmulatorRamPanel(
    pid: Int,
    regions: List<MemoryRegion>,
    onTargetRam: (MemoryRegion, Long, Long) -> Unit,
    onStatus: (message: String, isError: Boolean) -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var romPath by remember(pid) { mutableStateOf("") }
    var running by remember(pid) { mutableStateOf(false) }
    var progress by remember(pid) { mutableStateOf<Pair<Int, Int>?>(null) }
    var result by remember(pid) { mutableStateOf<EmulatorRamResult?>(null) }
    val cancel = remember(pid) { AtomicBoolean(false) }

    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Find emulator RAM (N64)", style = MaterialTheme.typography.titleMedium)
            Text(
                "Pick the emulator's game process (e.g. \"…:EmulationProcess\", not the launcher UI), with a N64 game running. " +
                    "It looks for the console's own boot-time fingerprints in memory and tells you where the emulated RAM is " +
                    "and how sure it is. A ROM file path is optional: it adds proof and shows where the cartridge image sits.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            OutlinedTextField(
                value = romPath,
                onValueChange = { romPath = it },
                label = { Text("ROM file path (optional)") },
                placeholder = { Text("/sdcard/Download/game.z64") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Button(
                onClick = {
                    running = true; progress = null; result = null; cancel.set(false)
                    LiveSession.setProgress("Finding emulator RAM", 0, 0)
                    scope.launch {
                        val r = withContext(Dispatchers.IO) {
                            runCatching {
                                EmulatorRam.findN64(context, pid, regions, romPath, { a, b -> progress = a to b }, { cancel.get() })
                            }
                        }
                        running = false; progress = null; LiveSession.clearProgress()
                        r.onSuccess { res ->
                            result = res
                            val b = res.best
                            onStatus(
                                if (b == null) "No N64 RAM found in this process." else
                                    "N64 RAM: ${b.effectiveTier} (${b.bits} bits).",
                                b == null
                            )
                        }.onFailure { onStatus(it.message ?: "Detection failed.", true) }
                    }
                },
                enabled = !running && regions.isNotEmpty(),
                modifier = Modifier.fillMaxWidth()
            ) { Text("Detect") }

            if (running) {
                val p = progress
                if (p != null && p.second > 0) LinearProgressIndicator(progress = { p.first.toFloat() / p.second }, modifier = Modifier.fillMaxWidth())
                else LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                TextButton(onClick = { cancel.set(true) }) { Text("Cancel") }
            }

            val res = result
            if (res != null && !running) {
                val best = res.best
                if (best == null) {
                    Text(
                        "Nothing found. Check that: this is the emulator's game process (not the launcher), a N64 game is actually " +
                            "running (not paused at a menu), and the emulator is a N64 one. Scanned ${res.regionsScanned} region(s), " +
                            "${res.megabytesRead} MB in ${res.millis} ms.",
                        style = MaterialTheme.typography.bodyMedium
                    )
                } else {
                    val region = regions.firstOrNull { best.base >= it.start && best.base < it.end }
                    val trusted = (best.effectiveTier == "certain" || best.effectiveTier == "high")
                    Text(
                        "${best.effectiveTier.uppercase()} — ${best.bits} bits of evidence (${best.groups.replace(",", ", ").replace(":", " ")})",
                        style = MaterialTheme.typography.titleSmall
                    )
                    Text(
                        (if (region != null) "In ${region.size shr 20} MB ${region.perms} ${region.path.ifBlank { "[anonymous]" }}, " +
                            "RAM starts at +0x${(best.base - region.start).toString(16)} of it. " else "") +
                            "Stored as ${best.transform} words." +
                            (res.rom.firstOrNull { it.transform == best.transform }?.let { " Cartridge image ${if (it.base >= best.base) "+" else "-"}0x${kotlin.math.abs(it.base - best.base).toString(16)} from RAM." } ?: "") +
                            (if (best.livePermille >= 0) " ${best.livePermille / 10.0}% of its pages changed in 0.4 s." else ""),
                        style = MaterialTheme.typography.bodySmall
                    )
                    val statics = res.ram.filter { res.isStaticCopy(it) }
                    if (statics.isNotEmpty()) {
                        Text(
                            "${statics.size} other copy(ies) of the same RAM exist but never change (save-state/rewind buffers) — ignored.",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    if (best.ambiguous) {
                        Text("Evidence is ambiguous between several nearby addresses — confirm manually before trusting it.",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    } else if (!trusted) {
                        Text("Weak evidence — treat as a suggestion and confirm it by hand.",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            enabled = region != null && trusted && !best.ambiguous,
                            onClick = { if (region != null) onTargetRam(region, best.base - region.start, res.ramSize) }
                        ) { Text("Target the RAM") }
                    }
                }
            }
        }
    }
}
