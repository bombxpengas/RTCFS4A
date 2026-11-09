package com.example.filecorruptor.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.example.filecorruptor.livemem.LiveSession
import com.example.filecorruptor.livemem.MemoryRegion
import com.example.filecorruptor.livemem.RootMemoryHelper
import com.example.filecorruptor.livemem.ValueFilter
import com.example.filecorruptor.livemem.ValueFormat
import com.example.filecorruptor.livemem.ValueSearch
import com.example.filecorruptor.livemem.ValueSearchState
import com.example.filecorruptor.livemem.ValueType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Value search (the Cheat-Engine workflow) — replaces the old NES signature scan, which guessed from
 * the *shape* of bytes, flagged far too many false positives and was heavy. This looks for something
 * specific you can see in the app (score, lives, coins, HP): scan for it, change it in the app, narrow
 * the list by what happened to it. It works on any emulator or Android game, and a couple of rounds
 * usually leaves one or two addresses, which can then be corrupted on their own.
 *
 * [onTargetAddress] is called with (region, offset inside the region, value size in bytes) to make that
 * exact value the corruption target.
 */
@Composable
fun ValueSearchPanel(
    pid: Int,
    regions: List<MemoryRegion>,
    onTargetAddress: (MemoryRegion, Long, Int) -> Unit,
    onStatus: (message: String, isError: Boolean) -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val search = remember(pid) { ValueSearch(context) }
    DisposableEffect(search) { onDispose { search.reset() } }

    var type by remember(pid) { mutableStateOf(ValueType.I32) }
    var valueText by remember(pid) { mutableStateOf("") }
    var setText by remember(pid) { mutableStateOf("") }
    var state by remember(pid) { mutableStateOf<ValueSearchState?>(null) }
    var running by remember(pid) { mutableStateOf(false) }
    var progress by remember(pid) { mutableStateOf<Pair<Long, Long>?>(null) }
    val cancel = remember(pid) { AtomicBoolean(false) }

    fun launchSearch(title: String, block: () -> ValueSearchState) {
        running = true
        progress = null
        cancel.set(false)
        LiveSession.setProgress(title, 0, 0)
        scope.launch {
            val result = withContext(Dispatchers.IO) { runCatching(block) }
            running = false
            progress = null
            LiveSession.clearProgress()
            result.onSuccess { st ->
                state = st
                onStatus(
                    when {
                        cancel.get() -> "Value search cancelled."
                        st.count == 0 -> "No matches."
                        else -> "${st.count}${if (st.truncated) "+" else ""} match(es)."
                    },
                    false
                )
            }.onFailure { e ->
                onStatus(e.message ?: "Value search failed.", true)
            }
        }
    }

    val onProgress: (Long, Long) -> Unit = { a, b -> progress = a to b }

    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Value search", style = MaterialTheme.typography.titleMedium)
            Text(
                "Find a specific number in the app — a score, lives, coins, HP: type what you see on screen and scan. " +
                    "Then change it in the app (lose a life, pick up a coin), come back and narrow the list with " +
                    "\"Exact value\", \"Changed\" or \"Increased/Decreased\". After two or three rounds you're usually " +
                    "down to one or two addresses, which you can corrupt on their own. Works with emulators and " +
                    "Android games alike.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                ValueType.values().forEach { t ->
                    if (t == type) Button(onClick = {}, enabled = !running && state == null) { Text(t.label) }
                    else OutlinedButton(onClick = { type = t }, enabled = !running && state == null) { Text(t.label) }
                }
            }

            OutlinedTextField(
                value = valueText,
                onValueChange = { valueText = it },
                label = { Text(if (state == null) "Value to find" else "Value now (for \"Exact value\")") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )

            val st = state
            if (st == null) {
                Button(
                    onClick = {
                        if (!ValueFormat.isValid(type, valueText)) {
                            onStatus("'${valueText.trim()}' isn't a valid ${type.label} value.", true)
                        } else {
                            launchSearch("Value search") {
                                search.first(pid, regions, type, valueText, { a, b ->
                                    progress = a to b
                                    LiveSession.setProgress("Value search", a.toInt(), b.toInt())
                                }, { cancel.get() })
                            }
                        }
                    },
                    enabled = !running && regions.isNotEmpty(),
                    modifier = Modifier.fillMaxWidth()
                ) { Text("First scan (${regions.size} region(s))") }
            } else {
                Text(
                    when {
                        st.count == 0 -> "No matches left. The value may be stored another way (try float, or a different size), " +
                            "or live in a region hidden by the list filter. Start a new search to try again."
                        st.truncated -> "${st.count}+ matches — that value is too common, the scan stopped early. " +
                            "Start a new search with a rarer value (not 0 or 1), or pick fewer regions."
                        else -> "${st.count} candidate address(es)" +
                            if (st.count > ValueSearch.SAMPLE) " — keep narrowing; the list shows at ${ValueSearch.SAMPLE} or fewer." else "."
                    },
                    style = MaterialTheme.typography.bodyMedium
                )
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    listOf(ValueFilter.EXACT, ValueFilter.CHANGED, ValueFilter.UNCHANGED, ValueFilter.INCREASED, ValueFilter.DECREASED).forEach { f ->
                        OutlinedButton(
                            onClick = {
                                if (f == ValueFilter.EXACT && !ValueFormat.isValid(type, valueText)) {
                                    onStatus("Type the value it has now first.", true)
                                } else {
                                    launchSearch("Value search") {
                                        search.next(f, valueText, { a, b -> progress = a to b }, { cancel.get() })
                                    }
                                }
                            },
                            enabled = !running && st.count > 0
                        ) { Text(f.label) }
                    }
                    TextButton(
                        onClick = { search.reset(); state = null },
                        enabled = !running
                    ) { Text("New search") }
                }
            }

            if (running) {
                val p = progress
                if (p != null && p.second > 0) {
                    LinearProgressIndicator(progress = { (p.first.toFloat() / p.second).coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth())
                } else {
                    LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                }
                TextButton(onClick = { cancel.set(true) }) { Text("Cancel") }
            }

            val shown = state
            if (shown != null && !running && shown.count in 1..ValueSearch.SAMPLE) {
                OutlinedTextField(
                    value = setText,
                    onValueChange = { setText = it },
                    label = { Text("Set a found value to (optional)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Card {
                    LazyColumn(Modifier.heightIn(max = 320.dp)) {
                        items(shown.hits) { hit ->
                            val region = regions.firstOrNull { hit.address >= it.start && hit.address < it.end }
                            ListItem(
                                headlineContent = {
                                    Text("0x${hit.address.toString(16)}  =  ${ValueFormat.format(search.type, hit.raw)}")
                                },
                                supportingContent = {
                                    Text(
                                        if (region != null)
                                            "${if (region.path.isNotBlank()) region.path else "[anonymous]"}  +0x${(hit.address - region.start).toString(16)}"
                                        else "outside the listed regions"
                                    )
                                },
                                trailingContent = {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        TextButton(
                                            enabled = region != null && ValueFormat.isValid(search.type, setText),
                                            onClick = {
                                                val bytes = ValueFormat.encode(search.type, setText)
                                                if (bytes != null) {
                                                    scope.launch {
                                                        val ok = withContext(Dispatchers.IO) {
                                                            RootMemoryHelper.writeMemory(context, pid, hit.address, bytes)
                                                        }
                                                        onStatus(
                                                            if (ok) "Wrote $setText to 0x${hit.address.toString(16)}."
                                                            else "Couldn't write to 0x${hit.address.toString(16)} — the app may have moved or freed it.",
                                                            !ok
                                                        )
                                                        if (ok) launchSearch("Value search") {
                                                            search.next(ValueFilter.ALL, "0", { a, b -> progress = a to b }, { cancel.get() })
                                                        }
                                                    }
                                                }
                                            }
                                        ) { Text("Set") }
                                        TextButton(
                                            enabled = region != null,
                                            onClick = { if (region != null) onTargetAddress(region, hit.address - region.start, search.type.size) }
                                        ) { Text("Corrupt") }
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
