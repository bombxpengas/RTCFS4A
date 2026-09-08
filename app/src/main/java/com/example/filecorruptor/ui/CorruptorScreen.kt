package com.example.filecorruptor.ui

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BrokenImage
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Save
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.filecorruptor.engine.CorruptionEngineExecutor
import com.example.filecorruptor.engine.EngineViewModel
import com.example.filecorruptor.engine.ParamValue
import com.example.filecorruptor.engine.isVisible
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

private data class PickedFile(
    val uri: Uri,
    val name: String,
    val bytes: ByteArray,
    val isImage: Boolean
)

@Composable
fun CorruptorScreen(engineViewModel: EngineViewModel = viewModel()) {
    val context = LocalContext.current
    val engines by engineViewModel.engines.collectAsState()
    val selectedEngineId by engineViewModel.selectedEngineId.collectAsState()
    val selectedEngine = engines.firstOrNull { it.id == selectedEngineId }

    var picked by remember { mutableStateOf<PickedFile?>(null) }
    var corrupted by remember { mutableStateOf<ByteArray?>(null) }
    var isProcessing by remember { mutableStateOf(false) }
    var savedMessage by remember { mutableStateOf<String?>(null) }

    // Bumped by the "Corrupt Again" button so the LaunchedEffect below re-runs
    // even when no parameter changed — otherwise, since the effect is keyed
    // on the parameter values, identical params meant identical (cached)
    // output no matter how many times you asked for a fresh corruption.
    var rerollTick by remember { mutableStateOf(0) }

    // Once a save location has been picked, Overwrite reuses it silently on
    // every later tap instead of reopening the system Save dialog — this is
    // what makes rapid "tweak a param, save, tweak again" iteration fast.
    var overwriteEnabled by remember { mutableStateOf(true) }
    var lastSavedUri by remember { mutableStateOf<Uri?>(null) }

    val openDocumentLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: return@rememberLauncherForActivityResult
        val name = queryDisplayName(context, uri) ?: "selected_file"
        val isImage = runCatching { BitmapFactory.decodeByteArray(bytes, 0, bytes.size) != null }.getOrDefault(false)
        picked = PickedFile(uri, name, bytes, isImage)
        corrupted = null
        savedMessage = null
        lastSavedUri = null // a new source file means a fresh save target
    }

    val createDocumentLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("*/*")
    ) { uri: Uri? ->
        val data = corrupted
        if (uri == null || data == null) return@rememberLauncherForActivityResult
        runCatching {
            context.contentResolver.takePersistableUriPermission(
                uri,
                android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION or android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )
        }
        lastSavedUri = uri
        context.contentResolver.openOutputStream(uri, "wt")?.use { it.write(data) }
        savedMessage = "Saved corrupted file."
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text("Corruptor", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Pick a file and an engine, then dial in exact parameters — every value here can be typed precisely, not just dragged.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Text("Engine", style = MaterialTheme.typography.titleMedium)
        if (engines.isEmpty()) {
            Text(
                "No engines installed yet.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else {
            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                items(engines) { engine ->
                    FilterChip(
                        selected = engine.id == selectedEngineId,
                        onClick = { engineViewModel.selectEngine(engine.id) },
                        label = { Text(engine.name) }
                    )
                }
            }
            selectedEngine?.let {
                if (it.description.isNotBlank()) {
                    Text(
                        it.description,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        FilledTonalButton(
            onClick = { openDocumentLauncher.launch(arrayOf("*/*")) },
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Filled.FolderOpen, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text(if (picked == null) "Select a file" else "Change file")
        }

        val file = picked
        val engine = selectedEngine
        if (file != null && engine != null) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(file.name, fontWeight = FontWeight.Medium, style = MaterialTheme.typography.titleMedium)
                    Text(
                        "${formatBytes(file.bytes.size.toLong())} • ${if (file.isImage) "Image preview available" else "Binary file"}",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            val engineValues = engineViewModel.valuesFor(engine.id)
            // Reading .toMap() here is a tracked Compose read of the
            // SnapshotStateMap, so editing any parameter below recomposes this
            // screen and produces a new (structurally-comparable) key for the
            // LaunchedEffect further down.
            val currentValues = engineValues.toMap()

            if (file.isImage) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    PreviewPane("Original", file.bytes, Modifier.weight(1f))
                    PreviewPane("Corrupted", corrupted, Modifier.weight(1f), isLoading = isProcessing)
                }
            } else if (corrupted != null) {
                HexPreview(corrupted!!)
            }

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

            LaunchedEffect(file.bytes, engine.id, currentValues, rerollTick) {
                isProcessing = true
                delay(120) // debounce rapid slider drags / typing
                val result = withContext(Dispatchers.Default) {
                    CorruptionEngineExecutor.run(file.bytes, engine, currentValues)
                }
                corrupted = result
                isProcessing = false
            }

            OutlinedButton(
                onClick = { rerollTick++ },
                enabled = !isProcessing,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Filled.Refresh, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Corrupt Again")
            }

            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(Modifier.weight(1f)) {
                    Text("Overwrite last saved file", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Medium)
                    Text(
                        if (lastSavedUri == null) "Next save will ask where to put it, then reuse that spot."
                        else "Saving now writes straight back to the same file — no dialog.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Switch(checked = overwriteEnabled, onCheckedChange = { overwriteEnabled = it })
            }

            Button(
                onClick = {
                    val data = corrupted ?: return@Button
                    val reuse = lastSavedUri
                    if (overwriteEnabled && reuse != null) {
                        context.contentResolver.openOutputStream(reuse, "wt")?.use { it.write(data) }
                        savedMessage = "Saved corrupted file."
                    } else {
                        val base = file.name.substringBeforeLast('.', file.name)
                        val ext = file.name.substringAfterLast('.', "")
                        val suggested = if (ext.isNotEmpty()) "${base}_corrupted.$ext" else "${base}_corrupted"
                        createDocumentLauncher.launch(suggested)
                    }
                },
                enabled = corrupted != null,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Filled.Save, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text(if (overwriteEnabled && lastSavedUri != null) "Save (overwrite)" else "Save corrupted file")
            }

            savedMessage?.let {
                AssistChip(onClick = { savedMessage = null }, label = { Text(it) })
            }
        }
    }
}

@Composable
private fun PreviewPane(label: String, bytes: ByteArray?, modifier: Modifier = Modifier, isLoading: Boolean = false) {
    Column(modifier) {
        Text(label, style = MaterialTheme.typography.labelLarge)
        Spacer(Modifier.height(4.dp))
        Box(
            Modifier
                .fillMaxWidth()
                .height(180.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(MaterialTheme.colorScheme.surfaceVariant),
            contentAlignment = Alignment.Center
        ) {
            val bitmap: Bitmap? = remember(bytes) {
                bytes?.let { runCatching { BitmapFactory.decodeByteArray(it, 0, it.size) }.getOrNull() }
            }
            when {
                isLoading -> CircularProgressIndicator()
                bitmap != null -> Image(
                    bitmap = bitmap.asImageBitmap(),
                    contentDescription = label,
                    modifier = Modifier.fillMaxSize(),
                    contentScale = ContentScale.Crop
                )
                else -> Icon(
                    Icons.Filled.BrokenImage,
                    contentDescription = "Could not decode image",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun HexPreview(bytes: ByteArray) {
    val preview = remember(bytes) { bytesToHexPreview(bytes, 256) }
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text("Hex preview (first 256 bytes)", style = MaterialTheme.typography.labelLarge)
            Spacer(Modifier.height(6.dp))
            Text(preview, style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace))
        }
    }
}

private fun bytesToHexPreview(bytes: ByteArray, limit: Int): String {
    val n = minOf(limit, bytes.size)
    val sb = StringBuilder()
    for (i in 0 until n) {
        sb.append(String.format("%02X ", bytes[i]))
        if ((i + 1) % 16 == 0) sb.append('\n')
    }
    return sb.toString()
}

private fun formatBytes(size: Long): String {
    if (size < 1024) return "$size B"
    val kb = size / 1024.0
    if (kb < 1024) return String.format("%.1f KB", kb)
    val mb = kb / 1024.0
    if (mb < 1024) return String.format("%.1f MB", mb)
    return String.format("%.2f GB", mb / 1024.0)
}

private fun queryDisplayName(context: android.content.Context, uri: Uri): String? {
    val cursor = context.contentResolver.query(uri, null, null, null, null)
    return cursor?.use {
        val idx = it.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
        if (idx >= 0 && it.moveToFirst()) it.getString(idx) else null
    }
}
