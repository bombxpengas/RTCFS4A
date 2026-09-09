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
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.FolderOpen
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
import androidx.documentfile.provider.DocumentFile
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
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private data class PickedFile(
    val uri: Uri,
    val name: String,
    val bytes: ByteArray,
    val isImage: Boolean
)

/** Walks a picked folder tree and returns every plain file in it — including
 *  subfolders, iteratively (no recursion) so a deep tree can't stack-overflow. */
private fun collectFilesRecursively(root: DocumentFile): List<DocumentFile> {
    val result = mutableListOf<DocumentFile>()
    val stack = ArrayDeque<DocumentFile>()
    stack.addLast(root)
    while (stack.isNotEmpty()) {
        val dir = stack.removeLast()
        for (child in dir.listFiles()) {
            if (child.isDirectory) stack.addLast(child) else if (child.isFile) result.add(child)
        }
    }
    return result
}

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

    // Holds the exact bytes a Save is writing, decoupled from the live
    // preview above — Save always computes a brand-new corruption right
    // before writing (see the Save button below), rather than reusing
    // whatever the auto-preview last happened to show.
    var pendingSaveBytes by remember { mutableStateOf<ByteArray?>(null) }
    val saveScope = rememberCoroutineScope()

    // Once a save location has been picked, Overwrite reuses it silently on
    // every later tap instead of reopening the system Save dialog — this is
    // what makes rapid "tweak a param, save, tweak again" iteration fast.
    var overwriteEnabled by remember { mutableStateOf(true) }
    var lastSavedUri by remember { mutableStateOf<Uri?>(null) }

    // --- Batch (folder) mode: same engine/parameters, applied to every file
    // found in a picked folder and its subfolders. ---
    var batchMode by remember { mutableStateOf(false) }
    var batchFiles by remember { mutableStateOf<List<DocumentFile>>(emptyList()) }
    var batchRunning by remember { mutableStateOf(false) }
    var batchProgress by remember { mutableStateOf(0) }
    var batchResultMessage by remember { mutableStateOf<String?>(null) }
    var showBatchConfirm by remember { mutableStateOf(false) }

    val openTreeLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        runCatching {
            context.contentResolver.takePersistableUriPermission(
                uri,
                android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION or android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )
        }
        val root = DocumentFile.fromTreeUri(context, uri)
        batchFiles = root?.let { collectFilesRecursively(it) }.orEmpty()
        batchResultMessage = null
    }

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
        val data = pendingSaveBytes
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
        pendingSaveBytes = null
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

        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
            SegmentedButton(
                selected = !batchMode,
                onClick = { batchMode = false },
                shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2)
            ) { Text("Single File") }
            SegmentedButton(
                selected = batchMode,
                onClick = { batchMode = true },
                shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2)
            ) { Text("Folder (Batch)") }
        }

        if (!batchMode) {
            FilledTonalButton(
                onClick = { openDocumentLauncher.launch(arrayOf("*/*")) },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Filled.FolderOpen, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text(if (picked == null) "Select a file" else "Change file")
            }
        } else {
            FilledTonalButton(
                onClick = { openTreeLauncher.launch(null) },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Filled.Folder, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text(if (batchFiles.isEmpty()) "Select a folder" else "Change folder")
            }
            if (batchFiles.isNotEmpty()) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
                ) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(
                            "${batchFiles.size} file${if (batchFiles.size == 1) "" else "s"} found (including subfolders)",
                            fontWeight = FontWeight.Medium,
                            style = MaterialTheme.typography.titleMedium
                        )
                        Text(
                            "Each file gets its own random draw from the current engine settings (a fixed seed applies the same transform to all of them instead). Corrupting replaces each original file in place — there's no undo, so make sure this is a folder you're fine overwriting.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }

        val file = picked
        val engine = selectedEngine
        if (engine != null && (batchMode || file != null)) {
            if (!batchMode && file != null) {
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
            }

            val engineValues = engineViewModel.valuesFor(engine.id)
            // Reading .toMap() here is a tracked Compose read of the
            // SnapshotStateMap, so editing any parameter below recomposes this
            // screen and produces a new (structurally-comparable) key for the
            // LaunchedEffect further down.
            val currentValues = engineValues.toMap()

            if (!batchMode && file != null) {
                if (file.isImage) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        PreviewPane("Original", file.bytes, Modifier.weight(1f))
                        PreviewPane("Corrupted", corrupted, Modifier.weight(1f), isLoading = isProcessing)
                    }
                } else if (corrupted != null) {
                    HexPreview(corrupted!!)
                }
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

            if (!batchMode && file != null) {
                LaunchedEffect(file.bytes, engine.id, currentValues) {
                    isProcessing = true
                    delay(120) // debounce rapid slider drags / typing
                    val result = withContext(Dispatchers.Default) {
                        CorruptionEngineExecutor.run(file.bytes, engine, currentValues)
                    }
                    corrupted = result
                    isProcessing = false
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
                        // Save always rolls a brand-new corruption right before
                        // writing — unless a fixed seed is set on the engine, in
                        // which case a fresh run naturally reproduces the same
                        // result, which is the point of a fixed seed.
                        saveScope.launch {
                            isProcessing = true
                            val result = withContext(Dispatchers.Default) {
                                CorruptionEngineExecutor.runWithSeed(file.bytes, engine, currentValues)
                            }
                            corrupted = result.bytes
                            isProcessing = false

                            // Record whatever seed actually produced this file —
                            // fixed or not — so Export Config (Settings tab) can
                            // capture the exact seed that made this result,
                            // instead of only ever reflecting a manually-typed one.
                            if (engineValues.containsKey("seed")) {
                                engineValues["seed"] = ParamValue.of(result.seedUsed.toString())
                            }

                            val reuse = lastSavedUri
                            if (overwriteEnabled && reuse != null) {
                                context.contentResolver.openOutputStream(reuse, "wt")?.use { it.write(result.bytes) }
                                savedMessage = "Saved corrupted file."
                            } else {
                                pendingSaveBytes = result.bytes
                                val base = file.name.substringBeforeLast('.', file.name)
                                val ext = file.name.substringAfterLast('.', "")
                                val suggested = if (ext.isNotEmpty()) "${base}_corrupted.$ext" else "${base}_corrupted"
                                createDocumentLauncher.launch(suggested)
                            }
                        }
                    },
                    enabled = !isProcessing,
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

            if (batchMode && batchFiles.isNotEmpty()) {
                if (batchRunning) {
                    LinearProgressIndicator(
                        progress = { if (batchFiles.isEmpty()) 0f else batchProgress / batchFiles.size.toFloat() },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Text(
                        "Processing $batchProgress of ${batchFiles.size}…",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                Button(
                    onClick = { showBatchConfirm = true },
                    enabled = !batchRunning,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Filled.Save, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("Corrupt All (Replace Files)")
                }

                batchResultMessage?.let {
                    AssistChip(onClick = { batchResultMessage = null }, label = { Text(it) })
                }

                if (showBatchConfirm) {
                    val filesToProcess = batchFiles
                    AlertDialog(
                        onDismissRequest = { showBatchConfirm = false },
                        title = { Text("Replace ${filesToProcess.size} file${if (filesToProcess.size == 1) "" else "s"}?") },
                        text = {
                            Text("Every file found will be corrupted and written straight back over the original. There's no undo — make sure you don't need these copies as-is.")
                        },
                        confirmButton = {
                            TextButton(onClick = {
                                showBatchConfirm = false
                                saveScope.launch {
                                    batchRunning = true
                                    batchProgress = 0
                                    batchResultMessage = null
                                    var succeeded = 0
                                    var failed = 0
                                    var lastSeedUsed: Long? = null

                                    for (doc in filesToProcess) {
                                        val outcome = runCatching {
                                            val bytes = context.contentResolver.openInputStream(doc.uri)
                                                ?.use { it.readBytes() } ?: error("could not read file")
                                            val result = withContext(Dispatchers.Default) {
                                                CorruptionEngineExecutor.runWithSeed(bytes, engine, currentValues)
                                            }
                                            lastSeedUsed = result.seedUsed

                                            // Replace the original in place — "wt" truncates
                                            // first so a smaller result never leaves trailing
                                            // bytes from the original behind.
                                            context.contentResolver.openOutputStream(doc.uri, "wt")
                                                ?.use { it.write(result.bytes) } ?: error("could not open output stream")
                                        }
                                        if (outcome.isSuccess) succeeded++ else failed++
                                        batchProgress++
                                    }

                                    // Same reasoning as the single-file Save: capture
                                    // whatever seed actually got used (from the last
                                    // file processed) so Export Config can reflect it.
                                    lastSeedUsed?.let { seed ->
                                        if (engineValues.containsKey("seed")) {
                                            engineValues["seed"] = ParamValue.of(seed.toString())
                                        }
                                    }

                                    batchRunning = false
                                    batchResultMessage = "Done: $succeeded replaced" +
                                        (if (failed > 0) ", $failed failed" else "") +
                                        " out of ${filesToProcess.size}."
                                }
                            }) { Text("Replace them") }
                        },
                        dismissButton = {
                            TextButton(onClick = { showBatchConfirm = false }) { Text("Cancel") }
                        }
                    )
                }
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
