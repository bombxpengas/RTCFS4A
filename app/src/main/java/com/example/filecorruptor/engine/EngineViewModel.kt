package com.example.filecorruptor.engine

import android.app.Application
import android.content.Context
import android.net.Uri
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.snapshots.SnapshotStateMap
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Owns the list of installed corruption engines (bundled + user-imported),
 * each engine's current parameter values, and JSON import/export. Shared
 * between the Corruptor and Settings screens so switching tabs doesn't lose
 * in-progress parameter tweaks.
 */
class EngineViewModel(application: Application) : AndroidViewModel(application) {

    private val importedDir: File by lazy {
        File(getApplication<Application>().filesDir, "engines").apply { mkdirs() }
    }

    private val _engines = MutableStateFlow<List<EngineDefinition>>(emptyList())
    val engines: StateFlow<List<EngineDefinition>> = _engines.asStateFlow()

    private val _selectedEngineId = MutableStateFlow<String?>(null)
    val selectedEngineId: StateFlow<String?> = _selectedEngineId.asStateFlow()

    // One Compose-observable value map per engine id, created lazily and kept
    // around so switching engines/tabs doesn't discard the user's tweaks.
    private val valuesByEngine = mutableMapOf<String, SnapshotStateMap<String, ParamValue>>()

    val statusMessage = mutableStateOf<String?>(null)
    val errorMessage = mutableStateOf<String?>(null)

    init {
        reload()
    }

    fun currentEngine(): EngineDefinition? =
        _engines.value.firstOrNull { it.id == _selectedEngineId.value }

    fun valuesFor(engineId: String): SnapshotStateMap<String, ParamValue> =
        valuesByEngine.getOrPut(engineId) {
            val defs = _engines.value.firstOrNull { it.id == engineId }?.parameters.orEmpty()
            val map = mutableStateMapOf<String, ParamValue>()
            defs.forEach { map[it.id] = ParamValue(it.default) }
            map
        }

    fun selectEngine(id: String) {
        _selectedEngineId.value = id
    }

    private fun reload() {
        viewModelScope.launch(Dispatchers.IO) {
            val loaded = mutableListOf<EngineDefinition>()
            val ctx = getApplication<Application>()

            val bundledNames = ctx.assets.list("engines").orEmpty()
            for (name in bundledNames) {
                if (!name.endsWith(".json")) continue
                runCatching {
                    val json = ctx.assets.open("engines/$name").bufferedReader().use { it.readText() }
                    loaded += EngineJson.parseEngine(json)
                }
            }

            importedDir.listFiles { f -> f.extension == "json" }?.forEach { file ->
                runCatching { loaded += EngineJson.parseEngine(file.readText()) }
            }

            // Later entries win on id collision, so a re-imported engine
            // (which we always write to importedDir) overrides its bundled
            // counterpart or a previous import with the same id.
            val byId = linkedMapOf<String, EngineDefinition>()
            loaded.forEach { byId[it.id] = it }
            val finalList = byId.values.toList()

            withContext(Dispatchers.Main) {
                _engines.value = finalList
                if (_selectedEngineId.value == null || finalList.none { it.id == _selectedEngineId.value }) {
                    _selectedEngineId.value = finalList.firstOrNull()?.id
                }
            }
        }
    }

    fun importEngine(context: Context, uri: Uri) {
        viewModelScope.launch(Dispatchers.IO) {
            val result = runCatching {
                val json = context.contentResolver.openInputStream(uri)
                    ?.bufferedReader()?.use { it.readText() }
                    ?: error("Could not open file")
                val engine = EngineJson.parseEngine(json)
                require(engine.id.isNotBlank()) { "Engine JSON is missing an \"id\"" }
                require(engine.operations.isNotEmpty()) { "Engine has no \"operations\" — it wouldn't do anything" }
                File(importedDir, "${engine.id}.json").writeText(json)
                engine
            }
            withContext(Dispatchers.Main) {
                result.onSuccess { engine ->
                    valuesByEngine.remove(engine.id) // re-derive defaults for the (re)imported engine
                    val updated = _engines.value.filterNot { it.id == engine.id } + engine
                    _engines.value = updated
                    _selectedEngineId.value = engine.id
                    statusMessage.value = "Imported engine: ${engine.name}"
                }.onFailure {
                    errorMessage.value = "Couldn't import engine: ${it.message}"
                }
            }
        }
    }

    fun exportConfig(context: Context, uri: Uri) {
        val engineId = _selectedEngineId.value
        if (engineId == null) {
            errorMessage.value = "No engine selected."
            return
        }
        val values = valuesFor(engineId).toMap()
        viewModelScope.launch(Dispatchers.IO) {
            val result = runCatching {
                val json = EngineJson.encodeConfig(engineId, values)
                context.contentResolver.openOutputStream(uri)?.use { it.write(json.toByteArray()) }
                    ?: error("Could not open output stream")
            }
            withContext(Dispatchers.Main) {
                result.onSuccess { statusMessage.value = "Exported config." }
                    .onFailure { errorMessage.value = "Couldn't export config: ${it.message}" }
            }
        }
    }

    fun importConfig(context: Context, uri: Uri) {
        viewModelScope.launch(Dispatchers.IO) {
            val result = runCatching {
                val json = context.contentResolver.openInputStream(uri)
                    ?.bufferedReader()?.use { it.readText() }
                    ?: error("Could not open file")
                EngineJson.parseConfig(json)
            }
            withContext(Dispatchers.Main) {
                result.onSuccess { parsed ->
                    val engine = _engines.value.firstOrNull { it.id == parsed.engineId }
                    if (engine == null) {
                        errorMessage.value =
                            "Config references engine \"${parsed.engineId}\", which isn't installed — import that engine first."
                        return@onSuccess
                    }
                    val map = valuesFor(engine.id)
                    parsed.values.forEach { (k, v) -> map[k] = v }
                    _selectedEngineId.value = engine.id
                    statusMessage.value = "Imported config for ${engine.name}."
                }.onFailure {
                    errorMessage.value = "Couldn't import config: ${it.message}"
                }
            }
        }
    }
}
