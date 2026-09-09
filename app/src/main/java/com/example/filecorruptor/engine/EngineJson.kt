package com.example.filecorruptor.engine

import org.json.JSONArray
import org.json.JSONObject

/**
 * Hand-rolled JSON (de)serialization using android.org.json — deliberately
 * avoiding kotlinx-serialization here to not add another Gradle
 * plugin/version to keep in sync (this project has already hit two build
 * breaks from version mismatches; org.json ships with the platform, so
 * there's nothing new to version-pin).
 */
object EngineJson {

    fun parseEngine(json: String): EngineDefinition {
        val root = JSONObject(json)

        val params = mutableListOf<ParameterDef>()
        val paramsArr = root.optJSONArray("parameters") ?: JSONArray()
        for (i in 0 until paramsArr.length()) {
            val p = paramsArr.getJSONObject(i)
            val optionsArr = p.optJSONArray("options")
            val options = if (optionsArr != null) (0 until optionsArr.length()).map { optionsArr.getString(it) } else emptyList()
            val visibleWhenValuesArr = p.optJSONArray("visibleWhenValues")
            val visibleWhenValues = if (visibleWhenValuesArr != null) {
                (0 until visibleWhenValuesArr.length()).map { visibleWhenValuesArr.getString(it) }
            } else emptyList()
            params += ParameterDef(
                id = p.getString("id"),
                label = p.optString("label", p.getString("id")),
                type = runCatching { ParamType.valueOf(p.optString("type", "number").uppercase()) }.getOrDefault(ParamType.NUMBER),
                min = p.optDouble("min", 0.0),
                max = p.optDouble("max", 100.0),
                step = p.optDouble("step", 1.0),
                default = p.optString("default", "0"),
                unit = p.optString("unit", ""),
                options = options,
                description = p.optString("description", ""),
                hidden = p.optBoolean("hidden", false),
                visibleWhenParam = p.optString("visibleWhenParam", "").ifBlank { null },
                visibleWhenValues = visibleWhenValues
            )
        }

        val ops = mutableListOf<OperationDef>()
        val opsArr = root.optJSONArray("operations") ?: JSONArray()
        for (i in 0 until opsArr.length()) {
            val o = opsArr.getJSONObject(i)
            val bindings = o.optJSONObject("params") ?: JSONObject()
            val paramMap = mutableMapOf<String, String>()
            bindings.keys().forEach { key -> paramMap[key] = bindings.get(key).toString() }
            val enabledParam = o.optString("enabledParam", "").ifBlank { null }
            ops += OperationDef(type = o.getString("type"), params = paramMap, enabledParam = enabledParam)
        }

        return EngineDefinition(
            id = root.getString("id"),
            name = root.optString("name", root.getString("id")),
            description = root.optString("description", ""),
            author = root.optString("author", ""),
            version = root.optString("version", "1.0"),
            parameters = params,
            operations = ops
        )
    }

    fun encodeConfig(engineId: String, values: Map<String, ParamValue>): String {
        val root = JSONObject()
        root.put("engineId", engineId)
        val valuesObj = JSONObject()
        // "lastSeedUsed" is internal bookkeeping (see below) — never exported
        // as its own field, only used to fill in "seed" when relevant.
        values.forEach { (k, v) -> if (k != "lastSeedUsed") valuesObj.put(k, v.asString()) }

        // If "seed" is left on auto (-1) but a run has actually happened, export
        // the concrete seed that run used instead of the literal -1 — so the
        // config file alone can reproduce that exact result — without ever
        // touching the live "seed" value itself. That's what keeps the field
        // parked on auto for next time instead of quietly flipping to manual.
        val seedValue = values["seed"]?.asLong()
        val lastSeedUsed = values["lastSeedUsed"]?.asLong()
        if (seedValue != null && seedValue < 0 && lastSeedUsed != null && lastSeedUsed >= 0) {
            valuesObj.put("seed", lastSeedUsed.toString())
        }

        root.put("values", valuesObj)
        return root.toString(2)
    }

    data class ParsedConfig(val engineId: String, val values: Map<String, ParamValue>)

    fun parseConfig(json: String): ParsedConfig {
        val root = JSONObject(json)
        val engineId = root.getString("engineId")
        val valuesObj = root.optJSONObject("values") ?: JSONObject()
        val values = mutableMapOf<String, ParamValue>()
        valuesObj.keys().forEach { k -> values[k] = ParamValue(valuesObj.get(k).toString()) }
        return ParsedConfig(engineId, values)
    }
}
