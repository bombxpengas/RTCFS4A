package com.example.filecorruptor.engine

/**
 * One user-adjustable (or hidden/internal) control that a corruption engine exposes.
 * Rendered in the UI according to [type]; consumed by [OperationDef.params] bindings.
 * Every field here is intentionally plain data (no platform types) so an
 * [EngineDefinition] can be parsed straight from hand-written JSON.
 */
data class ParameterDef(
    val id: String,
    val label: String,
    val type: ParamType,
    val min: Double = 0.0,
    val max: Double = 100.0,
    val step: Double = 1.0,
    val default: String,
    val unit: String = "",
    val options: List<String> = emptyList(), // DROPDOWN only
    val description: String = "",
    /** Hidden parameters still hold a value and can be bound by operations,
     *  but render no UI control — useful for fixed internal constants. */
    val hidden: Boolean = false
)

enum class ParamType { SLIDER, SWITCH, NUMBER, DROPDOWN }

/**
 * One corruption pass. [type] selects a built-in primitive (see
 * CorruptionEngineExecutor), and [params] binds that primitive's named
 * arguments (e.g. "intensity", "skipBytes", "chunkSize") to parameter ids
 * declared in the engine's own [ParameterDef] list.
 */
data class OperationDef(
    val type: String,
    val params: Map<String, String> = emptyMap()
)

data class EngineDefinition(
    val id: String,
    val name: String,
    val description: String = "",
    val author: String = "",
    val version: String = "1.0",
    val parameters: List<ParameterDef> = emptyList(),
    val operations: List<OperationDef> = emptyList()
)

/**
 * A single parameter's current value, stored as text so Compose state, JSON
 * config export/import, and every parameter type (number/bool/enum) can all
 * be handled uniformly without a polymorphic value hierarchy.
 */
data class ParamValue(val raw: String) {
    fun asDouble(): Double = raw.toDoubleOrNull() ?: 0.0
    fun asInt(): Int = asDouble().toInt()
    fun asLong(): Long = raw.toDoubleOrNull()?.toLong() ?: raw.toLongOrNull() ?: 0L
    fun asBoolean(): Boolean = raw.equals("true", ignoreCase = true)
    fun asString(): String = raw

    companion object {
        fun of(d: Double): ParamValue {
            val text = if (d == d.toLong().toDouble()) d.toLong().toString() else d.toString()
            return ParamValue(text)
        }
        fun of(b: Boolean) = ParamValue(b.toString())
        fun of(s: String) = ParamValue(s)
    }
}

fun EngineDefinition.defaultValues(): Map<String, ParamValue> =
    parameters.associate { it.id to ParamValue(it.default) }
