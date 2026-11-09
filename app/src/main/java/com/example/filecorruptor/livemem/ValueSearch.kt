package com.example.filecorruptor.livemem

import android.content.Context
import java.io.BufferedInputStream
import java.io.DataInputStream
import java.io.File
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** What kind of number to look for. Games and emulators store scores, lives, coins, health... as one of these. */
enum class ValueType(val code: String, val size: Int, val isFloat: Boolean, val label: String) {
    I32("i32", 4, false, "4-byte int"),
    F32("f32", 4, true, "float"),
    I16("i16", 2, false, "2-byte int"),
    I8("i8", 1, false, "1-byte"),
    I64("i64", 8, false, "8-byte int"),
    F64("f64", 8, true, "double")
}

/** How to narrow the candidates after the value changed in the target. */
enum class ValueFilter(val code: String, val label: String) {
    EXACT("exact", "Exact value"),
    CHANGED("changed", "Changed"),
    UNCHANGED("unchanged", "Unchanged"),
    INCREASED("increased", "Increased"),
    DECREASED("decreased", "Decreased"),
    ALL("all", "Refresh")
}

/** One candidate address and the raw bytes it held at the last scan (little-endian, zero-padded to 8). */
class ValueHit(val address: Long, val raw: Long)

class ValueSearchState(val count: Int, val truncated: Boolean, val hits: List<ValueHit>)

object ValueFormat {
    fun isValid(type: ValueType, text: String): Boolean {
        val t = text.trim()
        return if (type.isFloat) t.toDoubleOrNull()?.let { it.isFinite() } == true else t.toLongOrNull() != null
    }

    fun format(type: ValueType, raw: Long): String = when (type) {
        ValueType.I8 -> raw.toByte().toString()
        ValueType.I16 -> raw.toShort().toString()
        ValueType.I32 -> raw.toInt().toString()
        ValueType.I64 -> raw.toString()
        ValueType.F32 -> trimFloat(Float.fromBits(raw.toInt()).toDouble())
        ValueType.F64 -> trimFloat(Double.fromBits(raw))
    }

    private fun trimFloat(d: Double): String =
        if (d.isNaN() || d.isInfinite()) d.toString() else "%.6g".format(d)

    /** Bytes to write back for [text], or null if it isn't a valid number of this type. */
    fun encode(type: ValueType, text: String): ByteArray? {
        val t = text.trim()
        val buf = ByteBuffer.allocate(type.size).order(ByteOrder.LITTLE_ENDIAN)
        when (type) {
            ValueType.I8 -> buf.put((t.toLongOrNull() ?: return null).toByte())
            ValueType.I16 -> buf.putShort((t.toLongOrNull() ?: return null).toShort())
            ValueType.I32 -> buf.putInt((t.toLongOrNull() ?: return null).toInt())
            ValueType.I64 -> buf.putLong(t.toLongOrNull() ?: return null)
            ValueType.F32 -> buf.putFloat((t.toFloatOrNull() ?: return null))
            ValueType.F64 -> buf.putDouble(t.toDoubleOrNull() ?: return null)
        }
        return buf.array()
    }
}

/**
 * The Cheat-Engine workflow, on top of the native `vscan` / `vnext` helper commands: scan for a value
 * you can see in the app (score, lives, coins, HP), change it in the app, then keep only the addresses
 * that changed the way yours did. Two or three rounds normally leave one or two addresses — a specific,
 * checkable result, unlike a statistical "looks like game RAM" guess.
 *
 * Candidates live in a small file in the cache dir (16 bytes each, at most [MAX_RESULTS]); only the first
 * few are ever brought into the Java heap, so the size of the scanned regions doesn't matter.
 */
class ValueSearch(context: Context) {
    private val ctx = context.applicationContext
    private var current: File? = null
    private var spare: File? = null

    var type: ValueType = ValueType.I32
        private set
    var pid: Int = 0
        private set
    val active: Boolean get() = current != null

    private fun newFile(tag: String) = File(ctx.cacheDir, "valsearch_${tag}_${System.nanoTime()}.bin")

    /** First scan: every aligned occurrence of [valueText] in [regions]. Blocking — call from Dispatchers.IO. */
    fun first(
        pid: Int,
        regions: List<MemoryRegion>,
        type: ValueType,
        valueText: String,
        onProgress: (Long, Long) -> Unit,
        isCancelled: () -> Boolean
    ): ValueSearchState {
        require(regions.isNotEmpty()) { "no regions to scan" }
        require(ValueFormat.isValid(type, valueText)) { "'$valueText' isn't a valid ${type.label}" }
        reset()
        val regionsFile = newFile("regions")
        val out = newFile("a")
        val cancel = newFile("cancel")
        try {
            regionsFile.writeText(regions.joinToString("\n") { "${it.start.toString(16)} ${it.end.toString(16)}" })
            val run = RootMemoryHelper.runStreamingHelper(
                ctx,
                listOf("vscan", pid.toString(), regionsFile.absolutePath, type.code, valueText.trim(), out.absolutePath, MAX_RESULTS.toString(), cancel.absolutePath),
                cancel, onProgress, isCancelled
            )
            if (run.cancelled) { out.delete(); return ValueSearchState(0, false, emptyList()) }
            this.pid = pid
            this.type = type
            current = out
            return ValueSearchState(run.count, run.truncated, readHits(out, run.count))
        } catch (e: Exception) {
            out.delete()
            throw e
        } finally {
            regionsFile.delete()
        }
    }

    /** Keeps only the candidates matching [filter] (for [ValueFilter.EXACT], equal to [valueText]). */
    fun next(
        filter: ValueFilter,
        valueText: String,
        onProgress: (Long, Long) -> Unit,
        isCancelled: () -> Boolean
    ): ValueSearchState {
        val inFile = current ?: throw IllegalStateException("start a search first")
        if (filter == ValueFilter.EXACT) require(ValueFormat.isValid(type, valueText)) { "'$valueText' isn't a valid ${type.label}" }
        val out = spare ?: newFile("b")
        val cancel = newFile("cancel")
        try {
            val run = RootMemoryHelper.runStreamingHelper(
                ctx,
                listOf("vnext", pid.toString(), inFile.absolutePath, type.code, filter.code, valueText.trim().ifEmpty { "0" }, out.absolutePath, cancel.absolutePath),
                cancel, onProgress, isCancelled
            )
            if (run.cancelled) { out.delete(); return ValueSearchState(count(inFile), false, readHits(inFile, count(inFile))) }
            spare = inFile
            current = out
            return ValueSearchState(run.count, false, readHits(out, run.count))
        } catch (e: Exception) {
            if (out !== spare) out.delete()
            throw e
        }
    }

    fun reset() {
        current?.delete(); spare?.delete()
        current = null; spare = null
    }

    private fun count(file: File): Int = try {
        DataInputStream(FileInputStream(file)).use { d ->
            val h = ByteArray(8); d.readFully(h)
            ByteBuffer.wrap(h).order(ByteOrder.LITTLE_ENDIAN).getInt(4)
        }
    } catch (_: Exception) { 0 }

    /** Reads at most [SAMPLE] hits from the start of the candidate file. */
    private fun readHits(file: File, count: Int): List<ValueHit> {
        val n = minOf(count, SAMPLE)
        if (n <= 0) return emptyList()
        return DataInputStream(BufferedInputStream(FileInputStream(file), 16 * 1024)).use { d ->
            d.skipBytes(8)
            val rec = ByteArray(16)
            val out = ArrayList<ValueHit>(n)
            for (i in 0 until n) {
                d.readFully(rec)
                val b = ByteBuffer.wrap(rec).order(ByteOrder.LITTLE_ENDIAN)
                out += ValueHit(b.getLong(0), b.getLong(8))
            }
            out
        }
    }

    companion object {
        /** Cap on stored candidates (16 bytes each = 16 MB on disk, none of it in the Java heap). */
        const val MAX_RESULTS = 1_000_000

        /** How many hits are ever brought into memory for display. */
        const val SAMPLE = 200
    }
}
