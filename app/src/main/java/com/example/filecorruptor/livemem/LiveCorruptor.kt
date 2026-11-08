package com.example.filecorruptor.livemem

import android.content.Context
import com.example.filecorruptor.engine.CorruptionEngineExecutor
import com.example.filecorruptor.engine.EngineDefinition
import com.example.filecorruptor.engine.ParamValue
import com.example.filecorruptor.log.CrashReport
import com.example.filecorruptor.log.CrashReporter
import com.example.filecorruptor.log.RtcLog
import com.example.filecorruptor.safety.AntiCrash
import com.example.filecorruptor.safety.ScudoGuard

/**
 * One live-corruption pass over one memory region of one process, with the
 * anti-crash rules from [AntiCrash] applied and the outcome logged.
 *
 * Pipeline: read region → run the engine on a copy → (allocator-header guard) →
 * (pointer shield) → (quarantine) → write back only what changed, as
 * compare-and-swap patches while every thread of the target is frozen. If any
 * step fails, the target's state is checked: if it died,
 * the crash is collected ([CrashReporter]), logged, and learned from
 * ([AntiCrash.onProcessCrashed]), and [TargetDiedException] is thrown.
 *
 * Blocking; call from Dispatchers.IO.
 */
object LiveCorruptor {

    private const val TAG = "Live"
    private const val MAP_TTL_MS = 3_000L

    data class Outcome(
        val seedUsed: Long,
        /** Distinct byte runs written (0 = the engine happened to change nothing). */
        val patches: Int,
        val bytesWritten: Int,
        /** Pointer-sized words left untouched by the pointer shield. */
        val pointersShielded: Int,
        /** Bytes left untouched because they sit in a crash-quarantined area. */
        val quarantinedBytes: Int,
        /** Allocator chunk headers (Scudo) left untouched by the heap guard. */
        val headersProtected: Int = 0,
        /** Patches not written because the app changed that memory after our snapshot. */
        val stalePatches: Int = 0
    )

    /**
     * The region was unmapped by the app (a freed large allocation, a released
     * heap chunk) — normal for heap memory, not a crash. The target is dropped.
     */
    class RegionGoneException(message: String) : Exception(message)

    /** The target process is gone. [report] has the crash evidence, if any could be collected. */
    class TargetDiedException(message: String, val report: CrashReport?) : Exception(message)

    private class CachedMaps(val atMs: Long, val index: AntiCrash.MapIndex)

    private val mapCache = HashMap<Int, CachedMaps>()

    /** pid -> (when, crash already collected for it). Short-lived, since Android can recycle a pid. */
    private val reportedCrashes = HashMap<Int, Pair<Long, CrashReport>>()
    private const val REPORT_REUSE_MS = 20_000L

    /** The slice of a region one tick works on. */
    private class Window(val offset: Long, val length: Int)

    /** Next window start per target, so successive ticks sweep the whole region. */
    private val cursors = HashMap<String, Long>()

    private fun paramLong(engine: EngineDefinition, values: Map<String, ParamValue>, arg: String): Long {
        for (op in engine.operations) {
            val id = op.params[arg] ?: continue
            val v = values[id]?.asLong() ?: continue
            return v
        }
        return -1L
    }

    /**
     * Big regions are never loaded whole: a tick reads, corrupts and patches one window of at most
     * [MemoryGovernor.windowBytes]. If the engine has a range (rangeStart/rangeEnd) the windows stay
     * inside it; otherwise successive ticks sweep through the region.
     */
    private fun pickWindow(ctx: Context, process: LiveProcess, region: MemoryRegion, engine: EngineDefinition, values: Map<String, ParamValue>): Window {
        val size = region.size
        val wBytes = MemoryGovernor.windowBytes(ctx)
        if (size <= wBytes) return Window(0, size.toInt())

        val rs = paramLong(engine, values, "rangeStart")
        val re = paramLong(engine, values, "rangeEnd")
        val spanStart = if (rs >= 0) rs.coerceAtMost(size) else 0L
        val spanEnd = if (re >= 0) re.coerceIn(spanStart, size) else size
        if (spanEnd <= spanStart) return Window(0, minOf(size, wBytes).toInt())

        val base = spanStart and 4095L.inv()
        val total = spanEnd - base
        if (total <= wBytes) return Window(base, total.toInt())

        val key = "${process.pid}|${region.start}"
        val cur = synchronized(cursors) { cursors[key] ?: 0L }
        val rel = if (cur >= total) 0L else cur
        val len = minOf(wBytes, total - rel)
        synchronized(cursors) { cursors[key] = rel + len }
        return Window(base + rel, len.toInt())
    }

    /** Re-expresses the engine's range/header parameters relative to the window instead of the region. */
    private fun windowValues(engine: EngineDefinition, values: Map<String, ParamValue>, w: Window): Map<String, ParamValue> {
        val out = HashMap(values)
        for (op in engine.operations) {
            op.params["rangeStart"]?.let { id ->
                val v = values[id]?.asLong() ?: -1L
                if (v >= 0) out[id] = ParamValue.of((v - w.offset).coerceIn(0L, w.length.toLong()).toString())
            }
            op.params["rangeEnd"]?.let { id ->
                val v = values[id]?.asLong() ?: -1L
                if (v >= 0) out[id] = ParamValue.of((v - w.offset).coerceIn(0L, w.length.toLong()).toString())
            }
            if (w.offset > 0L) { // a header / skipped prefix only exists at the start of the region
                op.params["headerSize"]?.let { out[it] = ParamValue.of("0") }
                op.params["skipBytes"]?.let { out[it] = ParamValue.of("0") }
            }
        }
        return out
    }

    private fun mapIndexFor(context: Context, pid: Int): AntiCrash.MapIndex? {
        val now = System.currentTimeMillis()
        synchronized(mapCache) {
            mapCache[pid]?.let { if (now - it.atMs < MAP_TTL_MS) return it.index }
        }
        val regions = RootMemoryHelper.listMemoryMaps(context, pid)
        if (regions.isEmpty()) return null
        val index = AntiCrash.MapIndex(regions)
        synchronized(mapCache) { mapCache[pid] = CachedMaps(now, index) }
        return index
    }

    fun corruptTarget(
        context: Context,
        process: LiveProcess,
        region: MemoryRegion,
        engine: EngineDefinition,
        values: Map<String, ParamValue>
    ): Outcome {
        val ctx = context.applicationContext
        val cfg = AntiCrash.current()
        val where = "${process.name} [0x${region.start.toString(16)}-0x${region.end.toString(16)} ${region.perms} ${region.path}]"

        if (cfg.enabled && cfg.blockExecutable && region.isExecutable) {
            throw IllegalStateException(
                "refusing ${process.name}'s region 0x${region.start.toString(16)}: it is executable (code) — " +
                    "corrupting it crashes the app. Turn off \"Block executable regions\" in Logs to override."
            )
        }
        if (cfg.enabled && cfg.blockSystemRegions) {
            ScudoGuard.systemRegionReason(region.path)?.let { why ->
                throw IllegalStateException(
                    "refusing ${process.name}'s region 0x${region.start.toString(16)} (${region.path}): it is $why — " +
                        "corrupting it crashes the app instead of glitching it. Turn off \"Block system regions\" in Logs to override."
                )
            }
        }
        if (!region.isWritable) {
            throw IllegalStateException("region 0x${region.start.toString(16)} of ${process.name} is not writable")
        }

        val win = pickWindow(ctx, process, region, engine, values)
        val winStart = region.start + win.offset
        val (original, readError) = RootMemoryHelper.readMemoryResult(ctx, process.pid, winStart, win.length)
        if (original == null) {
            if (regionIsGone(ctx, process.pid, region, readError)) {
                throw RegionGoneException(
                    "region 0x${region.start.toString(16)}-0x${region.end.toString(16)} of ${process.name} " +
                        "was freed by the app — dropped from the targets"
                )
            }
            throw explainFailure(ctx, process, "could not read region", readError)
        }

        val run = CorruptionEngineExecutor.runWithSeed(original, engine, windowValues(engine, values, win), protectKnownHeaders = false)
        val corrupted = run.bytes // runWithSeed works on a copy; `original` is still pristine

        var shielded = 0
        var quarantinedBytes = 0
        var headers = 0
        if (cfg.enabled) {
            // 1. Allocator headers first: the only thing that ever actually crashed the target in the logs.
            if (cfg.heapGuard) {
                headers = ScudoGuard.shield(original, corrupted, ScudoGuard.kindOf(region.path), win.offset)
            }
            if (cfg.pointerShield) {
                mapIndexFor(ctx, process.pid)?.let {
                    shielded = AntiCrash.shieldPointers(original, corrupted, it) +
                        AntiCrash.shieldNullSlots(original, corrupted, it)
                }
            }
            if (cfg.quarantine && AntiCrash.isLearnable(region)) {
                quarantinedBytes = AntiCrash.applyQuarantine(AntiCrash.targetKey(process.name, region), original, corrupted, win.offset)
            }
        }

        if (cfg.enabled && cfg.minimalPatches) {
            val patches = AntiCrash.diffPatches(original, corrupted)
            if (patches.isEmpty()) {
                AntiCrash.addProtection(headers, 0)
                RtcLog.d(TAG, "$where seed=${run.seedUsed}: nothing left to write (headers=$headers shielded=$shielded quarantined=$quarantinedBytes)")
                return Outcome(run.seedUsed, 0, 0, shielded, quarantinedBytes, headers, 0)
            }
            if (AntiCrash.isLearnable(region)) {
                AntiCrash.recordCycle(AntiCrash.targetKey(process.name, region), patches, win.offset)
            }

            var applied = patches.size
            var stale = 0
            val writtenBytes = patches.sumOf { it.bytes.size } // bytes in the patch set; stale ones may be skipped
            if (cfg.verifyBeforeWrite) {
                val res = RootMemoryHelper.patchMemoryChecked(
                    ctx, process.pid, winStart, winStart + win.length,
                    patches.map {
                        CheckedPatch(
                            winStart + it.offset,
                            original.copyOfRange(it.offset, it.offset + it.bytes.size),
                            it.bytes
                        )
                    }
                )
                if (res.error != null) throw explainFailure(ctx, process, "write failed", res.error)
                applied = res.applied
                stale = res.skipped + res.unmapped
                if (stale > 0) {
                    RtcLog.d(TAG, "$where: ${res.skipped} patch(es) skipped (the app changed that memory after the snapshot), ${res.unmapped} unmapped")
                }
            } else {
                val err = RootMemoryHelper.patchMemory(
                    ctx, process.pid, winStart, winStart + win.length,
                    patches.map { MemoryPatch(winStart + it.offset, it.bytes) }
                )
                if (err != null) throw explainFailure(ctx, process, "write failed", err)
            }

            AntiCrash.addProtection(headers, stale)
            RtcLog.d(
                TAG,
                "$where seed=${run.seedUsed}: wrote $applied/${patches.size} patch(es) of $writtenBytes byte(s); " +
                    "headers=$headers shielded=$shielded quarantined=$quarantinedBytes stale=$stale"
            )
            return Outcome(run.seedUsed, applied, writtenBytes, shielded, quarantinedBytes, headers, stale)
        }

        // Anti-crash off (or minimal patches off): the original whole-region write-back.
        if (!RootMemoryHelper.writeMemory(ctx, process.pid, winStart, corrupted)) {
            throw explainFailure(ctx, process, "write failed", null)
        }
        RtcLog.d(TAG, "$where seed=${run.seedUsed}: wrote window 0x${win.offset.toString(16)}+${corrupted.size} (${corrupted.size} bytes)")
        return Outcome(run.seedUsed, 1, corrupted.size, shielded, quarantinedBytes, headers, 0)
    }

    /**
     * A failed read is "the region is gone" (not "the target died") when the
     * error is an I/O/fault error and the target's current maps no longer
     * cover the whole range. Heap memory does this constantly: Scudo unmaps
     * freed large blocks — the logs are full of `ERR read failed ... I/O error`.
     */
    private fun regionIsGone(ctx: Context, pid: Int, region: MemoryRegion, readError: String?): Boolean {
        val e = readError.orEmpty()
        val looksLikeVanished = e.contains("I/O error", ignoreCase = true) ||
            e.contains("Input/output", ignoreCase = true) ||
            e.contains("Bad address", ignoreCase = true)
        if (!looksLikeVanished) return false
        synchronized(mapCache) { mapCache.remove(pid) }
        val regions = RootMemoryHelper.listMemoryMaps(ctx, pid)
        if (regions.isEmpty()) return false // can't tell (maybe the process died) — let explainFailure decide
        return !AntiCrash.MapIndex(regions).coversRange(region.start, region.end)
    }

    /**
     * A read or write failed — find out why. If the target is gone, collect
     * the crash evidence and learn from it; otherwise it's an ordinary
     * failure (permission, mapping moved, ...).
     */
    private fun explainFailure(ctx: Context, process: LiveProcess, what: String, detail: String?): Exception {
        // Several targets can live in the same process; once its crash has been
        // collected, the others just reuse that report instead of repeating
        // the (slow, noisy) logcat/tombstone collection.
        synchronized(reportedCrashes) { reportedCrashes[process.pid] }
            ?.takeIf { System.currentTimeMillis() - it.first < REPORT_REUSE_MS }
            ?.let { return TargetDiedException(it.second.summary, it.second) }
        val state = CrashReporter.awaitState(ctx, process.pid, process.name)
        if (state == ProcState.DEAD) {
            synchronized(mapCache) { mapCache.remove(process.pid) }
            val report = CrashReporter.collect(ctx, process.pid, process.name)
            AntiCrash.onProcessCrashed(process.name, heapAbort = report.heapCorruption)
            synchronized(reportedCrashes) { reportedCrashes[process.pid] = System.currentTimeMillis() to report }
            return TargetDiedException(report.summary, report)
        }
        val message = "$what for ${process.name}" + (detail?.let { ": $it" } ?: "") +
            if (state == ProcState.STOPPED) " (the process is stuck stopped)" else ""
        RtcLog.w(TAG, message)
        return IllegalStateException(message)
    }
}
