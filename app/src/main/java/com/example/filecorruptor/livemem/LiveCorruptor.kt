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

        val (original, readError) = RootMemoryHelper.readMemoryResult(ctx, process.pid, region.start, region.size.toInt())
        if (original == null) {
            if (regionIsGone(ctx, process.pid, region, readError)) {
                throw RegionGoneException(
                    "region 0x${region.start.toString(16)}-0x${region.end.toString(16)} of ${process.name} " +
                        "was freed by the app — dropped from the targets"
                )
            }
            throw explainFailure(ctx, process, "could not read region", readError)
        }

        val run = CorruptionEngineExecutor.runWithSeed(original, engine, values, protectKnownHeaders = false)
        val corrupted = run.bytes // runWithSeed works on a copy; `original` is still pristine

        var shielded = 0
        var quarantinedBytes = 0
        var headers = 0
        if (cfg.enabled) {
            // 1. Allocator headers first: the only thing that ever actually crashed the target in the logs.
            if (cfg.heapGuard) {
                headers = ScudoGuard.shield(original, corrupted, ScudoGuard.kindOf(region.path))
            }
            if (cfg.pointerShield) {
                mapIndexFor(ctx, process.pid)?.let { shielded = AntiCrash.shieldPointers(original, corrupted, it) }
            }
            if (cfg.quarantine && AntiCrash.isLearnable(region)) {
                quarantinedBytes = AntiCrash.applyQuarantine(AntiCrash.targetKey(process.name, region), original, corrupted)
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
                AntiCrash.recordCycle(AntiCrash.targetKey(process.name, region), patches)
            }

            var applied = patches.size
            var stale = 0
            val writtenBytes = patches.sumOf { it.bytes.size } // bytes in the patch set; stale ones may be skipped
            if (cfg.verifyBeforeWrite) {
                val res = RootMemoryHelper.patchMemoryChecked(
                    ctx, process.pid, region.start, region.end,
                    patches.map {
                        CheckedPatch(
                            region.start + it.offset,
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
                    ctx, process.pid, region.start, region.end,
                    patches.map { MemoryPatch(region.start + it.offset, it.bytes) }
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
        if (!RootMemoryHelper.writeMemory(ctx, process.pid, region.start, corrupted)) {
            throw explainFailure(ctx, process, "write failed", null)
        }
        RtcLog.d(TAG, "$where seed=${run.seedUsed}: wrote whole region (${corrupted.size} bytes)")
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
