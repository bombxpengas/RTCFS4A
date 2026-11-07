package com.example.filecorruptor.livemem

import android.content.Context
import com.example.filecorruptor.engine.CorruptionEngineExecutor
import com.example.filecorruptor.engine.EngineDefinition
import com.example.filecorruptor.engine.ParamValue
import com.example.filecorruptor.log.CrashReport
import com.example.filecorruptor.log.CrashReporter
import com.example.filecorruptor.log.RtcLog
import com.example.filecorruptor.safety.AntiCrash

/**
 * One live-corruption pass over one memory region of one process, with the
 * anti-crash rules from [AntiCrash] applied and the outcome logged.
 *
 * Pipeline: read region → run the engine on a copy → (pointer shield) →
 * (quarantine) → write back only what changed, in one validated ptrace
 * attach. If any step fails, the target's state is checked: if it died,
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
        val quarantinedBytes: Int
    )

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
        if (!region.isWritable) {
            throw IllegalStateException("region 0x${region.start.toString(16)} of ${process.name} is not writable")
        }

        val (original, readError) = RootMemoryHelper.readMemoryResult(ctx, process.pid, region.start, region.size.toInt())
        if (original == null) throw explainFailure(ctx, process, "could not read region", readError)

        val run = CorruptionEngineExecutor.runWithSeed(original, engine, values, protectKnownHeaders = false)
        val corrupted = run.bytes // runWithSeed works on a copy; `original` is still pristine

        var shielded = 0
        var quarantinedBytes = 0
        if (cfg.enabled) {
            if (cfg.pointerShield) {
                mapIndexFor(ctx, process.pid)?.let { shielded = AntiCrash.shieldPointers(original, corrupted, it) }
            }
            if (cfg.quarantine) {
                quarantinedBytes = AntiCrash.applyQuarantine(AntiCrash.targetKey(process.name, region), original, corrupted)
            }
        }

        if (cfg.enabled && cfg.minimalPatches) {
            val patches = AntiCrash.diffPatches(original, corrupted)
            if (patches.isEmpty()) {
                RtcLog.d(TAG, "$where seed=${run.seedUsed}: nothing left to write (shielded=$shielded quarantined=$quarantinedBytes)")
                return Outcome(run.seedUsed, 0, 0, shielded, quarantinedBytes)
            }
            AntiCrash.recordCycle(AntiCrash.targetKey(process.name, region), patches)
            val err = RootMemoryHelper.patchMemory(
                ctx, process.pid, region.start, region.end,
                patches.map { MemoryPatch(region.start + it.offset, it.bytes) }
            )
            if (err != null) throw explainFailure(ctx, process, "write failed", err)

            val written = patches.sumOf { it.bytes.size }
            RtcLog.d(
                TAG,
                "$where seed=${run.seedUsed}: wrote ${patches.size} patch(es), $written byte(s); " +
                    "shielded=$shielded quarantined=$quarantinedBytes"
            )
            return Outcome(run.seedUsed, patches.size, written, shielded, quarantinedBytes)
        }

        // Anti-crash off (or minimal patches off): the original whole-region write-back.
        if (!RootMemoryHelper.writeMemory(ctx, process.pid, region.start, corrupted)) {
            throw explainFailure(ctx, process, "write failed", null)
        }
        RtcLog.d(TAG, "$where seed=${run.seedUsed}: wrote whole region (${corrupted.size} bytes)")
        return Outcome(run.seedUsed, 1, corrupted.size, shielded, quarantinedBytes)
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
            AntiCrash.onProcessCrashed(process.name)
            synchronized(reportedCrashes) { reportedCrashes[process.pid] = System.currentTimeMillis() to report }
            return TargetDiedException(report.summary, report)
        }
        val message = "$what for ${process.name}" + (detail?.let { ": $it" } ?: "") +
            if (state == ProcState.STOPPED) " (the process is stuck stopped)" else ""
        RtcLog.w(TAG, message)
        return IllegalStateException(message)
    }
}
