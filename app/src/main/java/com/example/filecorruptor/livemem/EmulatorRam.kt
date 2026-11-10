package com.example.filecorruptor.livemem

import android.content.Context
import com.example.filecorruptor.log.RtcLog
import java.io.File

/**
 * Automatic emulator-RAM detection (N64 first). The algorithm was developed and validated against a real
 * Mupen64Plus core in tools/emu-lab (see README there): console-specific anchors vote for the base address of
 * the emulated RAM, evidence is summed in bits, aliases/ambiguity/static copies are handled, and a detection is
 * reported with a confidence tier instead of being silently trusted. Runs natively (`findn64` in rtmem_helper.c).
 */
data class EmulatorRamCandidate(
    val kind: String,              // "ram" | "rom"
    val transform: String,         // byte order the emulator stores the console's words in: be / le32 / v64
    val base: Long,                // host address of emulated address 0 (RAM) / of ROM byte 0 (rom)
    val bits: Int,
    val ambiguous: Boolean,
    val livePermille: Int,         // share of 4 KB pages that changed over 0.4 s, in 1/1000 (-1 = n/a)
    val groups: String             // e.g. "vectors:76,globals:48,romcopy:96"
) {
    val tier: String get() = when { bits >= 80 -> "certain"; bits >= 40 -> "high"; bits >= 24 -> "possible"; else -> "weak" }
    val effectiveTier: String get() = if (ambiguous && (tier == "certain" || tier == "high")) "possible" else tier
}

class EmulatorRamResult(
    val ram: List<EmulatorRamCandidate>,
    val rom: List<EmulatorRamCandidate>,
    val regionsScanned: Int,
    val megabytesRead: Int,
    val millis: Long
) {
    /** The live (changing) candidate wins over static copies with equal evidence. */
    val best: EmulatorRamCandidate? get() = ram.sortedWith(compareByDescending<EmulatorRamCandidate> { it.bits }.thenByDescending { it.livePermille }).firstOrNull()
    fun isStaticCopy(c: EmulatorRamCandidate): Boolean =
        c.livePermille == 0 && ram.any { it !== c && it.bits == c.bits && it.livePermille > 0 }
    val ramSize: Long get() = 8L shl 20
}

object EmulatorRam {
    private const val TAG = "EmuRam"

    fun findN64(
        context: Context,
        pid: Int,
        regions: List<MemoryRegion>,
        romPath: String?,
        onProgress: (Int, Int) -> Unit,
        isCancelled: () -> Boolean
    ): EmulatorRamResult {
        val ctx = context.applicationContext
        val scan = RegionPriority.scanOrder(regions)
        require(scan.isNotEmpty()) { "no scannable memory in this process" }
        val regionsFile = File(ctx.cacheDir, "emuram_regions_${System.nanoTime()}.txt")
        val cancel = File(ctx.cacheDir, "emuram_cancel_${System.nanoTime()}")
        val ram = ArrayList<EmulatorRamCandidate>()
        val rom = ArrayList<EmulatorRamCandidate>()
        var stat = Triple(0, 0, 0L)
        try {
            regionsFile.writeText(scan.joinToString("\n") { "${it.start.toString(16)} ${it.end.toString(16)}" })
            val rp = romPath?.trim().orEmpty().ifEmpty { "-" }
            RootMemoryHelper.runStreamingHelper(
                ctx,
                listOf("findn64", pid.toString(), regionsFile.absolutePath, rp, cancel.absolutePath),
                cancel,
                { a, b -> onProgress(a.toInt(), b.toInt()) },
                isCancelled
            ) { line ->
                val p = line.split(" ")
                if (p[0] == "DET" && p.size >= 8) {
                    val c = EmulatorRamCandidate(
                        kind = p[1], transform = p[2], base = p[3].toLong(16), bits = p[4].toIntOrNull() ?: 0,
                        ambiguous = p[5] == "1", livePermille = p[6].toIntOrNull() ?: -1, groups = p[7]
                    )
                    if (c.kind == "ram") ram += c else rom += c
                } else if (p[0] == "STAT" && p.size >= 4) {
                    stat = Triple(p[1].toIntOrNull() ?: 0, p[2].toIntOrNull() ?: 0, p[3].toLongOrNull() ?: 0L)
                }
            }
        } finally {
            regionsFile.delete(); cancel.delete()
        }
        val result = EmulatorRamResult(ram, rom, stat.first, stat.second, stat.third)
        logResult(pid, regions, result)
        return result
    }

    /** Everything needed to learn this emulator's layout from a log: candidates, the mappings they sit in, ROM-RAM delta. */
    private fun logResult(pid: Int, regions: List<MemoryRegion>, r: EmulatorRamResult) {
        fun where(base: Long): String {
            val g = regions.firstOrNull { base >= it.start && base < it.end } ?: return "outside any mapping"
            return "in ${g.size shr 20}MB ${g.perms} '${g.path}' 0x${g.start.toString(16)}-0x${g.end.toString(16)} +0x${(base - g.start).toString(16)}"
        }
        RtcLog.i(TAG, "pid $pid: scanned ${r.regionsScanned} region(s), ${r.megabytesRead} MB read, ${r.millis} ms; ${r.ram.size} RAM / ${r.rom.size} ROM candidate(s)")
        for (c in r.ram) RtcLog.i(TAG, "  RAM ${c.effectiveTier} ${c.bits}b [${c.transform}] base=0x${c.base.toString(16)} live=${c.livePermille}‰ ${c.groups}${if (c.ambiguous) " AMBIGUOUS" else ""}${if (r.isStaticCopy(c)) " STATIC-COPY" else ""}  ${where(c.base)}")
        for (c in r.rom) RtcLog.i(TAG, "  ROM ${c.effectiveTier} ${c.bits}b [${c.transform}] base=0x${c.base.toString(16)}  ${where(c.base)}")
        val best = r.best
        if (best != null) r.rom.firstOrNull { it.transform == best.transform }?.let {
            RtcLog.i(TAG, "  layout law: ROM - RAM = 0x${(it.base - best.base).toString(16)}")
        }
    }
}
