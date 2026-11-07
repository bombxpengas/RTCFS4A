package com.example.filecorruptor.safety

import android.content.Context
import com.example.filecorruptor.livemem.MemoryRegion
import com.example.filecorruptor.log.RtcLog
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File

/**
 * Crash-avoidance rules shared by file corruption and live-RAM corruption.
 *
 * A corruptor can't know in general which bytes are "safe" — but a handful of
 * patterns account for most instant crashes, and those *can* be avoided:
 *
 *  **Files**
 *  - Overwriting a ROM/binary's fixed header (iNES, GBA/GB/NDS cartridge
 *    headers, N64 boot block, Genesis vectors, ELF/ZIP structure). The
 *    emulator or loader rejects the file outright instead of showing a glitch.
 *
 *  **Live RAM**
 *  - Overwriting a *pointer* (any aligned word whose value points into the
 *    target's own mapped memory) → the next dereference is a SIGSEGV.
 *  - Writing into a region the target has since freed/remapped, or into code.
 *  - Rewriting the whole region from a stale snapshot: the target kept
 *    running between our read and our write, so a full write-back reverts
 *    fields it just changed (half-updated pointers, lengths, refcounts).
 *    Writing only the bytes that actually changed shrinks that window to
 *    nearly nothing.
 *  - **Learned** bad spots: when a target dies, the areas touched just before
 *    are "struck"; an area implicated in two separate crashes is quarantined
 *    and left alone from then on.
 */
object AntiCrash {

    private const val TAG = "AntiCrash"
    private const val PREFS = "rtc_safety"

    data class Config(
        /** Master switch. Off = the original, unguarded behavior everywhere. */
        val enabled: Boolean = true,
        /** Files: restore known ROM/binary headers after corrupting. */
        val protectFileHeaders: Boolean = true,
        /** RAM: refuse regions that are executable (code). */
        val blockExecutable: Boolean = true,
        /** RAM: keep original value of any pointer-like word. */
        val pointerShield: Boolean = true,
        /** RAM: write only the changed bytes in one ptrace attach, validating the mapping first. */
        val minimalPatches: Boolean = true,
        /** RAM: leave areas implicated in repeated crashes alone. */
        val quarantine: Boolean = true,
        /** RAM: stop live corrupting the moment a target dies. */
        val stopOnCrash: Boolean = true
    )

    private val _config = MutableStateFlow(Config())
    val config: StateFlow<Config> = _config.asStateFlow()
    fun current(): Config = _config.value

    @Volatile private var prefsContext: Context? = null
    private var quarantineFile: File? = null

    fun init(context: Context) {
        val app = context.applicationContext
        prefsContext = app
        val p = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val d = Config()
        _config.value = Config(
            enabled = p.getBoolean("enabled", d.enabled),
            protectFileHeaders = p.getBoolean("protectFileHeaders", d.protectFileHeaders),
            blockExecutable = p.getBoolean("blockExecutable", d.blockExecutable),
            pointerShield = p.getBoolean("pointerShield", d.pointerShield),
            minimalPatches = p.getBoolean("minimalPatches", d.minimalPatches),
            quarantine = p.getBoolean("quarantine", d.quarantine),
            stopOnCrash = p.getBoolean("stopOnCrash", d.stopOnCrash)
        )
        RtcLog.verboseToFile = p.getBoolean("verboseLog", false)
        quarantineFile = File(app.filesDir, "quarantine.tsv")
        loadQuarantine()
        RtcLog.i(TAG, "config: ${_config.value}; quarantined areas: ${quarantinedAreaCount()}")
    }

    fun update(newConfig: Config) {
        _config.value = newConfig
        prefsContext?.getSharedPreferences(PREFS, Context.MODE_PRIVATE)?.edit()
            ?.putBoolean("enabled", newConfig.enabled)
            ?.putBoolean("protectFileHeaders", newConfig.protectFileHeaders)
            ?.putBoolean("blockExecutable", newConfig.blockExecutable)
            ?.putBoolean("pointerShield", newConfig.pointerShield)
            ?.putBoolean("minimalPatches", newConfig.minimalPatches)
            ?.putBoolean("quarantine", newConfig.quarantine)
            ?.putBoolean("stopOnCrash", newConfig.stopOnCrash)
            ?.apply()
        RtcLog.i(TAG, "config changed: $newConfig")
    }

    var verboseLog: Boolean
        get() = RtcLog.verboseToFile
        set(value) {
            RtcLog.verboseToFile = value
            prefsContext?.getSharedPreferences(PREFS, Context.MODE_PRIVATE)?.edit()
                ?.putBoolean("verboseLog", value)?.apply()
        }

    // ------------------------------------------------------------------
    // Files: protected headers
    // ------------------------------------------------------------------

    private fun hasBytes(d: ByteArray, off: Int, vararg v: Int): Boolean {
        if (off < 0 || off + v.size > d.size) return false
        for (i in v.indices) if ((d[off + i].toInt() and 0xFF) != v[i]) return false
        return true
    }

    /**
     * Byte ranges of [data] that must survive corruption for the file to
     * still load, judged from magic numbers in the (uncorrupted) original.
     * Unknown formats return an empty list — nothing is assumed.
     */
    fun protectedHeaderRanges(data: ByteArray): List<IntRange> {
        val size = data.size
        val ranges = mutableListOf<IntRange>()
        fun add(from: Int, toExclusive: Int) {
            val hi = minOf(toExclusive, size)
            if (from in 0 until hi) ranges += from until hi
        }

        when {
            // NES: "NES\x1A" iNES header (16 bytes)
            hasBytes(data, 0, 0x4E, 0x45, 0x53, 0x1A) -> add(0, 16)
            // N64 (z64 / v64 / n64 byte orders): header + boot code that the CIC check covers
            hasBytes(data, 0, 0x80, 0x37, 0x12, 0x40) ||
                hasBytes(data, 0, 0x37, 0x80, 0x40, 0x12) ||
                hasBytes(data, 0, 0x40, 0x12, 0x37, 0x80) -> add(0, 0x1000)
            // ELF: file header
            hasBytes(data, 0, 0x7F, 0x45, 0x4C, 0x46) -> add(0, 64)
            // ZIP: first local header + the end-of-central-directory record
            hasBytes(data, 0, 0x50, 0x4B, 0x03, 0x04) -> {
                add(0, 30)
                add(size - 22, size)
            }
        }
        // Formats identified by a signature at a fixed offset (can coexist with none of the above).
        // Genesis / Mega Drive: "SEGA" at 0x100 (or 0x101 for " SEGA"); vectors + header = 0x200
        if (hasBytes(data, 0x100, 0x53, 0x45, 0x47, 0x41) || hasBytes(data, 0x101, 0x53, 0x45, 0x47, 0x41)) add(0, 0x200)
        // Game Boy / GBC: Nintendo logo at 0x104, header through 0x14F
        if (hasBytes(data, 0x104, 0xCE, 0xED, 0x66, 0x66)) add(0x100, 0x150)
        // GBA: logo start at 4 AND the fixed 0x96 byte at 0xB2
        if (size >= 0xC0 && hasBytes(data, 4, 0x24, 0xFF, 0xAE, 0x51) && hasBytes(data, 0xB2, 0x96)) add(0, 0xC0)
        // Nintendo DS: logo CRC16 (0xCF56, little endian) at 0x15C
        if (size >= 0x200 && hasBytes(data, 0x15C, 0x56, 0xCF)) add(0, 0x200)

        return ranges
    }

    /**
     * Copies the protected header ranges of [original] back over [corrupted]
     * (same length). Returns how many bytes it had to put back (0 = nothing
     * recognized, or the corruption never touched the headers).
     */
    fun restoreProtectedHeaders(original: ByteArray, corrupted: ByteArray): Int {
        if (original.size != corrupted.size) return 0
        var restored = 0
        for (r in protectedHeaderRanges(original)) {
            for (i in r) {
                if (corrupted[i] != original[i]) {
                    corrupted[i] = original[i]
                    restored++
                }
            }
        }
        return restored
    }

    // ------------------------------------------------------------------
    // RAM: pointer shield
    // ------------------------------------------------------------------

    /** Sorted snapshot of a process's mapped address ranges, for "does this value look like a pointer?". */
    class MapIndex(regions: List<MemoryRegion>) {
        private val starts: LongArray
        private val ends: LongArray

        /** True if any mapping sits above 4 GiB, i.e. the target is a 64-bit process. */
        val is64Bit: Boolean

        init {
            val sorted = regions.filter { it.end > it.start }.sortedBy { it.start }
            starts = LongArray(sorted.size) { sorted[it].start }
            ends = LongArray(sorted.size) { sorted[it].end }
            is64Bit = sorted.any { it.end > 0xFFFFFFFFL }
        }

        val isEmpty: Boolean get() = starts.isEmpty()

        fun contains(value: Long): Boolean {
            var lo = 0
            var hi = starts.size - 1
            var idx = -1
            while (lo <= hi) {
                val mid = (lo + hi) ushr 1
                if (starts[mid] <= value) { idx = mid; lo = mid + 1 } else hi = mid - 1
            }
            return idx >= 0 && value < ends[idx]
        }
    }

    /**
     * For every pointer-sized, pointer-aligned word that [corrupted] changed,
     * if the *original* word looked like a pointer into the target's own
     * mappings, put the original bytes back. Returns the number of words
     * protected. A 64-bit target's top byte is masked off first, because
     * Android's heap tagging stores a tag there (e.g. 0xB4...).
     */
    fun shieldPointers(original: ByteArray, corrupted: ByteArray, maps: MapIndex): Int {
        if (maps.isEmpty) return 0
        val ps = if (maps.is64Bit) 8 else 4
        val n = minOf(original.size, corrupted.size)
        var protectedWords = 0
        var i = 0
        while (i + ps <= n) {
            var differs = false
            for (k in 0 until ps) {
                if (original[i + k] != corrupted[i + k]) { differs = true; break }
            }
            if (differs) {
                var v = 0L
                for (k in ps - 1 downTo 0) v = (v shl 8) or (original[i + k].toLong() and 0xFF)
                if (ps == 8) v = v and 0x00FFFFFFFFFFFFFFL
                if (maps.contains(v)) {
                    System.arraycopy(original, i, corrupted, i, ps)
                    protectedWords++
                }
            }
            i += ps
        }
        return protectedWords
    }

    // ------------------------------------------------------------------
    // RAM: minimal patches
    // ------------------------------------------------------------------

    /** A run of changed bytes at [offset] inside the region. */
    class Patch(val offset: Int, val bytes: ByteArray)

    /**
     * Turns "original vs corrupted" into the smallest set of byte runs that
     * actually changed. Runs separated by fewer than [mergeGap] unchanged
     * bytes are merged so a scattered corruption doesn't become thousands of
     * 1-byte writes.
     */
    fun diffPatches(original: ByteArray, corrupted: ByteArray, mergeGap: Int = 8): List<Patch> {
        val n = minOf(original.size, corrupted.size)
        val out = ArrayList<Patch>()
        var i = 0
        while (i < n) {
            if (original[i] == corrupted[i]) { i++; continue }
            val start = i
            var lastDiff = i
            var j = i + 1
            while (j < n && j - lastDiff <= mergeGap) {
                if (original[j] != corrupted[j]) lastDiff = j
                j++
            }
            out += Patch(start, corrupted.copyOfRange(start, lastDiff + 1))
            i = lastDiff + 1
        }
        return out
    }

    // ------------------------------------------------------------------
    // RAM: crash-learned quarantine
    // ------------------------------------------------------------------

    private const val BUCKET = 256
    private const val QUARANTINE_THRESHOLD = 2
    private const val RECENT_CYCLES = 2
    private const val MAX_QUARANTINE_ENTRIES = 50_000

    private val quarantineLock = Any()

    /** key -> (bucket index -> number of separate crashes it was implicated in) */
    private val strikes = HashMap<String, HashMap<Int, Int>>()

    /** key -> bucket sets touched by the last few cycles (newest last) */
    private val recentCycles = HashMap<String, ArrayDeque<Set<Int>>>()

    /**
     * Addresses move every launch (ASLR), so a "bad spot" is identified by
     * what survives a relaunch: the process name, the mapping's file path
     * (empty for anonymous memory), the mapping's size, and an offset into it.
     */
    fun targetKey(processName: String, region: MemoryRegion): String =
        "$processName|${region.path}|${region.size}"

    /** Remember which areas this cycle touched, so a crash right after can be attributed. */
    fun recordCycle(key: String, patches: List<Patch>) {
        if (patches.isEmpty()) return
        val buckets = HashSet<Int>()
        for (p in patches) {
            for (b in (p.offset / BUCKET)..((p.offset + p.bytes.size - 1) / BUCKET)) buckets += b
        }
        synchronized(quarantineLock) {
            val ring = recentCycles.getOrPut(key) { ArrayDeque() }
            ring.addLast(buckets)
            while (ring.size > RECENT_CYCLES) ring.removeFirst()
        }
    }

    /**
     * Put back the original bytes in every quarantined area of [corrupted].
     * Returns how many bytes were restored.
     */
    fun applyQuarantine(key: String, original: ByteArray, corrupted: ByteArray): Int {
        val bad: List<Int> = synchronized(quarantineLock) {
            strikes[key]?.filterValues { it >= QUARANTINE_THRESHOLD }?.keys?.toList().orEmpty()
        }
        if (bad.isEmpty()) return 0
        var restored = 0
        val n = minOf(original.size, corrupted.size)
        for (b in bad) {
            val lo = b.toLong() * BUCKET
            if (lo >= n) continue
            val hi = minOf(lo + BUCKET, n.toLong()).toInt()
            for (i in lo.toInt() until hi) {
                if (corrupted[i] != original[i]) {
                    corrupted[i] = original[i]
                    restored++
                }
            }
        }
        return restored
    }

    /**
     * Called when [processName] died. Every area touched by its last few
     * cycles gets one strike; an area reaching [QUARANTINE_THRESHOLD] strikes
     * (implicated in two separate crashes) is quarantined from then on.
     * Returns the number of areas newly quarantined.
     */
    fun onProcessCrashed(processName: String): Int {
        var newlyQuarantined = 0
        var changed = false
        synchronized(quarantineLock) {
            val prefix = "$processName|"
            for ((key, ring) in recentCycles) {
                if (!key.startsWith(prefix)) continue
                val suspects = HashSet<Int>()
                ring.forEach { suspects.addAll(it) }
                val map = strikes.getOrPut(key) { HashMap() }
                for (b in suspects) {
                    if (map.size >= MAX_QUARANTINE_ENTRIES && b !in map) continue
                    val before = map[b] ?: 0
                    map[b] = before + 1
                    if (before + 1 == QUARANTINE_THRESHOLD) newlyQuarantined++
                    changed = true
                }
            }
            // The process is gone; its next incarnation starts a fresh history.
            recentCycles.keys.removeAll { it.startsWith(prefix) }
        }
        if (changed) saveQuarantine()
        RtcLog.w(TAG, "$processName crashed — struck its recently-touched areas; $newlyQuarantined newly quarantined")
        return newlyQuarantined
    }

    fun quarantinedAreaCount(): Int = synchronized(quarantineLock) {
        strikes.values.sumOf { m -> m.values.count { it >= QUARANTINE_THRESHOLD } }
    }

    fun clearQuarantine() {
        synchronized(quarantineLock) {
            strikes.clear()
            recentCycles.clear()
        }
        quarantineFile?.delete()
        RtcLog.i(TAG, "quarantine cleared")
    }

    private fun loadQuarantine() {
        val f = quarantineFile ?: return
        if (!f.isFile) return
        try {
            synchronized(quarantineLock) {
                strikes.clear()
                f.forEachLine { line ->
                    val parts = line.split('\t')
                    if (parts.size != 3) return@forEachLine
                    val bucket = parts[1].toIntOrNull() ?: return@forEachLine
                    val count = parts[2].toIntOrNull() ?: return@forEachLine
                    strikes.getOrPut(parts[0]) { HashMap() }[bucket] = count
                }
            }
        } catch (e: Exception) {
            RtcLog.w(TAG, "could not read quarantine file — starting empty", e)
        }
    }

    private fun saveQuarantine() {
        val f = quarantineFile ?: return
        try {
            val text = synchronized(quarantineLock) {
                buildString {
                    for ((key, map) in strikes) for ((bucket, count) in map) {
                        append(key).append('\t').append(bucket).append('\t').append(count).append('\n')
                    }
                }
            }
            f.writeText(text)
        } catch (e: Exception) {
            RtcLog.w(TAG, "could not save quarantine file", e)
        }
    }
}
