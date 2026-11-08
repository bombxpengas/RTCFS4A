package com.example.filecorruptor.safety

/**
 * Crash *prediction* for live-RAM corruption, based on what the logs showed.
 *
 * Every real crash in the field logs was the same one:
 *
 *     signal 6 (SIGABRT) ... Abort message: 'Scudo ERROR: corrupted chunk header ...'
 *     #05 scudo::Allocator<...>::deallocate  <-  operator delete / free
 *
 * Android's allocator (Scudo) puts an 8-byte, checksummed header in front of
 * every allocation and verifies it when the block is freed. A corruptor that
 * writes into `[anon:scudo:primary]` / `[anon:scudo:secondary]` will sooner or
 * later hit one of those headers, and the process aborts the next time the app
 * frees that block — seconds or *minutes* later (528 s and 1825 s uptimes in
 * the logs), long after the write that caused it. SIGABRT is raised on purpose
 * by the allocator and `abort()` never returns, so it can't be survived once it
 * happens; the only fix is to predict which bytes are lethal and not write them.
 *
 * Scudo's chunk header (64-bit), little-endian, 16-byte aligned, 16 bytes
 * before the pointer the app sees:
 *
 *     bits  0..7   ClassId            (0 = secondary/large allocation)
 *     bits  8..9   State              (0 available, 1 allocated, 2 quarantined)
 *     bits 10..11  Origin / WasZeroed
 *     bits 12..31  SizeOrUnusedBytes
 *     bits 32..47  Offset             (non-zero for over-aligned allocations)
 *     bits 48..63  Checksum           (keyed with a per-process secret)
 *
 * The checksum can't be verified from outside (the key lives in the target),
 * but the *shape* of a header is distinctive enough to find them reliably: a
 * random 8-byte value passes the primary test about once in 340 slots, and a
 * false positive only means 8 bytes are left untouched.
 */
object ScudoGuard {

    enum class Kind { NONE, PRIMARY, SECONDARY }

    fun kindOf(path: String): Kind = when {
        path.contains("scudo:secondary") -> Kind.SECONDARY
        path.contains("scudo") -> Kind.PRIMARY
        else -> Kind.NONE
    }

    /** Headers are 16-byte aligned (the user pointer is 16-aligned and the header sits 16 bytes before it). */
    private const val SLOT = 16

    /** Android's Scudo has ~35 primary size classes; leave generous headroom. */
    private const val MAX_PRIMARY_CLASS = 64

    /** Over-aligned (memalign) chunks carry their padding in `Offset`, in 16-byte units. */
    private const val MAX_PRIMARY_OFFSET = 0x400

    /**
     * A secondary (large) allocation starts with Scudo's LargeBlock header (list
     * links, mapping base/size) and then the chunk header, sometimes a whole page
     * later when the app asked for page alignment (the log's crash: header at
     * +0xFF0). Everything before the user data is allocator bookkeeping.
     */
    private const val SECONDARY_PREFIX = 0x2000

    private fun readLongLe(b: ByteArray, i: Int): Long {
        var v = 0L
        for (k in 7 downTo 0) v = (v shl 8) or (b[i + k].toLong() and 0xFF)
        return v
    }

    /** Does the 8-byte word [w] have the shape of a Scudo chunk header? */
    fun looksLikeHeader(w: Long, kind: Kind): Boolean {
        val classId = (w and 0xFF).toInt()
        val state = ((w ushr 8) and 0x3).toInt()
        val offset = ((w ushr 32) and 0xFFFF).toInt()
        val checksum = ((w ushr 48) and 0xFFFF).toInt()
        // A real header always has a checksum; this also rejects small integers and zeroed memory.
        if (checksum == 0) return false
        return when (kind) {
            Kind.PRIMARY ->
                classId in 1..MAX_PRIMARY_CLASS && state <= 2 && offset <= MAX_PRIMARY_OFFSET
            Kind.SECONDARY ->
                classId == 0 && (state == 1 || state == 2)
            Kind.NONE -> false
        }
    }

    /**
     * Puts back every allocator header (and, for large blocks, the LargeBlock
     * prefix) that [corrupted] changed, judged from the untouched [original].
     * Returns the number of protected units (a header word, or the prefix bytes).
     */
    fun shield(original: ByteArray, corrupted: ByteArray, kind: Kind, regionOffset: Long = 0L): Int {
        if (kind == Kind.NONE) return 0
        val n = minOf(original.size, corrupted.size)
        var protectedUnits = 0
        var start = 0

        // [regionOffset] = where this buffer begins inside the region (live corruption works on windows).
        // Windows start on 4 KiB boundaries, so 16-byte header alignment is preserved.
        val prefixLeft = SECONDARY_PREFIX - regionOffset
        if (kind == Kind.SECONDARY && prefixLeft > 0) {
            val prefix = minOf(n.toLong(), prefixLeft).toInt()
            for (i in 0 until prefix) {
                if (corrupted[i] != original[i]) {
                    corrupted[i] = original[i]
                    protectedUnits++
                }
            }
            start = prefix - (prefix % SLOT)
            if (start < prefix) start += SLOT
        }

        var i = start
        while (i + 8 <= n) {
            var differs = false
            for (k in 0 until 8) {
                if (original[i + k] != corrupted[i + k]) { differs = true; break }
            }
            if (differs && looksLikeHeader(readLongLe(original, i), kind)) {
                System.arraycopy(original, i, corrupted, i, 8)
                protectedUnits++
            }
            i += SLOT
        }
        return protectedUnits
    }

    /**
     * Regions that are never worth corrupting because the result is a certain
     * crash rather than a glitch: live call stacks/TLS, the kernel-provided
     * vDSO/vvar pages, the dynamic linker's bookkeeping and Android's system
     * property area. Returns why, or null if the region is fine.
     */
    fun systemRegionReason(path: String): String? = when {
        path.startsWith("[stack") || path.contains("stack_and_tls") ->
            "a thread stack / TLS block (live call frames)"
        path == "[vdso]" || path.startsWith("[vvar") ->
            "a kernel-provided vDSO/vvar page"
        path.contains("linker_alloc") ->
            "the dynamic linker's own bookkeeping"
        path.contains("__properties__") || path.contains("System property") ->
            "Android's system-property area"
        else -> null
    }
}
