package com.example.filecorruptor.livemem

/**
 * Static, content-based fingerprints for NES-console memory shapes.
 *
 * These numbers aren't guessed — they come from actually parsing a real
 * FCEUX-format save state (Super Mario Bros. (Europe) (Rev A), the .fcs you
 * provided) chunk by chunk. FCEUX save states are: repeated
 * [1-byte section marker][4-byte LE section length][section body], and each
 * section body is itself repeated [4-byte tag][4-byte LE size][size bytes
 * of data]. Walking that structure on your file turned up exactly the
 * buffers a libretro-style NES core keeps:
 *
 *   RAM   (main CPU work RAM)   2048 bytes  (0x800)  — this is the target
 *   NTAR  (nametable RAM)       2048 bytes  (0x800)
 *   PRAM  (palette RAM)           32 bytes  (0x20)
 *   SPRA  (sprite/OAM RAM)        256 bytes (0x100)
 *
 * RAM itself is a bad thing to fingerprint by content: its 2048 bytes are
 * just whatever the game happened to be doing at save time, so a byte
 * pattern captured from one frame has no reason to reappear in a live
 * process sampled at some other moment. Matching it exactly would mean
 * matching the exact frame, not "this is RAM."
 *
 * PRAM and SPRA are the opposite: the NES hardware itself constrains their
 * *shape*, not just their size, in ways almost nothing else in a process's
 * memory shares:
 *
 *  - Every one of PRAM's 32 bytes in the captured state was <= 0x3F, with
 *    12 distinct values present (not a flat fill). That's not a
 *    coincidence of this frame — the PPU only ever exposes 6-bit color
 *    indices, so real palette RAM can *never* hold a byte > 0x3F. 32
 *    consecutive bytes that are all <= 0x3F, while not all identical, is
 *    extremely unlikely to happen by chance in unrelated memory (~1/4
 *    chance per byte if uniformly random => roughly 1e-19 across 32).
 *
 *  - SPRA showed the classic "parked sprite" pattern: 55 of its 64 OAM
 *    entries (sprite slots 9-63) were byte-for-byte identical, each
 *    exactly `F8 00 00 00` (Y=0xF8, tile=0, attributes=0, X=0) — the
 *    standard DMA trick games use to hide unused hardware sprites off the
 *    bottom of the screen. A *contiguous run* of dozens of identical 4-byte
 *    groups is a very unusual thing to find by accident in ordinary
 *    heap/allocator memory. (An earlier version of this detector counted
 *    matches anywhere in a window instead of requiring them contiguous,
 *    and it fired constantly on ordinary RAM — a byte value can easily
 *    recur 12+ times scattered across 256 bytes of real game state. Only
 *    a genuine *run* turned out to be a reliable signal; see the git
 *    history / PR notes for the before/after false-positive counts.)
 *
 * There's a second, even more directly useful thing the parse turned up:
 * this game's own 2048-byte RAM chunk contains, at RAM offset 0x200 (512)
 * through 0x233, a byte-for-byte copy of the same 9 active sprites found
 * in the SPRA chunk, immediately followed by the same `F8 00 00 00` × 55
 * parked-sprite run — confirmed by directly comparing the two chunks'
 * bytes. That's the standard NES OAM-DMA idiom: the game builds its sprite
 * table in a fixed CPU RAM page (almost always page 2, i.e. $0200-$02FF)
 * and copies it to the PPU's real OAM via the $4014 OAMDMA register once a
 * frame — a convention shared by the vast majority of NES games, not
 * something specific to this ROM. That means an OAM anchor found in *live
 * process memory* isn't only useful as "OAM/PALRAM must be nearby" — if
 * it's really this shadow copy, byte 0 of the 2048-byte RAM array can be
 * recovered from it directly (not just "nearby"). See
 * [proposeRamStartsFromOamShadow] for the actual arithmetic — it's not as
 * simple as subtracting 0x200 from the anchor, since the anchor is the
 * *parked run*, whose start shifts with however many sprites are active.
 *
 * None of this is certain from static content alone, so every function
 * below only ever produces *candidates* for the existing dynamic scanner
 * (analyzeRegionActivity / findBestFixedSizeWindows in LiveMemoryScreen.kt)
 * to confirm by actually watching bytes change over real gameplay — a
 * measurement always outranks a guess, however well-grounded the guess.
 */

enum class NesAnchorKind { PALETTE_RAM, SPRITE_OAM }

data class NesAnchorHit(
    val kind: NesAnchorKind,
    /** Byte offset of the anchor within the buffer that was scanned. */
    val offset: Int,
    val size: Int,
    /** 0.0-1.0 heuristic strength, not a real probability. Higher = rarer to see by chance. */
    val confidence: Double
) {
    val end: Int get() = offset + size
}

private const val PALETTE_SIZE = 32
private const val PALETTE_MAX_VALUE = 0x3F // PPU color index is 6 bits
private const val OAM_SIZE = 256
private const val OAM_ENTRY_SIZE = 4
private const val OAM_ENTRY_COUNT = OAM_SIZE / OAM_ENTRY_SIZE // 64

/**
 * Slides a 32-byte window across [bytes] looking for palette-RAM shape:
 * every byte <= 0x3F, with at least [minDistinctValues] distinct values so
 * a boring all-zero (or other flat-fill) span — which trivially satisfies
 * "every byte <= 0x3F" without carrying any real signal — doesn't count.
 * The reference capture had 12 distinct values among 32 bytes; 6 is used
 * as a conservative floor so real-but-quieter palettes still match.
 *
 * Runs a rolling histogram + rolling "count of bytes > max" so the whole
 * scan is O(bytes.size) regardless of region size, since these regions can
 * run into the low megabytes.
 *
 * Overlapping windows that all pass collapse into one hit at the start of
 * the run, since a genuine 32-byte palette buffer will pass the check at
 * every offset inside it, not just one — reporting all of them would just
 * be noise.
 */
fun findPaletteRamAnchors(bytes: ByteArray, minDistinctValues: Int = 6): List<NesAnchorHit> {
    val n = bytes.size
    if (n < PALETTE_SIZE) return emptyList()

    val hist = IntArray(256)
    var distinct = 0
    var overLimit = 0

    fun addByte(b: Int) {
        if (hist[b] == 0) distinct++
        hist[b]++
        if (b > PALETTE_MAX_VALUE) overLimit++
    }
    fun removeByte(b: Int) {
        hist[b]--
        if (hist[b] == 0) distinct--
        if (b > PALETTE_MAX_VALUE) overLimit--
    }

    for (i in 0 until PALETTE_SIZE) addByte(bytes[i].toInt() and 0xFF)

    val hits = mutableListOf<NesAnchorHit>()
    var runStart = -1

    fun windowPasses() = overLimit == 0 && distinct >= minDistinctValues

    var start = 0
    while (true) {
        val passes = windowPasses()
        if (passes && runStart == -1) {
            runStart = start
        } else if (!passes && runStart != -1) {
            // confidence is a placeholder here — every hit gets its real,
            // per-window confidence recomputed from its own bytes below.
            hits.add(NesAnchorHit(NesAnchorKind.PALETTE_RAM, runStart, PALETTE_SIZE, confidence = 0.0))
            runStart = -1
        }
        val nextStart = start + 1
        if (nextStart > n - PALETTE_SIZE) break
        removeByte(bytes[start].toInt() and 0xFF)
        addByte(bytes[nextStart + PALETTE_SIZE - 1].toInt() and 0xFF)
        start = nextStart
    }
    if (runStart != -1) {
        hits.add(NesAnchorHit(NesAnchorKind.PALETTE_RAM, runStart, PALETTE_SIZE, confidence = 0.0))
    }
    // Recompute a real per-hit confidence from that hit's own actual distinct-value count,
    // rather than the placeholder used mid-scan above.
    return hits.map { hit ->
        val slice = bytes.copyOfRange(hit.offset, hit.offset + PALETTE_SIZE)
        val distinctHere = slice.map { it.toInt() and 0xFF }.toSet().size
        // More distinct values = less likely to be a coincidental flat/near-flat span.
        val conf = (0.5 + 0.5 * (distinctHere.coerceAtMost(16) / 16.0)).coerceIn(0.5, 0.98)
        hit.copy(confidence = conf)
    }
}

/**
 * Looks for the "parked sprite" OAM signature: a long *contiguous run* of
 * one identical 4-byte group, whose first byte (the sprite's Y coordinate)
 * is at or above [yFloor]. Off-screen parking always uses a Y in
 * 0xF0-0xFF, since the NES's visible area is only 240 scanlines tall —
 * anything from 240 (0xF0) up is guaranteed off the bottom of the screen
 * regardless of which particular value (0xF8, 0xFE, 0xFF, ...) a given
 * game's code happens to load. Requiring *contiguity* (not just "this
 * value appears [minRun] times somewhere in a 256-byte window") is what
 * separates real parked-sprite rows from ordinary game data that happens
 * to reuse a byte value often but scattered — see the class doc for the
 * measured false-positive difference this made.
 *
 * Alignment isn't known in advance, so this tries 4 phases (byte offsets
 * 0..3 mod 4) rather than assuming the buffer starts on a 4-byte boundary
 * relative to wherever the scanned region happens to begin. Each phase is
 * a single O(n) pass, so the whole scan is O(n) regardless of region size.
 */
fun findOamAnchors(bytes: ByteArray, minRun: Int = 12, yFloor: Int = 0xF0): List<NesAnchorHit> {
    val n = bytes.size
    if (n < OAM_ENTRY_SIZE * minRun) return emptyList()
    val hits = mutableListOf<NesAnchorHit>()

    for (phase in 0 until OAM_ENTRY_SIZE) {
        val lastEntryStart = n - OAM_ENTRY_SIZE
        var g = phase
        var prevKey = -1
        var runStartByte = -1
        var runLen = 0

        fun flush() {
            if (runLen >= minRun && (prevKey and 0xFF) >= yFloor) {
                // Confidence scales with run length relative to a full 64-entry
                // OAM table (55/64 in the reference capture) — a longer run is
                // rarer to see by chance and closer to "this really is OAM".
                val conf = (0.6 + 0.35 * (runLen.toDouble() / OAM_ENTRY_COUNT)).coerceIn(0.6, 0.97)
                hits.add(NesAnchorHit(NesAnchorKind.SPRITE_OAM, runStartByte, runLen * OAM_ENTRY_SIZE, conf))
            }
        }

        while (g <= lastEntryStart) {
            val key = (bytes[g].toInt() and 0xFF) or
                ((bytes[g + 1].toInt() and 0xFF) shl 8) or
                ((bytes[g + 2].toInt() and 0xFF) shl 16) or
                ((bytes[g + 3].toInt() and 0xFF) shl 24)
            if (key == prevKey) {
                runLen++
            } else {
                flush()
                prevKey = key
                runStartByte = g
                runLen = 1
            }
            g += OAM_ENTRY_SIZE
        }
        flush()
    }

    return collapseOverlapping(hits)
}

/**
 * If an OAM anchor really is a game's in-RAM shadow copy of its sprite
 * table (see the class doc — confirmed byte-for-byte in the reference
 * capture) rather than the emulator core's standalone hardware-OAM array,
 * this recovers byte 0 of the 2048-byte RAM array from it.
 *
 * The anchor from [findOamAnchors] is the *parked run*, not the whole
 * 256-byte page — and the run's start varies with however many sprites
 * happen to be active (9 of them, in the reference capture), which isn't
 * knowable in general. An earlier version of this function subtracted the
 * page offset straight from the run's start and was wrong by exactly that
 * many bytes (36, in the reference capture) as a result.
 *
 * What's actually fixed, not variable, is the *end*: the standard
 * "clear the whole page to the off-screen sentinel, then only overwrite
 * the active entries" idiom means the parked run always extends to the
 * end of the page, however many actives precede it — confirmed in the
 * reference capture, where the run ends at exactly RAM offset 0x300, the
 * end of the $0200 page. So: pageEnd = hit.offset + hit.size, pageStart =
 * pageEnd - OAM_SIZE, and ramStart = pageStart - pageOffset. $0200 is by
 * far the most common page NES games use for this (it's the idiom shown
 * in Nintendo's own documentation and every widely-copied NES tutorial),
 * so it's proposed first/with the highest confidence; $0100/$0300/$0400
 * are included as fallbacks since a handful of games place it elsewhere.
 *
 * These are still just candidates — a caller should hand each one to
 * [analyzeRegionActivity]/[findBestFixedSizeWindows] (or at least eyeball
 * it with a hex preview) rather than trusting it outright. A standalone
 * hardware-OAM match, or a game that doesn't follow the "clear then fill"
 * idiom, will produce a wrong offset here that content alone can't rule out.
 */
fun proposeRamStartsFromOamShadow(oamHits: List<NesAnchorHit>, regionSize: Int, ramSize: Int = 0x800): List<Pair<Int, Double>> {
    val shadowPageOffsets = listOf(0x200 to 1.0, 0x100 to 0.6, 0x300 to 0.6, 0x400 to 0.5)
    val out = mutableListOf<Pair<Int, Double>>()
    for (hit in oamHits) {
        val pageStart = hit.end - OAM_SIZE // the run is assumed to extend to the page's end
        for ((pageOffset, pageConfidence) in shadowPageOffsets) {
            val ramStart = pageStart - pageOffset
            if (ramStart >= 0 && ramStart + ramSize <= regionSize) {
                out.add(ramStart to (hit.confidence * pageConfidence))
            }
        }
    }
    return out.sortedByDescending { it.second }
}

private fun collapseOverlapping(hits: List<NesAnchorHit>): List<NesAnchorHit> {
    if (hits.isEmpty()) return hits
    val sorted = hits.sortedBy { it.offset }
    val out = mutableListOf<NesAnchorHit>()
    for (hit in sorted) {
        val last = out.lastOrNull()
        if (last != null && hit.offset < last.end) {
            if (hit.confidence > last.confidence) out[out.size - 1] = hit
        } else {
            out.add(hit)
        }
    }
    return out
}

/**
 * Given anchors already found in one region (from [findPaletteRamAnchors]
 * and/or [findOamAnchors]), proposes byte offsets within that same region
 * worth handing to the existing 2048-byte fixed-size activity search
 * (findBestFixedSizeWindows in LiveMemoryScreen.kt) as a *first* guess —
 * this is a proximity heuristic, not a claim about actual layout, so
 * callers should still confirm with real activity sampling rather than
 * trusting a proposed offset outright.
 *
 * [searchRadius] bounds how far from an anchor to propose windows; 64 KB is
 * generous for same-translation-unit static arrays without assuming
 * anything tighter than that.
 */
fun proposeRamWindowsNearAnchors(
    anchors: List<NesAnchorHit>,
    regionSize: Int,
    ramSize: Int = 0x800,
    searchRadius: Int = 64 * 1024,
    step: Int = 256
): List<Int> {
    if (anchors.isEmpty()) return emptyList()
    val proposals = sortedSetOf<Int>()
    for (anchor in anchors) {
        var offset = (anchor.offset - searchRadius).coerceAtLeast(0)
        val limit = (anchor.offset + searchRadius).coerceAtMost(regionSize - ramSize)
        while (offset <= limit) {
            proposals.add(offset)
            offset += step
        }
    }
    return proposals.toList()
}
