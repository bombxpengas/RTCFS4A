package com.example.filecorruptor.engine

import kotlin.random.Random

/**
 * Runs an [EngineDefinition]'s operation pipeline against source bytes.
 *
 * Every primitive below takes plain resolved arguments rather than a fixed
 * settings object, so any engine — built-in or imported from JSON — can mix
 * and match them purely by declaring an "operations" list. This is what lets
 * a custom engine be "just JSON": the primitives are the only native code
 * involved, everything else (which primitive, with what parameters, exposed
 * through what UI controls) is data.
 */
object CorruptionEngineExecutor {

    /** [seedUsed] is whatever seed the run actually used — the manually-set
     *  one if "Use Fixed Seed" was on, otherwise the freshly-generated one —
     *  so callers (like Save) can record it back for config export. */
    data class EngineRunResult(val bytes: ByteArray, val seedUsed: Long)

    fun run(input: ByteArray, engine: EngineDefinition, values: Map<String, ParamValue>): ByteArray =
        runWithSeed(input, engine, values).bytes

    fun runWithSeed(input: ByteArray, engine: EngineDefinition, values: Map<String, ParamValue>): EngineRunResult {
        if (input.isEmpty() || engine.operations.isEmpty()) return EngineRunResult(input, 0L)
        val output = input.copyOf()

        // A single "seed" parameter now drives this: -1 (or missing) means
        // auto/random, anything >= 0 is used as a literal fixed seed. The
        // fallback auto-seed is kept within the same 0..999999999 range the
        // "seed" number field itself uses, so writing it back to that field
        // (see Save in CorruptorScreen) never gets silently clamped or loses
        // precision converting through the UI's Double-based number field.
        val declaredSeed = values["seed"]?.asLong() ?: -1L
        val actualSeed = if (declaredSeed >= 0) {
            declaredSeed
        } else {
            (System.nanoTime() % 1_000_000_000L).let { if (it < 0) it + 1_000_000_000L else it }
        }
        val random = Random(actualSeed)

        for (op in engine.operations) {
            if (op.enabledParam != null && values[op.enabledParam]?.asBoolean() != true) {
                continue // this whole pass is switched off — e.g. "Enable byte corruption"
            }
            applyOperation(output, op, values, random)
        }
        return EngineRunResult(output, actualSeed)
    }

    private fun resolveDouble(op: OperationDef, argName: String, values: Map<String, ParamValue>, default: Double): Double {
        val paramId = op.params[argName] ?: return default
        return values[paramId]?.asDouble() ?: default
    }

    private fun resolveInt(op: OperationDef, argName: String, values: Map<String, ParamValue>, default: Int): Int =
        resolveDouble(op, argName, values, default.toDouble()).toInt()

    private fun resolveString(op: OperationDef, argName: String, values: Map<String, ParamValue>, default: String): String {
        val paramId = op.params[argName] ?: return default
        return values[paramId]?.asString() ?: default
    }

    private fun resolveBool(op: OperationDef, argName: String, values: Map<String, ParamValue>, default: Boolean): Boolean {
        val paramId = op.params[argName] ?: return default
        return values[paramId]?.asBoolean() ?: default
    }

    /** For the Nightmare Engine's 8/16/32/64-bit min/max bounds, which can
     *  exceed what Double (used by resolveDouble/asDouble) can represent
     *  exactly — read the raw declared string as an unsigned 64-bit value. */
    private fun resolveULong(op: OperationDef, argName: String, values: Map<String, ParamValue>, default: ULong): ULong {
        val paramId = op.params[argName] ?: return default
        return values[paramId]?.raw?.toULongOrNull() ?: default
    }

    private fun applyOperation(buf: ByteArray, op: OperationDef, values: Map<String, ParamValue>, random: Random) {
        val skip = resolveInt(op, "skipBytes", values, 0).coerceIn(0, buf.size)
        val intensityPct = (resolveDouble(op, "intensity", values, 15.0) / 100.0).coerceIn(0.0, 1.0)

        when (op.type) {
            "random_bytes" -> randomBytes(buf, skip, intensityPct, random)
            "bit_flip" -> bitFlip(buf, skip, intensityPct, random)
            "chunk_shuffle" -> chunkShuffle(buf, skip, resolveInt(op, "chunkSize", values, 256), intensityPct, random)
            "chunk_reverse" -> chunkReverse(buf, skip, resolveInt(op, "chunkSize", values, 256), intensityPct, random)
            "byte_shift" -> byteShift(buf, skip, intensityPct, resolveInt(op, "shiftAmount", values, 32), random)
            "zero_out" -> zeroOut(buf, skip, intensityPct, random)
            "duplicate_block" -> duplicateBlock(buf, skip, resolveInt(op, "chunkSize", values, 256), intensityPct, random)
            "random_block_overwrite" -> randomBlockOverwrite(
                buf, skip, intensityPct,
                resolveInt(op, "blockMin", values, 1).coerceAtLeast(1),
                resolveInt(op, "blockMax", values, 4).coerceAtLeast(1),
                random
            )
            "byte_corrupt" -> byteCorrupt(
                buf,
                mode = resolveString(op, "mode", values, "Add"),
                amount = resolveInt(op, "amount", values, 1),
                increment = resolveInt(op, "increment", values, 1),
                frequency = resolveInt(op, "frequency", values, 1),
                rangeStart = resolveInt(op, "rangeStart", values, -1),
                rangeEnd = resolveInt(op, "rangeEnd", values, -1),
                headerSize = resolveInt(op, "headerSize", values, 0),
                replaceFrom = resolveInt(op, "replaceFrom", values, 0),
                replaceTo = resolveInt(op, "replaceTo", values, 255),
                avoidNesCpuJam = resolveBool(op, "avoidNesCpuJam", values, false)
            )
            "text_replace_literal" -> textReplaceLiteral(
                buf,
                find = resolveString(op, "find", values, ""),
                replaceWith = resolveString(op, "replace", values, "")
            )
            "vector_engine" -> vectorEngine(
                buf,
                precision = resolveInt(op, "precision", values, 4),
                alignment = resolveInt(op, "alignment", values, 0),
                iterations = resolveInt(op, "iterations", values, 200),
                rangeStart = resolveInt(op, "rangeStart", values, -1),
                rangeEnd = resolveInt(op, "rangeEnd", values, -1),
                headerSize = resolveInt(op, "headerSize", values, 0),
                bigEndian = resolveBool(op, "bigEndian", values, false),
                useValueList = resolveBool(op, "useValueList", values, false),
                valueListText = resolveString(op, "valueList", values, ""),
                min8 = resolveULong(op, "min8", values, 0UL),
                max8 = resolveULong(op, "max8", values, 0xFFUL),
                min16 = resolveULong(op, "min16", values, 0UL),
                max16 = resolveULong(op, "max16", values, 0xFFFFUL),
                min32 = resolveULong(op, "min32", values, 0UL),
                max32 = resolveULong(op, "max32", values, 0xFFFFFFFFUL),
                min64 = resolveULong(op, "min64", values, 0UL),
                max64 = resolveULong(op, "max64", values, ULong.MAX_VALUE),
                r = random
            )
            "nightmare_engine" -> nightmareEngine(
                buf,
                algo = resolveString(op, "algo", values, "Random"),
                precision = resolveInt(op, "precision", values, 4),
                alignment = resolveInt(op, "alignment", values, 0),
                iterations = resolveInt(op, "iterations", values, 200),
                rangeStart = resolveInt(op, "rangeStart", values, -1),
                rangeEnd = resolveInt(op, "rangeEnd", values, -1),
                headerSize = resolveInt(op, "headerSize", values, 0),
                bigEndian = resolveBool(op, "bigEndian", values, false),
                min8 = resolveULong(op, "min8", values, 0UL),
                max8 = resolveULong(op, "max8", values, 0xFFUL),
                min16 = resolveULong(op, "min16", values, 0UL),
                max16 = resolveULong(op, "max16", values, 0xFFFFUL),
                min32 = resolveULong(op, "min32", values, 0UL),
                max32 = resolveULong(op, "max32", values, 0xFFFFFFFFUL),
                min64 = resolveULong(op, "min64", values, 0UL),
                max64 = resolveULong(op, "max64", values, ULong.MAX_VALUE),
                r = random
            )
            "hellgenie_engine" -> hellgenieEngine(
                buf,
                precision = resolveInt(op, "precision", values, 4),
                alignment = resolveInt(op, "alignment", values, 0),
                iterations = resolveInt(op, "iterations", values, 200),
                rangeStart = resolveInt(op, "rangeStart", values, -1),
                rangeEnd = resolveInt(op, "rangeEnd", values, -1),
                headerSize = resolveInt(op, "headerSize", values, 0),
                bigEndian = resolveBool(op, "bigEndian", values, false),
                min8 = resolveULong(op, "min8", values, 0UL),
                max8 = resolveULong(op, "max8", values, 0xFFUL),
                min16 = resolveULong(op, "min16", values, 0UL),
                max16 = resolveULong(op, "max16", values, 0xFFFFUL),
                min32 = resolveULong(op, "min32", values, 0UL),
                max32 = resolveULong(op, "max32", values, 0xFFFFFFFFUL),
                min64 = resolveULong(op, "min64", values, 0UL),
                max64 = resolveULong(op, "max64", values, ULong.MAX_VALUE),
                r = random
            )
            "pipe_engine" -> pipeEngine(
                buf,
                precision = resolveInt(op, "precision", values, 4),
                alignment = resolveInt(op, "alignment", values, 0),
                sourceByte = resolveInt(op, "sourceByte", values, -1),
                iterations = resolveInt(op, "iterations", values, 200),
                rangeStart = resolveInt(op, "rangeStart", values, -1),
                rangeEnd = resolveInt(op, "rangeEnd", values, -1),
                headerSize = resolveInt(op, "headerSize", values, 0),
                r = random
            )
            "cluster_engine" -> clusterEngine(
                buf,
                shuffleType = resolveString(op, "shuffleType", values, "Random"),
                direction = resolveString(op, "direction", values, "Forwards"),
                chunkSize = resolveInt(op, "chunkSize", values, 3),
                modifier = resolveInt(op, "modifier", values, 1),
                precision = resolveInt(op, "precision", values, 4),
                alignment = resolveInt(op, "alignment", values, 0),
                iterations = resolveInt(op, "iterations", values, 100),
                rangeStart = resolveInt(op, "rangeStart", values, -1),
                rangeEnd = resolveInt(op, "rangeEnd", values, -1),
                headerSize = resolveInt(op, "headerSize", values, 0),
                r = random
            )
            else -> {
                // Unknown primitive (e.g. a custom engine referencing a type
                // this app version doesn't implement yet): skip it rather than
                // fail the whole pipeline, so the engine's other passes still run.
            }
        }
    }

    // ---- primitives (byte-level algorithms) ----

    private fun touchedCount(range: Int, fraction: Double): Int =
        (range * fraction).toInt().coerceAtLeast(if (range > 0 && fraction > 0) 1 else 0)

    private fun randomBytes(buf: ByteArray, start: Int, fraction: Double, r: Random) {
        val range = buf.size - start
        repeat(touchedCount(range, fraction)) {
            buf[start + r.nextInt(range)] = r.nextInt(256).toByte()
        }
    }

    private fun bitFlip(buf: ByteArray, start: Int, fraction: Double, r: Random) {
        val range = buf.size - start
        val totalBits = range * 8
        repeat(touchedCount(totalBits, fraction)) {
            val bitIdx = r.nextInt(totalBits)
            val byteIdx = start + bitIdx / 8
            buf[byteIdx] = (buf[byteIdx].toInt() xor (1 shl (bitIdx % 8))).toByte()
        }
    }

    private fun chunkShuffle(buf: ByteArray, start: Int, chunkSize: Int, fraction: Double, r: Random) {
        if (chunkSize <= 0) return
        val range = buf.size - start
        val chunkCount = range / chunkSize
        if (chunkCount < 2) return
        repeat(touchedCount(chunkCount, fraction)) {
            swapChunks(buf, start + r.nextInt(chunkCount) * chunkSize, start + r.nextInt(chunkCount) * chunkSize, chunkSize)
        }
    }

    private fun swapChunks(buf: ByteArray, offsetA: Int, offsetB: Int, size: Int) {
        for (i in 0 until size) {
            val tmp = buf[offsetA + i]
            buf[offsetA + i] = buf[offsetB + i]
            buf[offsetB + i] = tmp
        }
    }

    private fun chunkReverse(buf: ByteArray, start: Int, chunkSize: Int, fraction: Double, r: Random) {
        if (chunkSize <= 0) return
        val range = buf.size - start
        val chunkCount = range / chunkSize
        if (chunkCount == 0) return
        repeat(touchedCount(chunkCount, fraction)) {
            val offset = start + r.nextInt(chunkCount) * chunkSize
            var lo = offset
            var hi = offset + chunkSize - 1
            while (lo < hi) {
                val tmp = buf[lo]; buf[lo] = buf[hi]; buf[hi] = tmp
                lo++; hi--
            }
        }
    }

    private fun byteShift(buf: ByteArray, start: Int, fraction: Double, shiftAmount: Int, r: Random) {
        val range = buf.size - start
        val shift = shiftAmount.coerceIn(1, 255)
        repeat(touchedCount(range, fraction)) {
            val idx = start + r.nextInt(range)
            buf[idx] = ((buf[idx].toInt() and 0xFF) + shift).toByte()
        }
    }

    private fun zeroOut(buf: ByteArray, start: Int, fraction: Double, r: Random) {
        val range = buf.size - start
        repeat(touchedCount(range, fraction)) { buf[start + r.nextInt(range)] = 0 }
    }

    private fun duplicateBlock(buf: ByteArray, start: Int, chunkSize: Int, fraction: Double, r: Random) {
        if (chunkSize <= 0 || buf.size - start < chunkSize) return
        val range = buf.size - start
        val chunkCount = range / chunkSize
        if (chunkCount < 2) return
        val sourceOffset = start + r.nextInt(chunkCount) * chunkSize
        val source = buf.copyOfRange(sourceOffset, sourceOffset + chunkSize)
        repeat(touchedCount(chunkCount, fraction)) {
            val destOffset = start + r.nextInt(chunkCount) * chunkSize
            System.arraycopy(source, 0, buf, destOffset, chunkSize)
        }
    }

    /**
     * The classic ROM-corruptor-style pass: repeatedly overwrites a randomly
     * placed, randomly sized run of bytes (length in [blockMin, blockMax])
     * with random data, until roughly [fraction] of the eligible region has
     * been touched. Unlike [randomBytes] (which scatters single-byte hits),
     * this produces contiguous corrupted runs — the "chunky" glitch look
     * classic ROM corruptors are known for.
     */
    private fun randomBlockOverwrite(buf: ByteArray, start: Int, fraction: Double, blockMin: Int, blockMax: Int, r: Random) {
        val range = buf.size - start
        if (range <= 0) return
        val targetBytes = touchedCount(range, fraction)
        if (targetBytes <= 0) return
        val lo = minOf(blockMin, blockMax).coerceAtLeast(1)
        val hi = maxOf(blockMin, blockMax).coerceAtLeast(lo)
        var corrupted = 0
        var guard = 0
        val maxIterations = targetBytes * 4 + 64 // safety valve against pathological configs
        while (corrupted < targetBytes && guard < maxIterations) {
            guard++
            val blockLen = (lo + r.nextInt(hi - lo + 1)).coerceAtMost(range)
            val offset = start + r.nextInt(range - blockLen + 1)
            for (i in 0 until blockLen) buf[offset + i] = r.nextInt(256).toByte()
            corrupted += blockLen
        }
    }

    /**
     * The deterministic ROM-corruption engine this app was originally built
     * around: add/shift/replace a byte value, walking the range at a fixed
     * stride ([increment]) and only actually corrupting every [frequency]th
     * position that stride visits — two independently-meaningful knobs,
     * not the same option under two names. [rangeStart]/[rangeEnd] of -1
     * mean "auto" (just after the header / end of file, respectively).
     * [avoidNesCpuJam], when on, refuses to write a corrupted byte if doing
     * so would land on one of the 6502's undocumented KIL/JAM opcodes —
     * those halt the CPU dead until a hardware reset, which is a full
     * freeze rather than a glitch.
     */
    private fun byteCorrupt(
        buf: ByteArray,
        mode: String,
        amount: Int,
        increment: Int,
        frequency: Int,
        rangeStart: Int,
        rangeEnd: Int,
        headerSize: Int,
        replaceFrom: Int,
        replaceTo: Int,
        avoidNesCpuJam: Boolean
    ) {
        if (buf.isEmpty()) return
        val incr = increment.coerceAtLeast(1)
        val freq = frequency.coerceAtLeast(1)
        val header = headerSize.coerceIn(0, buf.size)

        // An explicit start always wins, even inside the header — that's a
        // deliberate choice. Leaving it at -1 defaults to just past the
        // header so a fresh ROM doesn't get its header corrupted.
        val start = if (rangeStart >= 0) rangeStart.coerceIn(0, buf.size) else header
        val end = if (rangeEnd >= 0) rangeEnd.coerceIn(0, buf.size) else buf.size
        if (start >= end) return

        val from = replaceFrom.coerceIn(0, 255)
        val to = replaceTo.coerceIn(0, 255)
        val modeKey = mode.trim().lowercase()

        var visited = 0
        var i = start
        while (i < end) {
            visited++
            if (visited % freq == 0) {
                val unsigned = buf[i].toInt() and 0xFF
                val corrupted = when (modeKey) {
                    "shift" -> shiftByteRight(unsigned, amount)
                    "replace" -> if (unsigned == from) to else unsigned
                    else -> (unsigned + amount).mod(256) // "add" (default)
                }
                if (!avoidNesCpuJam || corrupted !in NES_CPU_JAM_OPCODES) {
                    buf[i] = corrupted.toByte()
                }
            }
            i += incr
        }
    }

    /** Positive = shift right, negative = shift left, wrapping within the byte. */
    private fun shiftByteRight(value: Int, amount: Int): Int {
        val shift = ((amount % 8) + 8) % 8
        return if (amount >= 0) {
            ((value ushr shift) or (value shl (8 - shift))) and 0xFF
        } else {
            ((value shl shift) or (value ushr (8 - shift))) and 0xFF
        }
    }

    /** The 6502's undocumented opcodes that jam (halt) the CPU until reset. */
    private val NES_CPU_JAM_OPCODES = setOf(
        0x02, 0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x92, 0xB2, 0xD2, 0xF2
    )

    /**
     * Literal (non-regex) byte-sequence find/replace. The replacement is
     * padded or truncated to exactly match the search text's byte length,
     * so the file's total size never changes — resizing a ROM/binary file
     * generally breaks it outright, which is worse than any corruption.
     */
    private fun textReplaceLiteral(buf: ByteArray, find: String, replaceWith: String) {
        if (find.isEmpty()) return
        val findBytes = find.toByteArray(Charsets.ISO_8859_1)
        val rawReplace = replaceWith.toByteArray(Charsets.ISO_8859_1)
        val replaceBytes = ByteArray(findBytes.size) { idx ->
            if (idx < rawReplace.size) rawReplace[idx] else findBytes[idx]
        }

        var i = 0
        while (i <= buf.size - findBytes.size) {
            var matches = true
            for (j in findBytes.indices) {
                if (buf[i + j] != findBytes[j]) {
                    matches = false
                    break
                }
            }
            if (matches) {
                for (j in replaceBytes.indices) buf[i + j] = replaceBytes[j]
                i += findBytes.size
            } else {
                i++
            }
        }
    }

    /**
     * Ported from RTCV's real RTC_VectorEngine.GenerateUnit — the address
     * math below (safeAddress / out-of-range clamp) is copied line-for-line
     * from that C# source, not reinvented. What's adapted for a static file
     * instead of a live BizHawk memory domain:
     *  - "domain" doesn't apply — there's only one domain, the file itself.
     *  - LimiterList (a curated per-game address allow-list) becomes the
     *    generic [rangeStart]/[rangeEnd] this app already uses elsewhere —
     *    we don't have RTCV's per-game filter database, so the user-supplied
     *    range is the closest equivalent "only corrupt here" restriction.
     *  - ValueList (a curated per-game pool of "safe" constants, matched
     *    against the original bytes via GetRandomConstant) becomes an
     *    optional user-supplied hex list ([valueListText]); with it off, a
     *    uniformly random value within the chosen bit-width's Min/Max bounds
     *    is used instead (same bit-width + bounds UI as the Nightmare Engine),
     *    since we don't have RTCV's shipped value-list database to draw from.
     *  - UnlockPrecision/CachedPrecision (BizHawk-reported bus width) becomes
     *    a plain [precision] choice (1/2/4/8 bytes) the person sets directly —
     *    functionally the same as always running "unlocked" with an explicit
     *    value, just with real min/max control over what gets written now.
     * The original runs GenerateUnit once per engine tick for as long as
     * corruption is engaged live; [iterations] is how many of those ticks'
     * worth of writes to bake into this one-shot file transform.
     *
     * Note this only changes how the *value* to write is produced — the
     * address math below (safeAddress + its out-of-range clamp) is
     * untouched from the original port and still uses [alignment] the same
     * way the real RTC_VectorEngine.GenerateUnit does, which is genuinely
     * different from the Nightmare Engine's own clamp (that one uses
     * precision). Kept exactly as before so this stays a functionally
     * faithful port, not a merge of two different engines' math.
     */
    private fun vectorEngine(
        buf: ByteArray,
        precision: Int,
        alignment: Int,
        iterations: Int,
        rangeStart: Int,
        rangeEnd: Int,
        headerSize: Int,
        bigEndian: Boolean,
        useValueList: Boolean,
        valueListText: String,
        min8: ULong, max8: ULong,
        min16: ULong, max16: ULong,
        min32: ULong, max32: ULong,
        min64: ULong, max64: ULong,
        r: Random
    ) {
        if (buf.isEmpty() || iterations <= 0) return
        val prec = if (precision in intArrayOf(1, 2, 4, 8)) precision else 4
        val align = alignment.coerceAtLeast(0)
        val header = headerSize.coerceIn(0, buf.size)

        val start = if (rangeStart >= 0) rangeStart.coerceIn(0, buf.size) else header
        val end = if (rangeEnd >= 0) rangeEnd.coerceIn(0, buf.size) else buf.size
        if (end - start < prec) return

        val pool = if (useValueList) parseHexValueList(valueListText) else null

        repeat(iterations) {
            // Stand-in for RTCV picking a live memory address to consider —
            // here, any raw offset inside our allowed range.
            val address = start + r.nextInt(end - start)

            // --- exact port of RTC_VectorEngine.GenerateUnit begins ---
            var safeAddress = address - (address % prec) + align
            if (safeAddress > end - align) {
                safeAddress = end - (2 * align) + align // out of range: hit the last aligned address
            }
            // --- exact port ends ---

            // Safety net the original doesn't need (its MemoryInterface
            // handles bounds itself): never write outside our own range/buffer.
            if (safeAddress < start || safeAddress < 0 || safeAddress + prec > end || safeAddress + prec > buf.size) {
                return@repeat
            }

            val value: ULong = pool?.takeIf { it.isNotEmpty() }?.let { it[r.nextInt(it.size)] }
                ?: when (prec) {
                    1 -> randomULongInRange(r, min8, max8)
                    2 -> randomULongInRange(r, min16, max16)
                    8 -> randomULongInRange(r, min64, max64)
                    else -> randomULongInRange(r, min32, max32) // 4 (and any unexpected fallback)
                }
            writeUnsignedBytes(buf, safeAddress, prec, value, bigEndian)
        }
    }

    /** Parses a comma/space/newline separated list of hex constants, e.g. "DEADBEEF, 0x1234ABCD". */
    private fun parseHexValueList(text: String): List<ULong> =
        text.split(',', ' ', '\n', '\t', '\r')
            .map { it.trim().removePrefix("0x").removePrefix("0X") }
            .filter { it.isNotEmpty() }
            .mapNotNull { it.toULongOrNull(16) }

    /**
     * Ported from RTCV's real RTC_NightmareEngine.GenerateUnit. Each blast
     * rolls an operation according to [algo] (mirroring the Algo switch):
     * "Random" always SETs a brand-new value; "RandomTilt" randomly SETs,
     * ADDs 1, or SUBTRACTs 1; "Tilt" randomly ADDs or SUBTRACTs 1 — same
     * three-way and two-way random branches as RtcCore.RND.Next(1,4) /
     * Next(1,3) in the original. The address math (safeAddress + the
     * out-of-range clamp) is copied from that source too, and is genuinely
     * different from the Vector Engine's — Nightmare's clamp uses precision
     * where Vector's uses alignment, so they're not interchangeable.
     *
     * Adapted for a static file the same way as the Vector Engine: no
     * "domain" (only one, the file), and the Min/Max8/16/32/64Bit bounds
     * are plain parameters instead of a shared runtime spec. SET without a
     * standard precision (not 1/2/4/8) falls back to fully independent
     * random bytes, same as the original's "def" branch — not reachable
     * through this app's dropdown, but kept for fidelity.
     */
    private fun nightmareEngine(
        buf: ByteArray,
        algo: String,
        precision: Int,
        alignment: Int,
        iterations: Int,
        rangeStart: Int,
        rangeEnd: Int,
        headerSize: Int,
        bigEndian: Boolean,
        min8: ULong, max8: ULong,
        min16: ULong, max16: ULong,
        min32: ULong, max32: ULong,
        min64: ULong, max64: ULong,
        r: Random
    ) {
        if (buf.isEmpty() || iterations <= 0) return
        val prec = precision.coerceAtLeast(1)
        if (buf.size < prec) return
        val align = alignment.coerceAtLeast(0)
        val header = headerSize.coerceIn(0, buf.size)

        val start = if (rangeStart >= 0) rangeStart.coerceIn(0, buf.size) else header
        val end = if (rangeEnd >= 0) rangeEnd.coerceIn(0, buf.size) else buf.size
        if (end - start < prec) return

        val algoKey = algo.trim().lowercase()

        repeat(iterations) {
            // --- exact port of the Algo switch begins ---
            val type = when (algoKey) {
                "randomtilt" -> when (r.nextInt(1, 4)) { // RtcCore.RND.Next(1,4): 1..3
                    1 -> "add"
                    2 -> "subtract"
                    else -> "set"
                }
                "tilt" -> if (r.nextInt(1, 3) == 1) "add" else "subtract" // Next(1,3): 1..2
                else -> "set" // "random"
            }
            // --- end port ---

            val address = start + r.nextInt(end - start)

            // --- exact port of RTC_NightmareEngine.GenerateUnit's address math ---
            var safeAddress = address - (address % prec) + align
            if (safeAddress > end - prec && end > prec) {
                safeAddress = end - (2 * prec) + align
            }
            // --- end port ---

            if (safeAddress < start || safeAddress < 0 || safeAddress + prec > end || safeAddress + prec > buf.size) {
                return@repeat
            }

            when (type) {
                "set" -> {
                    when (prec) {
                        1 -> writeUnsignedBytes(buf, safeAddress, 1, randomULongInRange(r, min8, max8), bigEndian)
                        2 -> writeUnsignedBytes(buf, safeAddress, 2, randomULongInRange(r, min16, max16), bigEndian)
                        4 -> writeUnsignedBytes(buf, safeAddress, 4, randomULongInRange(r, min32, max32), bigEndian)
                        8 -> writeUnsignedBytes(buf, safeAddress, 8, randomULongInRange(r, min64, max64), bigEndian)
                        else -> for (i in 0 until prec) buf[safeAddress + i] = r.nextInt(256).toByte() // ported "def" fallback
                    }
                }
                "add" -> tiltValue(buf, safeAddress, prec, bigEndian, +1)
                "subtract" -> tiltValue(buf, safeAddress, prec, bigEndian, -1)
            }
        }
    }

    /**
     * Ported from RTCV's real RTC_HellgenieEngine.GenerateUnit. It's the
     * simplest of the four engines: every blast always writes a brand-new
     * random value within the chosen bit-width's Min/Max bounds — no
     * Algo choice, no tilt, just SET. Structurally this is the same as the
     * Nightmare Engine's "Random" mode, but Hellgenie's own address clamp
     * formula is copied here independently rather than assumed identical,
     * since porting each engine from its own source is the point.
     */
    private fun hellgenieEngine(
        buf: ByteArray,
        precision: Int,
        alignment: Int,
        iterations: Int,
        rangeStart: Int,
        rangeEnd: Int,
        headerSize: Int,
        bigEndian: Boolean,
        min8: ULong, max8: ULong,
        min16: ULong, max16: ULong,
        min32: ULong, max32: ULong,
        min64: ULong, max64: ULong,
        r: Random
    ) {
        if (buf.isEmpty() || iterations <= 0) return
        val prec = precision.coerceAtLeast(1)
        if (buf.size < prec) return
        val align = alignment.coerceAtLeast(0)
        val header = headerSize.coerceIn(0, buf.size)

        val start = if (rangeStart >= 0) rangeStart.coerceIn(0, buf.size) else header
        val end = if (rangeEnd >= 0) rangeEnd.coerceIn(0, buf.size) else buf.size
        if (end - start < prec) return

        repeat(iterations) {
            val address = start + r.nextInt(end - start)

            // --- exact port of RTC_HellgenieEngine.GenerateUnit's address math ---
            var safeAddress = address - (address % prec) + align
            if (safeAddress > end - prec && end > prec) {
                safeAddress = end - (2 * prec) + align // out of range: hit the last aligned address
            }
            // --- end port ---

            if (safeAddress < start || safeAddress < 0 || safeAddress + prec > end || safeAddress + prec > buf.size) {
                return@repeat
            }

            when (prec) {
                1 -> writeUnsignedBytes(buf, safeAddress, 1, randomULongInRange(r, min8, max8), bigEndian)
                2 -> writeUnsignedBytes(buf, safeAddress, 2, randomULongInRange(r, min16, max16), bigEndian)
                4 -> writeUnsignedBytes(buf, safeAddress, 4, randomULongInRange(r, min32, max32), bigEndian)
                8 -> writeUnsignedBytes(buf, safeAddress, 8, randomULongInRange(r, min64, max64), bigEndian)
                else -> for (i in 0 until prec) buf[safeAddress + i] = r.nextInt(256).toByte() // ported "def" fallback
            }
        }
    }

    /**
     * Ported from RTCV's real RTC_PipeEngine.GenerateUnit: reads a
     * Precision-byte value from one "source" address and copies it,
     * unmodified, into a run of random destination addresses — the classic
     * "pipe one value everywhere" broadcast effect. The original re-reads
     * a live, continuously-tracked source every tick (StoreType.CONTINUOUS)
     * and can pull that source from a completely different memory domain;
     * neither applies to a static single-file transform, so this takes one
     * snapshot of the source bytes up front and pipes that same snapshot
     * into every destination this run picks. [sourceByte] of -1 picks that
     * source address randomly once per run; 0 or above uses it directly —
     * handy for deliberately broadcasting a byte offset you already know is
     * interesting. Both the source and destination address math are exact
     * ports of the original's own (precision-based) clamp formula.
     */
    private fun pipeEngine(
        buf: ByteArray,
        precision: Int,
        alignment: Int,
        sourceByte: Int,
        iterations: Int,
        rangeStart: Int,
        rangeEnd: Int,
        headerSize: Int,
        r: Random
    ) {
        if (buf.isEmpty() || iterations <= 0) return
        val prec = precision.coerceAtLeast(1)
        if (buf.size < prec) return
        val align = alignment.coerceAtLeast(0)
        val header = headerSize.coerceIn(0, buf.size)

        val start = if (rangeStart >= 0) rangeStart.coerceIn(0, buf.size) else header
        val end = if (rangeEnd >= 0) rangeEnd.coerceIn(0, buf.size) else buf.size
        if (end - start < prec) return

        // --- exact port of the source ("pipe start") address math ---
        val rawSourceAddress = if (sourceByte >= 0) sourceByte else start + r.nextInt(end - start)
        var safeSourceAddress = rawSourceAddress - (rawSourceAddress % prec) + align
        if (safeSourceAddress > buf.size - prec && buf.size > prec) {
            safeSourceAddress = buf.size - (2 * prec) + align
        }
        // --- end port ---
        if (safeSourceAddress < 0 || safeSourceAddress + prec > buf.size) return

        val sourceBytes = buf.copyOfRange(safeSourceAddress, safeSourceAddress + prec)

        repeat(iterations) {
            val address = start + r.nextInt(end - start)

            // --- exact port of the destination address math ---
            var safeAddress = address - (address % prec) + align
            if (safeAddress > end - prec && end > prec) {
                safeAddress = end - (2 * prec) + align
            }
            // --- end port ---

            if (safeAddress < start || safeAddress < 0 || safeAddress + prec > end || safeAddress + prec > buf.size) {
                return@repeat
            }

            sourceBytes.copyInto(buf, safeAddress)
        }
    }

    /** Uniformly-ish random ULong in [min, max] inclusive (min > max is treated as just min). */
    private fun randomULongInRange(r: Random, min: ULong, max: ULong): ULong {
        if (min >= max) return min
        val span = max - min
        val hi = (r.nextInt().toLong() and 0xFFFFFFFFL)
        val lo = (r.nextInt().toLong() and 0xFFFFFFFFL)
        val raw = ((hi shl 32) or lo).toULong()
        return if (span == ULong.MAX_VALUE) raw else min + (raw % (span + 1UL))
    }

    /** Writes [size] bytes (1/2/4/8) of [value] at [offset], honoring byte order. */
    private fun writeUnsignedBytes(buf: ByteArray, offset: Int, size: Int, value: ULong, bigEndian: Boolean) {
        for (i in 0 until size) {
            val shift = if (bigEndian) (size - 1 - i) * 8 else i * 8
            buf[offset + i] = ((value shr shift) and 0xFFUL).toByte()
        }
    }

    /** Reads the existing [size]-byte value at [offset], adds [delta] (wrapping within that bit-width), writes it back. */
    private fun tiltValue(buf: ByteArray, offset: Int, size: Int, bigEndian: Boolean, delta: Int) {
        var current = 0UL
        for (i in 0 until size) {
            val b = (buf[offset + i].toInt() and 0xFF).toULong()
            val shift = if (bigEndian) (size - 1 - i) * 8 else i * 8
            current = current or (b shl shift)
        }
        val bits = size * 8
        val mask = if (bits >= 64) ULong.MAX_VALUE else (1UL shl bits) - 1UL
        // delta.toLong().toULong() reinterprets -1 as 0xFFFF...FFFF, so adding
        // it is the same as subtracting 1, mod 2^64 — masking then truncates
        // that correctly down to the size's own bit width.
        val updated = (current + delta.toLong().toULong()) and mask
        writeUnsignedBytes(buf, offset, size, updated, bigEndian)
    }

    /**
     * Ported from RTCV's real RTC_ClusterEngine.GenerateUnit: reads a run of
     * [chunkSize] consecutive [precision]-byte segments starting at a
     * computed aligned address, reorders those segments (Random shuffle,
     * Reverse, Rotate Forwards, Rotate Backwards, or Overwrite-with-one-
     * segment), and writes them back to the same span. Unlike Vector/
     * Nightmare, this never invents a new byte value — it only rearranges
     * bytes already in the file.
     *
     * Adapted for a static file: LimiterListHash/FilterAll (RTCV's curated
     * per-game address permission checks, which is also where the real
     * engine actually reads its Precision from) become the plain
     * [rangeStart]/[rangeEnd]/[headerSize] range this app already uses
     * elsewhere, with [precision] exposed directly as a value you set.
     * OutputMultipleUnits is a pure implementation detail of RTCV's live
     * BlastUnit system (one write vs. several) with no effect on the
     * resulting bytes, so it's dropped — the file ends up identical either way.
     */
    private fun clusterEngine(
        buf: ByteArray,
        shuffleType: String,
        direction: String,
        chunkSize: Int,
        modifier: Int,
        precision: Int,
        alignment: Int,
        iterations: Int,
        rangeStart: Int,
        rangeEnd: Int,
        headerSize: Int,
        r: Random
    ) {
        if (buf.isEmpty() || iterations <= 0) return
        val prec = precision.coerceAtLeast(1)
        val chunks = chunkSize.coerceAtLeast(2) // shuffling a single segment is a no-op
        val align = alignment.coerceAtLeast(0)
        val header = headerSize.coerceIn(0, buf.size)

        val start = if (rangeStart >= 0) rangeStart.coerceIn(0, buf.size) else header
        val end = if (rangeEnd >= 0) rangeEnd.coerceIn(0, buf.size) else buf.size
        val spanBytes = chunks * prec
        if (end - start < spanBytes) return

        val backwards = direction.trim().equals("Backwards", ignoreCase = true)

        repeat(iterations) {
            val address = start + r.nextInt(end - start)

            // --- exact port of RTC_ClusterEngine.GenerateUnit's address math ---
            var safeAddress = address - (address % prec) + align
            if (safeAddress > end - prec) {
                safeAddress = end - (prec * 2) + align // out of range: hit the last aligned address
            }
            if (safeAddress + spanBytes >= end) return@repeat // ported "chunk doesn't fit: abort"
            // --- end port ---

            if (safeAddress < start || safeAddress < 0 || safeAddress + spanBytes > buf.size) return@repeat

            // Read the chunk's segments out.
            val segments = ArrayList<ByteArray>(chunks)
            for (j in 0 until chunks) {
                val segStart = safeAddress + j * prec
                segments.add(buf.copyOfRange(segStart, segStart + prec))
            }

            val srcUnit = if (backwards) chunks - 1 else 0

            // --- exact port of the ShuffleType switch ---
            when (shuffleType.trim().lowercase()) {
                "reverse" -> segments.reverse()
                "rotate forwards" -> repeat(modifier.coerceAtLeast(0)) { rotateForward(segments) }
                "rotate backwards" -> repeat(modifier.coerceAtLeast(0)) { rotateBackward(segments) }
                "overwrite" -> {
                    val src = segments[srcUnit]
                    for (j in segments.indices) segments[j] = src
                }
                else -> shuffleRandom(segments, r) // "random" (default)
            }
            // --- end port ---

            for (j in 0 until chunks) {
                segments[j].copyInto(buf, safeAddress + j * prec)
            }
        }
    }

    /** Exact port of RTC_ClusterEngine's Fisher-Yates: RtcCore.RND.Next(n+1) each step. */
    private fun shuffleRandom(list: MutableList<ByteArray>, r: Random) {
        var n = list.size
        while (n > 1) {
            n--
            val k = r.nextInt(n + 1)
            val tmp = list[k]
            list[k] = list[n]
            list[n] = tmp
        }
    }

    private fun rotateForward(list: MutableList<ByteArray>) {
        val x = list.removeAt(list.size - 1)
        list.add(0, x)
    }

    private fun rotateBackward(list: MutableList<ByteArray>) {
        val x = list.removeAt(0)
        list.add(x)
    }
}
