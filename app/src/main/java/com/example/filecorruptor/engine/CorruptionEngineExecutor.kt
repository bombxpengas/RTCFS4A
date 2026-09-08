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

    fun run(input: ByteArray, engine: EngineDefinition, values: Map<String, ParamValue>): ByteArray {
        if (input.isEmpty() || engine.operations.isEmpty()) return input
        val output = input.copyOf()

        // Two special, opt-in parameter ids: an engine that declares a "seed"
        // (number) and "useSeed" (switch) parameter gets reproducible output;
        // engines that don't declare them just get fresh randomness each run.
        val useSeed = values["useSeed"]?.asBoolean() == true
        val seedValue = values["seed"]
        val random = if (useSeed && seedValue != null) Random(seedValue.asLong()) else Random(System.nanoTime())

        for (op in engine.operations) {
            if (op.enabledParam != null && values[op.enabledParam]?.asBoolean() != true) {
                continue // this whole pass is switched off — e.g. "Enable byte corruption"
            }
            applyOperation(output, op, values, random)
        }
        return output
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
     *    uniformly random 32-bit value is used instead, since we don't have
     *    RTCV's shipped value-list database to draw from.
     *  - UnlockPrecision/CachedPrecision (BizHawk-reported bus width) becomes
     *    a plain [precision] number the person sets directly — functionally
     *    the same as always running "unlocked" with an explicit value.
     * The original runs GenerateUnit once per engine tick for as long as
     * corruption is engaged live; [iterations] is how many of those ticks'
     * worth of writes to bake into this one-shot file transform.
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
        r: Random
    ) {
        if (buf.size < 4 || iterations <= 0) return
        val precisionSafe = precision.coerceAtLeast(1)
        val align = alignment.coerceAtLeast(0)
        val header = headerSize.coerceIn(0, buf.size)

        val start = if (rangeStart >= 0) rangeStart.coerceIn(0, buf.size) else header
        val end = if (rangeEnd >= 0) rangeEnd.coerceIn(0, buf.size) else buf.size
        if (end - start < 4) return

        val pool = if (useValueList) parseHexValueList(valueListText) else null

        repeat(iterations) {
            // Stand-in for RTCV picking a live memory address to consider —
            // here, any raw offset inside our allowed range.
            val address = start + r.nextInt(end - start)

            // --- exact port of RTC_VectorEngine.GenerateUnit begins ---
            var safeAddress = address - (address % precisionSafe) + align // 32-bit trunc
            if (safeAddress > end - align) {
                safeAddress = end - (2 * align) + align // out of range: hit the last aligned address
            }
            // --- exact port ends ---

            // Safety net the original doesn't need (its MemoryInterface
            // handles bounds itself): never write outside our own range/buffer.
            if (safeAddress < start || safeAddress < 0 || safeAddress + 4 > end || safeAddress + 4 > buf.size) {
                return@repeat
            }

            val value = pool?.takeIf { it.isNotEmpty() }?.let { it[r.nextInt(it.size)] } ?: r.nextInt()
            writeInt32(buf, safeAddress, value, bigEndian)
        }
    }

    /** Parses a comma/space/newline separated list of hex 32-bit constants, e.g. "DEADBEEF, 0x1234ABCD". */
    private fun parseHexValueList(text: String): List<Int> =
        text.split(',', ' ', '\n', '\t', '\r')
            .map { it.trim().removePrefix("0x").removePrefix("0X") }
            .filter { it.isNotEmpty() }
            .mapNotNull { it.toLongOrNull(16)?.toInt() }

    private fun writeInt32(buf: ByteArray, offset: Int, value: Int, bigEndian: Boolean) {
        if (bigEndian) {
            buf[offset] = ((value ushr 24) and 0xFF).toByte()
            buf[offset + 1] = ((value ushr 16) and 0xFF).toByte()
            buf[offset + 2] = ((value ushr 8) and 0xFF).toByte()
            buf[offset + 3] = (value and 0xFF).toByte()
        } else {
            buf[offset] = (value and 0xFF).toByte()
            buf[offset + 1] = ((value ushr 8) and 0xFF).toByte()
            buf[offset + 2] = ((value ushr 16) and 0xFF).toByte()
            buf[offset + 3] = ((value ushr 24) and 0xFF).toByte()
        }
    }

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
}
