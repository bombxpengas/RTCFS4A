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
}
