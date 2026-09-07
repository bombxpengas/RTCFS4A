package com.example.filecorruptor.corruptor

import kotlin.random.Random

/**
 * Corruption algorithms, modeled on what apps like "Real Time Corruptor" offer.
 * Every function returns a NEW ByteArray — the original input is never mutated,
 * so the UI can always re-run corruption from the pristine source (needed for
 * a live-updating intensity slider).
 */
enum class CorruptionMode(val label: String, val description: String) {
    RANDOM_BYTES(
        "Random Bytes",
        "Overwrites random bytes with random values — classic static/noise glitch."
    ),
    BIT_FLIP(
        "Bit Flip",
        "Flips random individual bits — subtle, often preserves more file structure."
    ),
    CHUNK_SHUFFLE(
        "Chunk Shuffle",
        "Shuffles the order of fixed-size chunks — big blocky glitches, datamosh-like."
    ),
    CHUNK_REVERSE(
        "Chunk Reverse",
        "Reverses the byte order inside random chunks."
    ),
    BYTE_SHIFT(
        "Byte Shift",
        "Adds a random offset to byte values — color-shift / smear look on images."
    ),
    ZERO_OUT(
        "Zero Out",
        "Replaces random bytes with 0x00 — creates dropout / missing-block glitches."
    ),
    DUPLICATE_BLOCK(
        "Duplicate Block",
        "Copies one chunk over other chunks — repeating/echo glitch pattern."
    );
}

data class CorruptionSettings(
    val mode: CorruptionMode = CorruptionMode.RANDOM_BYTES,
    /** 0f..1f — roughly, the fraction of the touched region that gets altered. */
    val intensity: Float = 0.15f,
    /**
     * Number of bytes at the very start of the file to leave untouched.
     * Keeping a file's header intact is what lets a corrupted JPEG/PNG/MP4
     * still partially decode instead of becoming totally unreadable.
     */
    val preserveHeaderBytes: Int = 128,
    /** Chunk size in bytes used by CHUNK_SHUFFLE / CHUNK_REVERSE / DUPLICATE_BLOCK. */
    val chunkSize: Int = 256,
    val seed: Long? = null
)

object FileCorruptor {

    fun corrupt(input: ByteArray, settings: CorruptionSettings): ByteArray {
        if (input.isEmpty()) return input
        val random = settings.seed?.let { Random(it) } ?: Random(System.nanoTime())
        val start = settings.preserveHeaderBytes.coerceIn(0, input.size)
        val output = input.copyOf()

        when (settings.mode) {
            CorruptionMode.RANDOM_BYTES -> randomBytes(output, start, settings.intensity, random)
            CorruptionMode.BIT_FLIP -> bitFlip(output, start, settings.intensity, random)
            CorruptionMode.CHUNK_SHUFFLE -> chunkShuffle(output, start, settings.chunkSize, settings.intensity, random)
            CorruptionMode.CHUNK_REVERSE -> chunkReverse(output, start, settings.chunkSize, settings.intensity, random)
            CorruptionMode.BYTE_SHIFT -> byteShift(output, start, settings.intensity, random)
            CorruptionMode.ZERO_OUT -> zeroOut(output, start, settings.intensity, random)
            CorruptionMode.DUPLICATE_BLOCK -> duplicateBlock(output, start, settings.chunkSize, settings.intensity, random)
        }
        return output
    }

    private fun touchedByteCount(range: Int, intensity: Float): Int =
        (range * intensity.coerceIn(0f, 1f)).toInt().coerceAtLeast(if (range > 0) 1 else 0)

    private fun randomBytes(buf: ByteArray, start: Int, intensity: Float, r: Random) {
        val range = buf.size - start
        val count = touchedByteCount(range, intensity)
        repeat(count) {
            val idx = start + r.nextInt(range)
            buf[idx] = r.nextInt(256).toByte()
        }
    }

    private fun bitFlip(buf: ByteArray, start: Int, intensity: Float, r: Random) {
        val range = buf.size - start
        // Bit-level intensity: total bits available = range * 8
        val totalBits = range * 8
        val count = touchedByteCount(totalBits, intensity)
        repeat(count) {
            val bitIdx = r.nextInt(totalBits)
            val byteIdx = start + bitIdx / 8
            val bitInByte = bitIdx % 8
            buf[byteIdx] = (buf[byteIdx].toInt() xor (1 shl bitInByte)).toByte()
        }
    }

    private fun chunkShuffle(buf: ByteArray, start: Int, chunkSize: Int, intensity: Float, r: Random) {
        if (chunkSize <= 0) return
        val range = buf.size - start
        val chunkCount = range / chunkSize
        if (chunkCount < 2) return
        val swaps = touchedByteCount(chunkCount, intensity)
        repeat(swaps) {
            val a = r.nextInt(chunkCount)
            val b = r.nextInt(chunkCount)
            swapChunks(buf, start + a * chunkSize, start + b * chunkSize, chunkSize)
        }
    }

    private fun swapChunks(buf: ByteArray, offsetA: Int, offsetB: Int, size: Int) {
        for (i in 0 until size) {
            val tmp = buf[offsetA + i]
            buf[offsetA + i] = buf[offsetB + i]
            buf[offsetB + i] = tmp
        }
    }

    private fun chunkReverse(buf: ByteArray, start: Int, chunkSize: Int, intensity: Float, r: Random) {
        if (chunkSize <= 0) return
        val range = buf.size - start
        val chunkCount = range / chunkSize
        if (chunkCount == 0) return
        val reversals = touchedByteCount(chunkCount, intensity)
        repeat(reversals) {
            val chunkIdx = r.nextInt(chunkCount)
            val offset = start + chunkIdx * chunkSize
            var lo = offset
            var hi = offset + chunkSize - 1
            while (lo < hi) {
                val tmp = buf[lo]
                buf[lo] = buf[hi]
                buf[hi] = tmp
                lo++; hi--
            }
        }
    }

    private fun byteShift(buf: ByteArray, start: Int, intensity: Float, r: Random) {
        val range = buf.size - start
        val count = touchedByteCount(range, intensity)
        val shiftAmount = (intensity * 255).toInt().coerceIn(1, 255)
        repeat(count) {
            val idx = start + r.nextInt(range)
            buf[idx] = ((buf[idx].toInt() and 0xFF) + shiftAmount).toByte()
        }
    }

    private fun zeroOut(buf: ByteArray, start: Int, intensity: Float, r: Random) {
        val range = buf.size - start
        val count = touchedByteCount(range, intensity)
        repeat(count) {
            val idx = start + r.nextInt(range)
            buf[idx] = 0
        }
    }

    private fun duplicateBlock(buf: ByteArray, start: Int, chunkSize: Int, intensity: Float, r: Random) {
        if (chunkSize <= 0 || buf.size - start < chunkSize) return
        val range = buf.size - start
        val chunkCount = range / chunkSize
        if (chunkCount < 2) return
        val sourceOffset = start + r.nextInt(chunkCount) * chunkSize
        val source = buf.copyOfRange(sourceOffset, sourceOffset + chunkSize)
        val copies = touchedByteCount(chunkCount, intensity)
        repeat(copies) {
            val destChunk = r.nextInt(chunkCount)
            val destOffset = start + destChunk * chunkSize
            System.arraycopy(source, 0, buf, destOffset, chunkSize)
        }
    }
}
