package com.example.filecorruptor.stub

import java.io.OutputStream
import kotlin.random.Random

/**
 * Generates placeholder / dummy files of an exact target size, similar to
 * "File Stub" apps. Useful for testing upload size limits, filling storage
 * for QA, or producing junk files with a specific extension.
 */
enum class FillPattern(val label: String) {
    ZEROS("All Zeros (0x00)"),
    ONES("All Ones (0xFF)"),
    RANDOM("Random Bytes"),
    REPEATING_TEXT("Repeating Text Pattern")
}

data class StubSettings(
    val sizeBytes: Long,
    val fillPattern: FillPattern = FillPattern.ZEROS,
    val repeatingText: String = "STUB",
)

object FileStubGenerator {

    private const val BUFFER_SIZE = 64 * 1024

    /**
     * Streams [settings.sizeBytes] worth of data to [out]. Streaming (rather than
     * allocating one giant ByteArray) lets this comfortably generate stub files
     * far larger than would fit safely in memory.
     */
    fun generate(out: OutputStream, settings: StubSettings) {
        var remaining = settings.sizeBytes
        val buffer = ByteArray(minOf(BUFFER_SIZE.toLong(), remaining.coerceAtLeast(1)).toInt())
        val random = Random(System.nanoTime())
        val patternBytes = settings.repeatingText.toByteArray(Charsets.UTF_8)
            .ifEmpty { "STUB".toByteArray(Charsets.UTF_8) }
        var patternCursor = 0

        while (remaining > 0) {
            val chunkSize = minOf(buffer.size.toLong(), remaining).toInt()
            when (settings.fillPattern) {
                FillPattern.ZEROS -> java.util.Arrays.fill(buffer, 0, chunkSize, 0)
                FillPattern.ONES -> java.util.Arrays.fill(buffer, 0, chunkSize, 0xFF.toByte())
                FillPattern.RANDOM -> random.nextBytes(buffer, 0, chunkSize)
                FillPattern.REPEATING_TEXT -> {
                    for (i in 0 until chunkSize) {
                        buffer[i] = patternBytes[patternCursor % patternBytes.size]
                        patternCursor++
                    }
                }
            }
            out.write(buffer, 0, chunkSize)
            remaining -= chunkSize
        }
        out.flush()
    }

    /** Human-friendly size presets shown in the UI. */
    fun presetSizes(): List<Pair<String, Long>> = listOf(
        "1 KB" to 1_024L,
        "100 KB" to 100L * 1024,
        "1 MB" to 1_024L * 1024,
        "10 MB" to 10L * 1024 * 1024,
        "100 MB" to 100L * 1024 * 1024,
        "1 GB" to 1_024L * 1024 * 1024,
    )
}
