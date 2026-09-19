package com.example.filecorruptor.livemem

import android.content.Context
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

data class LiveProcess(val pid: Int, val name: String)

data class MemoryRegion(val start: Long, val end: Long, val perms: String, val path: String) {
    val size: Long get() = end - start
    val isWritable: Boolean get() = perms.length >= 2 && perms[0] == 'r' && perms[1] == 'w'

    /**
     * Matches the real RTCV's own default targeting rule for a raw,
     * non-cooperative process (see RTCV.ProcessCorrupt.ProcessWatch.
     * GetInterfaces: `(mbi.Protect | ProtectMode) == ProtectMode` with
     * ProtectMode defaulting to plain PAGE_READWRITE alone) — read+write
     * is required, but executable pages are explicitly excluded. An
     * executable region is far more likely to be JIT-compiled code, a
     * trampoline, or similar structural machinery than plain game data,
     * and corrupting it tends to produce an instant crash (jumping into
     * garbage instructions) rather than a glitch. Our previous filter
     * only checked for 'rw' and let 'rwx' regions through unfiltered.
     */
    val isSafeToCorrupt: Boolean get() =
        perms.length >= 3 && perms[0] == 'r' && perms[1] == 'w' && perms[2] != 'x'
}

/**
 * Talks to a small root-privileged native helper binary (see
 * app/src/main/cpp/rtmem_helper.c) that does the actual ptrace-based
 * process-memory read/write. The helper ships disguised as a lib*.so under
 * jniLibs purely so Android's own packaging pipeline installs it with
 * executable permissions automatically — it's a real standalone program,
 * never loaded as a library, and only ever invoked through `su -c`.
 *
 * This is the same fundamental technique tools like GameGuardian use on
 * rooted Android. There is no Android equivalent to BizHawk's cooperative
 * "memory domain" API the real RTCV integrates with, so for an arbitrary,
 * non-cooperating emulator app the only option is a direct OS-level attach,
 * gated entirely behind root the device owner already granted.
 *
 * Every function here does blocking process I/O — always call from a
 * background dispatcher (e.g. Dispatchers.IO), never the main thread.
 */
object RootMemoryHelper {

    fun helperPath(context: Context): String =
        File(context.applicationInfo.nativeLibraryDir, "librtmemhelper.so").absolutePath

    /** Plain (non-root) file check — if this is false, nothing else here can
     *  possibly work, regardless of root/SELinux, because there's simply no
     *  file to execute. See the packaging.jniLibs.useLegacyPackaging note in
     *  build.gradle.kts for why this could be false on some AGP defaults. */
    fun helperExists(context: Context): Boolean = File(helperPath(context)).exists()

    private fun buildCommand(context: Context, args: List<String>): String =
        (listOf(helperPath(context)) + args).joinToString(" ") { arg ->
            "'" + arg.replace("'", "'\\''") + "'"
        }

    private fun runAsRoot(context: Context, vararg args: String): List<String> =
        runRawDiagnostic(context, *args).lines().filter { it.isNotEmpty() }

    /** Same as [runAsRoot] but returns the exact raw stdout+stderr as one
     *  string, unfiltered and unparsed — for a debug panel when something
     *  isn't working and you need to see exactly what actually happened
     *  (su rejected the request, the file wasn't found, a permission error
     *  from ptrace/SELinux, etc.) instead of just an empty result. */
    fun runRawDiagnostic(context: Context, vararg args: String): String {
        val command = buildCommand(context, args.toList())
        return runCatching {
            val process = ProcessBuilder("su", "-c", command)
                .redirectErrorStream(true)
                .start()
            val output = BufferedReader(InputStreamReader(process.inputStream)).readText()
            val exitCode = process.waitFor()
            if (output.isBlank()) "(no output, exit code $exitCode)" else output
        }.getOrElse { e -> "ERR could not invoke su: ${e.message} — is this device rooted?" }
    }

    /** Blocking; call from a background dispatcher. */
    fun hasRoot(): Boolean = runCatching {
        val process = ProcessBuilder("su", "-c", "id").redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        process.waitFor()
        output.contains("uid=0")
    }.getOrDefault(false)

    fun listProcesses(context: Context): List<LiveProcess> {
        return runAsRoot(context, "list_processes").mapNotNull { line ->
            val parts = line.split("\t", limit = 2)
            if (parts.size != 2) return@mapNotNull null
            val pid = parts[0].toIntOrNull() ?: return@mapNotNull null
            // cmdline is NUL-separated argv; keep just argv[0].
            val name = parts[1].substringBefore('\u0000').ifBlank { "pid $pid" }
            LiveProcess(pid, name)
        }.sortedBy { it.name.lowercase() }
    }

    fun listMemoryMaps(context: Context, pid: Int): List<MemoryRegion> {
        return runAsRoot(context, "list_maps", pid.toString()).mapNotNull { line ->
            // e.g. "12c00000-12e00000 rw-p 00000000 00:00 0     [heap]"
            val parts = line.trim().split(Regex("\\s+"), limit = 6)
            if (parts.size < 2) return@mapNotNull null
            val range = parts[0].split("-")
            if (range.size != 2) return@mapNotNull null
            val start = range[0].toLongOrNull(16) ?: return@mapNotNull null
            val end = range[1].toLongOrNull(16) ?: return@mapNotNull null
            val perms = parts.getOrElse(1) { "" }
            val path = parts.getOrElse(5) { "" }
            MemoryRegion(start, end, perms, path)
        }
    }

    /** Reads [length] bytes at [address] in [pid]'s memory, or null on failure. */
    fun readMemory(context: Context, pid: Int, address: Long, length: Int): ByteArray? {
        val outFile = File(context.cacheDir, "rtmem_read_${System.nanoTime()}.bin")
        val result = runAsRoot(
            context, "read", pid.toString(), address.toString(16), length.toString(), outFile.absolutePath
        )
        if (result.firstOrNull()?.trim() != "OK") {
            outFile.delete()
            return null
        }
        val bytes = runCatching { outFile.readBytes() }.getOrNull()
        outFile.delete()
        return bytes
    }

    /** Writes [bytes] into [pid]'s memory starting at [address]. Returns success. */
    fun writeMemory(context: Context, pid: Int, address: Long, bytes: ByteArray): Boolean {
        val inFile = File(context.cacheDir, "rtmem_write_${System.nanoTime()}.bin")
        return try {
            inFile.writeBytes(bytes)
            val result = runAsRoot(context, "write", pid.toString(), address.toString(16), inFile.absolutePath)
            result.firstOrNull()?.trim() == "OK"
        } finally {
            inFile.delete()
        }
    }
}
