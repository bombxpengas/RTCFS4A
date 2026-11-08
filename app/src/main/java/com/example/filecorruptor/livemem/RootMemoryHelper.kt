package com.example.filecorruptor.livemem

import android.content.Context
import com.example.filecorruptor.log.RtcLog
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.TimeUnit

data class LiveProcess(val pid: Int, val name: String)

data class MemoryRegion(val start: Long, val end: Long, val perms: String, val path: String) {
    val size: Long get() = end - start
    val isWritable: Boolean get() = perms.length >= 2 && perms[0] == 'r' && perms[1] == 'w'
    val isExecutable: Boolean get() = perms.length >= 3 && perms[2] == 'x'

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

/** One small write inside a process: [bytes] go to absolute [address]. */
class MemoryPatch(val address: Long, val bytes: ByteArray)

/**
 * A compare-and-swap write: [bytes] replace what is at [address] only if the
 * target's memory there STILL equals [expected] (the snapshot the patch was
 * computed from). Both arrays have the same length.
 */
class CheckedPatch(val address: Long, val expected: ByteArray, val bytes: ByteArray)

/** Outcome of [RootMemoryHelper.patchMemoryChecked]. [error] != null means nothing was written. */
data class PatchResult(
    val error: String? = null,
    val applied: Int = 0,
    /** Memory no longer matched the snapshot (the app freed/re-used/rewrote it): left alone. */
    val skipped: Int = 0,
    /** The range was no longer mapped read/write: left alone. */
    val unmapped: Int = 0,
    val failed: Int = 0,
    val threadsFrozen: Int = 0
)

enum class ProcState { ALIVE, STOPPED, DEAD, UNKNOWN }

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
 *
 * Every `su` call has a timeout: a helper stuck attaching to a process in
 * uninterruptible sleep used to block the calling coroutine forever.
 */
object RootMemoryHelper {

    private const val TAG = "Root"
    private const val DEFAULT_TIMEOUT_MS = 30_000L

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

    private class ExecResult(val output: String, val exitCode: Int, val timedOut: Boolean)

    /** Runs [cmd], merging stderr into stdout, killing it if it outlives [timeoutMs]. */
    private fun exec(timeoutMs: Long, vararg cmd: String): ExecResult {
        val process = ProcessBuilder(*cmd).redirectErrorStream(true).start()
        val sb = StringBuilder()
        val reader = Thread {
            try {
                process.inputStream.bufferedReader().use { r ->
                    val buf = CharArray(8192)
                    while (true) {
                        val n = r.read(buf)
                        if (n < 0) break
                        synchronized(sb) { sb.append(buf, 0, n) }
                    }
                }
            } catch (_: Exception) {
            }
        }
        reader.isDaemon = true
        reader.start()

        val finished = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
        if (!finished) process.destroyForcibly()
        reader.join(1000)
        val out = synchronized(sb) { sb.toString() }
        val exit = if (finished) process.exitValue() else -1
        return ExecResult(out, exit, !finished)
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
            val result = exec(DEFAULT_TIMEOUT_MS, "su", "-c", command)
            when {
                result.timedOut -> {
                    RtcLog.w(TAG, "helper '${args.firstOrNull()}' timed out after ${DEFAULT_TIMEOUT_MS}ms")
                    "ERR helper timed out after ${DEFAULT_TIMEOUT_MS / 1000}s${if (result.output.isNotBlank()) "\n" + result.output else ""}"
                }
                result.output.isBlank() -> "(no output, exit code ${result.exitCode})"
                else -> result.output
            }
        }.getOrElse { e -> "ERR could not invoke su: ${e.message} — is this device rooted?" }
    }

    /**
     * Runs an arbitrary shell command as root (used for logcat / tombstone
     * collection). Returns its combined output, or an "ERR ..." string.
     * [command] is passed to `su -c` verbatim — only ever call it with
     * strings built by this app, never with user input.
     */
    fun runRootShell(command: String, timeoutMs: Long = DEFAULT_TIMEOUT_MS): String =
        runCatching {
            val result = exec(timeoutMs, "su", "-c", command)
            if (result.timedOut) "ERR timed out after ${timeoutMs}ms\n${result.output}" else result.output
        }.getOrElse { e -> "ERR could not invoke su: ${e.message}" }

    /** Blocking; call from a background dispatcher. */
    fun hasRoot(): Boolean = runCatching {
        // Generous: the very first call shows the root-grant prompt and
        // waits for the person to tap Allow.
        val result = exec(60_000L, "su", "-c", "id")
        result.output.contains("uid=0")
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

    /**
     * Whether [pid] is still the process named [name]. The helper compares
     * argv[0], so a pid the kernel has since recycled for something else
     * reports [ProcState.DEAD] rather than a false [ProcState.ALIVE].
     * [ProcState.STOPPED] also covers "tombstoned is mid crash-dump".
     */
    fun processState(context: Context, pid: Int, name: String): ProcState {
        val first = runAsRoot(context, "alive", pid.toString(), name).firstOrNull()?.trim().orEmpty()
        return when {
            first.startsWith("ALIVE") -> ProcState.ALIVE
            first.startsWith("STOPPED") -> ProcState.STOPPED
            first.startsWith("DEAD") -> ProcState.DEAD
            else -> ProcState.UNKNOWN
        }
    }

    /** Reads [length] bytes at [address] in [pid]'s memory, or null on failure. */
    fun readMemory(context: Context, pid: Int, address: Long, length: Int): ByteArray? =
        readMemoryResult(context, pid, address, length).first

    /** Like [readMemory], but also returns the helper's error text on failure. */
    fun readMemoryResult(context: Context, pid: Int, address: Long, length: Int): Pair<ByteArray?, String?> {
        val outFile = File(context.cacheDir, "rtmem_read_${System.nanoTime()}.bin")
        val result = runAsRoot(
            context, "read", pid.toString(), address.toString(16), length.toString(), outFile.absolutePath
        )
        if (result.firstOrNull()?.trim() != "OK") {
            outFile.delete()
            val err = result.firstOrNull()?.trim() ?: "no output from helper"
            RtcLog.d(TAG, "read pid=$pid addr=0x${address.toString(16)} len=$length failed: $err")
            return null to err
        }
        val bytes = runCatching { outFile.readBytes() }.getOrNull()
        outFile.delete()
        return if (bytes != null) bytes to null else null to "could not read helper output file"
    }

    /** Writes [bytes] into [pid]'s memory starting at [address]. Returns success. */
    fun writeMemory(context: Context, pid: Int, address: Long, bytes: ByteArray): Boolean {
        val inFile = File(context.cacheDir, "rtmem_write_${System.nanoTime()}.bin")
        return try {
            inFile.writeBytes(bytes)
            val result = runAsRoot(context, "write", pid.toString(), address.toString(16), inFile.absolutePath)
            val ok = result.firstOrNull()?.trim() == "OK"
            if (!ok) RtcLog.d(TAG, "write pid=$pid addr=0x${address.toString(16)} failed: ${result.firstOrNull()}")
            ok
        } finally {
            inFile.delete()
        }
    }

    /**
     * Anti-crash write path: applies [patches] in a single ptrace attach, and
     * only if the whole [regionStart, regionEnd) range is *still* a plain
     * read/write mapping in the target. Returns null on success, or the
     * helper's error text (e.g. "region ... is no longer mapped read/write",
     * "attach failed: No such process").
     */
    fun patchMemory(
        context: Context,
        pid: Int,
        regionStart: Long,
        regionEnd: Long,
        patches: List<MemoryPatch>
    ): String? {
        if (patches.isEmpty()) return null
        val total = patches.sumOf { 12 + it.bytes.size }
        val buf = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN)
        for (p in patches) {
            buf.putLong(p.address)
            buf.putInt(p.bytes.size)
            buf.put(p.bytes)
        }
        val inFile = File(context.cacheDir, "rtmem_patch_${System.nanoTime()}.bin")
        return try {
            inFile.writeBytes(buf.array())
            val result = runAsRoot(
                context, "patch", pid.toString(),
                regionStart.toString(16), regionEnd.toString(16), inFile.absolutePath
            )
            val first = result.firstOrNull()?.trim()
            if (first == "OK") null else (first ?: "no output from helper")
        } finally {
            inFile.delete()
        }
    }

    /**
     * The safest write path: freezes every thread of [pid], then applies each
     * [CheckedPatch] only where memory still equals the snapshot. See `cpatch`
     * in rtmem_helper.c. Falls back to the plain single-attach path if the
     * installed helper predates `cpatch`.
     */
    fun patchMemoryChecked(
        context: Context,
        pid: Int,
        regionStart: Long,
        regionEnd: Long,
        patches: List<CheckedPatch>
    ): PatchResult {
        if (patches.isEmpty()) return PatchResult()
        val total = patches.sumOf { 12 + it.expected.size + it.bytes.size }
        val buf = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN)
        for (p in patches) {
            buf.putLong(p.address)
            buf.putInt(p.bytes.size)
            buf.put(p.expected)
            buf.put(p.bytes)
        }
        val inFile = File(context.cacheDir, "rtmem_cpatch_${System.nanoTime()}.bin")
        return try {
            inFile.writeBytes(buf.array())
            val result = runAsRoot(
                context, "cpatch", pid.toString(),
                regionStart.toString(16), regionEnd.toString(16), inFile.absolutePath
            )
            val first = result.firstOrNull()?.trim()
            when {
                first == null -> PatchResult(error = "no output from helper")
                first.startsWith("ERR unknown command") -> {
                    RtcLog.w(TAG, "helper has no cpatch — using the plain patch path")
                    val err = patchMemory(context, pid, regionStart, regionEnd, patches.map { MemoryPatch(it.address, it.bytes) })
                    PatchResult(error = err, applied = if (err == null) patches.size else 0)
                }
                first.startsWith("OK") -> {
                    val kv = Regex("(\\w+)=(\\d+)").findAll(first).associate { it.groupValues[1] to it.groupValues[2].toInt() }
                    PatchResult(
                        applied = kv["applied"] ?: 0,
                        skipped = kv["skipped"] ?: 0,
                        unmapped = kv["unmapped"] ?: 0,
                        failed = kv["failed"] ?: 0,
                        threadsFrozen = kv["frozen"] ?: 0
                    )
                }
                else -> PatchResult(error = first)
            }
        } finally {
            inFile.delete()
        }
    }
}
