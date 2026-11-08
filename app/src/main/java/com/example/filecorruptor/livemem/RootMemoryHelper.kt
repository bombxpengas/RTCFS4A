package com.example.filecorruptor.livemem

import android.content.Context
import com.example.filecorruptor.log.RtcLog
import java.io.BufferedInputStream
import java.io.DataInputStream
import java.io.File
import java.io.FileInputStream
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
        // Preferred: stream the bytes straight from the helper's stdout. The file route below writes the
        // whole region to flash storage and reads it back — for an 80 MB region on a 50 ms tick that is
        // gigabytes of pointless writes and a big reason other apps stutter.
        val streamed = readViaPipe(context, pid, address, length)
        if (streamed.first != null) return streamed
        val err = streamed.second.orEmpty()
        if (!err.startsWith(PIPE_UNSUPPORTED)) return streamed // a real error (unreadable/unmapped), not a transport problem
        return readViaFile(context, pid, address, length)
    }

    private const val PIPE_UNSUPPORTED = "pipe transport unavailable"

    private fun readViaPipe(context: Context, pid: Int, address: Long, length: Int): Pair<ByteArray?, String?> {
        val command = buildCommand(context, listOf("readbin", pid.toString(), address.toString(16), length.toString()))
        var process: Process? = null
        try {
            process = ProcessBuilder("su", "-c", command).redirectErrorStream(false).start()
            val p = process
            // Drain stderr so a chatty su can never fill its pipe and deadlock us.
            Thread { try { val sink = ByteArray(4096); p.errorStream.use { while (it.read(sink) >= 0) { /* discard */ } } } catch (_: Exception) {} }
                .apply { isDaemon = true }.start()
            val watchdog = Thread {
                try { Thread.sleep(DEFAULT_TIMEOUT_MS) ; if (p.isAlive) p.destroyForcibly() } catch (_: InterruptedException) {}
            }.apply { isDaemon = true; start() }
            try {
                val input = BufferedInputStream(p.inputStream, 64 * 1024)
                val head = StringBuilder()
                while (head.length < 200) {
                    val b = input.read()
                    if (b < 0) return null to "$PIPE_UNSUPPORTED (no output)"
                    if (b == '\n'.code) break
                    head.append(b.toChar())
                }
                val line = head.toString().trim()
                if (line.startsWith("ERR unknown command")) return null to "$PIPE_UNSUPPORTED (old helper)"
                if (line.startsWith("ERR")) return null to line
                if (line != "DATA $length") return null to "$PIPE_UNSUPPORTED (unexpected header '${line.take(60)}')"
                val out = try { ByteArray(length) } catch (_: OutOfMemoryError) {
                    return null to "out of memory allocating ${length / 1_048_576} MB"
                }
                var done = 0
                while (done < length) {
                    val n = input.read(out, done, length - done)
                    if (n < 0) return null to "$PIPE_UNSUPPORTED (stream ended after $done of $length bytes)"
                    done += n
                }
                return out to null
            } finally {
                watchdog.interrupt()
            }
        } catch (e: Exception) {
            return null to "$PIPE_UNSUPPORTED (${e.message})"
        } finally {
            process?.let { if (it.isAlive) it.destroyForcibly() }
        }
    }

    private fun readViaFile(context: Context, pid: Int, address: Long, length: Int): Pair<ByteArray?, String?> {
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

    // ------------------------------------------------------------------
    // Bounded-memory activity scan (native; see `activity` in rtmem_helper.c)
    // ------------------------------------------------------------------

    /**
     * Change counters for one region. [granule] bytes share one counter (1 = byte-exact);
     * [counts] is null if the region didn't fit the memory budget even at the coarsest granule.
     * Counters are unsigned bytes (saturate at 255).
     */
    class ActivityRegionResult(val region: MemoryRegion, val granule: Int, val counts: ByteArray?)

    class ActivityScanOutcome(val results: List<ActivityRegionResult>, val cancelled: Boolean)

    /**
     * Samples [regions] of [pid] [samples] times, [intervalMs] apart, entirely inside the native
     * helper (which keeps ~[budgetMb] MB of state in total, runs niced, and never stops the target),
     * and returns per-region change counters. [onProgress] gets (done, total) after each sample;
     * [isCancelled] is polled with every progress line. Blocking — call from Dispatchers.IO.
     */
    fun activityScan(
        context: Context,
        pid: Int,
        regions: List<MemoryRegion>,
        samples: Int,
        intervalMs: Long,
        budgetMb: Int,
        onProgress: (done: Int, total: Int) -> Unit,
        isCancelled: () -> Boolean
    ): ActivityScanOutcome {
        require(regions.isNotEmpty()) { "no regions to scan" }
        val tag = System.nanoTime()
        val regionsFile = File(context.cacheDir, "rtmem_act_regions_$tag.txt")
        val outFile = File(context.cacheDir, "rtmem_act_out_$tag.bin")
        val cancelFile = File(context.cacheDir, "rtmem_act_cancel_$tag")
        try {
            regionsFile.writeText(regions.joinToString("\n") { "${it.start.toString(16)} ${it.end.toString(16)}" })
            val command = buildCommand(
                context,
                listOf(
                    "activity", pid.toString(), regionsFile.absolutePath, samples.toString(), intervalMs.toString(),
                    outFile.absolutePath, budgetMb.toString(), cancelFile.absolutePath
                )
            )
            val process = ProcessBuilder("su", "-c", command).redirectErrorStream(true).start()
            val lastLine = java.util.concurrent.atomic.AtomicLong(System.currentTimeMillis())
            val watchdog = Thread {
                try {
                    while (process.isAlive) {
                        Thread.sleep(1000)
                        if (System.currentTimeMillis() - lastLine.get() > ACTIVITY_STALL_MS) { process.destroyForcibly(); break }
                    }
                } catch (_: InterruptedException) {}
            }.apply { isDaemon = true; start() }

            var cancelled = false
            var error: String? = null
            var done = false
            try {
                process.inputStream.bufferedReader().use { r ->
                    while (true) {
                        val line = r.readLine() ?: break
                        lastLine.set(System.currentTimeMillis())
                        when {
                            line.startsWith("P ") -> {
                                val parts = line.split(" ")
                                onProgress(parts.getOrNull(1)?.toIntOrNull() ?: 0, parts.getOrNull(2)?.toIntOrNull() ?: samples)
                                if (!cancelled && isCancelled()) { cancelled = true; cancelFile.writeText("x") }
                            }
                            line == "DONE" -> done = true
                            line == "CANCELLED" -> cancelled = true
                            line.startsWith("ERR") -> error = line
                        }
                    }
                }
            } finally {
                watchdog.interrupt()
                if (process.isAlive) process.destroyForcibly()
            }
            if (cancelled) return ActivityScanOutcome(emptyList(), true)
            if (error != null) throw IllegalStateException(error)
            if (!done || !outFile.isFile) throw IllegalStateException("the scan helper stopped before finishing (it may have been killed)")

            DataInputStream(BufferedInputStream(FileInputStream(outFile), 256 * 1024)).use { input ->
                val head = ByteArray(8)
                input.readFully(head)
                val hb = ByteBuffer.wrap(head).order(ByteOrder.LITTLE_ENDIAN)
                hb.position(4)
                val n = hb.int
                val results = ArrayList<ActivityRegionResult>(n)
                val rec = ByteArray(28)
                for (i in 0 until n) {
                    input.readFully(rec)
                    val rb = ByteBuffer.wrap(rec).order(ByteOrder.LITTLE_ENDIAN)
                    rb.position(16)
                    val gran = rb.int
                    val nGran = rb.int
                    val status = rb.int
                    val region = regions.getOrNull(i) ?: continue
                    val counts = if (status == 0) ByteArray(nGran).also { input.readFully(it) } else null
                    results += ActivityRegionResult(region, gran, counts)
                }
                return ActivityScanOutcome(results, false)
            }
        } finally {
            regionsFile.delete(); outFile.delete(); cancelFile.delete()
        }
    }

    private const val ACTIVITY_STALL_MS = 120_000L
}
