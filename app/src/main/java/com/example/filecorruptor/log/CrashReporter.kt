package com.example.filecorruptor.log

import android.content.Context
import com.example.filecorruptor.livemem.ProcState
import com.example.filecorruptor.livemem.RootMemoryHelper

/** What we could learn about why a corruption target went away. */
data class CrashReport(
    val pid: Int,
    val processName: String,
    /** e.g. "SIGSEGV", or null if no fatal-signal line was found. */
    val signal: String?,
    /** e.g. "0x7f12345678", or null. */
    val faultAddress: String?,
    /** One human-readable line, safe to show in a status card. */
    val summary: String,
    val logcat: String,
    val tombstone: String?,
    /** The allocator/libc abort message, e.g. "Scudo ERROR: corrupted chunk header ...", or null. */
    val abortMessage: String? = null,
    /** True when the process aborted because the heap allocator found its own metadata overwritten. */
    val heapCorruption: Boolean = false
) {
    /** The whole thing as one text blob (for the log file / share). */
    fun fullText(): String = buildString {
        appendLine("=== $summary ===")
        if (tombstone != null) {
            appendLine("--- tombstone ---")
            appendLine(tombstone)
        }
        appendLine("--- logcat (crash buffer + fatal-signal lines) ---")
        appendLine(logcat.ifBlank { "(nothing captured)" })
    }
}

/**
 * Pulls crash evidence for a process that died while we were corrupting it.
 *
 * This app already runs everything through `su`, so — unlike a normal app,
 * which can only see its own logcat — it can read the *whole* device's crash
 * buffer and `/data/tombstones`, which is where a native crash (SIGSEGV,
 * SIGABRT, SIGBUS... the usual result of corrupted memory) is recorded.
 */
object CrashReporter {

    private const val TAG = "Crash"

    // Matches both the logcat form ("Fatal signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x...")
    // and the tombstone form ("signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x...").
    private val FATAL_SIGNAL =
        Regex("(?:Fatal signal|signal) (\\d+) \\((\\w+)\\)[^\\n]*?fault addr (0x[0-9a-fA-F]+|-+)")

    private val ABORT_MESSAGE = Regex("Abort message: '(.*)'")
    private val DEBUG_LINE = Regex("^\\S+\\s+\\S+\\s+\\d+\\s+\\d+\\s+[A-Z]\\s+DEBUG\\s*:")

    private fun isHeapAbort(message: String?): Boolean =
        message != null && (message.contains("Scudo ERROR") || message.contains("corrupted chunk header"))

    /** Does this logcat (threadtime) line belong to [pid] — by its own pid column or by naming it? */
    private fun mentionsPid(line: String, pid: Int): Boolean {
        val cols = line.trim().split(Regex("\\s+"), limit = 6)
        if (cols.size >= 5 && cols[2] == pid.toString()) return true
        return line.contains("pid: $pid,") || line.contains("pid $pid)") || line.contains("pid=$pid ") ||
            line.contains("($pid)") || line.contains(" $pid,")
    }

    /**
     * The device-wide crash buffer keeps *old* crashes of other processes — and of earlier
     * incarnations of this one. Reading it unfiltered is how a process that was merely closed got
     * reported as "crashed: SIGABRT" from someone else's stale tombstone lines. Keeps only lines
     * about [pid] (plus whole `DEBUG` tombstone blocks whose header names it). Returns the kept
     * text and how many unrelated lines were dropped.
     */
    internal fun filterForPid(text: String, pid: Int): Pair<String, Int> {
        val lines = text.lines()
        val keep = BooleanArray(lines.size)
        for (i in lines.indices) if (mentionsPid(lines[i], pid)) keep[i] = true
        var i = 0
        while (i < lines.size) {
            if (!DEBUG_LINE.containsMatchIn(lines[i])) { i++; continue }
            var j = i
            var mine = false
            while (j < lines.size && DEBUG_LINE.containsMatchIn(lines[j])) {
                if (lines[j].contains("pid: $pid,")) mine = true
                j++
            }
            if (mine) for (k in i until j) keep[k] = true
            i = j
        }
        var omitted = 0
        val kept = ArrayList<String>()
        for (k in lines.indices) {
            val l = lines[k]
            when {
                keep[k] || l.startsWith("---") -> kept += l
                l.isNotBlank() -> omitted++
            }
        }
        return kept.joinToString("\n") to omitted
    }

    /**
     * Waits (up to ~3 s) for a process that stopped answering to settle into
     * a definite state. A crashing process is briefly *stopped* while
     * tombstoned dumps it, so STOPPED is polled rather than trusted.
     */
    fun awaitState(context: Context, pid: Int, name: String): ProcState {
        var state = RootMemoryHelper.processState(context, pid, name)
        var tries = 0
        while (state == ProcState.STOPPED && tries < 12) {
            Thread.sleep(250)
            state = RootMemoryHelper.processState(context, pid, name)
            tries++
        }
        return state
    }

    /**
     * Not tied to one pid: the device's recent native-crash log plus the
     * newest tombstone. For the Logs screen's "collect crash logs" button —
     * handy when the target died while the live loop wasn't running.
     * Blocking; call from Dispatchers.IO.
     */
    fun collectRecent(): String {
        val logcat = RootMemoryHelper.runRootShell("logcat -d -v threadtime -b crash -t 300 2>&1", 25_000L).trim()
        val tomb = RootMemoryHelper.runRootShell(
            "f=\$(ls -t /data/tombstones/tombstone_* 2>/dev/null | grep -v '\\.pb\$' | head -n 1); " +
                "if [ -n \"\$f\" ]; then echo \"== \$f\"; head -c 16000 \"\$f\"; fi",
            25_000L
        ).trim()
        val text = buildString {
            appendLine("--- logcat crash buffer (newest last) ---")
            appendLine(logcat.ifBlank { "(empty — no native crash recorded since the buffer was last cleared)" })
            appendLine()
            appendLine("--- newest tombstone ---")
            appendLine(tomb.ifBlank { "(none readable)" })
        }
        RtcLog.saveReport("crashlog", text)?.let { RtcLog.i(TAG, "collected device crash log -> ${it.absolutePath}") }
        return text
    }

    /** Blocking; call from Dispatchers.IO. Also writes the report to the log + a report file. */
    fun collect(context: Context, pid: Int, processName: String): CrashReport {
        // debuggerd/tombstoned finish writing the tombstone a moment after the process dies.
        runCatching { Thread.sleep(800) }

        val rawCrash = RootMemoryHelper.runRootShell("logcat -d -v threadtime -b crash -t 600 2>&1", 25_000L)
        val rawMain = RootMemoryHelper.runRootShell(
            "logcat -d -v threadtime -b main -b system -t 4000 2>&1 | " +
                "grep -E 'Fatal signal|DEBUG|libc|am_proc_died|am_crash|Process .* has died|$pid' | tail -n 400",
            25_000L
        )
        val (crashPart, omittedA) = filterForPid(rawCrash, pid)
        val (mainPart, omittedB) = filterForPid(rawMain, pid)
        val omitted = omittedA + omittedB
        val logcat = buildString {
            appendLine(crashPart.trim().ifBlank { "(no crash-buffer lines for pid $pid)" })
            appendLine("--- main/system, filtered to pid $pid ---")
            appendLine(mainPart.trim())
            if (omitted > 0) appendLine("($omitted unrelated log line(s) from other processes / older crashes omitted)")
        }.trim()

        // Newest few text tombstones (skip the protobuf .pb twins), first one whose header names this pid.
        val tombCmd =
            "for f in \$(ls -t /data/tombstones/tombstone_* 2>/dev/null | grep -v '\\.pb\$' | head -n 8); do " +
                "if grep -q 'pid: $pid,' \"\$f\" 2>/dev/null; then echo \"== \$f\"; head -c 16000 \"\$f\"; break; fi; done"
        val tombRaw = RootMemoryHelper.runRootShell(tombCmd, 25_000L).trim()
        val tombstone = tombRaw.takeIf { it.isNotBlank() && !it.startsWith("ERR") }

        val match = FATAL_SIGNAL.find(tombstone.orEmpty()) ?: FATAL_SIGNAL.find(logcat)
        val signal = match?.groupValues?.get(2)
        val fault = match?.groupValues?.get(3)?.takeIf { it.startsWith("0x") }

        val abortMessage = (ABORT_MESSAGE.find(tombstone.orEmpty()) ?: ABORT_MESSAGE.find(logcat))?.groupValues?.get(1)
        val heapCorruption = isHeapAbort(abortMessage)

        val summary = if (match != null) {
            "$processName (pid $pid) crashed: $signal (signal ${match.groupValues[1]})" +
                (fault?.let { ", fault address $it" } ?: "") +
                (if (heapCorruption) " — heap allocator aborted on an overwritten chunk header" else "")
        } else {
            "$processName (pid $pid) is gone — no crash signature found (it may have been closed, " +
                "killed by Android's low-memory killer, or exited on its own)"
        }

        val report = CrashReport(pid, processName, signal, fault, summary, logcat, tombstone, abortMessage, heapCorruption)

        RtcLog.e(TAG, summary)
        val saved = RtcLog.saveReport("crash_${processName.replace(Regex("[^A-Za-z0-9._-]"), "_")}", report.fullText())
        if (saved != null) RtcLog.i(TAG, "full crash report saved to ${saved.absolutePath}")
        // The head of the tombstone has the signal + backtrace; keep that in the main log too.
        if (tombstone != null) RtcLog.e(TAG, "tombstone (head):\n" + tombstone.take(3000))
        return report
    }
}
