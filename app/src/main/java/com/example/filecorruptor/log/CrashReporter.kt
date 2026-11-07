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
    val tombstone: String?
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

        val logcatCmd =
            "logcat -d -v threadtime -b crash -t 200 2>&1; echo '--- main/system, filtered ---'; " +
                "logcat -d -v threadtime -b main -b system -t 3000 2>&1 | " +
                "grep -E 'Fatal signal|DEBUG|libc|am_proc_died|am_crash|Process .* has died|$pid' | tail -n 80"
        val logcat = RootMemoryHelper.runRootShell(logcatCmd, 25_000L).trim()

        // Newest few text tombstones (skip the protobuf .pb twins), first one whose header names this pid.
        val tombCmd =
            "for f in \$(ls -t /data/tombstones/tombstone_* 2>/dev/null | grep -v '\\.pb\$' | head -n 8); do " +
                "if grep -q 'pid: $pid,' \"\$f\" 2>/dev/null; then echo \"== \$f\"; head -c 16000 \"\$f\"; break; fi; done"
        val tombRaw = RootMemoryHelper.runRootShell(tombCmd, 25_000L).trim()
        val tombstone = tombRaw.takeIf { it.isNotBlank() && !it.startsWith("ERR") }

        val match = FATAL_SIGNAL.find(tombstone.orEmpty()) ?: FATAL_SIGNAL.find(logcat)
        val signal = match?.groupValues?.get(2)
        val fault = match?.groupValues?.get(3)?.takeIf { it.startsWith("0x") }

        val summary = if (match != null) {
            "$processName (pid $pid) crashed: $signal (signal ${match.groupValues[1]})" +
                (fault?.let { ", fault address $it" } ?: "")
        } else {
            "$processName (pid $pid) is gone — no crash signature found (it may have been closed, " +
                "killed by Android's low-memory killer, or exited on its own)"
        }

        val report = CrashReport(pid, processName, signal, fault, summary, logcat, tombstone)

        RtcLog.e(TAG, summary)
        val saved = RtcLog.saveReport("crash_${processName.replace(Regex("[^A-Za-z0-9._-]"), "_")}", report.fullText())
        if (saved != null) RtcLog.i(TAG, "full crash report saved to ${saved.absolutePath}")
        // The head of the tombstone has the signal + backtrace; keep that in the main log too.
        if (tombstone != null) RtcLog.e(TAG, "tombstone (head):\n" + tombstone.take(3000))
        return report
    }
}
