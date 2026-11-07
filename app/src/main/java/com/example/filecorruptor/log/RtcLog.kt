package com.example.filecorruptor.log

import android.content.Context
import android.os.Build
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File
import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale

/**
 * App-wide logger. Every line goes to three places:
 *
 *  1. **logcat**, tag `RTCFS4A/<area>` — so `adb logcat -s RTCFS4A` (or a root
 *     `logcat` on-device) shows it live.
 *  2. A **rolling file** (`rtcfs4a.log`, rotated to `rtcfs4a.1.log` at ~512 KB),
 *     kept in the app's external files dir (`Android/data/<pkg>/files/logs`)
 *     so it can be pulled without root, falling back to internal storage.
 *  3. A small **in-memory ring** exposed as [entries] for the Logs screen.
 *
 * DEBUG lines are noisy (one per live-corruption tick) so they only reach
 * logcat and the in-memory ring unless [verboseToFile] is on.
 *
 * Safe to call before [init] (e.g. from the engine executor in unit-ish
 * contexts): it just skips the file and still logs to logcat/memory.
 */
object RtcLog {

    const val LOGCAT_TAG = "RTCFS4A"
    private const val MAX_FILE_BYTES = 512L * 1024L
    private const val MAX_MEMORY_ENTRIES = 600
    private const val MAX_READ_BYTES = 400 * 1024

    enum class Level(val letter: Char, val priority: Int) {
        DEBUG('D', Log.DEBUG),
        INFO('I', Log.INFO),
        WARN('W', Log.WARN),
        ERROR('E', Log.ERROR)
    }

    data class Entry(val timeMs: Long, val level: Level, val tag: String, val message: String) {
        fun format(): String =
            "${SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US).format(Date(timeMs))} ${level.letter}/$tag: $message"
    }

    private val lock = Any()
    private val ring = ArrayDeque<Entry>()
    private val _entries = MutableStateFlow<List<Entry>>(emptyList())
    val entries: StateFlow<List<Entry>> = _entries.asStateFlow()

    @Volatile private var dir: File? = null
    @Volatile private var handlerInstalled = false

    /** When true, DEBUG lines (live-tick details) are also written to the file. */
    @Volatile var verboseToFile: Boolean = false

    fun init(context: Context) {
        if (dir != null) return
        val app = context.applicationContext
        val base = app.getExternalFilesDir(null) ?: app.filesDir
        var logs = File(base, "logs")
        if (!logs.isDirectory && !logs.mkdirs()) {
            logs = File(app.filesDir, "logs").also { it.mkdirs() }
        }
        dir = logs
        installCrashHandler()
        i(
            "App",
            "session start — ${Build.MANUFACTURER} ${Build.MODEL}, Android ${Build.VERSION.RELEASE} " +
                "(API ${Build.VERSION.SDK_INT}), ABI ${Build.SUPPORTED_ABIS.joinToString()}"
        )
    }

    fun d(tag: String, message: String) = log(Level.DEBUG, tag, message, null)
    fun i(tag: String, message: String) = log(Level.INFO, tag, message, null)
    fun w(tag: String, message: String, t: Throwable? = null) = log(Level.WARN, tag, message, t)
    fun e(tag: String, message: String, t: Throwable? = null) = log(Level.ERROR, tag, message, t)

    fun log(level: Level, tag: String, message: String, t: Throwable?) {
        val full = if (t != null) message + "\n" + Log.getStackTraceString(t) else message
        // Logging must never be the thing that crashes the app.
        try {
            Log.println(level.priority, "$LOGCAT_TAG/$tag", full)
        } catch (_: Throwable) {
        }
        val entry = Entry(System.currentTimeMillis(), level, tag, full)
        synchronized(lock) {
            ring.addLast(entry)
            while (ring.size > MAX_MEMORY_ENTRIES) ring.removeFirst()
            _entries.value = ring.toList()
            if (level != Level.DEBUG || verboseToFile) appendToFile(entry)
        }
    }

    private fun currentFile(): File? = dir?.let { File(it, "rtcfs4a.log") }

    private fun appendToFile(entry: Entry) {
        val file = currentFile() ?: return
        try {
            if (file.length() > MAX_FILE_BYTES) {
                val old = File(file.parentFile, "rtcfs4a.1.log")
                old.delete()
                file.renameTo(old)
            }
            file.appendText(entry.format() + "\n")
        } catch (_: Exception) {
            // Out of space / storage unmounted: keep running, logcat + ring still work.
        }
    }

    /** Folder the log files live in, or null before [init]. */
    fun logDirPath(): String? = dir?.absolutePath

    /** The persisted log (previous + current file, newest last), capped so a huge file can't OOM the UI. */
    fun readPersistedText(): String {
        val d = dir ?: return ""
        return try {
            val text = listOf(File(d, "rtcfs4a.1.log"), File(d, "rtcfs4a.log"))
                .filter { it.isFile }
                .joinToString("") { it.readText() }
            if (text.length > MAX_READ_BYTES) text.substring(text.length - MAX_READ_BYTES) else text
        } catch (_: Exception) {
            ""
        }
    }

    /** Saves a standalone report (e.g. a crash dump) next to the log; returns the file or null. */
    fun saveReport(prefix: String, text: String): File? {
        val d = dir ?: return null
        return try {
            val stamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
            File(d, "${prefix}_$stamp.txt").also { it.writeText(text) }
        } catch (_: Exception) {
            null
        }
    }

    fun clear() {
        synchronized(lock) {
            ring.clear()
            _entries.value = emptyList()
            dir?.let { d ->
                File(d, "rtcfs4a.log").delete()
                File(d, "rtcfs4a.1.log").delete()
            }
        }
    }

    private fun installCrashHandler() {
        if (handlerInstalled) return
        handlerInstalled = true
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            try {
                log(Level.ERROR, "FATAL", "Uncaught exception on thread '${thread.name}' — app is going down", throwable)
            } catch (_: Throwable) {
            }
            previous?.uncaughtException(thread, throwable)
        }
    }
}
