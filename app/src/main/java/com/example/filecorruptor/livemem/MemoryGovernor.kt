package com.example.filecorruptor.livemem

import android.app.ActivityManager
import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * One place that decides how much memory a scan or a corruption tick may use, so the app neither hits
 * its own heap limit (OutOfMemoryError) nor squeezes the rest of the phone (other apps stuttering,
 * Android's low-memory killer waking up).
 *
 * Two limits are in play and both are respected:
 *  - the app's Java heap (hard cap, 512 MB in the logs — overrun = crash), and
 *  - the device's free RAM (soft — overrun = everything else gets slow).
 *
 * Big regions are never loaded whole: live corruption works on a *window* of the region per tick
 * ([windowBytes]); scans run natively with a fixed state budget ([analysisBudgetMb]).
 */
object MemoryGovernor {

    private const val PREFS = "rtc_memory"
    private const val MB = 1024L * 1024L

    /** Window sizes offered in the UI (MB). */
    val WINDOW_CHOICES_MB = listOf(1, 2, 4, 8, 16, 32, 64)
    private const val DEFAULT_WINDOW_MB = 8

    private val _windowMb = MutableStateFlow(DEFAULT_WINDOW_MB)
    val windowMb: StateFlow<Int> = _windowMb.asStateFlow()
    @Volatile private var loaded = false

    private fun ensureLoaded(context: Context) {
        if (loaded) return
        synchronized(this) {
            if (loaded) return
            val saved = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getInt("windowMb", DEFAULT_WINDOW_MB)
            _windowMb.value = if (saved in WINDOW_CHOICES_MB) saved else DEFAULT_WINDOW_MB
            loaded = true
        }
    }

    /** Call once at startup (and from any screen that shows the setting). */
    fun init(context: Context) = ensureLoaded(context)

    fun setWindowMb(context: Context, mb: Int) {
        ensureLoaded(context)
        val v = if (mb in WINDOW_CHOICES_MB) mb else DEFAULT_WINDOW_MB
        _windowMb.value = v
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putInt("windowMb", v).apply()
    }

    /** Free space left in this app's Java heap before OutOfMemoryError. */
    fun javaHeadroomBytes(): Long {
        val rt = Runtime.getRuntime()
        return rt.maxMemory() - (rt.totalMemory() - rt.freeMemory())
    }

    /** True when Android itself says memory is tight (the point where other apps start to suffer). */
    fun systemIsLowOnMemory(context: Context): Boolean = try {
        val am = context.applicationContext.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val info = ActivityManager.MemoryInfo()
        am.getMemoryInfo(info)
        info.lowMemory || info.availMem < info.threshold * 2
    } catch (_: Exception) {
        false
    }

    /**
     * How many bytes of a region one live-corruption tick may load. A tick holds the snapshot, the
     * engine's working copy, the patch list and the helper's copy — roughly 4-5x the window — so the
     * window is also capped to an eighth of the Java heap headroom, and shrinks hard when the
     * phone is low on memory. Always a multiple of 4096 (allocator headers stay aligned).
     */
    fun windowBytes(context: Context): Long {
        ensureLoaded(context)
        var w = _windowMb.value * MB
        w = minOf(w, javaHeadroomBytes() / 8)
        if (systemIsLowOnMemory(context)) w = minOf(w, 2 * MB)
        w = w and 4095L.inv()
        return maxOf(w, 256L * 1024)
    }

    /** State budget (MB) for the native activity scan; smaller when the phone is under pressure. */
    fun analysisBudgetMb(context: Context): Int {
        val base = 48
        if (systemIsLowOnMemory(context)) return 16
        // Half of the state comes back into the Java heap as counters — never ask for more than that can hold.
        return minOf(base.toLong(), javaHeadroomBytes() / (4 * MB) * 1).toInt().coerceAtLeast(8)
    }
}
