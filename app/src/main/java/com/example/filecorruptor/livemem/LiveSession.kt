package com.example.filecorruptor.livemem

import android.content.Context
import com.example.filecorruptor.engine.EngineDefinition
import com.example.filecorruptor.engine.ParamValue
import com.example.filecorruptor.log.RtcLog
import com.example.filecorruptor.safety.AntiCrash
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** One process + one memory region of it that gets corrupted. */
data class LiveTarget(val process: LiveProcess, val region: MemoryRegion)

/** Everything a UI (the Live RAM screen *or* the floating overlay) needs to show. */
data class SessionState(
    val running: Boolean = false,
    val busy: Boolean = false,
    val ticks: Int = 0,
    val tickIntervalMs: Int = 250,
    val targetCount: Int = 0,
    val engineName: String? = null,
    /** Latest result/status text, with [isError] and a [messageSeq] that changes on every new message (even identical text). */
    val message: String? = null,
    val isError: Boolean = false,
    val messageSeq: Long = 0,
    /** Long-running scan progress; null label = nothing running. [progressTotal] 0 = indeterminate. */
    val progressLabel: String? = null,
    val progressDone: Int = 0,
    val progressTotal: Int = 0
)

/**
 * The live-corruption "session": targets, engine, the Corrupt-Once action and
 * the Live loop. It lives in the process, not in a Compose screen, for one
 * reason: the floating overlay has to drive it while the app's window is
 * hidden. A stopped Activity's composition stops recomposing, so a loop that
 * was started by a `LaunchedEffect` inside the screen could never be started
 * (or stopped) from the overlay. Here the loop runs on its own coroutine
 * scope and both UIs are just controls over the same [state].
 *
 * Thread-safe; the setters can be called from any thread.
 */
object LiveSession {

    private const val TAG = "Session"

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val cycleMutex = Mutex()
    private var loopJob: Job? = null

    private val _state = MutableStateFlow(SessionState())
    val state: StateFlow<SessionState> = _state.asStateFlow()

    private val _targets = MutableStateFlow<List<LiveTarget>>(emptyList())
    val targetsFlow: StateFlow<List<LiveTarget>> = _targets.asStateFlow()
    val targets: List<LiveTarget> get() = _targets.value

    @Volatile private var appContext: Context? = null

    /** The selected engine and its live (Compose-observable) parameter values. */
    @Volatile var engine: EngineDefinition? = null
        private set
    @Volatile var values: MutableMap<String, ParamValue>? = null
        private set

    fun setTargets(list: List<LiveTarget>) {
        if (_targets.value == list) return
        _targets.value = list
        _state.update { it.copy(targetCount = list.size) }
    }

    fun setEngine(context: Context, engine: EngineDefinition?, values: MutableMap<String, ParamValue>?) {
        appContext = context.applicationContext
        this.engine = engine
        this.values = values
        val name = engine?.name
        if (_state.value.engineName != name) _state.update { it.copy(engineName = name) }
    }

    fun setTickInterval(ms: Int) {
        val clamped = ms.coerceIn(50, 2000)
        if (_state.value.tickIntervalMs != clamped) _state.update { it.copy(tickIntervalMs = clamped) }
    }

    // ---- scan progress (shown in the overlay) ----

    fun setProgress(label: String, done: Int, total: Int) {
        _state.update { it.copy(progressLabel = label, progressDone = done, progressTotal = total) }
    }

    fun clearProgress() {
        if (_state.value.progressLabel != null) {
            _state.update { it.copy(progressLabel = null, progressDone = 0, progressTotal = 0) }
        }
    }

    fun setMessage(text: String, isError: Boolean) {
        _state.update { it.copy(message = text, isError = isError, messageSeq = it.messageSeq + 1) }
    }

    // ---- actions ----

    /** One pass over every target. Ignored while the live loop runs or another pass is in flight. */
    fun corruptOnce() {
        val s = _state.value
        if (s.running || s.busy) return
        if (!hasWork()) return
        scope.launch {
            cycleMutex.withLock {
                _state.update { it.copy(busy = true) }
                try {
                    val r = runCycle()
                    if (r.deadPids.isNotEmpty()) removeTargets(r.deadPids)
                    setMessage(
                        when {
                            r.failed == 0 -> "Corrupted all ${r.succeeded} target(s) once."
                            r.succeeded == 0 -> r.lastError ?: "All ${r.failed} target(s) failed."
                            else -> "Corrupted ${r.succeeded}, failed ${r.failed}" + (r.lastError?.let { " — $it" } ?: "")
                        },
                        isError = r.failed > 0
                    )
                } finally {
                    _state.update { it.copy(busy = false) }
                }
            }
        }
    }

    fun start() {
        if (_state.value.running) return
        if (!hasWork()) return
        val eng = engine
        RtcLog.i(TAG, "live corrupting STARTED: engine=${eng?.id} targets=${targets.size} tick=${_state.value.tickIntervalMs}ms")
        values?.let { v ->
            val params = v.entries.joinToString(", ") { "${it.key}=${it.value.raw}" }.take(600)
            RtcLog.i(TAG, "params=[$params]")
        }
        targets.forEach { t ->
            RtcLog.i(
                TAG,
                "target ${t.process.name} pid=${t.process.pid} 0x${t.region.start.toString(16)}-" +
                    "0x${t.region.end.toString(16)} ${t.region.perms} ${t.region.path}"
            )
        }
        _state.update { it.copy(running = true, ticks = 0) }
        loopJob = scope.launch {
            while (true) {
                val keepGoing = cycleMutex.withLock { tickOnce() }
                if (!keepGoing) break
                delay(_state.value.tickIntervalMs.toLong())
            }
        }
    }

    fun stop() {
        loopJob?.cancel()
        loopJob = null
        if (_state.value.running) {
            RtcLog.i(TAG, "live corrupting stopped after ${_state.value.ticks} tick(s)")
            _state.update { it.copy(running = false) }
            setMessage("Live corrupting stopped after ${_state.value.ticks} tick(s).", isError = false)
        }
    }

    // ---- internals ----

    private fun hasWork(): Boolean {
        val problem = when {
            engine == null || values == null -> "Pick an engine first."
            targets.isEmpty() -> "Add at least one target (process + region) in the Live RAM tab first."
            appContext == null -> "The app isn't ready yet — open the Live RAM tab once."
            else -> null
        }
        if (problem != null) setMessage(problem, isError = true)
        return problem == null
    }

    private fun removeTargets(deadPids: Set<Int>) {
        setTargets(targets.filterNot { it.process.pid in deadPids })
    }

    private fun finishWithMessage(text: String, isError: Boolean) {
        _state.update { it.copy(running = false) }
        setMessage(text, isError)
    }

    /** One live tick. Returns false when the loop should end. */
    private fun tickOnce(): Boolean {
        val r = runCycle()
        val ticks = _state.value.ticks
        if (r.deadPids.isNotEmpty()) {
            removeTargets(r.deadPids)
            // Stop right away so we never keep hammering a relaunched process
            // (new pid, new addresses) with stale targets.
            if (AntiCrash.current().stopOnCrash || targets.isEmpty()) {
                RtcLog.e(TAG, "stopped after $ticks tick(s): target died — ${r.lastError}")
                finishWithMessage("Live corrupting stopped after $ticks tick(s) — ${r.lastError}. Details in the Logs tab.", true)
                return false
            }
        }
        if (r.succeeded == 0) {
            val why = r.lastError ?: "no targets left"
            RtcLog.w(TAG, "stopped after $ticks tick(s): every target failed — $why")
            finishWithMessage("Live corrupting stopped — $why", r.failed > 0)
            return false
        }
        _state.update { it.copy(ticks = it.ticks + 1) }
        return true
    }

    private class CycleResult(val succeeded: Int, val failed: Int, val lastError: String?, val deadPids: Set<Int>)

    /**
     * One pass over every target. One target's failure (OOM on a huge region,
     * process exited, ...) never stops the others.
     */
    private fun runCycle(): CycleResult {
        val ctx = appContext
        val eng = engine
        val vals = values
        val current = targets
        if (ctx == null || eng == null || vals == null || current.isEmpty()) {
            return CycleResult(0, 0, "no targets or engine", emptySet())
        }
        val snapshot = vals.toMap()
        var succeeded = 0
        var failed = 0
        var lastError: String? = null
        var lastSeed: Long? = null
        val dead = mutableSetOf<Int>()
        for (t in current) {
            try {
                lastSeed = LiveCorruptor.corruptTarget(ctx, t.process, t.region, eng, snapshot).seedUsed
                succeeded++
            } catch (e: Throwable) { // includes OutOfMemoryError: one huge region must not kill the loop
                failed++
                if (e is LiveCorruptor.TargetDiedException) dead += t.process.pid
                lastError = when (e) {
                    is OutOfMemoryError ->
                        "out of memory on ${t.process.name} (${t.region.size / 1_048_576} MB) — too large to hold twice at once"
                    else -> e.message ?: e.toString()
                }
                RtcLog.w(TAG, "${t.process.name}: $lastError")
            }
        }
        lastSeed?.let { seed ->
            if (vals.containsKey("lastSeedUsed")) vals["lastSeedUsed"] = ParamValue.of(seed.toString())
        }
        return CycleResult(succeeded, failed, lastError, dead)
    }
}
