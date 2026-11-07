package com.example.filecorruptor.overlay

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.IBinder
import android.provider.Settings
import android.view.ContextThemeWrapper
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.SeekBar
import android.widget.Switch
import android.widget.TextView
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.example.filecorruptor.engine.ParamType
import com.example.filecorruptor.engine.ParamValue
import com.example.filecorruptor.livemem.LiveSession
import com.example.filecorruptor.livemem.RootMemoryHelper
import com.example.filecorruptor.livemem.SessionState
import com.example.filecorruptor.log.RtcLog
import com.example.filecorruptor.safety.AntiCrash
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlin.math.abs

/**
 * The "minimized mode": a small draggable window that floats above every
 * other app (an emulator, say) so the corruptor can be driven without
 * split-screen or freeform windows.
 *
 *  - Collapsed: a round "RTC" bubble. Tap to expand, drag to move.
 *  - Expanded: target/engine summary, status + tick counter, scan progress,
 *    **Corrupt** and **Live** buttons, tick-speed and intensity sliders, the
 *    anti-crash switch and the last log line. Drag it by its title bar.
 *
 * It is only a *control surface*: everything real happens in [LiveSession],
 * which keeps running on its own scope while the app's window is hidden.
 * Runs as a foreground service so Android doesn't kill the process the
 * moment the app goes to the background. Needs the "Display over other
 * apps" permission (see [ensurePermission]).
 *
 * Plain Views rather than Compose on purpose: a Service has no lifecycle
 * owner for a ComposeView, and this has to be rock solid.
 */
class OverlayService : Service() {

    companion object {
        @Volatile var isRunning: Boolean = false
            private set

        private const val CHANNEL_ID = "rtc_overlay"
        private const val NOTIFICATION_ID = 4711
        private const val ACTION_STOP = "com.example.filecorruptor.overlay.STOP"

        fun canDrawOverlays(context: Context): Boolean = Settings.canDrawOverlays(context)

        /**
         * True if the overlay may be shown. The device is rooted anyway (the
         * app needs it), so first try granting the permission through
         * `appops` instead of sending the person to Settings. Blocking.
         */
        fun ensurePermission(context: Context): Boolean {
            // Android 13+: let the "overlay is on" notification show without a runtime prompt (ignored if it fails).
            if (Build.VERSION.SDK_INT >= 33) {
                RootMemoryHelper.runRootShell("pm grant ${context.packageName} android.permission.POST_NOTIFICATIONS", 10_000L)
            }
            if (canDrawOverlays(context)) return true
            RootMemoryHelper.runRootShell("appops set ${context.packageName} SYSTEM_ALERT_WINDOW allow", 15_000L)
            return canDrawOverlays(context)
        }

        /** Intent for the system "Display over other apps" screen for this app. */
        fun permissionSettingsIntent(context: Context): Intent =
            Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:${context.packageName}"))

        fun start(context: Context) {
            ContextCompat.startForegroundService(context, Intent(context, OverlayService::class.java))
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, OverlayService::class.java))
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var windowManager: WindowManager
    private lateinit var params: WindowManager.LayoutParams
    private lateinit var ui: Context
    private var root: FrameLayout? = null

    private lateinit var bubble: TextView
    private lateinit var panel: LinearLayout
    private lateinit var statusDot: TextView
    private lateinit var infoText: TextView
    private lateinit var statusText: TextView
    private lateinit var progressLabel: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var corruptButton: Button
    private lateinit var liveButton: Button
    private lateinit var tickLabel: TextView
    private lateinit var tickSeek: SeekBar
    private lateinit var intensityRow: LinearLayout
    private lateinit var intensityLabel: TextView
    private lateinit var intensitySeek: SeekBar
    private lateinit var antiCrashSwitch: Switch
    private lateinit var logText: TextView

    private var tickDragging = false
    private var intensityDragging = false
    private var updatingAntiCrashSwitch = false
    private var intensityEngineId: String? = null
    private var intensityMin = 0.0
    private var intensityStep = 1.0
    private var intensityId: String? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        isRunning = true
        windowManager = getSystemService(WINDOW_SERVICE) as WindowManager
        ui = ContextThemeWrapper(this, android.R.style.Theme_DeviceDefault)

        startAsForeground()

        if (!canDrawOverlays(this)) {
            RtcLog.w("Overlay", "overlay permission missing — not showing the window")
            stopSelf()
            return
        }
        buildViews()
        RtcLog.i("Overlay", "overlay shown")

        scope.launch { LiveSession.state.collect { render(it) } }
        scope.launch {
            AntiCrash.config.collect { cfg ->
                updatingAntiCrashSwitch = true
                antiCrashSwitch.isChecked = cfg.enabled
                updatingAntiCrashSwitch = false
            }
        }
        scope.launch {
            RtcLog.entries.collect { list ->
                val last = list.lastOrNull { it.level != RtcLog.Level.DEBUG }
                if (last != null) logText.text = last.format()
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        // Closing the overlay also stops a running live loop: with the window
        // gone and the app hidden there would be no visible way to stop it.
        LiveSession.stop()
        scope.cancel()
        root?.let { runCatching { windowManager.removeView(it) } }
        root = null
        isRunning = false
        RtcLog.i("Overlay", "overlay closed")
        super.onDestroy()
    }

    // ------------------------------------------------------------------
    // foreground notification
    // ------------------------------------------------------------------

    private fun startAsForeground() {
        val channel = NotificationChannel(CHANNEL_ID, "RTCFS4A overlay", NotificationManager.IMPORTANCE_LOW)
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).createNotificationChannel(channel)

        val stopIntent = PendingIntent.getService(
            this, 0,
            Intent(this, OverlayService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val openIntent = packageManager.getLaunchIntentForPackage(packageName)?.let {
            PendingIntent.getActivity(this, 1, it, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        }
        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_menu_edit)
            .setContentTitle("RTCFS4A overlay is on")
            .setContentText("Tap to open the app, or stop the overlay.")
            .setOngoing(true)
            .setContentIntent(openIntent)
            .addAction(0, "Stop overlay", stopIntent)
            .build()

        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    // ------------------------------------------------------------------
    // views
    // ------------------------------------------------------------------

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density + 0.5f).toInt()

    private fun roundedBackground(color: Int, radiusDp: Int): GradientDrawable =
        GradientDrawable().apply {
            setColor(color)
            cornerRadius = dp(radiusDp).toFloat()
        }

    private fun label(text: String, sizeSp: Float = 12f, color: Int = Color.WHITE): TextView =
        TextView(ui).apply {
            this.text = text
            textSize = sizeSp
            setTextColor(color)
        }

    private fun headerButton(text: String, onClick: () -> Unit): TextView =
        label(text, 16f).apply {
            gravity = Gravity.CENTER
            setPadding(dp(10), dp(4), dp(10), dp(4))
            setOnClickListener { onClick() }
        }

    private fun actionButton(text: String, color: Int, onClick: () -> Unit): Button =
        Button(ui).apply {
            this.text = text
            textSize = 13f
            setAllCaps(false)
            setTextColor(Color.WHITE)
            minHeight = 0
            minimumHeight = 0
            setPadding(dp(8), dp(8), dp(8), dp(8))
            background = roundedBackground(color, 10)
            setOnClickListener { onClick() }
        }

    private fun buildViews() {
        val rootView = FrameLayout(ui)

        // ---- collapsed bubble ----
        bubble = label("RTC", 13f).apply {
            gravity = Gravity.CENTER
            setTypeface(typeface, Typeface.BOLD)
            background = roundedBackground(0xE6101418.toInt(), 28)
            layoutParams = FrameLayout.LayoutParams(dp(56), dp(56))
            visibility = View.GONE
        }

        // ---- expanded panel ----
        panel = LinearLayout(ui).apply {
            orientation = LinearLayout.VERTICAL
            background = roundedBackground(0xE6101418.toInt(), 14)
            setPadding(dp(10), dp(6), dp(10), dp(10))
            layoutParams = FrameLayout.LayoutParams(dp(268), FrameLayout.LayoutParams.WRAP_CONTENT)
        }

        val header = LinearLayout(ui).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        statusDot = label("●", 14f, Color.GRAY).apply { setPadding(0, 0, dp(6), 0) }
        val title = label("RTCFS4A", 14f).apply {
            setTypeface(typeface, Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        header.addView(statusDot)
        header.addView(title)
        header.addView(headerButton("—") { setExpanded(false) })
        header.addView(headerButton("⤢") { openApp() })
        header.addView(headerButton("✕") { stopSelf() })
        panel.addView(header)

        infoText = label("").apply { setPadding(0, dp(4), 0, 0) }
        statusText = label("Ready", 12f, 0xFFB8C0CC.toInt()).apply { setPadding(0, dp(2), 0, dp(4)) }
        panel.addView(infoText)
        panel.addView(statusText)

        progressLabel = label("", 11f, 0xFFB8C0CC.toInt()).apply { visibility = View.GONE }
        progressBar = ProgressBar(ui, null, android.R.attr.progressBarStyleHorizontal).apply {
            visibility = View.GONE
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(6))
        }
        panel.addView(progressLabel)
        panel.addView(progressBar)

        val buttons = LinearLayout(ui).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dp(8), 0, dp(4))
        }
        corruptButton = actionButton("⚡ Corrupt", 0xFFB3261E.toInt()) { LiveSession.corruptOnce() }
        liveButton = actionButton("▶ Live", 0xFF2E6F40.toInt()) {
            if (LiveSession.state.value.running) LiveSession.stop() else LiveSession.start()
        }
        val half = { LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f) }
        buttons.addView(corruptButton, half().apply { rightMargin = dp(4) })
        buttons.addView(liveButton, half().apply { leftMargin = dp(4) })
        panel.addView(buttons)

        // tick speed: 50..2000 ms in 10 ms steps
        tickLabel = label("Tick every 250 ms", 11f, 0xFFB8C0CC.toInt())
        tickSeek = SeekBar(ui).apply {
            max = 195
            setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                override fun onProgressChanged(sb: SeekBar?, progress: Int, fromUser: Boolean) {
                    if (fromUser) LiveSession.setTickInterval(50 + progress * 10)
                }
                override fun onStartTrackingTouch(sb: SeekBar?) { tickDragging = true }
                override fun onStopTrackingTouch(sb: SeekBar?) { tickDragging = false }
            })
        }
        panel.addView(tickLabel)
        panel.addView(tickSeek)

        // intensity: only shown when the selected engine has an "intensity" slider
        intensityRow = LinearLayout(ui).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
        }
        intensityLabel = label("Intensity", 11f, 0xFFB8C0CC.toInt())
        intensitySeek = SeekBar(ui).apply {
            setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                override fun onProgressChanged(sb: SeekBar?, progress: Int, fromUser: Boolean) {
                    if (!fromUser) return
                    val id = intensityId ?: return
                    val v = intensityMin + progress * intensityStep
                    LiveSession.values?.set(id, ParamValue.of(v))
                    intensityLabel.text = "Intensity: ${ParamValue.of(v).raw}"
                }
                override fun onStartTrackingTouch(sb: SeekBar?) { intensityDragging = true }
                override fun onStopTrackingTouch(sb: SeekBar?) { intensityDragging = false }
            })
        }
        intensityRow.addView(intensityLabel)
        intensityRow.addView(intensitySeek)
        panel.addView(intensityRow)

        antiCrashSwitch = Switch(ui).apply {
            text = "Anti-crash"
            setTextColor(Color.WHITE)
            textSize = 12f
            setOnCheckedChangeListener { _, checked ->
                if (!updatingAntiCrashSwitch) AntiCrash.update(AntiCrash.current().copy(enabled = checked))
            }
        }
        panel.addView(antiCrashSwitch, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = dp(6) })

        logText = label("", 10f, 0xFF8A93A0.toInt()).apply {
            maxLines = 2
            typeface = Typeface.MONOSPACE
            setPadding(0, dp(6), 0, 0)
        }
        panel.addView(logText)

        rootView.addView(bubble)
        rootView.addView(panel)

        params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            // Never take focus: the emulator underneath must keep receiving the keyboard/controller input.
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.START
            x = dp(12)
            y = dp(96)
        }

        attachDrag(header, null)
        attachDrag(bubble) { setExpanded(true) }

        root = rootView
        windowManager.addView(rootView, params)
        setExpanded(true)
    }

    private fun setExpanded(expanded: Boolean) {
        panel.visibility = if (expanded) View.VISIBLE else View.GONE
        bubble.visibility = if (expanded) View.GONE else View.VISIBLE
    }

    /** Drag the whole overlay by [handle]; a touch that barely moves counts as a tap ([onTap]). */
    private fun attachDrag(handle: View, onTap: (() -> Unit)?) {
        var downX = 0f
        var downY = 0f
        var startX = 0
        var startY = 0
        var moved = false
        val slop = dp(6)
        handle.setOnTouchListener { _, e ->
            when (e.action) {
                MotionEvent.ACTION_DOWN -> {
                    downX = e.rawX; downY = e.rawY
                    startX = params.x; startY = params.y
                    moved = false
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    val dx = e.rawX - downX
                    val dy = e.rawY - downY
                    if (abs(dx) > slop || abs(dy) > slop) moved = true
                    if (moved) {
                        params.x = startX + dx.toInt()
                        params.y = startY + dy.toInt()
                        root?.let { runCatching { windowManager.updateViewLayout(it, params) } }
                    }
                    true
                }
                MotionEvent.ACTION_UP -> {
                    if (!moved) onTap?.invoke()
                    true
                }
                else -> false
            }
        }
    }

    private fun openApp() {
        // Allowed from the background because the app holds the overlay permission.
        packageManager.getLaunchIntentForPackage(packageName)?.let {
            it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED)
            startActivity(it)
        }
    }

    // ------------------------------------------------------------------
    // state -> views
    // ------------------------------------------------------------------

    private fun render(s: SessionState) {
        statusDot.setTextColor(
            when {
                s.running -> 0xFF4CAF50.toInt()
                s.message != null && s.isError -> 0xFFE57373.toInt()
                else -> Color.GRAY
            }
        )
        infoText.text = if (s.targetCount == 0) {
            "No targets — pick them in the app (Live RAM tab)."
        } else {
            "${s.targetCount} target${if (s.targetCount == 1) "" else "s"} · ${s.engineName ?: "no engine"}"
        }
        statusText.text = when {
            s.running -> "LIVE · tick ${s.ticks}"
            s.busy -> "Working…"
            else -> s.message ?: "Ready"
        }
        statusText.setTextColor(if (!s.running && s.isError) 0xFFE57373.toInt() else 0xFFB8C0CC.toInt())

        val label = s.progressLabel
        if (label == null) {
            progressLabel.visibility = View.GONE
            progressBar.visibility = View.GONE
        } else {
            progressLabel.visibility = View.VISIBLE
            progressBar.visibility = View.VISIBLE
            if (s.progressTotal > 0) {
                progressBar.isIndeterminate = false
                progressBar.max = s.progressTotal
                progressBar.progress = s.progressDone
                progressLabel.text = "$label ${s.progressDone}/${s.progressTotal}"
            } else {
                progressBar.isIndeterminate = true
                progressLabel.text = "$label…"
            }
        }

        corruptButton.isEnabled = !s.busy && !s.running && s.targetCount > 0
        corruptButton.alpha = if (corruptButton.isEnabled) 1f else 0.45f
        liveButton.text = if (s.running) "■ Stop" else "▶ Live"
        liveButton.background = roundedBackground(if (s.running) 0xFF8A5A00.toInt() else 0xFF2E6F40.toInt(), 10)
        liveButton.isEnabled = s.targetCount > 0 || s.running
        liveButton.alpha = if (liveButton.isEnabled) 1f else 0.45f

        tickLabel.text = "Tick every ${s.tickIntervalMs} ms"
        if (!tickDragging) tickSeek.progress = ((s.tickIntervalMs - 50) / 10).coerceIn(0, 195)

        bindIntensity()
    }

    /** Shows an intensity slider if the current engine declares a slider parameter called "intensity". */
    private fun bindIntensity() {
        val engine = LiveSession.engine
        val values = LiveSession.values
        val def = engine?.parameters?.firstOrNull { it.id == "intensity" && it.type == ParamType.SLIDER }
        if (engine == null || values == null || def == null || def.step <= 0.0 || def.max <= def.min) {
            intensityRow.visibility = View.GONE
            intensityId = null
            intensityEngineId = null
            return
        }
        intensityRow.visibility = View.VISIBLE
        intensityId = def.id
        intensityMin = def.min
        intensityStep = def.step
        if (intensityEngineId != engine.id) {
            intensityEngineId = engine.id
            intensitySeek.max = ((def.max - def.min) / def.step).toInt().coerceAtLeast(1)
        }
        if (!intensityDragging) {
            val current = values[def.id]?.asDouble() ?: def.default.toDoubleOrNull() ?: def.min
            intensitySeek.progress = ((current - def.min) / def.step).toInt().coerceIn(0, intensitySeek.max)
            intensityLabel.text = "Intensity: ${ParamValue.of(current).raw}${def.unit}"
        }
    }
}
