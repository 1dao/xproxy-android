package app.xproxy

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Spannable
import android.text.SpannableString
import android.text.style.ForegroundColorSpan
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

class MainActivity : Activity() {

    private val VPN_REQUEST_CODE = 0x0F

    // UI 组件
    private lateinit var ipEditText: EditText
    private lateinit var portEditText: EditText
    private lateinit var userEditText: EditText
    private lateinit var passwordEditText: EditText
    private lateinit var toggleButton: Button
    private lateinit var logTextView: TextView
    private lateinit var logScrollView: ScrollView

    // 日志缓冲 - 改为存储带颜色信息的Pair
    private val logEntries = ArrayDeque<Pair<String, Int>>(1000)
    private val mainHandler = Handler(Looper.getMainLooper())
    private val logLock = Object()
    private var pendingUpdate = false

    // 监听 VPN 断开广播
    private val disconnectReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == MyVpnService.ACTION_VPN_DISCONNECTED) {
                Toast.makeText(this@MainActivity, "VPN 服务异常断开，请检查网络", Toast.LENGTH_LONG).show()
                updateButtonState()
            }
        }
    }

    companion object {
        init {
            try {
                System.loadLibrary("xproxy_native")
                Log.d("MainActivity", "Native library loaded successfully")
            } catch (e: UnsatisfiedLinkError) {
                Log.e("MainActivity", "Failed to load native library", e)
            }
        }
    }

    // Native 方法声明
    external fun nativeStartLogCallback(): Int

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // 初始化视图
        ipEditText = findViewById(R.id.etIp)
        portEditText = findViewById(R.id.etPort)
        userEditText = findViewById(R.id.etUser)
        passwordEditText = findViewById(R.id.etPassword)
        toggleButton = findViewById(R.id.btnToggleVpn)
        logTextView = findViewById(R.id.tvLog)
        logScrollView = findViewById(R.id.logScrollView)

        // 加载保存的配置
        loadConfig()

        toggleButton.setOnClickListener {
            if (MyVpnService.isServiceActuallyRunning()) {
                toggleButton.text = "启动 VPN"
                setInputsEnabled(true)
                stopVpn()
            } else {
                toggleButton.text = "关闭 VPN"
                setInputsEnabled(false)
                startVpn()
            }
        }

        // 初始化日志回调
        try {
            nativeStartLogCallback()
            addLogEntry("日志系统初始化完成", Color.GREEN)
        } catch (e: Exception) {
            Log.e("MainActivity", "Failed to init log callback", e)
            addLogEntry("日志初始化失败: ${e.message}", Color.RED)
        }
    }

    override fun onStart() {
        super.onStart()
        updateButtonState()
        val filter = IntentFilter(MyVpnService.ACTION_VPN_DISCONNECTED)
        LocalBroadcastManager.getInstance(this).registerReceiver(disconnectReceiver, filter)
    }

    override fun onResume() {
        super.onResume()
        updateButtonState()
        // 广播注册已移到onStart()中，使用LocalBroadcastManager
    }

    override fun onPause() {
        super.onPause()
        // 广播注销已移到onStop()中，使用LocalBroadcastManager
    }

    override fun onStop() {
        super.onStop()
        LocalBroadcastManager.getInstance(this).unregisterReceiver(disconnectReceiver)
    }

    // 供 Native 层调用的日志回调方法
    fun onNativeLog(level: Int, tag: String, msg: String) {
        val color = when (level) {
            2 -> Color.GRAY        // VERBOSE
            3 -> Color.GRAY        // DEBUG
            4 -> Color.GREEN       // INFO
            5 -> Color.YELLOW      // WARN
            6 -> Color.RED         // ERROR
            7 -> Color.RED         // FATAL
            else -> Color.WHITE
        }

        val levelStr = when (level) {
            2 -> "V"
            3 -> "D"
            4 -> "I"
            5 -> "W"
            6 -> "E"
            7 -> "F"
            else -> "?"
        }

        val line = "[$levelStr/$tag] $msg"
        addLogEntry(line, color)
    }

    private fun addLogEntry(line: String, color: Int) {
        synchronized(logLock) {
            logEntries.addLast(Pair(line, color))
            while (logEntries.size > 1000) {
                logEntries.removeFirst()
            }
        }

        if (!pendingUpdate) {
            pendingUpdate = true
            mainHandler.postDelayed({
                refreshLogView()
                pendingUpdate = false
            }, 100)
        }
    }

    private fun refreshLogView() {
        val entries: List<Pair<String, Int>>
        synchronized(logLock) {
            entries = logEntries.toList()
        }

        // 构建SpannableString，每一行都有独立颜色
        val fullText = entries.joinToString("\n") { it.first }
        val spannable = SpannableString(fullText)

        var pos = 0
        entries.forEach { (line, color) ->
            val start = pos
            val end = pos + line.length
            spannable.setSpan(
                ForegroundColorSpan(color),
                start,
                end,
                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE
            )
            pos = end + 1  // +1 for \n
        }

        logTextView.setText(spannable, TextView.BufferType.SPANNABLE)

        logScrollView.post {
            logScrollView.fullScroll(ScrollView.FOCUS_DOWN)
        }
    }

    private fun loadConfig() {
    }

    private fun saveConfig() {
        val prefs = getSharedPreferences(MyVpnService.PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().apply {
            putString(MyVpnService.KEY_SSH_IP, ipEditText.text.toString())
            putInt(MyVpnService.KEY_SSH_PORT, portEditText.text.toString().toIntOrNull() ?: 22)
            putString(MyVpnService.KEY_SSH_USER, userEditText.text.toString())
            apply()
        }
    }

    private fun startVpn() {
        val ip = ipEditText.text.toString()
        val port = portEditText.text.toString()
        val user = userEditText.text.toString()
        val password = passwordEditText.text.toString()

        if (ip.isBlank() || port.isBlank() || user.isBlank() || password.isBlank()) {
            Toast.makeText(this, "请填写所有配置项", Toast.LENGTH_SHORT).show()
            setInputsEnabled(true)
            return
        }

        saveConfig()

        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, VPN_REQUEST_CODE)
        } else {
            onActivityResult(VPN_REQUEST_CODE, RESULT_OK, null)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == RESULT_OK) {
                val intent = Intent(this, MyVpnService::class.java).apply {
                    action = "START"
                    putExtra(MyVpnService.KEY_SSH_IP, ipEditText.text.toString())
                    putExtra(MyVpnService.KEY_SSH_PORT, portEditText.text.toString().toIntOrNull() ?: 22)
                    putExtra(MyVpnService.KEY_SSH_USER, userEditText.text.toString())
                    putExtra(MyVpnService.KEY_SSH_PASSWORD, passwordEditText.text.toString())
                }
                startService(intent)
            } else {
                toggleButton.text = "启动 VPN"
            }
        }
    }

    private fun stopVpn() {
        val intent = Intent(this, MyVpnService::class.java).apply {
            action = "STOP"
        }
        startService(intent)
    }

    private fun updateButtonState() {
        val isRunning = MyVpnService.isServiceActuallyRunning()
        toggleButton.text = if (isRunning) "关闭 VPN" else "启动 VPN"
        setInputsEnabled(!isRunning)
    }

    private fun setInputsEnabled(enabled: Boolean) {
        ipEditText.isEnabled = enabled
        portEditText.isEnabled = enabled
        userEditText.isEnabled = enabled
        passwordEditText.isEnabled = enabled
    }
}
