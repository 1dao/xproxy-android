package app.xproxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Looper
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import android.util.Log
import java.io.IOException
import android.os.PowerManager

class MyVpnService : VpnService() {

    companion object {
        private const val TAG = "XProxyService"

        // 公共常量：供 Activity 和 Service 共享
        const val ACTION_VPN_DISCONNECTED = "app.xproxy.VPN_DISCONNECTED"
        const val PREFS_NAME = "xproxy_prefs"
        const val KEY_SSH_IP = "ssh_ip"
        const val KEY_SSH_PORT = "ssh_port"
        const val KEY_SSH_USER = "ssh_user"
        const val KEY_SSH_PASSWORD = "ssh_password" // 注意：密码仅作传递，不建议持久化明文

        @Volatile
        var isRunning = false

        // Native 方法
        external fun isNativeThreadRunning(): Boolean

        fun isServiceActuallyRunning(): Boolean {
            return try {
                // 如果 native 线程已死，同步 Java 状态
                if (!isNativeThreadRunning()) {
                    isRunning = false
                }
                isRunning
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Native function not available", e)
                isRunning
            } catch (e: Throwable) {
                Log.e(TAG, "Unexpected error checking native status", e)
                isRunning
            }
        }

        init {
            try {
                System.loadLibrary("xproxy_native")
                Log.d(TAG, "Native library loaded successfully")
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Failed to load native library", e)
            }
        }

        private const val VPN_IP = "10.0.0.2"
        private const val PAC_URL = "http://127.0.0.1:7890/proxy.pac"
        private const val PAC_CONFIG_FILE = "pac_config.txt"

        fun getPacConfigPath(context: android.content.Context): String {
            val file = java.io.File(context.filesDir, PAC_CONFIG_FILE)
            if (!file.exists()) {
                try {
                    context.assets.open(PAC_CONFIG_FILE).use { input ->
                        java.io.FileOutputStream(file).use { output ->
                            input.copyTo(output)
                        }
                    }
                    Log.d(TAG, "Copied $PAC_CONFIG_FILE to ${file.absolutePath}")
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to copy $PAC_CONFIG_FILE", e)
                }
            }
            return file.absolutePath
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var tunFd: Int = -1
    private val CHANNEL_ID = "XProxyVpnServiceChannel"
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        when {
            action == "START" -> {
                val notification = createForegroundNotification("正在连接...", "正在建立 SSH 隧道")
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
                } else {
                    startForeground(1, notification)
                }

                val ip = intent.getStringExtra(KEY_SSH_IP)?.trim()?.trimEnd(':') ?: ""
                val port = intent.getIntExtra(KEY_SSH_PORT, 22)
                val user = intent.getStringExtra(KEY_SSH_USER)?.trim() ?: ""
                val password = intent.getStringExtra(KEY_SSH_PASSWORD) ?: ""

                Log.d(TAG, "启动服务: $user@$ip:$port")

                // 保存配置（备份，主要配置由 Activity 管理）
                getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit().apply {
                    putString(KEY_SSH_IP, ip)
                    putInt(KEY_SSH_PORT, port)
                    putString(KEY_SSH_USER, user)
                    apply()
                }

                setupVpnTunnel(ip, port, user, password)
            }
            action == "STOP" -> {
                stopVpnInternal()
            }
            // action == null -> {
            //     stopSelf()
            // }
        }
        return START_STICKY
    }

    private fun setupVpnTunnel(ip: String, port: Int, user: String, password: String) {
        // just for keep process alive
        val builder = Builder()
            .setSession("XProxy")
            .addAddress("10.0.0.2", 24)
            .addDnsServer("8.8.8.8")
            // .addRoute("1.1.1.1", 32)  // 全局路由
            .setMtu(1500)
            .setBlocking(false)

        vpnInterface = builder.establish()
        tunFd = vpnInterface?.fd ?: -1

        if (tunFd < 0) {
            Log.e(TAG, "TUN 接口建立失败")
            stopSelf()
            return
        }

        Log.d(TAG, "TUN 接口建立成功, fd=$tunFd")

        val pacConfigPath = getPacConfigPath(this)
        Log.d(TAG, "PAC config path: $pacConfigPath")

        // 读取 PAC 内容用于调试
        try {
            val content = java.io.File(pacConfigPath).readText()
            Log.d(TAG, "PAC 内容预览: ${content.take(100)}...")
        } catch (e: Exception) {
            Log.e(TAG, "读取 PAC 文件失败", e)
        }

        // 启动 Native 代理
        val result = startSshProxyNative(-1, ip, port, user, password, 1080, 7890, pacConfigPath)
        if (result != 0) {
            Log.e(TAG, "startSshProxyNative 启动失败，返回值: $result")
            isRunning = false
            stopSelf()
            return
        }

        try {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager?
            wakeLock = pm?.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                "xproxy:ssh_tunnel"
            )?.apply {
                setReferenceCounted(false)
                acquire(12*60*60*1000L)
            }
        } catch (e: SecurityException) {
            Log.e(TAG, "无法获取WakeLock: ${e.message}")
        } catch (e: Exception) {
            Log.e(TAG, "获取WakeLock失败: ${e.message}")
        }
        wakeLock?.setReferenceCounted(false)
        wakeLock?.acquire(12 * 60 * 60 * 1000L)
        if (wakeLock?.isHeld != true) {
            Log.e(TAG, "❌ WakeLock 未能持有，后台会被挂起！")
        }
        Log.d(TAG, "WakeLock acquired: ${wakeLock?.isHeld}")

        isRunning = true
        Log.d(TAG, "startSshProxyNative 启动成功")

        // 更新通知状态
        updateNotification("VPN 服务运行中", "已连接至 $ip:$port")
    }

    private fun stopVpnInternal() {
        Log.d(TAG, "停止服务")
        isRunning = false
        stopSshProxyNative()
        // 一直等待，直到线程返回
        while (isNativeThreadRunning()) {
            Thread.sleep(1500)
        }

        try {
            wakeLock?.takeIf { it.isHeld }?.release()
        } catch (e: Exception) {
            Log.e(TAG, "释放WakeLock失败: ${e.message}")
        }
        wakeLock = null

        cleanupVpnTunnel()

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun cleanupVpnTunnel() {
        try {
            vpnInterface?.close()
            vpnInterface = null
            Log.d(TAG, "VPN 隧道已关闭")
        } catch (e: IOException) {
            Log.e(TAG, "关闭 VPN 隧道失败", e)
        }
    }

    // --- 通知相关 ---
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "XProxy VPN Service",
                NotificationManager.IMPORTANCE_HIGH
            )
            val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }
    }

    private fun createForegroundNotification(title: String, content: String): Notification {
        val notificationIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, notificationIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(content)
            .setSmallIcon(android.R.drawable.ic_menu_view)
            .setContentIntent(pendingIntent)
            .build()
    }

    private fun updateNotification(title: String, content: String) {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(1, createForegroundNotification(title, content))
    }

    // --- Native 方法声明 ---
    private external fun startSshProxyNative(
        tunFd: Int,
        host: String,
        port: Int,
        user: String,
        pass: String,
        socksPort: Int,
        httpPort: Int,
        pacFile: String,
    ): Int

    private external fun stopSshProxyNative(): Int

    fun onSshDisconnected() {
        Log.d(TAG, "Native回调：SSH连接已断开")
        if (isRunning) {
            val intent = Intent(ACTION_VPN_DISCONNECTED)
            LocalBroadcastManager.getInstance(this).sendBroadcast(intent)
            stopSelf()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        isRunning = false
        Log.d(TAG, "VPN 服务已销毁")
    }
}
