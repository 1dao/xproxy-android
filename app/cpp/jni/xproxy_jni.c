#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <malloc.h>
#include <android/log.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/resource.h>
#include "main.h"

#define LOG_TAG "xproxy_jni"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

static void sig_handler(int sig) {
    LOGE("!!! Signal %d received, native code crashed !!!", sig);
    _exit(1);
}

void native_notify_ssh_disconnected();

static char g_pac_config_path[512] = "pac_config.txt";

static pthread_t xproxy_thread_id = 0;

// 日志回调相关
static JavaVM* g_vm = NULL;
static jobject g_callback_obj = NULL;  // MainActivity 实例
static jmethodID g_log_method = NULL;   // onNativeLog 方法 ID

// SSH 断开回调相关
static jobject g_service_obj = NULL;    // MyVpnService 实例
static jmethodID g_on_disconnect_method = NULL;  // onSshDisconnected 方法 ID

pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_service_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int tun_fd;
    char *host;
    int port;
    char *user;
    char *pass;
    int socks_port;
    int http_port;
    int vpn_mode;
    char *pac_config_path;
} XProxyArgs;

extern int xproxy_main(int argc, char *argv[]);

// 初始化 JNI 回调（在启动时调用）
static void init_log_callback(JNIEnv* env, jobject thiz) {
    pthread_mutex_lock(&g_log_mutex);

    // 保存 JVM 引用
    if (g_vm == NULL) {
        (*env)->GetJavaVM(env, &g_vm);
    }

    // 删除旧的引用
    if (g_callback_obj != NULL) {
        (*env)->DeleteGlobalRef(env, g_callback_obj);
        g_callback_obj = NULL;
    }

    // 创建新的全局引用
    if (thiz != NULL) {
        g_callback_obj = (*env)->NewGlobalRef(env, thiz);

        // 获取 MainActivity 类和方法
        jclass clazz = (*env)->GetObjectClass(env, thiz);
        g_log_method = (*env)->GetMethodID(env, clazz, "onNativeLog", "(ILjava/lang/String;Ljava/lang/String;)V");
        (*env)->DeleteLocalRef(env, clazz);

        LOGI("Log callback initialized");
    }

    pthread_mutex_unlock(&g_log_mutex);
}

// 清理 JNI 回调
static void cleanup_log_callback(JNIEnv* env) {
    pthread_mutex_lock(&g_log_mutex);

    if (g_callback_obj != NULL) {
        (*env)->DeleteGlobalRef(env, g_callback_obj);
        g_callback_obj = NULL;
    }
    g_log_method = NULL;

    pthread_mutex_unlock(&g_log_mutex);
}

// Native 层调用的日志函数
// 注意：此函数只负责将日志发送到 Java 层 UI，logcat 输出由 xlog.h 宏中的 __android_log_print 处理
void native_log_to_java(int level, const char* tag, const char* msg) {
    if (g_vm == NULL || g_callback_obj == NULL || g_log_method == NULL) {
        // 没有回调，直接返回（logcat 已由宏输出）
        return;
    }

    JNIEnv* env = NULL;
    int need_detach = 0;

    // 获取当前线程的 JNIEnv
    jint get_env_result = (*g_vm)->GetEnv(g_vm, (void**)&env, JNI_VERSION_1_6);
    if (get_env_result == JNI_EDETACHED) {
        // 当前线程未附加到 JVM
        if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != 0) {
            return;  // 无法附加，直接返回（logcat 已由宏输出）
        }
        need_detach = 1;
    } else if (get_env_result != JNI_OK || env == NULL) {
        return;  // 无法获取 JNIEnv，直接返回（logcat 已由宏输出）
    }

    // 调用 Java 方法
    jstring jtag = (*env)->NewStringUTF(env, tag ? tag : "xproxy");
    jstring jmsg = (*env)->NewStringUTF(env, msg ? msg : "");

    (*env)->CallVoidMethod(env, g_callback_obj, g_log_method, (jint)level, jtag, jmsg);

    (*env)->DeleteLocalRef(env, jtag);
    (*env)->DeleteLocalRef(env, jmsg);

    // 如果需要，分离线程
    if (need_detach) {
        (*g_vm)->DetachCurrentThread(g_vm);
    }
}

void* run_xproxy_thread(void* arg) {
    xproxy_thread_id = pthread_self();
    // nice(-10);
    setpriority(PRIO_PROCESS, 0, -8);

    // First line - should always execute
    fprintf(stderr, ">>> run_xproxy_thread ENTERED\n");
    fflush(stderr);

    signal(SIGSEGV, sig_handler);
    signal(SIGABRT, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGPIPE, sig_handler);

    XProxyArgs *args = (XProxyArgs*)arg;

    LOGI("[JNI Thread] Starting xproxy_main...");
    LOGI("[JNI] host=%s, port=%d, user=%s", args->host ? args->host : "null", args->port, args->user ? args->user : "null");
    LOGI("[JNI] socks_port=%d, http_port=%d, vpn_mode=%d, pac_config_path=%s", args->socks_port, args->http_port, args->vpn_mode, args->pac_config_path);

    char sport[16], shport[16], ssp[16], shp[16], tun_fd_str[16], vpn_mode_str[16];
    sprintf(sport, "%d", args->port);
    sprintf(ssp, "%d", args->socks_port);
    sprintf(shp, "%d", args->http_port);
    sprintf(tun_fd_str, "%d", args->tun_fd);
    sprintf(vpn_mode_str, "%d", args->vpn_mode);

    char *argv[] = {
        "xproxy",
        "-h", args->host ? args->host : "",
        "-p", sport,
        "-u", args->user ? args->user : "",
        "-P", args->pass ? args->pass : "",
        "-l", ssp,
        "-t", shp,
        "--tun-fd", tun_fd_str,
        "--vpn-mode", vpn_mode_str,
        "--pac-file", args->pac_config_path,
        NULL
    };
    int argc = 19;  // 修正：数组有19个非NULL元素（索引0-18）

    LOGI("[JNI] Calling xproxy_main with args:");
    LOGI("[JNI] argv[0]=%s argv[1]=%s argv[2]=%s", argv[0], argv[1], argv[2]);
    LOGI("[JNI] argv[3]=%s argv[4]=%s argv[5]=%s argv[6]=%s", argv[3], argv[4], argv[5], argv[6]);
    LOGI("[JNI] argv[7]=%s argv[8]=%s argv[9]=%s argv[10]=%s", argv[7], argv[8], argv[9], argv[10]);
    LOGI("[JNI] argv[11]=%s argv[12]=%s argv[13]=%s argv[14]=%s", argv[11], argv[12], argv[13], argv[14]);
    LOGI("[JNI] argv[15]=%s argv[16]=%s", argv[15], argv[16]);
    LOGI("[JNI] argv[15]=%s argv[16]=%s argv[17]=%s argv[18]=%s", argv[15], argv[16], argv[17], argv[18]);

    xproxy_main(argc, argv);

    xproxy_thread_id = 0;

    free(args->host);
    free(args->user);
    free(args->pass);
    free(args->pac_config_path);
    free(args);

    // callback ui
    native_notify_ssh_disconnected();

    return NULL;
}

JNIEXPORT jint JNICALL
Java_app_xproxy_MainActivity_nativeStartLogCallback(
    JNIEnv* env,
    jobject thiz)
{
    LOGI("JNI nativeStartLogCallback called");
    init_log_callback(env, thiz);
    return 0;
}

JNIEXPORT jint JNICALL
Java_app_xproxy_MyVpnService_startSshProxyNative(
    JNIEnv *env,
    jobject thiz,
    jint tunFd,
    jstring host,
    jint port,
    jstring user,
    jstring pass,
    jint socks_port,
    jint http_port,
    jstring pac_config_path)
{
    const char *c_host = (*env)->GetStringUTFChars(env, host, NULL);
    const char *c_user = (*env)->GetStringUTFChars(env, user, NULL);
    const char *c_pass = (*env)->GetStringUTFChars(env, pass, NULL);
    const char *c_pac_path = (*env)->GetStringUTFChars(env, pac_config_path, NULL);

    LOGI("JNI startSshProxyNative: tunFd=%d, host=%s, port=%d, socks_port=%d, http_port=%d, pac_config_path=%s",
         tunFd, c_host ? c_host : "null", port, socks_port, http_port, c_pac_path ? c_pac_path : "null");

    pthread_mutex_lock(&g_service_mutex);
    if (g_vm == NULL) {
        (*env)->GetJavaVM(env, &g_vm);
    }
    if (g_service_obj != NULL) {
        (*env)->DeleteGlobalRef(env, g_service_obj);
        g_service_obj = NULL;
    }
    g_service_obj = (*env)->NewGlobalRef(env, thiz);
    if (g_service_obj != NULL) {
        jclass clazz = (*env)->GetObjectClass(env, thiz);
        g_on_disconnect_method = (*env)->GetMethodID(env, clazz, "onSshDisconnected", "()V");
        (*env)->DeleteLocalRef(env, clazz);
    }
    pthread_mutex_unlock(&g_service_mutex);

    XProxyArgs *args = (XProxyArgs*)malloc(sizeof(XProxyArgs));
    args->tun_fd = tunFd;
    args->host = strdup(c_host);
    args->port = port;
    args->user = strdup(c_user);
    args->pass = strdup(c_pass);
    args->socks_port = socks_port;
    args->http_port = http_port;
    args->vpn_mode = (tunFd > 0) ? 1 : 0;
    args->pac_config_path = strdup(c_pac_path);

    (*env)->ReleaseStringUTFChars(env, host, c_host);
    (*env)->ReleaseStringUTFChars(env, user, c_user);
    (*env)->ReleaseStringUTFChars(env, pass, c_pass);
    (*env)->ReleaseStringUTFChars(env, pac_config_path, c_pac_path);

    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, run_xproxy_thread, args) != 0) {
        free(args->host);
        free(args->user);
        free(args->pass);
        free(args->pac_config_path);
        free(args);
        return -3;
    }
    pthread_detach(thread_id);

    return 0;
}

JNIEXPORT jint JNICALL
Java_app_xproxy_MyVpnService_stopSshProxyNative(JNIEnv *env, jobject thiz) {
    LOGI("JNI stopSshProxyNative called");
    stop_xproxy();

    pthread_mutex_lock(&g_service_mutex);
    if (g_service_obj != NULL) {
        (*env)->DeleteGlobalRef(env, g_service_obj);
        g_service_obj = NULL;
    }
    g_on_disconnect_method = NULL;
    pthread_mutex_unlock(&g_service_mutex);

    return 0;
}

#include <errno.h>

JNIEXPORT jboolean JNICALL
Java_app_xproxy_MyVpnService_isNativeThreadRunning(JNIEnv *env, jobject thiz) {
    if (xproxy_thread_id == 0) {
        return (jboolean)0;
    }

    int kill_result = pthread_kill(xproxy_thread_id, 0);
    return (jboolean)(kill_result == 0);
}

JNIEXPORT jboolean JNICALL
Java_app_xproxy_MyVpnService_00024Companion_isNativeThreadRunning(JNIEnv *env, jobject thiz) {
    if (xproxy_thread_id == 0) {
        return (jboolean)0;
    }

    int kill_result = pthread_kill(xproxy_thread_id, 0);
    return (jboolean)(kill_result == 0);
}

void native_notify_ssh_disconnected() {
    if (g_vm == NULL || g_service_obj == NULL || g_on_disconnect_method == NULL) {
        return;
    }

    JNIEnv* env = NULL;
    int need_detach = 0;

    // 获取当前线程的 JNIEnv
    jint ret = (*g_vm)->GetEnv(g_vm, (void**)&env, JNI_VERSION_1_6);
    if (ret == JNI_EDETACHED) {
        if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != 0) {
            return;
        }
        need_detach = 1;
    } else if (ret != JNI_OK || env == NULL) {
        return;
    }

    // 调用 Java 方法
    (*env)->CallVoidMethod(env, g_service_obj, g_on_disconnect_method);

    if (need_detach) {
        (*g_vm)->DetachCurrentThread(g_vm);
    }
}
