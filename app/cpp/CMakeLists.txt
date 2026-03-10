cmake_minimum_required(VERSION 3.22.1)
project(xproxy_native)

# 开启 C11 标准（对应你的 Makefile -std=c11）
set(CMAKE_C_STANDARD 11)

# 定义路径
set(CORE_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../../core)
set(WOLFSSL_ROOT ${CORE_ROOT}/3rd/wolfssl)
set(WOLFSSH_ROOT ${CORE_ROOT}/3rd/wolfssh)

# 编译宏定义 (保持与 Makefile 一致)
add_definitions(-DWOLFSSL_USER_SETTINGS -DWOLFSSH_USER_SETTINGS -DWOLFSSH_FWD)

# 头文件包含路径
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CORE_ROOT}
    ${WOLFSSL_ROOT}
    ${WOLFSSL_ROOT}/wolfssl
    ${WOLFSSH_ROOT}
    ${WOLFSSH_ROOT}/wolfssh
)

# 收集源文件 (手动列出以确保精确，参考你的 Makefile)
set(XPROXY_SRCS
    ${CORE_ROOT}/main.c ${CORE_ROOT}/xpoll.c ${CORE_ROOT}/socks5_server.c ${CORE_ROOT}/ssh_tunnel.c
    ${CORE_ROOT}/xargs.c ${CORE_ROOT}/https_proxy.c ${CORE_ROOT}/xpac_server.c tun_handler.c
    jni/xproxy_jni.c
)

# 收集 wolfCrypt 源码
file(GLOB WOLFCRYPT_SRCS "${WOLFSSL_ROOT}/wolfcrypt/src/*.c")

# 收集 wolfSSH 源码
file(GLOB WOLFSSH_SRCS "${WOLFSSH_ROOT}/src/*.c")

# 编译生成动态库
add_library(xproxy_native SHARED
    ${XPROXY_SRCS}
    ${WOLFCRYPT_SRCS}
    ${WOLFSSH_SRCS}
)

# 链接安卓系统库 (log用于调试，android用于VpnService)
target_link_libraries(xproxy_native log android)
