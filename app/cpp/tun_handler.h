#ifndef TUN_HANDLER_H
#define TUN_HANDLER_H

#include <stdint.h>
#include "xpoll.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TUN 设备处理器配置 */
typedef struct {
    int tun_fd;                    /* TUN 设备文件描述符 */
    int socks5_port;               /* SOCKS5 代理端口 */
    int http_port;                 /* HTTP 代理端口 */
    xPollState* xpoll;             /* 事件循环实例 */
    int vpn_mode;                  /* VPN模式标志 */
} TunHandlerConfig;

/**
 * 初始化 TUN 设备处理器
 * @param config 配置参数
 * @return 0 成功, -1 失败
 */
int tun_handler_init(const TunHandlerConfig* config);

/**
 * 清理 TUN 设备处理器
 */
void tun_handler_cleanup(void);

/**
 * 获取 TUN 处理器的 socket (用于事件监听)
 * @return socket 描述符, -1 表示未初始化
 */
int tun_handler_get_fd(void);

#ifdef __cplusplus
}
#endif

#endif /* TUN_HANDLER_H */
