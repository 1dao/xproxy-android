#include "tun_handler.h"
#include "xpoll.h"
#include "socket_util.h"
#include "ssh_tunnel.h"
#include "socks5_server.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>  // Add for write/read functions

#ifdef __ANDROID__
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define LOG_TAG "tun_handler"
#include "xlog.h"
#define TLOGI XLOGI
#define TLOGE XLOGE
#define TLOGD XLOGD
#else
#define TLOGI(...) printf(__VA_ARGS__)
#define TLOGE(...) fprintf(stderr, __VA_ARGS__)
#define TLOGD(...) printf(__VA_ARGS__)
#endif

/* IP 包头部结构 */
struct ip_header {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_off;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed));

/* TCP 头部结构 */
struct tcp_header {
    uint16_t src_port;          /* 源端口 */
    uint16_t dst_port;          /* 目的端口 */
    uint32_t seq_num;           /* 序列号 */
    uint32_t ack_num;           /* 确认号 */
    uint8_t data_offset;        /* 数据偏移 (4 bits) + 保留 (4 bits) */
    uint8_t flags;              /* 标志 */
    uint16_t window;            /* 窗口大小 */
    uint16_t checksum;          /* 校验和 */
    uint16_t urgent_ptr;        /* 紧急指针 */
} __attribute__((packed));

/* UDP 头部结构 */
struct udp_header {
    uint16_t src_port;          /* 源端口 */
    uint16_t dst_port;          /* 目的端口 */
    uint16_t length;            /* 长度 */
    uint16_t checksum;          /* 校验和 */
} __attribute__((packed));

/* 计算 TCP 校验和 (包含伪首部) */
static uint16_t tcp_checksum(struct sockaddr_in* src_addr, struct sockaddr_in* dst_addr,
                            struct tcp_header* tcp, int tcp_len, const uint8_t* data, int data_len);

/* 连接状态枚举 */
typedef enum {
    TUN_CONN_INIT,          /* 初始化 */
    TUN_CONN_CONNECTING,    /* 连接中 */
    TUN_CONN_CONNECTED,     /* 已连接 */
    TUN_CONN_ERROR,         /* 错误状态 */
    TUN_CONN_CLOSED         /* 已关闭 */
} TunConnState;

/* 连接结构 */
typedef struct {
    int active;
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dst_ip;
    uint16_t dst_port;
    SOCKET_T tun_sock;
    SOCKET_T proxy_sock;
    int protocol; /* 6=TCP, 17=UDP */
    uint32_t seq_num;  /* TCP 序列号 */
    uint32_t ack_num;  /* TCP 确认号 */
    TunConnState state; /* 连接状态 */

    /* 数据缓冲区
     * write_buffer 只装客户端应用数据，CONNECTED 之前只积累不发送；
     * socks_buf 只装 SOCKS5 协议报文（greeting/CONNECT），始终优先发送。
     * 两者分开，避免应用数据插进握手序列污染协议。
     */
    char read_buffer[8192];
    int read_buffer_size;
    char write_buffer[8192];
    int write_buffer_size;
    char socks_buf[64];
    int socks_buf_size;

    /* SOCKS5 握手阶段
     * 0 = 尚未发送握手
     * 1 = 已发送握手，等待方法选择回复 (需要 2 字节)
     * 2 = 已发送connect请求，等待连接回复 (需要 10 字节)
     * 完成后 state 会变为 TUN_CONN_CONNECTED
     */
    int socks_stage;
    int socks_need_len;  /* 当前阶段需要的字节数 */

    /* 额外状态信息 */
    int retry_count;
    long64 last_retry_time;
} TunConnection;

/* 全局变量 */
static int g_tun_fd = -1;
static int g_socks5_port = 1080;
static int g_http_port = 7890;
static xPollState* g_xpoll = NULL;
static int g_vpn_mode = 0;  // VPN 模式标志
static int g_initialized = 0;

/* 连接映射表 */
#define MAX_CONNECTIONS 1024
static TunConnection g_connections[MAX_CONNECTIONS];

/* 初始化连接表 */
static void init_connections(void) {
    memset(g_connections, 0, sizeof(g_connections));
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        g_connections[i].tun_sock = INVALID_SOCKET;
        g_connections[i].proxy_sock = INVALID_SOCKET;
        g_connections[i].state = TUN_CONN_CLOSED;
        g_connections[i].socks_stage = 0;
        g_connections[i].socks_need_len = 0;
    }
}

/* 查找或创建连接 */
static TunConnection* find_or_create_connection(uint32_t src_ip, uint16_t src_port,
                                               uint32_t dst_ip, uint16_t dst_port,
                                               int protocol) {
    /* 先查找现有连接 */
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_connections[i].active &&
            g_connections[i].src_ip == src_ip &&
            g_connections[i].src_port == src_port &&
            g_connections[i].dst_ip == dst_ip &&
            g_connections[i].dst_port == dst_port &&
            g_connections[i].protocol == protocol) {
            return &g_connections[i];
        }
    }

    /* 创建新连接 */
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_connections[i].state == TUN_CONN_CLOSED) {
            g_connections[i].active = 1;
            g_connections[i].src_ip = src_ip;
            g_connections[i].src_port = src_port;
            g_connections[i].dst_ip = dst_ip;
            g_connections[i].dst_port = dst_port;
            g_connections[i].protocol = protocol;
            g_connections[i].proxy_sock = INVALID_SOCKET;
            g_connections[i].state = TUN_CONN_INIT;
            g_connections[i].read_buffer_size = 0;
            g_connections[i].write_buffer_size = 0;
            g_connections[i].socks_buf_size = 0;
            g_connections[i].socks_stage = 0;
            g_connections[i].socks_need_len = 0;
            g_connections[i].retry_count = 0;
            g_connections[i].last_retry_time = 0;
            return &g_connections[i];
        }
    }

    return NULL; /* 连接表已满 */
}

/* 计算 IP 校验和 */
static uint16_t ip_checksum(void* vdata, size_t length) {
    uint8_t* data = (uint8_t*)vdata;  /* 必须无符号：char 在 x86 上有符号，会导致校验和错误 */
    uint32_t acc = 0;
    uint8_t swapped = 0;

    for (size_t i = 0; i < length; i++) {
        if (i % 2 == 0) {
            acc += data[i];
        } else {
            acc += data[i] << 8;
        }
    }

    while (acc >> 16) {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }

    return ~acc;
}

/* 构造 TCP 响应包并写入 TUN */
static int send_tcp_response(TunConnection* conn, const uint8_t* data, int data_len, uint8_t tcp_flags) {
    uint8_t packet[65535];
    int ip_header_len = 20;
    int tcp_header_len;
    int total_len;

    /* Determine TCP header length based on flags */
    if (tcp_flags & 0x02) { // SYN flag - needs options
        tcp_header_len = 24; // Regular 20 + 4 bytes for MSS option
    } else {
        tcp_header_len = 20; // Regular TCP header
    }
    total_len = ip_header_len + tcp_header_len + data_len;

    /* 构造 IP 头 */
    struct ip_header* ip = (struct ip_header*)packet;
    ip->ver_ihl = 0x45;  /* IPv4, 20 bytes header */
    ip->tos = 0;
    ip->total_len = htons(total_len);
    ip->id = htons(0x1234);
    ip->flags_off = 0;
    ip->ttl = 64;
    ip->proto = 6;  /* TCP */
    ip->check = 0;
    ip->daddr = conn->dst_ip;   /* 源地址 = 原目标地址 */
    ip->saddr = conn->src_ip;   /* 目标地址 = 原源地址 */
    ip->check = ip_checksum(ip, ip_header_len);

    /* 构造 TCP 头 */
    struct tcp_header* tcp = (struct tcp_header*)(packet + ip_header_len);
    tcp->src_port = htons(conn->dst_port);  /* 源端口 = 原目标端口 */
    tcp->dst_port = htons(conn->src_port);  /* 目标端口 = 原源端口 */
    tcp->seq_num = htonl(conn->seq_num);
    tcp->ack_num = htonl(conn->ack_num);
    tcp->data_offset = (tcp_header_len >> 2) << 4;  /* Header length in 32-bit words */
    tcp->flags = tcp_flags;
    tcp->window = htons(65535);
    tcp->checksum = 0;
    tcp->urgent_ptr = 0;

    /* Add MSS option if SYN flag is set */
    if (tcp_flags & 0x02) { // SYN flag
        uint8_t* options = (uint8_t*)(tcp + 1);
        options[0] = 0x02;  // MSS option kind
        options[1] = 0x04;  // MSS option length
        options[2] = 0x05;  // MSS value MSB (1400 = 0x0578)
        options[3] = 0x78;  // MSS value LSB
    }

    /* 复制数据 */
    if (data_len > 0) {
        memcpy(packet + ip_header_len + tcp_header_len, data, data_len);
    }

    /* 计算 TCP 校验和 (需要伪首部) */
    tcp->checksum = tcp_checksum((struct sockaddr_in*)&(struct sockaddr_in){.sin_addr.s_addr = conn->dst_ip},
                                 (struct sockaddr_in*)&(struct sockaddr_in){.sin_addr.s_addr = conn->src_ip},
                                 tcp, tcp_header_len, data, data_len);

    /* 写入 TUN 设备 */
    int n = write(g_tun_fd, packet, total_len);
    if (n < 0) {
        TLOGE("[TUN] Failed to write to TUN: %s", strerror(errno));
        return -1;
    }

    TLOGD("[TUN] Sent TCP response: %d bytes, flags=%02X", n, tcp_flags);
    return n;
}

/* 计算 TCP 校验和 (包含伪首部) - 使用栈上缓冲区避免 malloc */
static uint16_t tcp_checksum(struct sockaddr_in* src_addr, struct sockaddr_in* dst_addr,
                            struct tcp_header* tcp, int tcp_header_len, const uint8_t* data, int data_len) {
    uint32_t sum = 0;

    // 1. 累加伪首部 (12 bytes)
    uint32_t src = src_addr->sin_addr.s_addr;
    uint32_t dst = dst_addr->sin_addr.s_addr;
    sum += (src >> 16) & 0xFFFF;
    sum += src & 0xFFFF;
    sum += (dst >> 16) & 0xFFFF;
    sum += dst & 0xFFFF;
    sum += 6;  // protocol
    sum += tcp_header_len + data_len;

    // 2. 累加 TCP 头 (按 16-bit 字)
    uint16_t* tcp_ptr = (uint16_t*)tcp;
    int tcp_words = tcp_header_len / 2;
    for (int i = 0; i < tcp_words; i++) {
        sum += ntohs(tcp_ptr[i]);
    }

    // 3. 累加数据部分 (按 16-bit 字)
    if (data && data_len > 0) {
        int data_words = data_len / 2;
        uint16_t* data_ptr = (uint16_t*)data;
        for (int i = 0; i < data_words; i++) {
            sum += ntohs(data_ptr[i]);
        }
        // 处理奇数字节
        if (data_len % 2) {
            uint8_t odd_byte = data[data_len - 1];
            sum += odd_byte << 8;
        }
    }

    // 4. Fold carry bit
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return htons(~(uint16_t)sum);
}

/* 构造 UDP 响应包并写入 TUN（用于 DNS 应答回注）
 * IPv4 下 UDP 校验和填 0 表示不校验，协议栈接受。
 */
static int send_udp_response(TunConnection* conn, const uint8_t* data, int data_len) {
    uint8_t packet[4096];
    int ip_header_len = 20;
    int udp_header_len = 8;
    int total_len = ip_header_len + udp_header_len + data_len;

    if (data_len <= 0 || total_len > (int)sizeof(packet)) {
        TLOGE("[TUN] Invalid UDP response length: %d", data_len);
        return -1;
    }

    struct ip_header* ip = (struct ip_header*)packet;
    ip->ver_ihl = 0x45;
    ip->tos = 0;
    ip->total_len = htons(total_len);
    ip->id = htons(0x1234);
    ip->flags_off = 0;
    ip->ttl = 64;
    ip->proto = 17;  /* UDP */
    ip->check = 0;
    ip->saddr = conn->dst_ip;   /* 源地址 = 原目标地址 */
    ip->daddr = conn->src_ip;   /* 目标地址 = 原源地址 */
    ip->check = ip_checksum(ip, ip_header_len);

    struct udp_header* udp = (struct udp_header*)(packet + ip_header_len);
    udp->src_port = htons(conn->dst_port);
    udp->dst_port = htons(conn->src_port);
    udp->length = htons(udp_header_len + data_len);
    udp->checksum = 0;

    memcpy(packet + ip_header_len + udp_header_len, data, data_len);

    int n = write(g_tun_fd, packet, total_len);
    if (n < 0) {
        TLOGE("[TUN] Failed to write UDP response to TUN: %s", strerror(errno));
        return -1;
    }
    TLOGD("[TUN] Sent UDP response: %d bytes to port %d", n, conn->src_port);
    return n;
}

/* DNS-over-TCP 响应流分帧：read_buffer 中按 [2字节长度][DNS报文] 逐条取出，
 * 转成 UDP 包写回 TUN。返回处理的报文条数。
 */
static void close_connection(TunConnection* conn);
static int drain_dns_responses(TunConnection* conn) {
    int count = 0;
    while (conn->read_buffer_size >= 2) {
        int msg_len = ((uint8_t)conn->read_buffer[0] << 8) | (uint8_t)conn->read_buffer[1];
        if (msg_len <= 0) {
            TLOGE("[TUN] Invalid DNS-over-TCP length: %d", msg_len);
            close_connection(conn);
            return count;
        }
        if (conn->read_buffer_size < 2 + msg_len) {
            break;  /* 报文不完整，等更多数据 */
        }
        send_udp_response(conn, (uint8_t*)conn->read_buffer + 2, msg_len);
        count++;
        int remain = conn->read_buffer_size - 2 - msg_len;
        if (remain > 0) {
            memmove(conn->read_buffer, conn->read_buffer + 2 + msg_len, remain);
        }
        conn->read_buffer_size = remain;
    }
    return count;
}

/* 连接清理函数 */
static void close_connection(TunConnection* conn) {
    if (!conn || !conn->active) return;

    if (conn->proxy_sock != INVALID_SOCKET) {
        xpoll_del_event(g_xpoll, conn->proxy_sock, XPOLL_ALL);
        CLOSE_SOCKET(conn->proxy_sock);
        conn->proxy_sock = INVALID_SOCKET;
    }

    conn->active = 0;
    conn->state = TUN_CONN_CLOSED;
    memset(conn, 0, sizeof(TunConnection));
    conn->tun_sock = INVALID_SOCKET;
    conn->proxy_sock = INVALID_SOCKET;
    conn->state = TUN_CONN_CLOSED;
}

    /* 回调函数声明 */
    static void proxy_write_callback(xPollState* loop, SOCKET_T fd, int mask, void* clientData);
    static void proxy_error_callback(xPollState* loop, SOCKET_T fd, int mask, void* clientData);

    /* 代理 socket 可读回调 */
    static void proxy_read_callback(xPollState* loop, SOCKET_T fd, int mask, void* clientData) {
    TunConnection* conn = (TunConnection*)clientData;
    if (!conn || !conn->active) {
        return;
    }

    uint8_t buffer[4096];
    int n = recv(fd, (char*)buffer, sizeof(buffer), 0);

    if (n <= 0) {
        if (n < 0) {
            if (socket_check_eagain()) {
                TLOGE("[TUN] Proxy recv would block: %s", strerror(errno));
                return;
            }
            TLOGE("[TUN] Proxy recv error: %s", strerror(errno));
        } else {
            TLOGD("[TUN] Proxy connection closed");
        }

        /* TCP 连接需要通知客户端关闭；DNS(UDP) 会话直接清理 */
        if (conn->protocol == 6) {
            send_tcp_response(conn, NULL, 0, 0x11);  /* FIN+ACK */
        }

        /* 清理连接 */
        close_connection(conn);
        return;
    }

    TLOGD("[TUN] Received %d bytes from proxy, state=%d, socks_stage=%d", n, conn->state, conn->socks_stage);

    // 如果还在 SOCKS 握手阶段，先处理协议而不是直接透传
    if (conn->state == TUN_CONN_CONNECTING) {
        // 将收到的数据追加到读取缓冲区
        if (conn->read_buffer_size + n > sizeof(conn->read_buffer)) {
            TLOGE("[TUN] Read buffer overflow, closing connection");
            close_connection(conn);
            return;
        }
        memcpy(conn->read_buffer + conn->read_buffer_size, buffer, n);
        conn->read_buffer_size += n;

        // 处理 SOCKS5 握手阶段 1：方法选择响应 (需要 2 字节)
        if (conn->socks_stage == 1) {
            if (conn->read_buffer_size >= 2) {
                if (conn->read_buffer[0] == 0x05 && conn->read_buffer[1] == 0x00) {
                    TLOGI("[TUN] SOCKS5 method none accepted");
                    // 发出 CONNECT 请求
                    uint8_t req[10];
                    req[0] = 0x05;
                    req[1] = 0x01;     // CMD=CONNECT
                    req[2] = 0x00;     // RSV
                    req[3] = 0x01;     // ATYP=IPv4
                    uint32_t ip = conn->dst_ip;  /* 来自 IP 头，已是网络字节序，不可再 htonl */
                    memcpy(&req[4], &ip, 4);
                    uint16_t port = htons(conn->dst_port);
                    memcpy(&req[8], &port, 2);
                    if (conn->socks_buf_size + sizeof(req) <= sizeof(conn->socks_buf)) {
                        memcpy(conn->socks_buf + conn->socks_buf_size, req, sizeof(req));
                        conn->socks_buf_size += sizeof(req);
                        TLOGI("[TUN] CONNECT request queued: dst=%d.%d.%d.%d:%d",
                               (conn->dst_ip >> 0) & 0xFF, (conn->dst_ip >> 8) & 0xFF,
                               (conn->dst_ip >> 16) & 0xFF, (conn->dst_ip >> 24) & 0xFF,
                               conn->dst_port);

                        // 明确注册可写事件，确保 proxy_write_callback 被调用
                        xpoll_add_event(g_xpoll, conn->proxy_sock, XPOLL_WRITABLE,
                                       proxy_read_callback, proxy_write_callback, proxy_error_callback, conn);
                    }
                    conn->socks_stage = 2;
                    conn->socks_need_len = 10;  // 等待连接回复，需要 10 字节
                    conn->read_buffer_size = 0;  // 清空缓冲区
                } else {
                    TLOGE("[TUN] SOCKS5 no acceptable auth method (0x%02X)", (uint8_t)conn->read_buffer[1]);
                    close_connection(conn);
                }
            }
            return;
        }
        // 处理 SOCKS5 握手阶段 2：连接回复 (需要 10 字节)
        else if (conn->socks_stage == 2) {
            if (conn->read_buffer_size >= 10) {
                if (conn->read_buffer[0] == 0x05 && conn->read_buffer[1] == 0x00) {
                    TLOGI("[TUN] SOCKS5 CONNECT succeeded");
                    conn->state = TUN_CONN_CONNECTED;

                    /* 回复后面可能已粘连了隧道数据，摘出来按正常数据处理 */
                    int extra = conn->read_buffer_size - 10;
                    if (extra > 0) {
                        memmove(conn->read_buffer, conn->read_buffer + 10, extra);
                    }
                    conn->read_buffer_size = extra;
                    if (extra > 0) {
                        if (conn->protocol == 17) {
                            drain_dns_responses(conn);
                        } else {
                            send_tcp_response(conn, (uint8_t*)conn->read_buffer, extra, 0x18);
                            conn->seq_num += extra;
                            conn->read_buffer_size = 0;
                        }
                    }

                    /* 握手期间积压的客户端数据现在可以发了 */
                    if (conn->active && conn->write_buffer_size > 0) {
                        xpoll_add_event(g_xpoll, conn->proxy_sock, XPOLL_WRITABLE,
                                       proxy_read_callback, proxy_write_callback, proxy_error_callback, conn);
                    }
                } else {
                    TLOGE("[TUN] SOCKS5 CONNECT failed rep=0x%02X", (uint8_t)conn->read_buffer[1]);
                    if (conn->protocol == 6) {
                        send_tcp_response(conn, NULL, 0, 0x14);  /* RST+ACK 通知客户端 */
                    }
                    close_connection(conn);
                }
            }
            return;
        }
    }

    // 只有连接成功后才将 proxy 中的数据写回 TUN
    if (conn->state == TUN_CONN_CONNECTED) {
        if (conn->protocol == 17) {
            /* DNS-over-TCP 响应：积累后分帧转回 UDP */
            if (conn->read_buffer_size + n > (int)sizeof(conn->read_buffer)) {
                TLOGE("[TUN] DNS read buffer overflow");
                close_connection(conn);
                return;
            }
            memcpy(conn->read_buffer + conn->read_buffer_size, buffer, n);
            conn->read_buffer_size += n;
            conn->last_retry_time = time_get_ms();  /* 记录活跃时间供空闲回收 */
            drain_dns_responses(conn);
        } else {
            /* 发送数据到 TUN */
            send_tcp_response(conn, buffer, n, 0x18);  /* PSH+ACK */
            /* 更新序列号 */
            conn->seq_num += n;
        }
    }
}

/* 代理 socket 可写回调
 * 发送顺序：SOCKS5 协议报文 (socks_buf) 永远优先；
 * 客户端数据 (write_buffer) 只在握手完成 (CONNECTED) 后发送。
 */
static void proxy_write_callback(xPollState* loop, SOCKET_T fd, int mask, void* clientData) {
    TunConnection* conn = (TunConnection*)clientData;
    if (!conn || !conn->active) {
        return;
    }

    /* 1. 先发协议报文 */
    if (conn->socks_buf_size > 0) {
        int sent = send(fd, conn->socks_buf, conn->socks_buf_size, 0);
        if (sent < 0) {
            if (socket_check_eagain()) return;
            TLOGE("[TUN] Proxy send error (socks): %s", strerror(errno));
            close_connection(conn);
            return;
        }
        if (sent < conn->socks_buf_size) {
            memmove(conn->socks_buf, conn->socks_buf + sent, conn->socks_buf_size - sent);
            conn->socks_buf_size -= sent;
            return;  /* 协议没发完，数据继续等 */
        }
        conn->socks_buf_size = 0;
    }

    /* 2. 握手完成后发客户端数据 */
    if (conn->state == TUN_CONN_CONNECTED && conn->write_buffer_size > 0) {
        int sent = send(fd, conn->write_buffer, conn->write_buffer_size, 0);
        if (sent < 0) {
            if (socket_check_eagain()) return;
            TLOGE("[TUN] Proxy send error (data): %s", strerror(errno));
            close_connection(conn);
            return;
        }
        if (sent < conn->write_buffer_size) {
            memmove(conn->write_buffer, conn->write_buffer + sent, conn->write_buffer_size - sent);
            conn->write_buffer_size -= sent;
            return;
        }
        conn->write_buffer_size = 0;
    }

    /* 3. 没有可发送的数据了，移除可写事件（握手中积压的数据等 CONNECTED 时重新注册） */
    if (conn->socks_buf_size == 0 &&
        (conn->state != TUN_CONN_CONNECTED || conn->write_buffer_size == 0)) {
        xpoll_del_event(g_xpoll, fd, XPOLL_WRITABLE);
    }
}

/* 代理 socket 错误回调 */
static void proxy_error_callback(xPollState* loop, SOCKET_T fd, int mask, void* clientData) {
    TunConnection* conn = (TunConnection*)clientData;
    TLOGE("[TUN] Proxy socket error, fd=%d, mask=%d", (int)fd, mask);
    close_connection(conn);
}

/* 创建到 SOCKS5 代理的异步连接 */
static SOCKET_T connect_to_socks5_async(TunConnection* conn) {
    SOCKET_T sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        TLOGE("[TUN] Failed to create socket: %s", strerror(errno));
        return INVALID_SOCKET;
    }

    /* 设置非阻塞 */
    socket_set_nonblocking(sock);

    /* 连接到 SOCKS5 代理 */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (g_vpn_mode) {
        /* VPN 模式下所有目标都会被 TUN 拦截并转发到 SOCKS5 代理。
         * 如果目标正好是本机的 HTTP/SOCKS 端口（包括 PAC 文件和管理界面），
         * 直接连接到 127.0.0.1 而不是再次走回 10.0.0.2:xxxx，否则会产生
         * 递归代理/循环依赖，导致 PAC 获取失败或代理失效。
         */
        if (conn->dst_ip == inet_addr("10.0.0.2") &&
            (conn->dst_port == g_http_port || conn->dst_port == g_socks5_port)) {
            addr.sin_addr.s_addr = inet_addr("127.0.0.1");
            addr.sin_port = htons(conn->dst_port);
        } else {
            // 普通流量走 VPN 内部的 SOCKS5 地址
            addr.sin_addr.s_addr = inet_addr("10.0.0.2");
            addr.sin_port = htons(g_socks5_port);
        }
    } else {
        // 非 VPN 模式直接使用本机 loopback
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        addr.sin_port = htons(g_socks5_port);
    }

    int ret = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        TLOGE("[TUN] Failed to connect to SOCKS5: %s", strerror(errno));
        CLOSE_SOCKET(sock);
        return INVALID_SOCKET;
    }

    /* 注册到事件循环：需要可写事件以便发送握手/后续缓冲数据 */
    if (xpoll_add_event(g_xpoll, sock, XPOLL_READABLE | XPOLL_WRITABLE | XPOLL_ERROR,
                        proxy_read_callback, proxy_write_callback, proxy_error_callback, conn) != 0) {
        TLOGE("[TUN] Failed to add proxy socket to xpoll");
        CLOSE_SOCKET(sock);
        return INVALID_SOCKET;
    }

    /* 排队 SOCKS5 握手 (0x05,0x01,0x00)，由 proxy_write_callback 在连接可写后发出 */
    if (conn) {
        const uint8_t greet[] = {0x05, 0x01, 0x00};
        memcpy(conn->socks_buf, greet, sizeof(greet));
        conn->socks_buf_size = sizeof(greet);
        conn->socks_stage = 1;
        conn->socks_need_len = 2;  /* 等待方法选择响应，需要 2 字节 */
        TLOGI("[TUN] Sent SOCKS5 handshake: 0x05 0x01 0x00, waiting for method response");
    }

    TLOGI("[TUN] Async connection to SOCKS5 proxy initiated for %d.%d.%d.%d:%d",
          (conn->dst_ip >> 0) & 0xFF, (conn->dst_ip >> 8) & 0xFF,
          (conn->dst_ip >> 16) & 0xFF, (conn->dst_ip >> 24) & 0xFF, conn->dst_port);

    return sock;
}

/* 处理 TCP 包 */
static int handle_tcp_packet(const uint8_t* packet, int packet_len) {
    const struct ip_header* ip = (const struct ip_header*)packet;
    int ip_header_len = (ip->ver_ihl & 0x0F) * 4;

    if (ip_header_len < 20 || packet_len < ip_header_len + 20) {
        TLOGE("[TUN] Invalid TCP packet length");
        return -1;
    }

    const struct tcp_header* tcp = (const struct tcp_header*)(packet + ip_header_len);

    uint32_t src_ip = ip->saddr;
    uint16_t src_port = ntohs(tcp->src_port);
    uint32_t dst_ip = ip->daddr;
    uint16_t dst_port = ntohs(tcp->dst_port);
    uint8_t tcp_flags = tcp->flags;
    uint32_t seq_num = ntohl(tcp->seq_num);
    uint32_t ack_num = ntohl(tcp->ack_num);

    TLOGD("[TUN] TCP packet: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d, flags=%02X, seq=%u, ack=%u",
          (src_ip >> 0) & 0xFF, (src_ip >> 8) & 0xFF,
          (src_ip >> 16) & 0xFF, (src_ip >> 24) & 0xFF, src_port,
          (dst_ip >> 0) & 0xFF, (dst_ip >> 8) & 0xFF,
          (dst_ip >> 16) & 0xFF, (dst_ip >> 24) & 0xFF, dst_port,
          tcp_flags, seq_num, ack_num);

    /* 查找或创建连接 */
    TunConnection* conn = find_or_create_connection(src_ip, src_port, dst_ip, dst_port, 6);
    if (!conn) {
        TLOGE("[TUN] Failed to create connection");
        return -1;
    }

    /* 非 SYN 包命中了新建条目 = 残留连接的杂散包（如对端关闭后的重传/FIN），
     * 回 RST 让客户端立即放弃，避免幽灵连接占用连接表 */
    if (conn->state == TUN_CONN_INIT && !((tcp_flags & 0x02) && !(tcp_flags & 0x10))) {
        conn->seq_num = ack_num;
        conn->ack_num = seq_num + 1;
        send_tcp_response(conn, NULL, 0, 0x04);  /* RST */
        close_connection(conn);
        return 0;
    }

    /* 处理 SYN 包 (新连接) */
    if ((tcp_flags & 0x02) && !(tcp_flags & 0x10)) {
        TLOGI("[TUN] New TCP connection: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
              (src_ip >> 0) & 0xFF, (src_ip >> 8) & 0xFF,
              (src_ip >> 16) & 0xFF, (src_ip >> 24) & 0xFF, src_port,
              (dst_ip >> 0) & 0xFF, (dst_ip >> 8) & 0xFF,
              (dst_ip >> 16) & 0xFF, (dst_ip >> 24) & 0xFF, dst_port);

        /* 初始化序列号 */
        conn->seq_num = 1000;  /* 初始序列号 */
        conn->ack_num = seq_num + 1;

        /* 发送 SYN+ACK */
        send_tcp_response(conn, NULL, 0, 0x12);  /* SYN+ACK */

        /* 连接到 SOCKS5 代理 */
        if (conn->proxy_sock == INVALID_SOCKET) {
            conn->proxy_sock = connect_to_socks5_async(conn);
            if (conn->proxy_sock != INVALID_SOCKET) {
                conn->state = TUN_CONN_CONNECTING;
                TLOGI("[TUN] Proxy socket connecting: fd=%d", (int)conn->proxy_sock);
            } else {
                TLOGE("[TUN] Failed to connect to SOCKS5 proxy");
                /* 发送 RST */
                send_tcp_response(conn, NULL, 0, 0x14);  /* RST+ACK */
                close_connection(conn);
                return -1;
            }
        }
        return 0;
    }

    /* 连接到 SOCKS5 还未完成时，我们仍需要响应客户端 ACK，
     * 避免应用重传浪费时间。但由于代理尚未就绪，
     * 数据只能先缓存（或丢弃），后续在连接完成后处理。
     */
    if (conn->state != TUN_CONN_CONNECTED) {
        if (tcp_flags & 0x10) {
            conn->ack_num = seq_num;
            int tcp_header_len = ((tcp->data_offset >> 4) & 0x0F) * 4;
            int data_len = packet_len - ip_header_len - tcp_header_len;
            if (data_len > 0) {
                const uint8_t* data = packet + ip_header_len + tcp_header_len;
                if (conn->write_buffer_size + data_len <= (int)sizeof(conn->write_buffer)) {
                    memcpy(conn->write_buffer + conn->write_buffer_size, data, data_len);
                    conn->write_buffer_size += data_len;
                }
                /* ACK 必须覆盖已收下的数据，否则客户端会重传导致重复缓冲 */
                conn->ack_num = seq_num + data_len;
            }
            /* 发送 ACK 给客户端 */
            send_tcp_response(conn, NULL, 0, 0x10);
        }
        return 0;
    }

    /* 处理 ACK 包 */
    if (tcp_flags & 0x10) {
        conn->ack_num = seq_num;

        /* 如果有数据,转发到代理 */
        int tcp_header_len = ((tcp->data_offset >> 4) & 0x0F) * 4;
        int data_len = packet_len - ip_header_len - tcp_header_len;

        if (data_len > 0 && conn->proxy_sock != INVALID_SOCKET) {
            const uint8_t* data = packet + ip_header_len + tcp_header_len;

            // Store data in write buffer
            if (conn->write_buffer_size + data_len > sizeof(conn->write_buffer)) {
                TLOGE("[TUN] Write buffer overflow");
                close_connection(conn);
                return -1;
            }

            memcpy(conn->write_buffer + conn->write_buffer_size, data, data_len);
            conn->write_buffer_size += data_len;

            /* 注册可写事件触发实际发送（事件掩码是合并语义，重复注册无害） */
            xpoll_add_event(g_xpoll, conn->proxy_sock, XPOLL_WRITABLE,
                           proxy_read_callback, proxy_write_callback, proxy_error_callback, conn);

            TLOGD("[TUN] Buffered %d bytes for proxy", data_len);

            /* 发送 ACK 确认 */
            conn->ack_num += data_len;
            send_tcp_response(conn, NULL, 0, 0x10);  /* ACK */
        }
    }

    /* 处理 FIN 包：确认对方 FIN 并发出我方 FIN（简化的四次挥手合并回复），
     * 否则客户端会卡在 FIN_WAIT 等超时 */
    if (tcp_flags & 0x01) {
        TLOGI("[TUN] TCP connection closing");

        int tcp_header_len = ((tcp->data_offset >> 4) & 0x0F) * 4;
        int data_len = packet_len - ip_header_len - tcp_header_len;
        conn->ack_num = seq_num + data_len + 1;  /* FIN 占一个序号 */
        send_tcp_response(conn, NULL, 0, 0x11);  /* FIN+ACK */

        /* 关闭代理连接 */
        close_connection(conn);
    }

    /* 处理 RST 包 */
    if (tcp_flags & 0x04) {
        TLOGI("[TUN] TCP connection reset");

        /* 关闭代理连接 */
        close_connection(conn);
    }

    return 0;
}

/* 处理 UDP 包
 * DNS (端口 53)：转成 DNS-over-TCP 经 SOCKS5/SSH 隧道转发，响应回注为 UDP。
 * 其它 UDP（如 QUIC 443）：静默丢弃，应用会自动回退到 TCP。
 */
static int handle_udp_packet(const uint8_t* packet, int packet_len) {
    const struct ip_header* ip = (const struct ip_header*)packet;
    int ip_header_len = (ip->ver_ihl & 0x0F) * 4;

    if (ip_header_len < 20 || packet_len < ip_header_len + 8) {
        TLOGE("[TUN] Invalid UDP packet length");
        return -1;
    }

    const struct udp_header* udp = (const struct udp_header*)(packet + ip_header_len);

    uint32_t src_ip = ip->saddr;
    uint16_t src_port = ntohs(udp->src_port);
    uint32_t dst_ip = ip->daddr;
    uint16_t dst_port = ntohs(udp->dst_port);
    int udp_data_len = ntohs(udp->length) - 8;

    if (dst_port != 53) {
        TLOGD("[TUN] Dropping non-DNS UDP packet to port %d", dst_port);
        return 0;
    }

    /* 校验 DNS 报文长度 */
    if (udp_data_len <= 0 || ip_header_len + 8 + udp_data_len > packet_len) {
        TLOGE("[TUN] Invalid DNS payload length: %d", udp_data_len);
        return -1;
    }
    const uint8_t* payload = packet + ip_header_len + 8;

    TLOGD("[TUN] DNS query: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d, %d bytes",
          (src_ip >> 0) & 0xFF, (src_ip >> 8) & 0xFF,
          (src_ip >> 16) & 0xFF, (src_ip >> 24) & 0xFF, src_port,
          (dst_ip >> 0) & 0xFF, (dst_ip >> 8) & 0xFF,
          (dst_ip >> 16) & 0xFF, (dst_ip >> 24) & 0xFF, dst_port, udp_data_len);

    TunConnection* conn = find_or_create_connection(src_ip, src_port, dst_ip, dst_port, 17);
    if (!conn) {
        TLOGE("[TUN] DNS connection table full");
        return -1;
    }

    /* DNS-over-TCP 帧：2 字节长度前缀 + 原始查询报文 */
    if (conn->write_buffer_size + 2 + udp_data_len > (int)sizeof(conn->write_buffer)) {
        TLOGE("[TUN] DNS write buffer overflow");
        close_connection(conn);
        return -1;
    }
    conn->write_buffer[conn->write_buffer_size]     = (udp_data_len >> 8) & 0xFF;
    conn->write_buffer[conn->write_buffer_size + 1] = udp_data_len & 0xFF;
    memcpy(conn->write_buffer + conn->write_buffer_size + 2, payload, udp_data_len);
    conn->write_buffer_size += 2 + udp_data_len;
    conn->last_retry_time = time_get_ms();

    if (conn->state == TUN_CONN_INIT) {
        /* 新 DNS 会话：经 SOCKS5 连接到原目标 DNS 服务器的 TCP 53 */
        conn->proxy_sock = connect_to_socks5_async(conn);
        if (conn->proxy_sock == INVALID_SOCKET) {
            TLOGE("[TUN] Failed to connect DNS session to SOCKS5");
            close_connection(conn);
            return -1;
        }
        conn->state = TUN_CONN_CONNECTING;
    } else if (conn->state == TUN_CONN_CONNECTED) {
        /* 同一 socket 的后续查询（如 A/AAAA 并发）：注册可写事件冲刷 */
        xpoll_add_event(g_xpoll, conn->proxy_sock, XPOLL_WRITABLE,
                       proxy_read_callback, proxy_write_callback, proxy_error_callback, conn);
    }
    /* CONNECTING 状态下只积累，握手完成后统一冲刷 */

    return 0;
}

/* 周期性维护：回收空闲的 DNS 会话（DNS 一问一答，10 秒无活动即可关闭），
 * 由主循环每次 tick 调用，内部限频为每秒一次。
 */
void tun_handler_update(void) {
    static long64 last_sweep = 0;

    if (!g_initialized) return;

    long64 now = time_get_ms();
    if (now - last_sweep < 1000) return;
    last_sweep = now;

    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        TunConnection* conn = &g_connections[i];
        if (conn->active && conn->protocol == 17 &&
            now - conn->last_retry_time > 10000) {
            TLOGD("[TUN] Closing idle DNS session (port %d)", conn->src_port);
            close_connection(conn);
        }
    }
}

/* TUN 设备读取回调 */
static void tun_read_callback(xPollState* loop, SOCKET_T fd, int mask, void* clientData) {
    uint8_t buffer[65535];
    int n = read(fd, buffer, sizeof(buffer));

    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            TLOGE("[TUN] Read error: %s", strerror(errno));
        }
        return;
    }

    if (n < 20) {
        TLOGE("[TUN] Packet too small: %d bytes", n);
        return;
    }

    /* 解析 IP 包 */
    const struct ip_header* ip = (const struct ip_header*)buffer;
    int version = (ip->ver_ihl >> 4) & 0x0F;

    if (version != 4) {
        TLOGD("[TUN] Ignoring non-IPv4 packet (version=%d)", version);
        return;
    }

    int protocol = ip->proto;
    TLOGD("[TUN] Received IP packet: protocol=%d, length=%d", protocol, n);

    switch (protocol) {
        case 6: /* TCP */
            handle_tcp_packet(buffer, n);
            break;
        case 17: /* UDP */
            handle_udp_packet(buffer, n);
            break;
        default:
            TLOGD("[TUN] Ignoring protocol %d", protocol);
            break;
    }
}

int tun_handler_init(const TunHandlerConfig* config) {
    if (g_initialized) {
        TLOGE("[TUN] Handler already initialized");
        return -1;
    }

    if (!config || config->tun_fd < 0) {
        TLOGE("[TUN] Invalid config or TUN fd");
        return -1;
    }

    g_tun_fd = config->tun_fd;
    g_socks5_port = config->socks5_port;
    g_http_port = config->http_port;
    g_xpoll = config->xpoll;
    g_vpn_mode = config->vpn_mode;

    /* 设置 TUN 设备为非阻塞 */
    if (socket_set_nonblocking(g_tun_fd) < 0) {
        TLOGE("[TUN] Failed to set TUN fd non-blocking: %s", strerror(errno));
        return -1;
    }

    /* 初始化连接表 */
    init_connections();

    /* 注册到事件循环 */
    if (xpoll_add_event(g_xpoll, g_tun_fd, XPOLL_READABLE,
                        tun_read_callback, NULL, NULL, NULL) != 0) {
        TLOGE("[TUN] Failed to add to xpoll");
        return -1;
    }

    g_initialized = 1;
    TLOGI("[TUN] Handler initialized successfully (fd=%d)", g_tun_fd);
    TLOGI("[TUN] SOCKS5 port: %d, HTTP port: %d, VPN mode: %s",
          g_socks5_port, g_http_port, g_vpn_mode ? "yes" : "no");

    return 0;
}

void tun_handler_cleanup(void) {
    if (!g_initialized) {
        return;
    }

    /* 从事件循环移除 */
    if (g_xpoll && g_tun_fd >= 0) {
        xpoll_del_event(g_xpoll, g_tun_fd, XPOLL_READABLE);
    }

    /* 关闭所有代理连接 */
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_connections[i].active) {
            close_connection(&g_connections[i]);
        }
    }

    g_initialized = 0;
    TLOGI("[TUN] Handler cleaned up");
}

int tun_handler_get_fd(void) {
    return g_initialized ? g_tun_fd : -1;
}
