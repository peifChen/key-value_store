

#include "nty_coroutine.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "kvstore.h"

#define MAX_CLIENT_NUM			1000000
#define TIME_SUB_MS(tv1, tv2)  ((tv1.tv_sec - tv2.tv_sec) * 1000 + (tv1.tv_usec - tv2.tv_usec) / 1000)

#ifndef BUFFER_LENGTH
#define BUFFER_LENGTH 8192
#endif

// 单帧最大长度做个上限防御（可按需调大）
#define MAX_FRAME_SIZE (16 * 1024 * 1024)  // 16MB

typedef int (*msg_handler)(char *msg, int length, char *response);
static msg_handler kvs_handler;

// 动态输入缓冲的扩容
static int ensure_cap(char **buf, int *cap, int need) {
    if (need <= *cap) return 0;
    int ncap = (*cap > 0) ? *cap : 4096;
    while (ncap < need) ncap <<= 1;
    char *tmp = (char *)realloc(*buf, (size_t)ncap);
    if (!tmp) return -1;
    *buf = tmp;
    *cap = ncap;
    return 0;
}

// 发送一帧（4 字节大端长度 + payload）
static int send_frame(int fd, const char *data, int len) {
    if (len < 0) len = 0;
    uint32_t be = htonl((uint32_t)len);
    struct iovec iov[2];
    iov[0].iov_base = &be;
    iov[0].iov_len  = 4;
    iov[1].iov_base = (void *)data;
    iov[1].iov_len  = (size_t)len;

    ssize_t total = 0;
    // 使用 writev 尽量一次性写出
    ssize_t n = writev(fd, iov, 2);
    if (n < 0) return -1;
    total = n;

    // 理论上 writev 一次应能写完 4+len，但稳妥起见补发未写完的部分
    size_t want = 4 + (size_t)len;
    if ((size_t)total == want) return (int)total;

    // 补发剩余
    // 计算已经写了多少：如果小于4，说明连长度都没写完
    if (total < 4) {
        // 先把剩余的长度字段写完
        size_t off = (size_t)total;
        while (off < 4) {
            n = send(fd, ((char *)&be) + off, 4 - off, 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                return -1;
            }
            off += (size_t)n;
        }
        total = 4;
    }
    // 再写payload剩余
    size_t wrote_payload = (size_t)total - 4;
    while (wrote_payload < (size_t)len) {
        n = send(fd, data + wrote_payload, len - (int)wrote_payload, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        wrote_payload += (size_t)n;
    }
    return 4 + len;
}

static void server_reader(void *arg) {
    int fd = *(int *)arg;
    free(arg);  // 释放在 accept() 处分配的 fd 指针

    char *inbuf = NULL;
    int cap = 0;
    int len = 0;

    for (;;) {
        char tmp[64 * 1024];
        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n == 0) {  // 对端关闭
            break;
        }
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recv");
            break;
        }

        if (ensure_cap(&inbuf, &cap, len + (int)n) != 0) {
            fprintf(stderr, "ERROR: OOM on ensure_cap\n");
            break;
        }
        memcpy(inbuf + len, tmp, (size_t)n);
        len += (int)n;

        // 解析循环：尽可能多地切出完整帧
        for (;;) {
            if (len < 4) break;  // 头都不够

            uint8_t *p = (uint8_t *)inbuf;
            int body_len = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];

            if (body_len < 0 || body_len > MAX_FRAME_SIZE) {
                // 非法长度，回错并断开
                const char *msg = "ERROR: bad length";
                (void)send_frame(fd, msg, (int)strlen(msg));
                len = 0; // 丢弃缓冲
                goto out; // 直接关闭连接
            }
            if (len < 4 + body_len) {
                // 头够，但体不够，继续 recv
                break;
            }

            // 拿到一帧完整消息
            char *payload = inbuf + 4;
            int   plen    = body_len;

            // 交给上层协议处理。注意：kvserver_request 期望 C 字符串，这里补 \0
            char *line = (char *)malloc((size_t)plen + 1);
            if (!line) {
                const char *msg = "ERROR: oom";
                (void)send_frame(fd, msg, (int)strlen(msg));
                len = 0;
                goto out;
            }
            memcpy(line, payload, (size_t)plen);
            line[plen] = '\0';

            char response[BUFFER_LENGTH] = {0};
            int  slen = -1;
            if (kvs_handler) {
                slen = kvs_handler(line, plen, response);
            }
            free(line);

            if (slen < 0) {
                const char *msg = "ERROR";
                if (send_frame(fd, msg, (int)strlen(msg)) < 0) goto out;
            } else {
                if (send_frame(fd, response, slen) < 0) goto out;
            }

            // 从缓冲中移除已消费帧
            int consumed = 4 + body_len;
            memmove(inbuf, inbuf + consumed, (size_t)(len - consumed));
            len -= consumed;
            // 继续 while，尝试切下一帧
        }
    }

out:
    if (inbuf) free(inbuf);
    close(fd);
}


static void server(void *arg) {
    unsigned short port = *(unsigned short *)arg;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in local, remote;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port   = htons(port);
    local.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        perror("bind");
        close(fd);
        return;
    }

    if (listen(fd, 256) < 0) {
        perror("listen");
        close(fd);
        return;
    }

    printf("listen port : %d\n", port);

    for (;;) {
        socklen_t len = sizeof(struct sockaddr_in);
        int cli_fd = accept(fd, (struct sockaddr *)&remote, &len);
        if (cli_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        // 不能传栈地址，分配独立指针给协程
        int *pfd = (int *)malloc(sizeof(int));
        if (!pfd) {
            close(cli_fd);
            continue;
        }
        *pfd = cli_fd;

        nty_coroutine *read_co = NULL;
        nty_coroutine_create(&read_co, server_reader, pfd);
    }
}

int nty_start(unsigned short port, msg_handler handler) {
    kvs_handler = handler;
    nty_coroutine *co = NULL;
    nty_coroutine_create(&co, server, &port);
    nty_schedule_run();
    return 0;
}




