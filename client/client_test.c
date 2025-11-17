#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>


#define MAX_MSG_LENGTH        1024
#define TIME_SUB_MS(tv1, tv2)  ((tv1.tv_sec - tv2.tv_sec) * 1000 + (tv1.tv_usec - tv2.tv_usec) / 1000)

/* =======================  长度头协议工具  ======================= */

// 读满 n 字节
static int read_exact(int fd, void *buf, int n) {
    char *p = (char *)buf;
    int off = 0;
    while (off < n) {
        ssize_t r = recv(fd, p + off, n - off, 0);
        if (r == 0) return 0;               // 对端关闭
        if (r < 0) {
            if (errno == EINTR) continue;
            perror("recv");
            return -1;
        }
        off += (int)r;
    }
    return off;
}

// 写满 n 字节
static int write_exact(int fd, const void *buf, int n) {
    const char *p = (const char *)buf;
    int off = 0;
    while (off < n) {
        ssize_t w = send(fd, p + off, n - off, 0);
        if (w < 0) {
            if (errno == EINTR) continue;
            perror("send");
            return -1;
        }
        off += (int)w;
    }
    return off;
}

// 发送一帧：4B 大端长度 + payload
static int send_frame(int fd, const char *data, int len) {
    if (len < 0) len = 0;
    uint32_t be = htonl((uint32_t)len);
    struct iovec iov[2];
    iov[0].iov_base = &be;
    iov[0].iov_len  = 4;
    iov[1].iov_base = (void *)data;
    iov[1].iov_len  = (size_t)len;

    ssize_t n = writev(fd, iov, 2);
    if (n < 0) {
        perror("writev");
        return -1;
    }
    size_t want = 4 + (size_t)len;
    if ((size_t)n == want) return (int)n;

    // 补写未写完部分
    if (n < 4) {
        size_t off = (size_t)n;
        if (write_exact(fd, ((char *)&be) + off, (int)(4 - off)) < 0) return -1;
        n = 4;
    }
    size_t wrote_payload = (size_t)n - 4;
    if (wrote_payload < (size_t)len) {
        if (write_exact(fd, data + wrote_payload, (int)((size_t)len - wrote_payload)) < 0) return -1;
    }
    return 4 + len;
}

// 接收一帧（malloc 出 payload，调用者负责 free）
static int recv_frame_alloc(int fd, char **out_data, int *out_len) {
    uint32_t be_len = 0;
    int r = read_exact(fd, &be_len, 4);
    if (r <= 0) return r; // 0=对端关闭，-1=出错
    int len = (int)ntohl(be_len);
    if (len < 0) return -1;

    char *buf = (char *)malloc((size_t)len + 1);
    if (!buf) {
        fprintf(stderr, "malloc %d failed\n", len);
        // 仍需把这帧读走，避免流被破坏
        char trash[4096];
        int left = len;
        while (left > 0) {
            int chunk = left > (int)sizeof(trash) ? (int)sizeof(trash) : left;
            int rr = read_exact(fd, trash, chunk);
            if (rr <= 0) break;
            left -= rr;
        }
        return -1;
    }
    r = read_exact(fd, buf, len);
    if (r <= 0) { free(buf); return r; }
    buf[len] = '\0';

    *out_data = buf;
    *out_len  = len;
    return len;
}

/* =======================  “五段式”编码器  =======================

  payload = [ cmd C-string(含\0, 至少4字节) ][ 4B key_len ][ 4B val_len ][ key ][ val ]

  - 4B 长度为网络字节序
  - key/value 可以为 NULL 或长度 0
*/
static int build_binary_payload(const char *cmd, const void *key, int key_len, const void *val, int val_len,
                                char **out_buf, int *out_len)
{
    if (!cmd || !out_buf || !out_len) return -1;
    int cmd_len = (int)strlen(cmd);
    int cmd_block = cmd_len + 1; // 含 \0
    if (cmd_block < 4) cmd_block = 4;

    int total = cmd_block + 4 + 4 + key_len + val_len;
    char *buf = (char *)malloc((size_t)total);
    if (!buf) return -1;

    char *p = buf;
    // 命令串
    memset(p, 0, (size_t)cmd_block);
    memcpy(p, cmd, (size_t)cmd_len);
    p += cmd_block;

    // 长度（BE）
    uint32_t be_key = htonl((uint32_t)key_len);
    uint32_t be_val = htonl((uint32_t)val_len);
    memcpy(p, &be_key, 4); p += 4;
    memcpy(p, &be_val, 4); p += 4;

    // key
    if (key_len > 0 && key) { memcpy(p, key, (size_t)key_len); p += key_len; }
    // val
    if (val_len > 0 && val) { memcpy(p, val, (size_t)val_len); p += val_len; }

    *out_buf = buf; *out_len = total; return 0;
}

/* 一个小辅助：字符串 key/value 的便捷封装 */
static int send_cmd_kv(int fd, const char *cmd, const char *key, const char *val,
                       char **out_resp, int *out_rlen)
{
    int klen = key ? (int)strlen(key) : 0;
    int vlen = val ? (int)strlen(val) : 0;
    char *payload = NULL; int plen = 0;
    if (build_binary_payload(cmd, key, klen, val, vlen, &payload, &plen) != 0) return -1;

    if (send_frame(fd, payload, plen) < 0) { free(payload); return -1; }
    free(payload);

    char *resp = NULL; int rlen = 0;
    int rr = recv_frame_alloc(fd, &resp, &rlen);
    if (rr <= 0) { if (resp) free(resp); return -1; }
    if (out_resp) *out_resp = resp; else free(resp);
    if (out_rlen) *out_rlen = rlen;
    return 0;
}

/* 新增：显式长度版本（用于文件内容） */
static int send_cmd_kv_len(int fd, const char *cmd, const char *key, const void *val, int val_len,
                           char **out_resp, int *out_rlen)
{
    int klen = key ? (int)strlen(key) : 0;
    char *payload = NULL; int plen = 0;
    if (build_binary_payload(cmd, key, klen, val, val_len, &payload, &plen) != 0) return -1;

    if (send_frame(fd, payload, plen) < 0) { free(payload); return -1; }
    free(payload);

    char *resp = NULL; int rlen = 0;
    int rr = recv_frame_alloc(fd, &resp, &rlen);
    if (rr <= 0) { if (resp) free(resp); return -1; }
    if (out_resp) *out_resp = resp; else free(resp);
    if (out_rlen) *out_rlen = rlen;
    return 0;
}



/* =======================  性能统计  ======================= */

typedef struct {
    struct timeval start_time;
    struct timeval end_time;
    long operations_count;
    long total_data_size;
} benchmark_t;

void benchmark_start(benchmark_t *bench) {
    memset(bench, 0, sizeof(benchmark_t));
    gettimeofday(&bench->start_time, NULL);
}
void benchmark_stop(benchmark_t *bench) {
    gettimeofday(&bench->end_time, NULL);
}
void benchmark_report(benchmark_t *bench, const char *name) {
    long elapsed_us = (bench->end_time.tv_sec - bench->start_time.tv_sec) * 1000000 +
                      (bench->end_time.tv_usec - bench->start_time.tv_usec);
    double elapsed_sec = elapsed_us / 1000000.0;
    double ops_per_sec = bench->operations_count / elapsed_sec;
    double throughput_mb = (bench->total_data_size / (1024.0 * 1024.0)) / elapsed_sec;

    printf("\n=== %s 性能报告 ===\n", name);
    printf("总操作数: %ld\n", bench->operations_count);
    printf("总数据量: %.2f MB\n", bench->total_data_size / (1024.0 * 1024.0));
    printf("总耗时: %.3f 秒\n", elapsed_sec);
    printf("操作频率: %.2f ops/sec\n", ops_per_sec);
    printf("吞吐量: %.2f MB/s\n", throughput_mb);
    printf("平均每次操作耗时: %.3f 微秒\n", (double)elapsed_us / bench->operations_count);
}

/* =======================  基础收发封装（长度头协议）  ======================= */

int send_msg(int connfd, char *msg, int length) {
    int len = (length >= 0) ? length : (int)strlen(msg);
    return send_frame(connfd, msg, len);
}
int recv_msg(int connfd, char *msg, int length) {
    // 为保持兼容原接口，这里接收到的数据若超过 length-1 将截断，但我们一般使用 alloc 版本
    char *data = NULL;
    int   dlen = 0;
    int r = recv_frame_alloc(connfd, &data, &dlen);
    if (r <= 0) { if (data) free(data); return r; }
    int copy = (dlen < (length - 1)) ? dlen : (length - 1);
    memcpy(msg, data, (size_t)copy);
    msg[copy] = '\0';
    free(data);
    return copy;
}

// 更推荐：直接拿完整帧（malloc）
static char *send_cmd_and_recv(int fd, const char *cmd, int *out_len_opt) {
    if (send_frame(fd, cmd, (int)strlen(cmd)) < 0) {
        fprintf(stderr, "send_frame failed\n");
        exit(1);
    }
    char *resp = NULL;
    int   rlen = 0;
    int rr = recv_frame_alloc(fd, &resp, &rlen);
    if (rr <= 0) {
        fprintf(stderr, "recv_frame failed\n");
        exit(1);
    }
    if (out_len_opt) *out_len_opt = rlen;
    return resp; // 记得 free
}

/* =======================  连接  ======================= */

int connect_tcpserver(const char *ip, unsigned short port) {
    int connfd = socket(AF_INET, SOCK_STREAM, 0);
    if (connfd < 0) {
        perror("socket");
        return -1;
    }
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip);
    server_addr.sin_port = htons(port);
    if (0 != connect(connfd, (struct sockaddr*)&server_addr, sizeof(struct sockaddr_in))) {
        perror("connect");
        close(connfd);
        return -1;
    }
    return connfd;
}

/* =======================  辅助命令  ======================= */
static int send_simple_cmd(int fd, const char *cmd, char **out_resp, int *out_rlen) {
    // 对于 MEMINFO/STATS 这类无 key/value 的命令，也用统一编码（key_len=val_len=0）
    return send_cmd_kv(fd, cmd, "", NULL, out_resp, out_rlen);
}

/* =======================  辅助：获取服务器内存信息  ======================= */

void get_server_memory_info(int connfd) {
    printf("\n=== 服务器内存使用情况 ===\n");

    int rlen = 0;
    char *meminfo_response = send_cmd_and_recv(connfd, "MEMINFO", &rlen);
    if (meminfo_response && strstr(meminfo_response, "ERROR") == NULL) {
        printf("%s\n", meminfo_response);
        free(meminfo_response);
        return;
    }
    if (meminfo_response) free(meminfo_response);

    printf("MEMINFO不可用，使用STATS命令...\n");
    char *stats_response = send_cmd_and_recv(connfd, "STATS", &rlen);
    if (stats_response) {
        printf("%s\n", stats_response);
        free(stats_response);
    } else {
        printf("无法获取服务器内存信息\n");
    }
}

/* =======================  测试用例（长度头协议）  ======================= */

static void testcase3(int fd, const char *cmd, const char *key, const char *val, const char *expect, const char *casename) {
    char *resp = NULL; int rlen = 0;
    if (send_cmd_kv(fd, cmd, key, val, &resp, &rlen) != 0) {
        fprintf(stderr, "send_cmd_kv failed: %s\n", casename);
        exit(1);
    }
    if (strcmp(resp, expect) != 0) {
        printf("==> FAILED -> %s, '%s' != '%s'\n", casename, resp, expect);
        free(resp); exit(1);
    }
    free(resp);
}

void array_testcase(int fd) {
    testcase3(fd, "SET", "Teacher", "King", "OK\r\n", "SET-Teacher");
    testcase3(fd, "GET", "Teacher", NULL, "King\r\n", "GET-Teacher");
    testcase3(fd, "MOD", "Teacher", "Darren", "OK\r\n", "MOD-Teacher");
    testcase3(fd, "GET", "Teacher", NULL, "Darren\r\n", "GET-Teacher");
    testcase3(fd, "EXIST", "Teacher", NULL, "EXIST\r\n", "EXIST-Teacher");
    testcase3(fd, "DEL", "Teacher", NULL, "OK\r\n", "DEL-Teacher");
}

void array_testcase_1w(int fd) {
    int count = 10000, count_w = 5;
    struct timeval tv_begin; gettimeofday(&tv_begin, NULL);
    for (int j=0;j<count_w;j++) for (int i=0;i<count;i++) array_testcase(fd);
    struct timeval tv_end; gettimeofday(&tv_end, NULL);
    int time_used = TIME_SUB_MS(tv_end, tv_begin);
    printf("array testcase --> time_used: %d, qps: %d\n", time_used, 90000 * 1000 / time_used);
}

void rbtree_testcase(int fd) {
    testcase3(fd, "RSET", "Teacher", "King", "OK\r\n", "RSET-Teacher");
    testcase3(fd, "RGET", "Teacher", NULL, "King\r\n", "RGET-King-Teacher");
    testcase3(fd, "RMOD", "Teacher", "Darren", "OK\r\n", "RMOD-D-Teacher");
    testcase3(fd, "RGET", "Teacher", NULL, "Darren\r\n", "RGET-Darren-Teacher");
    testcase3(fd, "REXIST", "Teacher", NULL, "EXIST\r\n", "REXIST-Teacher");
    testcase3(fd, "RDEL", "Teacher", NULL, "OK\r\n", "RDEL-Teacher");
    testcase3(fd, "RGET", "Teacher", NULL, "NO EXIST\r\n", "RGET-K-Teacher");
    testcase3(fd, "RMOD", "Teacher", "KING", "NO EXIST\r\n", "RMOD-K-Teacher");
    testcase3(fd, "REXIST", "Teacher", NULL, "NO EXIST\r\n", "REXIST-Teacher");
}

void rbtree_testcase_1w(int fd) {
    int count = 10000;
    struct timeval tv_begin; gettimeofday(&tv_begin, NULL);
    for (int i=0;i<count;i++) rbtree_testcase(fd);
    struct timeval tv_end; gettimeofday(&tv_end, NULL);
    int time_used = TIME_SUB_MS(tv_end, tv_begin);
    printf("rbtree testcase --> time_used: %d, qps: %d\n", time_used, 90000 * 1000 / time_used);
}

void rbtree_testcase_3w(int fd) {
    int count = 10000;
    struct timeval tv_begin; gettimeofday(&tv_begin, NULL);
    for (int i=0;i<count;i++) {
        char key[64], val[64];
        snprintf(key, sizeof(key), "Teacher%d", i);
        snprintf(val, sizeof(val), "King%d", i);
        testcase3(fd, "RSET", key, val, "OK\r\n", "RSET-TeacherN");
    }
    for (int i=0;i<count;i++) {
        char key[64], expect[64];
        snprintf(key, sizeof(key), "Teacher%d", i);
        snprintf(expect, sizeof(expect), "King%d\r\n", i);
        testcase3(fd, "RGET", key, NULL, expect, "RGET-TeacherN");
    }
    for (int i=0;i<count;i++) {
        char key[64], val[64];
        snprintf(key, sizeof(key), "Teacher%d", i);
        snprintf(val, sizeof(val), "King%d", i);
        testcase3(fd, "RMOD", key, val, "OK\r\n", "RMOD-TeacherN");
    }
    struct timeval tv_end; gettimeofday(&tv_end, NULL);
    int time_used = TIME_SUB_MS(tv_end, tv_begin);
    printf("rbtree testcase --> time_used: %d, qps: %d\n", time_used, 30000 * 1000 / time_used);
}

void hash_testcase_1w(int fd) {
    int count = 10000;
    benchmark_t bench; benchmark_start(&bench);
    struct timeval tv_begin; gettimeofday(&tv_begin, NULL);

    for (int i=0;i<count;i++) {
        testcase3(fd, "HSET", "Teacher", "King", "OK\r\n", "HSET-Teacher");
        testcase3(fd, "HGET", "Teacher", NULL, "King\r\n", "HGET-King-Teacher");
        testcase3(fd, "HMOD", "Teacher", "Darren", "OK\r\n", "HMOD-D-Teacher");
        testcase3(fd, "HGET", "Teacher", NULL, "Darren\r\n", "HGET-Darren-Teacher");
        testcase3(fd, "HEXIST", "Teacher", NULL, "EXIST\r\n", "HEXIST-Teacher");
        testcase3(fd, "HDEL", "Teacher", NULL, "OK\r\n", "HDEL-Teacher");
        testcase3(fd, "HGET", "Teacher", NULL, "NO EXIST\r\n", "HGET-K-Teacher");
        testcase3(fd, "HMOD", "Teacher", "KING", "NO EXIST\r\n", "HMOD-K-Teacher");
        testcase3(fd, "HEXIST", "Teacher", NULL, "NO EXIST\r\n", "HEXIST-Teacher");
    }

    struct timeval tv_end; gettimeofday(&tv_end, NULL);
    int time_used = TIME_SUB_MS(tv_end, tv_begin);
    printf("hash testcase --> time_used: %d, qps: %d\n", time_used, 30000 * 1000 / time_used);

    benchmark_stop(&bench);
    benchmark_report(&bench, "小内存测试（<4KB）");
    // 取内存统计，用统一编码发送
    char *resp = NULL; int rlen = 0;
    if (send_simple_cmd(fd, "MEMINFO", &resp, &rlen) == 0 && resp) {
        printf("\n=== 服务器内存使用情况 ===\n%s\n", resp);
        free(resp);
    }
}

/* 小/大/边界/混合测试：把发命令处都替换为 send_cmd_kv */
void memory_test_small(int fd, int count) {
    printf("开始小内存测试（<4KB），循环次数: %d\n", count);
    benchmark_t bench; benchmark_start(&bench);
    for (int i=0;i<count;i++) {
        char skey[32], sval[128], nval[128];
        snprintf(skey,sizeof(skey),"sk_%d",i);
        snprintf(sval,sizeof(sval),"sv_%d_abcde",i);
        snprintf(nval,sizeof(nval),"new_%d_12",i);

        testcase3(fd,"HSET",skey,sval,"OK\r\n","SET-Small");
        char *resp=NULL; int rlen=0; send_cmd_kv(fd,"GET",skey,NULL,&resp,&rlen); if(resp) free(resp);
        testcase3(fd,"HMOD",skey,nval,"OK\r\n","MOD-Small");
        resp=NULL; rlen=0; send_cmd_kv(fd,"HGET",skey,NULL,&resp,&rlen); if(resp){
            if (i % 1000 == 0 && i > 0) {
                printf("result= '%s'", resp);
            }
            free(resp);
        } 
        testcase3(fd,"HEXIST",skey,NULL,"EXIST\r\n","EXIST-Small");
        testcase3(fd,"HDEL",skey,NULL,"OK\r\n","DEL-Small");
    }
    benchmark_stop(&bench);
    benchmark_report(&bench,"小内存测试（<4KB）");

            // 取内存统计，用统一编码发送
    char *resp = NULL; int rlen = 0;
    if (send_simple_cmd(fd, "MEMINFO", &resp, &rlen) == 0 && resp) {
        printf("\n=== 服务器内存使用情况 ===\n%s\n", resp);
        free(resp);
    }
}

void memory_test_large(int fd, int count) {
    printf("开始大内存测试（>4KB），循环次数: %d\n", count);
    benchmark_t bench; benchmark_start(&bench);
    char large_value[8*1024]; memset(large_value,'L',sizeof(large_value)-1); large_value[sizeof(large_value)-1]='\0';
    char new_large_value[6*1024]; memset(new_large_value,'N',sizeof(new_large_value)-1); new_large_value[sizeof(new_large_value)-1]='\0';
    for (int i=0;i<count;i++) {
        char k[64]; snprintf(k,sizeof(k),"large_key_%d",i);
        testcase3(fd,"RSET",k,large_value,"OK\r\n","RSET-Large");
        char *resp=NULL; int rlen=0; send_cmd_kv(fd,"RGET",k,NULL,&resp,&rlen); if(resp) free(resp);
        testcase3(fd,"RMOD",k,new_large_value,"OK\r\n","RMOD-Large");
        resp=NULL; rlen=0; send_cmd_kv(fd,"RGET",k,NULL,&resp,&rlen); 
        if(resp){
            if (i % 1000 == 0 && i > 0) {
                printf("result= '%s'", resp);
            }
            free(resp);
        } 
        testcase3(fd,"REXIST",k,NULL,"EXIST\r\n","REXIST-Large");
        testcase3(fd,"RDEL",k,NULL,"OK\r\n","RDEL-Large");
    }
    benchmark_stop(&bench);
    benchmark_report(&bench,"大内存测试（>4KB）");
}

void memory_test_threshold(int fd, int count) {
    printf("开始边界内存测试（~4KB），循环次数: %d\n", count);
    benchmark_t bench; benchmark_start(&bench);
    char v1[4*1024 - 100]; memset(v1,'T',sizeof(v1)-1); v1[sizeof(v1)-1] = '\0';
    char v2[4*1024 + 100]; memset(v2,'O',sizeof(v2)-1); v2[sizeof(v2)-1] = '\0';
    for (int i=0;i<count;i++) {
        char k1[32],k2[32]; snprintf(k1,sizeof(k1),"threshold_key_%d",i); snprintf(k2,sizeof(k2),"over_threshold_key_%d",i);
        testcase3(fd,"SET",k1,v1,"OK\r\n","SET-Threshold");
        testcase3(fd,"SET",k2,v2,"OK\r\n","SET-OverThreshold");
        char *r=NULL; int rl=0; send_cmd_kv(fd,"GET",k1,NULL,&r,&rl); if(r) free(r);
        r=NULL; rl=0; send_cmd_kv(fd,"GET",k2,NULL,&r,&rl); if(r) free(r);
        testcase3(fd,"DEL",k1,NULL,"OK\r\n","DEL-Threshold");
        testcase3(fd,"DEL",k2,NULL,"OK\r\n","DEL-OverThreshold");
    }
    benchmark_stop(&bench);
    benchmark_report(&bench,"边界内存测试（~4KB）");
}

void memory_test_mixed(int fd, int count) {
    printf("开始混合内存测试，循环次数: %d\n", count);
    benchmark_t bench; benchmark_start(&bench);
    char small_value[512]; char medium_value[2*1024]; char large_value[8*1024];
    memset(small_value,'S',sizeof(small_value)-1); small_value[sizeof(small_value)-1]='\0';
    memset(medium_value,'M',sizeof(medium_value)-1); medium_value[sizeof(medium_value)-1]='\0';
    memset(large_value,'L',sizeof(large_value)-1); large_value[sizeof(large_value)-1]='\0';

    for (int i=0;i<count;i++) {
        char sk[32], mk[32], lk[32];
        snprintf(sk,sizeof(sk),"small_%d",i);
        snprintf(mk,sizeof(mk),"medium_%d",i);
        snprintf(lk,sizeof(lk),"large_%d",i);

        testcase3(fd,"HSET",sk,small_value,"OK\r\n","SET-Small");
        testcase3(fd,"HSET",mk,medium_value,"OK\r\n","SET-Medium");
        testcase3(fd,"HSET",lk,large_value,"OK\r\n","SET-Large");

        char *r=NULL; int rl=0;
        send_cmd_kv(fd,"HGET",sk,NULL,&r,&rl); if(r) free(r);
        r=NULL; rl=0; send_cmd_kv(fd,"HGET",mk,NULL,&r,&rl); if(r) free(r);
        r=NULL; rl=0; send_cmd_kv(fd,"HGET",lk,NULL,&r,&rl); if(r) free(r);

        testcase3(fd,"HEXIST",sk,NULL,"EXIST\r\n","EXIST-Mixed");
        testcase3(fd,"HEXIST",mk,NULL,"EXIST\r\n","EXIST-Mixed");
        testcase3(fd,"HEXIST",lk,NULL,"EXIST\r\n","EXIST-Mixed");

        // testcase3(fd,"HDEL",sk,NULL,"OK\r\n","DEL-Mixed");
        testcase3(fd,"HDEL",mk,NULL,"OK\r\n","DEL-Mixed");
        testcase3(fd,"HDEL",lk,NULL,"OK\r\n","DEL-Mixed");
    }
    benchmark_stop(&bench);
    benchmark_report(&bench,"混合内存测试");

        // 取内存统计，用统一编码发送
    char *resp = NULL; int rlen = 0;
    if (send_simple_cmd(fd, "MEMINFO", &resp, &rlen) == 0 && resp) {
        printf("\n=== 服务器内存使用情况 ===\n%s\n", resp);
        free(resp);
    }
}

//传文件进kvstore中
/* =======================  文件 -> SET 支持  ======================= */

static const char* basename_of(const char* path) {
    const char *slash = strrchr(path, '/');
#ifdef _WIN32
    const char *bslash = strrchr(path, '\\');
    if (!slash || (bslash && bslash > slash)) slash = bslash;
#endif
    return slash ? slash + 1 : path;
}

static int set_file_as_kv(int fd, const char *filepath) {
    struct stat st;
    if (stat(filepath, &st) != 0) {
        perror("stat");
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "not a regular file: %s\n", filepath);
        return -1;
    }
    size_t fsize = (size_t)st.st_size;
    FILE *fp = fopen(filepath, "rb");
    if (!fp) { perror("fopen"); return -1; }

    char *buf = (char *)malloc(fsize + 1);
    if (!buf) { fclose(fp); fprintf(stderr, "oom\n"); return -1; }
    size_t rd = fread(buf, 1, fsize, fp);
    fclose(fp);
    if (rd != fsize) {
        fprintf(stderr, "read size mismatch: expect %zu, got %zu\n", fsize, rd);
        free(buf);
        return -1;
    }
    buf[fsize] = '\0'; // 让服务端按字符串逻辑处理，保持与原机制一致

    const char *key = basename_of(filepath);
    char *resp = NULL; int rlen = 0;
    int rc = send_cmd_kv_len(fd, "SET", key, buf, (int)fsize, &resp, &rlen);
    free(buf);
    if (rc != 0) {
        fprintf(stderr, "send SET failed\n");
        return -1;
    }
    if (resp) {
        printf("%s", resp); // 打印服务器回包，如 "OK\r\n"
        free(resp);
    }
    char *r=NULL; int rl=0;
    send_cmd_kv(fd,"GET",key,NULL,&r,&rl); 
    if(r){
        printf("result= '%s'", r);
        free(r);
    }

    return 0;
}



/* =======================  main  ======================= */
int main(int argc, char *argv[]) {
    if (argc < 4) { printf("arg error\n"); return -1; }
    char *ip = argv[1]; int port = atoi(argv[2]); int mode = atoi(argv[3]);
    int data_count = 100000;

    int fd = connect_tcpserver(ip, (unsigned short)port);
    if (fd < 0) return -1;

    if (mode == 0) rbtree_testcase_1w(fd);
    else if (mode == 1) rbtree_testcase_3w(fd);
    else if (mode == 2) array_testcase_1w(fd);
    else if (mode == 3) hash_testcase_1w(fd);
    else if (mode == 4) memory_test_small(fd, data_count);
    else if (mode == 5) memory_test_large(fd, data_count);
    else if (mode == 6) memory_test_threshold(fd, data_count);
    else if (mode == 7) memory_test_mixed(fd, data_count);
    else if (mode == 8) {
        if (argc != 5) {
            printf("Mode 8 requires a file path argument!\n");
            close(fd);
            return -1;
        }
        const char *filepath = argv[4];
        int rc = set_file_as_kv(fd, filepath);
        close(fd);
        return rc == 0 ? 0 : -1;
    }

    else printf("未知测试模式: %d\n", mode);

    close(fd);
    return 0;
}
