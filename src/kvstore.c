#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include "kvstore.h"

static const char *PERSISTENCE_FILE = "./out/kvstore.dat";
#define KVS_MAX_TOKENS 1024

const char *command[] = {
    "SET", "GET", "DEL", "MOD", "EXIST",
    "RSET", "RGET", "RDEL", "RMOD", "REXIST",
    "HSET", "HGET", "HDEL", "HMOD", "HEXIST",
    "MULTI_COMMAND", "FINISH"
};

enum {
    KVS_CMD_START = 0,
    KVS_CMD_SET = KVS_CMD_START,
    KVS_CMD_GET,
    KVS_CMD_DEL,
    KVS_CMD_MOD,
    KVS_CMD_EXIST,
    KVS_CMD_RSET,
    KVS_CMD_RGET,
    KVS_CMD_RDEL,
    KVS_CMD_RMOD,
    KVS_CMD_REXIST,
    KVS_CMD_HSET,
    KVS_CMD_HGET,
    KVS_CMD_HDEL,
    KVS_CMD_HMOD,
    KVS_CMD_HEXIST,
    KVS_CMD_MULTI_COMMAND,
    KVS_CMD_FINISH,
    KVS_CMD_COUNT,
};

// 去除 token 尾部 CR/LF
static void strip_trailing_crlf(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\r' || s[n - 1] == '\n')) {
        s[--n] = '\0';
    }
}

void signal_handler(int sig) {
    memory_pool_stats();
    printf("\n收到 %d 条数据, 保存数据中...\n", sig);

#if PERSISTENCE_METHOD == PERSISTENCE_INCREMENTAL
    kvserver_incremental_save();
#elif PERSISTENCE_METHOD == PERSISTENCE_ALL
    kvserver_save(CHECKPOINT_FILE);
#endif
    printf("已保存\n");
    exit(0);
}

int kvserver_split_token(char *msg, char *tokens[]) {
    if (msg == NULL || tokens == NULL) return -1;
    int idx = 0;
    char *token = strtok(msg, " ");
    while (token != NULL && idx < KVS_MAX_TOKENS) {
        tokens[idx++] = token;
        token = strtok(NULL, " ");
    }
    for (int i = 0; i < idx; i++) strip_trailing_crlf(tokens[i]);
    return idx;
}

/* ===================== 二进制协议解码 =====================

 帧负载格式：
  [ 命令C字符串(含\0，至少4字节，若<4则\0填充到4) ]
  [ 4B key_len (BE) ]
  [ 4B val_len (BE) ]
  [ key bytes ]
  [ val bytes ]

 返回值：
   >=0：成功；已把 tokens/ count 填好（tokens 指向临时堆内存，调用方负责释放）
   <0 ：不是新协议或解码失败（可回退旧文本处理）
*/
static int decode_binary_command(const char *buf, int len, char ***out_tokens, int *out_count, char **to_free) {
    if (!buf || len <= 0 || !out_tokens || !out_count || !to_free) return -1;

    // 1) 找命令字符串（必须包含 '\0'），且命令块起码 4 字节
    int cmd_min = KVS_CMD_MIN_BLOCK;
    if (len < cmd_min + 8) return -1; // 还没有长度段就不行

    // 命令串：从开头起，直到遇到 '\0'。如果 '\0' 出现在 1..N 之间，我们接受；
    // 要求命令块至少 4B：即便命令很短，也应该在帧里用\0填到 >=4B，这里我们不强依赖 padding 长度，只要后续长度字段位置合理即可。
    const char *p = buf;
    const char *end = buf + len;

    const char *nul = (const char*)memchr(p, '\0', (size_t)len);
    if (!nul) return -1;               // 没有 \0，不是新协议
    int cmd_len = (int)(nul - p);      // 不包含 \0 的长度
    int cmd_block = cmd_len + 1;       // 含 \0
    if (cmd_block < KVS_CMD_MIN_BLOCK) cmd_block = KVS_CMD_MIN_BLOCK;

    // 2) 读取 key_len / val_len
    if (buf + cmd_block + 8 > end) return -1;
    const uint32_t *plen = (const uint32_t *)(buf + cmd_block);
    uint32_t be_key = 0, be_val = 0;
    memcpy(&be_key, plen, 4);
    memcpy(&be_val, plen+1, 4);
    int key_len = (int)ntohl(be_key);
    int val_len = (int)ntohl(be_val);
    if (key_len < 0 || val_len < 0) return -1;

    // 3) 边界检查
    if (buf + cmd_block + 8 + key_len + val_len > end) return -1;

    const char *key_ptr = buf + cmd_block + 8;
    const char *val_ptr = key_ptr + key_len;

    // 4) 为 tokens 分配内存（一次性大块，便于释放）
    // tokens[0]=cmd, [1]=key, [2]=value(可选)
    int token_cnt = 1 + (key_len>0 ? 1:1) + (val_len>0 ? 1:0); // 至少需要一个 key（有些命令会用到），为了统一，若 key_len==0 也给空串
    if (key_len == 0) token_cnt = 2; // 只有 cmd 和 key(空)
    if (val_len > 0) token_cnt = 3;

    char **tokens = (char **)malloc(sizeof(char *) * KVS_MAX_TOKENS);
    if (!tokens) return -1;
    memset(tokens, 0, sizeof(char *) * KVS_MAX_TOKENS);

    // 为串内容分配一个拼接块：cmd + key + value（各+1 终止）
    size_t alloc_sz = (size_t)cmd_len + 1 + (size_t)key_len + 1 + (size_t)val_len + 1;
    char *storage = (char *)malloc(alloc_sz);
    if (!storage) { free(tokens); return -1; }
    memset(storage, 0, alloc_sz);

    char *w = storage;

    // cmd
    memcpy(w, p, (size_t)cmd_len);
    tokens[0] = w; w += (size_t)cmd_len + 1;

    // key（允许 key_len==0）
    if (key_len > 0) {
        memcpy(w, key_ptr, (size_t)key_len);
        tokens[1] = w; w += (size_t)key_len + 1;
    } else {
        tokens[1] = w; *w = '\0'; w += 1;
    }

    // value（可空）
    if (val_len > 0) {
        memcpy(w, val_ptr, (size_t)val_len);
        tokens[2] = w; w += (size_t)val_len + 1;
    }

    *out_tokens = tokens;
    *out_count = val_len > 0 ? 3 : 2;
    *to_free = storage;
    return 0;
}

int kvserver_protocol_process(char **tokens, int count, char *response) {
	// printf("[DEBUG] cmd=%s, count=%d, key=%s, val_present=%s, len(msg?)=%d\n",
    //    tokens[0], count, (count>1?tokens[1]:"(null)"),
    //    (count>2? "yes":"no"),(int)sizeof((char *)tokens[0]));
    if (tokens[0] == NULL || count == 0 || response == NULL) return -1;

    // 内存统计
    if (strcmp(tokens[0], "MEMINFO") == 0) {
        char buf[4096] = {0};
        get_detailed_memory_stats(buf, sizeof(buf));
        return snprintf(response, BUFFER_LENGTH, "%s\r\n", buf);
    }
    if (strcmp(tokens[0], "STATS") == 0) {
        char buf[1024] = {0};
        get_detailed_memory_stats(buf, sizeof(buf));
        return snprintf(response, BUFFER_LENGTH, "%s\r\n", buf);
    }

    if (strcmp(tokens[0], "MULTI_COMMAND") == 0) {
        return snprintf(response, BUFFER_LENGTH, "READY_FOR_MULTI_COMMANDS\r\n");
    }
    if (strcmp(tokens[0], "FINISH") == 0) {
        return snprintf(response, BUFFER_LENGTH, "MULTI_COMMANDS_FINISHED\r\n");
    }

    int cmd = KVS_CMD_START;
    for (cmd = KVS_CMD_START; cmd < KVS_CMD_COUNT; cmd++) {
        if (strcmp(tokens[0], command[cmd]) == 0) break;
    }

    int length = 0;
    int ret = 0;
    char *key = (count > 1) ? tokens[1] : NULL;
    char *value = (count > 2) ? tokens[2] : NULL;

    if (strcmp(tokens[0], "SAVE") == 0) {
#if PERSISTENCE_METHOD != PERSISTENCE_NOTHING

#if PERSISTENCE_METHOD == PERSISTENCE_INCREMENTAL
        int r = kvserver_incremental_save();
#elif PERSISTENCE_METHOD == PERSISTENCE_ALL
        int r = kvserver_save(CHECKPOINT_FILE);
#endif
        if (r >= 0) return snprintf(response, BUFFER_LENGTH, "OK: Saved %d items\r\n", r);
        return snprintf(response, BUFFER_LENGTH, "ERROR: Save failed\r\n");
#else
        return snprintf(response, BUFFER_LENGTH, "ERROR: Save failed\r\n");
#endif
    }
    if (strcmp(tokens[0], "LOAD") == 0) {
#if PERSISTENCE_METHOD != PERSISTENCE_NOTHING

#if PERSISTENCE_METHOD == PERSISTENCE_INCREMENTAL
        int r = kvserver_load_from_incremental();
#elif PERSISTENCE_METHOD == PERSISTENCE_ALL
        int r = kvserver_load(CHECKPOINT_FILE);
#endif
        if (r >= 0) return snprintf(response, BUFFER_LENGTH, "OK: Loaded %d items\r\n", r);
        return snprintf(response, BUFFER_LENGTH, "ERROR: Load failed\r\n");
#else
        return snprintf(response, BUFFER_LENGTH, "ERROR: Load failed\r\n");
#endif
    }

#if ENABLE_ARRAY
    if (cmd == KVS_CMD_SET) {
        ret = kvserver_array_set(&global_array, key, value);
        if (ret < 0) {
            length = snprintf(response, BUFFER_LENGTH, "ERROR\r\n");
        } else {
            if (ret == 0) {
                length = snprintf(response, BUFFER_LENGTH, "OK\r\n");
                global_array.total++;
                if (g_server_role == ROLE_MASTER) {
                    sync_broadcast_to_slaves(SYNC_SET, key, value);
                }
                kvserver_log_operation(DS_ARRAY, OP_SET, key, value);
            } else {
                length = snprintf(response, BUFFER_LENGTH, "EXIST\r\n");
            }
        }
    } else if (cmd == KVS_CMD_GET) {
        char *result = kvserver_array_get(&global_array, key);
        if (result == NULL) {
            length = snprintf(response, BUFFER_LENGTH, "NO EXIST\r\n");
        } else {
            length = snprintf(response, BUFFER_LENGTH, "%s\r\n", result);
        }
    } else if (cmd == KVS_CMD_DEL) {
        ret = kvserver_array_del(&global_array, key);
        if (ret < 0) {
            length = snprintf(response, BUFFER_LENGTH, "ERROR\r\n");
        } else if (ret == 0) {
            length = snprintf(response, BUFFER_LENGTH, "OK\r\n");
            global_array.total--;
            kvserver_log_operation(DS_ARRAY, OP_DEL, key, NULL);
            if (g_server_role == ROLE_MASTER) {
                sync_broadcast_to_slaves(SYNC_DEL, key, NULL);
            }
        } else {
            length = snprintf(response, BUFFER_LENGTH, "NO EXIST\r\n");
        }
    } else if (cmd == KVS_CMD_MOD) {
        ret = kvserver_array_mod(&global_array, key, value);
        if (ret < 0) {
            length = snprintf(response, BUFFER_LENGTH, "ERROR\r\n");
        } else if (ret == 0) {
            length = snprintf(response, BUFFER_LENGTH, "OK\r\n");
            kvserver_log_operation(DS_ARRAY, OP_MOD, key, value);
            if (g_server_role == ROLE_MASTER) {
                sync_broadcast_to_slaves(SYNC_MOD, key, value);
            }
        } else {
            length = snprintf(response, BUFFER_LENGTH, "NO EXIST\r\n");
        }
    } else if (cmd == KVS_CMD_EXIST) {
        ret = kvserver_array_exist(&global_array, key);
        length = snprintf(response, BUFFER_LENGTH, "%s\r\n", ret == 0 ? "EXIST" : "NO EXIST");
    }
#endif

#if ENABLE_RBTREE
    if (cmd == KVS_CMD_RSET) {
        ret = kvs_rbtree_set(&global_rbtree, key, value);
        if (ret < 0) {
            length = snprintf(response, BUFFER_LENGTH, "ERROR\r\n");
        } else if (ret == 0) {
            length = snprintf(response, BUFFER_LENGTH, "OK\r\n");
            kvserver_log_operation(DS_RBTREE, OP_SET, key, value);
            if (g_server_role == ROLE_MASTER) {
                sync_broadcast_to_slaves(SYNC_SET, key, value);
            }
        } else {
            length = snprintf(response, BUFFER_LENGTH, "EXIST\r\n");
        }
    } else if (cmd == KVS_CMD_RGET) {
        char *result = kvs_rbtree_get(&global_rbtree, key);
        if (result == NULL) {
            length = snprintf(response, BUFFER_LENGTH, "NO EXIST\r\n");
        } else {
            length = snprintf(response, BUFFER_LENGTH, "%s\r\n", result);
        }
    } else if (cmd == KVS_CMD_RDEL) {
        ret = kvs_rbtree_del(&global_rbtree, key);
        if (ret < 0) {
            length = snprintf(response, BUFFER_LENGTH, "ERROR\r\n");
        } else if (ret == 0) {
            length = snprintf(response, BUFFER_LENGTH, "OK\r\n");
            kvserver_log_operation(DS_RBTREE, OP_DEL, key, NULL);
            if (g_server_role == ROLE_MASTER) {
                sync_broadcast_to_slaves(SYNC_DEL, key, NULL);
            }
        } else {
            length = snprintf(response, BUFFER_LENGTH, "NO EXIST\r\n");
        }
    } else if (cmd == KVS_CMD_RMOD) {
        ret = kvs_rbtree_mod(&global_rbtree, key, value);
        if (ret < 0) {
            length = snprintf(response, BUFFER_LENGTH, "ERROR\r\n");
        } else if (ret == 0) {
            length = snprintf(response, BUFFER_LENGTH, "OK\r\n");
            kvserver_log_operation(DS_RBTREE, OP_MOD, key, value);
            if (g_server_role == ROLE_MASTER) {
                sync_broadcast_to_slaves(SYNC_MOD, key, value);
            }
        } else {
            length = snprintf(response, BUFFER_LENGTH, "NO EXIST\r\n");
        }
    } else if (cmd == KVS_CMD_REXIST) {
        ret = kvs_rbtree_exist(&global_rbtree, key);
        length = snprintf(response, BUFFER_LENGTH, "%s\r\n", ret == 0 ? "EXIST" : "NO EXIST");
    }
#endif

#if ENABLE_HASH
    if (cmd == KVS_CMD_HSET) {
        ret = kvs_hash_set(&global_hash, key, value);
        if (ret < 0) {
            length = snprintf(response, BUFFER_LENGTH, "ERROR\r\n");
        } else {
            if (ret == 0) {
                length = snprintf(response, BUFFER_LENGTH, "OK\r\n");
                kvserver_log_operation(DS_HASH, OP_SET, key, value);
                if (g_server_role == ROLE_MASTER) {
                    sync_broadcast_to_slaves(SYNC_SET, key, value);
                }
            } else {
                length = snprintf(response, BUFFER_LENGTH, "EXIST\r\n");
            }
        }
    } else if (cmd == KVS_CMD_HGET) {
        char *result = kvs_hash_get(&global_hash, key);
        if (result == NULL) {
            length = snprintf(response, BUFFER_LENGTH, "NO EXIST\r\n");
        } else {
            length = snprintf(response, BUFFER_LENGTH, "%s\r\n", result);
        }
    } else if (cmd == KVS_CMD_HDEL) {
        ret = kvs_hash_del(&global_hash, key);
        if (ret < 0) {
            length = snprintf(response, BUFFER_LENGTH, "ERROR\r\n");
        } else {
            if (ret == 0) {
                length = snprintf(response, BUFFER_LENGTH, "OK\r\n");
                kvserver_log_operation(DS_HASH, OP_DEL, key, NULL);
                if (g_server_role == ROLE_MASTER) {
                    sync_broadcast_to_slaves(SYNC_DEL, key, NULL);
                }
            } else {
                length = snprintf(response, BUFFER_LENGTH, "NO EXIST\r\n");
            }
        }
    } else if (cmd == KVS_CMD_HMOD) {
        ret = kvs_hash_mod(&global_hash, key, value);
        if (ret < 0) {
            length = snprintf(response, BUFFER_LENGTH, "ERROR\r\n");
        } else if (ret == 0) {
            length = snprintf(response, BUFFER_LENGTH, "OK\r\n");
            kvserver_log_operation(DS_HASH, OP_MOD, key, value);
            if (g_server_role == ROLE_MASTER) {
                sync_broadcast_to_slaves(SYNC_MOD, key, value);
            }
        } else {
            length = snprintf(response, BUFFER_LENGTH, "NO EXIST\r\n");
        }
    } else if (cmd == KVS_CMD_HEXIST) {
        ret = kvs_hash_exist(&global_hash, key);
        length = snprintf(response, BUFFER_LENGTH, "%s\r\n", ret == 0 ? "EXIST" : "NO EXIST");
    }
#endif

    if (strcmp(tokens[0], "CHECKPOINT") == 0) {
        int r = kvserver_incremental_save();
        if (r >= 0) return snprintf(response, BUFFER_LENGTH, "OK: 检查点创建了 %d 个元素\r\n", r);
        return snprintf(response, BUFFER_LENGTH, "ERROR: 检查点创建失败\r\n");
    }

    if (length == 0 && cmd == KVS_CMD_COUNT) {
        length = snprintf(response, BUFFER_LENGTH, "ERROR\r\n");
    }
    return length;
}

int kvserver_process_multi_commands(char *multi_cmd_block, int length, char *response) {
    if (multi_cmd_block == NULL || length <= 0 || response == NULL) return -1;

    char *saveptr = NULL;
    char *line = strtok_r(multi_cmd_block, "\n", &saveptr);
    int response_length = 0;
    char temp_response[BUFFER_LENGTH] = {0};

    if (line && strcmp(line, "#MULTI_COMMAND") == 0) {
        line = strtok_r(NULL, "\n", &saveptr);
    }

    while (line != NULL) {
        line[strcspn(line, "\r\n")] = 0;

        if (strcmp(line, "#FINISH") == 0) break;
        if (strlen(line) == 0) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        memset(temp_response, 0, sizeof(temp_response));
        int ret = kvserver_request(line, (int)strlen(line), temp_response);

        if (ret >= 0) {
            int temp_len = (int)strlen(temp_response);
            if (response_length + temp_len < BUFFER_LENGTH - 1) {
                strcat(response + response_length, temp_response);
                response_length += temp_len;
            } else {
                strcat(response + response_length, "ERROR: Response buffer full\r\n");
                break;
            }
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }
    return response_length;
}

/* ===================== 入口：request（改造点） ===================== */
int kvserver_request(char *msg, int length, char *response) {
    if (msg == NULL || length <= 0 || response == NULL) return -1;

    // 1) 优先尝试按“新二进制协议”解码
    char **tokens = NULL; int count = 0; char *storage = NULL;
    if (decode_binary_command(msg, length, &tokens, &count, &storage) == 0) {
        int r = kvserver_protocol_process(tokens, count, response);
        if (storage) free(storage);
        if (tokens) free(tokens);
        return r;
    }

    // 2) 兼容旧文本协议（例如 MULTI 命令块）
    if (strncmp(msg, "#MULTI_COMMAND", 14) == 0) {
        return kvserver_process_multi_commands(msg, length, response);
    }

    char *toks[KVS_MAX_TOKENS] = {0};
    // 注意：这里会修改 msg（strtok），但网络层已做了拷贝（line[plen] = '\0'），不影响下一帧
    int cnt = kvserver_split_token(msg, toks);
    if (cnt == -1) return -1;
    return kvserver_protocol_process(toks, cnt, response);
}


int kvserver_response(struct conn *c) { (void)c; return 0; }


int init_kvengine(void) {
    if (memory_pool_init(MP_DEFAULT_SIZE) < 0) {
        printf("ERROR: Failed to initialize memory pool\n");
    } else {
        printf("Memory pool initialized successfully\n");
    }

#if ENABLE_ARRAY
    memset(&global_array, 0, sizeof(kvserver_array_t));
    kvserver_array_create(&global_array);
#endif
#if ENABLE_RBTREE
    memset(&global_rbtree, 0, sizeof(kvs_rbtree_t));
    kvs_rbtree_create(&global_rbtree);
#endif
#if ENABLE_HASH
    memset(&global_hash, 0, sizeof(kvs_hash_t));
    kvs_hash_create(&global_hash);
#endif

#if PERSISTENCE_METHOD != PERSISTENCE_NOTHING

#if PERSISTENCE_METHOD == PERSISTENCE_INCREMENTAL
    if (kvserver_incremental_init() < 0) {
        printf("Warning: Incremental persistence init failed\n");
    }
    kvserver_load_from_incremental();
#elif PERSISTENCE_METHOD == PERSISTENCE_ALL
    kvserver_load(CHECKPOINT_FILE);
#endif
#endif

    return 0;
}

void dest_kvengine(void) {
#if ENABLE_ARRAY
    kvserver_array_destory(&global_array);
#endif
#if ENABLE_RBTREE
    kvs_rbtree_destory(&global_rbtree);
#endif
#if ENABLE_HASH
    kvs_hash_destory(&global_hash);
#endif
    memory_pool_destroy();
}

int main(int argc, char *argv[]) {
    int port = atoi(argv[1]);

    init_kvengine();

    if (argc == 2) {
        int sync_port = port + 1000;
        sync_master_init(10, sync_port);
        printf("Starting as MASTER on port %d, sync port: %d\n", port, sync_port);
    } else if (argc == 4) {
        char *master_ip = argv[2];
        int master_port = atoi(argv[3]);
        sync_slave_init(master_ip, master_port + 1000);
        sync_slave_start();
        printf("Starting as SLAVE on port %d, master: %s:%d\n", port, master_ip, master_port + 1000);
    } else {
        printf("Invalid arguments\n");
        return -1;
    }
#if PERSISTENCE_METHOD != PERSISTENCE_NOTHING
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#endif

#if (NETWORK_SELECT == NETWORK_REACTOR)
    reactor_entry(port, kvserver_request);
#elif (NETWORK_SELECT == NETWORK_NTYCO)
    nty_start(port, kvserver_request);
#elif (NETWORK_SELECT == NETWORK_IOURING)
    uring_start(port, kvserver_request);
#endif
    dest_kvengine();
    return 0;
}