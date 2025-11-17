#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include "kvstore.h"


static FILE *wal_file = NULL;
static int operation_count = 0;

// 初始化增量持久化
int kvserver_incremental_init(void) {
    // 创建out目录
    mkdir("./out", 0755);
    
    // 打开或创建WAL文件
    wal_file = fopen(WAL_FILE, "a+");
    if (!wal_file) {
        printf("Error: Cannot open WAL file %s\n", WAL_FILE);
        return -1;
    }
    
    operation_count = 0;
    printf("Incremental persistence initialized\n");
    return 0;
}

// 关闭增量持久化
void kvserver_incremental_close(void) {
    if (wal_file) {
        fclose(wal_file);
        wal_file = NULL;
    }
}

// 记录操作到日志
int kvserver_log_operation(data_structure_t ds_type, operation_type_t op_type, const char *key, const char *value) {
    if (!wal_file || !key) {
        return -1;
    }
    
    time_t now = time(NULL);
    const char *ds_str, *op_str;
    int key_len = strlen(key);
    int value_len = value ? strlen(value) : 0;
    
    // 数据结构类型
    switch (ds_type) {
        case DS_ARRAY: ds_str = "ARRAY"; break;
        case DS_RBTREE: ds_str = "RBTREE"; break;
        case DS_HASH: ds_str = "HASH"; break;
        default: ds_str = "UNKNOWN"; break;
    }
    
    // 操作类型
    switch (op_type) {
        case OP_SET: op_str = "SET"; break;
        case OP_DEL: op_str = "DEL"; break;
        case OP_MOD: op_str = "MOD"; break;
        default: op_str = "UNKNOWN"; break;
    }
    
    // 写入日志条目：时间戳|数据结构类型|操作类型|key长度|value长度|key内容value内容
    fprintf(wal_file, "%ld|%s|%s|k_l=%d;v_l=%d;%s%s\n", 
            now, ds_str, op_str, key_len, value_len, key, value ? value : "");
    
    fflush(wal_file); // 确保立即写入磁盘
    
    operation_count++;
    
    // 如果操作次数超过阈值，创建检查点
    if (operation_count >= MAX_LOG_ENTRIES) {
        kvserver_create_checkpoint();
    }
    
    return 0;
}

// 从操作日志恢复数据
int kvserver_load_from_incremental(void) {
    // 首先尝试从检查点加载
    if (kvserver_load(CHECKPOINT_FILE) >= 0) {
        printf("Loaded data from checkpoint\n");
    }
    
    // 然后重放WAL日志
    FILE *wal = fopen(WAL_FILE, "r");
    if (!wal) {
        printf("No WAL file found, starting fresh\n");
        return 0;
    }
    
    char line[1024];
    int replayed_count = 0;
    
    while (fgets(line, sizeof(line), wal)) {
        // 去除换行符
        line[strcspn(line, "\n")] = 0;
        
        // 解析日志条目：时间戳|数据结构类型|操作类型|key长度|value长度|key内容value内容
        char *timestamp_str = strtok(line, "|");
        char *ds_str = strtok(NULL, "|");  // 数据结构类型
        char *op_str = strtok(NULL, "|");  // 操作类型
        char *length_info = strtok(NULL, "|"); // "k_l=X;v_l=Y"
        char *data = strtok(NULL, ""); // 剩余的key和value内容
        
        if (!timestamp_str || !ds_str || !op_str || !length_info || !data) {
            continue; // 跳过无效条目
        }
        
        // 解析长度信息
        int key_len = 0, value_len = 0;
        if (sscanf(length_info, "k_l=%d;v_l=%d", &key_len, &value_len) != 2) {
            continue; // 长度信息格式错误
        }
        
        if (key_len <= 0 || key_len > 256) {
            continue; // 键长度不合理
        }
        
        // 提取key和value
        char key[257] = {0};
        char value[769] = {0};
        
        strncpy(key, data, key_len);
        key[key_len] = '\0';
        
        if (value_len > 0 && value_len <= 768) {
            strncpy(value, data + key_len, value_len);
            value[value_len] = '\0';
        }
        
        // 根据数据结构类型和操作类型重放操作
        if (strcmp(ds_str, "ARRAY") == 0) {
#if ENABLE_ARRAY
            if (strcmp(op_str, "SET") == 0) {
                kvserver_array_set(&global_array, key, value);
            } 
            else if (strcmp(op_str, "DEL") == 0) {
                kvserver_array_del(&global_array, key);
            }
            else if (strcmp(op_str, "MOD") == 0) {
                kvserver_array_mod(&global_array, key, value);
            }
#endif
        }
        else if (strcmp(ds_str, "RBTREE") == 0) {
#if ENABLE_RBTREE
            if (strcmp(op_str, "SET") == 0) {
                kvs_rbtree_set(&global_rbtree, key, value);
            } 
            else if (strcmp(op_str, "DEL") == 0) {
                kvs_rbtree_del(&global_rbtree, key);
            }
            else if (strcmp(op_str, "MOD") == 0) {
                kvs_rbtree_mod(&global_rbtree, key, value);
            }
#endif
        }
        else if (strcmp(ds_str, "HASH") == 0) {
#if ENABLE_HASH
            if (strcmp(op_str, "SET") == 0) {
                kvs_hash_set(&global_hash, key, value);
            } 
            else if (strcmp(op_str, "DEL") == 0) {
                kvs_hash_del(&global_hash, key);
            }
            else if (strcmp(op_str, "MOD") == 0) {
                kvs_hash_mod(&global_hash, key, value);
            }
#endif
        }
        
        replayed_count++;
    }
    
    fclose(wal);
    printf("Replayed %d operations from WAL\n", replayed_count);
    
    // 重放后创建新的检查点并清空WAL
    kvserver_create_checkpoint();
    
    return replayed_count;
}

// 创建检查点
int kvserver_create_checkpoint(void) {
    printf("Creating checkpoint...\n");
    
    // 保存当前状态到检查点文件
    int saved_count = kvserver_save(CHECKPOINT_FILE);
    if (saved_count < 0) {
        printf("Error: Failed to create checkpoint\n");
        return -1;
    }
    
    // 清空WAL文件
    if (wal_file) {
        fclose(wal_file);
    }
    
    wal_file = fopen(WAL_FILE, "w");
    if (!wal_file) {
        printf("Error: Cannot recreate WAL file\n");
        return -1;
    }
    
    operation_count = 0;
    printf("Checkpoint created with %d items, WAL cleared\n", saved_count);
    return saved_count;
}

// 增量保存（创建检查点）
int kvserver_incremental_save(void) {
    return kvserver_create_checkpoint();
}