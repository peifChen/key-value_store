#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <zlib.h>  // 用于CRC校验
#include "kvstore.h"

// 安全的文件写入函数
int safe_write(FILE *file, const void *data, size_t size) {
    return fwrite(data, 1, size, file) == size;
}

// 安全的文件读取函数
int safe_read(FILE *file, void *data, size_t size) {
    return fread(data, 1, size, file) == size;
}

// 二进制格式保存数据
int kvserver_save(const char *filename) {
    if (!filename) {
        filename = "kvstore.dat";
    }
    
    FILE *file = fopen(filename, "wb");
    if (!file) {
        printf("Error: Cannot create file %s\n", filename);
        return -1;
    }
    
    // 准备文件头
    kvs_file_header_t header;
    header.magic = KVS_MAGIC_NUMBER;
    header.version = KVS_VERSION;
    header.timestamp = (uint64_t)time(NULL);

    
    // 先写入空的文件头（稍后填充校验和）
    if (!safe_write(file, &header, sizeof(header))) {
        fclose(file);
        return -1;
    }
    
    uint32_t total_records = 0;
    
    // 保存数组数据
#if ENABLE_ARRAY
    printf("=== 保存数组数据 (临时方案) ===\n");
    int array_valid_count = 0;
    
    // 遍历整个数组，而不仅仅是前total个元素
    for (int i = 0; i < KVS_ARRAY_SIZE; i++) {
        // 只保存有效的键值对
        if (global_array.table[i].key != NULL && global_array.table[i].value != NULL) {
            kvs_record_header_t record_header;
            record_header.key_length = strlen(global_array.table[i].key);
            record_header.value_length = strlen(global_array.table[i].value);
            record_header.data_type = 0; // 0表示array
            memset(record_header.reserved, 0, sizeof(record_header.reserved));
            
            printf("保存数组[%d]: key='%s', value='%s'\n", 
                   i, global_array.table[i].key, global_array.table[i].value);
            
            if (!safe_write(file, &record_header, sizeof(record_header)) ||
                !safe_write(file, global_array.table[i].key, record_header.key_length) ||
                !safe_write(file, global_array.table[i].value, record_header.value_length)) {
                fclose(file);
                return -1;
            }
            
            total_records++;
            array_valid_count++;
        }
    }
    printf("数组保存完成: %d 个有效记录\n", array_valid_count);
#endif
// #if ENABLE_ARRAY
//     for (int i = 0; i < global_array.total; i++) {
//         if (global_array.table[i].key && global_array.table[i].value) {
//             kvs_record_header_t record_header;
//             record_header.key_length = strlen(global_array.table[i].key);
//             record_header.value_length = strlen(global_array.table[i].value);
//             record_header.data_type = 0; // 0表示array
//             memset(record_header.reserved, 0, sizeof(record_header.reserved));
            
//             // 写入记录头
//             if (!safe_write(file, &record_header, sizeof(record_header))) {
//                 fclose(file);
//                 return -1;
//             }
            
//             // 写入key数据
//             if (!safe_write(file, global_array.table[i].key, record_header.key_length)) {
//                 fclose(file);
//                 return -1;
//             }
            
//             // 写入value数据
//             if (!safe_write(file, global_array.table[i].value, record_header.value_length)) {
//                 fclose(file);
//                 return -1;
//             }
            
//             total_records++;
//         }
//     }
// #endif

    // 保存红黑树数据
#if ENABLE_RBTREE
    // 使用中序遍历保存红黑树
    rbtree_node *stack[1000]; // 假设树深度不超过1000
    int top = -1;
    rbtree_node *current = global_rbtree.root;
    
    while (current != global_rbtree.nil || top != -1) {
        while (current != global_rbtree.nil) {
            stack[++top] = current;
            current = current->left;
        }
        
        current = stack[top--];
        
        // 保存当前节点
        if (current->key && current->value) {
            kvs_record_header_t record_header;
            record_header.key_length = strlen(current->key);
            record_header.value_length = strlen((char*)current->value);
            record_header.data_type = 1; // 1表示rbtree
            memset(record_header.reserved, 0, sizeof(record_header.reserved));
            
            if (!safe_write(file, &record_header, sizeof(record_header)) ||
                !safe_write(file, current->key, record_header.key_length) ||
                !safe_write(file, (char*)current->value, record_header.value_length)) {
                fclose(file);
                return -1;
            }
            
            total_records++;
        }
        
        current = current->right;
    }
#endif

    // 保存哈希表数据
#if ENABLE_HASH
    for (int i = 0; i < global_hash.max_slots; i++) {
        hashnode_t *node = global_hash.nodes[i];
        while (node) {
            if (node->key && node->value) {
                kvs_record_header_t record_header;
                record_header.key_length = strlen(node->key);
                record_header.value_length = strlen(node->value);
                record_header.data_type = 2; // 2表示hash
                memset(record_header.reserved, 0, sizeof(record_header.reserved));
                
                if (!safe_write(file, &record_header, sizeof(record_header)) ||
                    !safe_write(file, node->key, record_header.key_length) ||
                    !safe_write(file, node->value, record_header.value_length)) {
                    fclose(file);
                    return -1;
                }
                
                total_records++;
            }
            node = node->next;
        }
    }
#endif
    
    fclose(file);
    printf("Successfully saved %u records in binary format to %s\n", total_records, filename);
    return total_records;
}

// 二进制格式加载数据
int kvserver_load(const char *filename) {
    if (!filename) {
        filename = "kvstore.dat";
    }
    
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Info: No binary data file %s\n", filename);
        return 0;
    }
    
    // 读取文件头
    kvs_file_header_t header;
    if (!safe_read(file, &header, sizeof(header))) {
        fclose(file);
        printf("Error: Cannot read file header\n");
        return -1;
    }
    
    // // 验证魔数
    // if (header.magic != KVS_MAGIC_NUMBER) {
    //     fclose(file);
    //     printf("Error: Invalid file format (wrong magic number)\n");
    //     return -1;
    // }
    
    // // 验证版本
    // if (header.version != KVS_VERSION) {
    //     fclose(file);
    //     printf("Error: Unsupported file version %u\n", header.version);
    //     return -1;
    // }
    
    uint32_t loaded_records = 0;
    
    // 读取所有记录
    while (!feof(file)) {
        kvs_record_header_t record_header;
        
        // 尝试读取记录头
        if (fread(&record_header, sizeof(record_header), 1, file) != 1) {
            // 可能是文件结束
            break;
        }
        
        // 验证长度合理性
        if (record_header.key_length > 1024 * 1024 || record_header.value_length > 10 * 1024 * 1024) {
            printf("Warning: Skipping record with suspicious sizes (key:%u, value:%u)\n", 
                   record_header.key_length, record_header.value_length);
            
            // 跳过这个损坏的记录
            fseek(file, record_header.key_length + record_header.value_length, SEEK_CUR);
            continue;
        }
        
        // 分配内存并读取key
        char *key = malloc(record_header.key_length + 1);
        char *value = malloc(record_header.value_length + 1);
        
        if (!key || !value) {
            free(key);
            free(value);
            printf("Error: Memory allocation failed\n");
            break;
        }
        
        if (!safe_read(file, key, record_header.key_length) ||
            !safe_read(file, value, record_header.value_length)) {
            free(key);
            free(value);
            printf("Error: Failed to read record data\n");
            break;
        }
        
        // 添加字符串终止符
        key[record_header.key_length] = '\0';
        value[record_header.value_length] = '\0';
        
        printf("Loading: type=%d, key='%s', value='%s'\n", 
               record_header.data_type, key, value);
        
        // 根据数据类型加载到相应的数据结构
        switch (record_header.data_type) {
#if ENABLE_ARRAY
            case 0:  //array
            kvserver_array_set(&global_array, key, value);
#endif
#if ENABLE_RBTREE
            case 1: // rbtree
                kvs_rbtree_set(&global_rbtree, key, value);
                break;
#endif
#if ENABLE_HASH
            case 2: // hash
                kvs_hash_set(&global_hash, key, value);
                break;
#endif
            default:
                printf("Warning: Unknown data type %u for key %s\n", record_header.data_type, key);
                break;
        }
        
        free(key);
        free(value);
        loaded_records++;
    }
    
    fclose(file);
    printf("Successfully loaded %u records from binary file %s\n", loaded_records, filename);
    return loaded_records;
}