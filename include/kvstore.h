



#ifndef __SERVER_H__
#define __SERVER_H__

#define BUFFER_LENGTH		262144

#define NETWORK_REACTOR 	0
#define NETWORK_NTYCO		1
#define NETWORK_IOURING	    2

#define NETWORK_SELECT		NETWORK_NTYCO

#define ENABLE_ARRAY		1
#define ENABLE_RBTREE		1
#define ENABLE_HASH			1

#define ALLOCATOR_CUSTOM 0
#define ALLOCATOR_SYSTEM 1
#define ALLOCATOR_JEMALLOC 2

#define MEMORY_ALLOCATOR ALLOCATOR_SYSTEM

#define PERSISTENCE_ALL 0
#define PERSISTENCE_INCREMENTAL 1
#define PERSISTENCE_NOTHING 2

#define PERSISTENCE_METHOD PERSISTENCE_NOTHING

#define WAL_FILE "./out/wal.log"          // 操作日志文件
#define CHECKPOINT_FILE "./out/checkpoint.dat" // 检查点文件
#define MAX_LOG_ENTRIES 100             // 最大日志条目数，超过则创建检查点

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>

#define KVS_CMD_MIN_BLOCK 4

// 内存池配置
#define MP_DEFAULT_SIZE        (4 * 1024 * 1024)  // 4MB默认内存池大小
#define MP_BLOCK_SIZE          (2 * 1024 * 1024)// 小块内存大小
#define MP_LARGE_THRESHOLD     (4 * 1024)         // 4KB以上算大内存
#define MP_ALIGNMENT           8                  // 内存对齐

//同步功能
// 在server.h中添加
#define SYNC_PORT_BASE		16380
#define SYNC_BUFFER_SIZE	4096

// 同步操作类型
typedef enum {
    SYNC_SET = 0,
    SYNC_DEL,
    SYNC_MOD,
    SYNC_FULL,      // 全量同步
    SYNC_PING,      // 心跳检测
    SYNC_PONG
} sync_operation_t;

// 同步消息头
typedef struct sync_header_s {
    uint32_t magic;         // 魔数 0x53594E43 ("SYNC")
    uint32_t version;       // 协议版本
    sync_operation_t op;    // 操作类型
    uint32_t data_len;      // 数据长度
    uint64_t timestamp;     // 时间戳
    uint64_t sequence;      // 序列号
} sync_header_t;

// 服务器角色
typedef enum {
    ROLE_MASTER = 0,
    ROLE_SLAVE
} server_role_t;

// 从服务器信息
typedef struct slave_info_s {
    int fd;
    struct sockaddr_in addr;
    uint64_t last_ack;      // 最后确认的序列号
    time_t last_active;     // 最后活跃时间
} slave_info_t;

// 主服务器配置
typedef struct master_config_s {
    slave_info_t *slaves;
    int slave_count;
    int max_slaves;
    pthread_mutex_t lock;
    uint64_t sequence;      // 全局序列号
} master_config_t;

// 从服务器配置
typedef struct slave_config_s {
    char master_ip[16];
    int master_port;
    int master_fd;
    int connected;
    uint64_t sync_sequence; // 同步到的序列号
    pthread_t sync_thread;
} slave_config_t;


// 全局配置
extern server_role_t g_server_role;
extern master_config_t g_master;
extern slave_config_t g_slave;

void* sync_master_accept_thread(void *arg);
int sync_master_init(int max_slaves, int sync_port);
int sync_slave_init(const char *master_ip, int master_port);
int sync_pack_message(sync_operation_t op, const char *key, const char *value, char *buffer, int buffer_size);
int sync_unpack_message(const char *buffer, int length, sync_header_t *header, char *key, char *value);
int sync_unpack_message(const char *buffer, int length, sync_header_t *header, char *key, char *value);
void sync_broadcast_to_slaves(sync_operation_t op, const char *key, const char *value);
int sync_connect_to_master();
void sync_handle_master_message(const char *buffer, int length);
void* sync_slave_thread(void *arg);
int sync_slave_start();



#if ENABLE_ARRAY

typedef struct kvserver_array_item_s {
	char *key;
	char *value;
} kvserver_array_item_t;

#define KVS_ARRAY_SIZE		1024

typedef struct kvserver_array_s {
	kvserver_array_item_t *table;
	int idx;
	int total;
} kvserver_array_t;

extern kvserver_array_t global_array;

int kvserver_array_create(kvserver_array_t *inst);
void kvserver_array_destory(kvserver_array_t *inst);

int kvserver_array_set(kvserver_array_t *inst, char *key, char *value);
char* kvserver_array_get(kvserver_array_t *inst, char *key);
int kvserver_array_del(kvserver_array_t *inst, char *key);
int kvserver_array_mod(kvserver_array_t *inst, char *key, char *value);
int kvserver_array_exist(kvserver_array_t *inst, char *key);

#endif


#if ENABLE_RBTREE

#define RED				1
#define BLACK 			2

#define ENABLE_KEY_CHAR		1

#if ENABLE_KEY_CHAR
typedef char* KEY_TYPE;
#else
typedef int KEY_TYPE; // key
#endif

typedef struct _rbtree_node {
	unsigned char color;
	struct _rbtree_node *right;
	struct _rbtree_node *left;
	struct _rbtree_node *parent;
	KEY_TYPE key;
	void *value;
} rbtree_node;

typedef struct _rbtree {
	rbtree_node *root;
	rbtree_node *nil;
} rbtree;

typedef struct _rbtree kvs_rbtree_t;
extern kvs_rbtree_t global_rbtree;

int kvs_rbtree_create(kvs_rbtree_t *inst);
void kvs_rbtree_destory(kvs_rbtree_t *inst);
int kvs_rbtree_set(kvs_rbtree_t *inst, char *key, char *value);
char* kvs_rbtree_get(kvs_rbtree_t *inst, char *key);
int kvs_rbtree_del(kvs_rbtree_t *inst, char *key);
int kvs_rbtree_mod(kvs_rbtree_t *inst, char *key, char *value);
int kvs_rbtree_exist(kvs_rbtree_t *inst, char *key);

// void rbtree_save_traversal(FILE *file, rbtree *T, rbtree_node *node);
// void rbtree_save_iterative(FILE *file, rbtree *T);
int rbtree_count_nodes(rbtree *T, rbtree_node *node);



#endif

#if ENABLE_HASH

#define MAX_KEY_LEN	1024
#define MAX_VALUE_LEN	1024
#define MAX_TABLE_SIZE	1024

#define ENABLE_KEY_POINTER	1


typedef struct hashnode_s {
#if ENABLE_KEY_POINTER
	char *key;
	char *value;
#else
	char key[MAX_KEY_LEN];
	char value[MAX_VALUE_LEN];
#endif
	struct hashnode_s *next;
	
} hashnode_t;


typedef struct hashtable_s {

	hashnode_t **nodes; //* change **, 

	int max_slots;
	int count;

} hashtable_t;

typedef struct hashtable_s kvs_hash_t;
extern kvs_hash_t global_hash;

// ===== File KV (binary-safe) =====
typedef struct file_kv_entry_s {
    char   *key;        // 文件名
    uint8_t *data;      // 二进制内容
    size_t  len;        // 长度
    struct file_kv_entry_s *next;
} file_kv_entry_t;

typedef struct file_kv_table_s {
    file_kv_entry_t **slots;
    int max_slots;
    int count;
    pthread_mutex_t lock;
} file_kv_table_t;

extern file_kv_table_t g_filekv;

int filekv_init(file_kv_table_t *t, int slots);
void filekv_destroy(file_kv_table_t *t);
int filekv_set(file_kv_table_t *t, const char *key, const uint8_t *data, size_t len);   // 新增/覆盖
int filekv_mod(file_kv_table_t *t, const char *key, const uint8_t *data, size_t len);   // 必须已存在
int filekv_del(file_kv_table_t *t, const char *key);                                    // 0 ok, 1 noexist
int filekv_exist(file_kv_table_t *t, const char *key);                                  // 0 exist, 1 noexist
// 拷贝出一份到 *out（malloc），调用者 free；返回0成功/1不存在/-1错误
int filekv_get_copy(file_kv_table_t *t, const char *key, uint8_t **out, size_t *out_len);

int kvs_hash_create(kvs_hash_t *hash);
void kvs_hash_destory(kvs_hash_t *hash);
int kvs_hash_set(hashtable_t *hash, char *key, char *value);
char * kvs_hash_get(kvs_hash_t *hash, char *key);
int kvs_hash_mod(kvs_hash_t *hash, char *key, char *value);
int kvs_hash_del(kvs_hash_t *hash, char *key);
int kvs_hash_exist(kvs_hash_t *hash, char *key);

#endif



void *kvserver_malloc(size_t size);
void kvserver_free(void *ptr);

typedef int (*RCALLBACK)(int fd);


struct conn {
	int fd;

	char rbuffer[BUFFER_LENGTH];
	int rlength;

	char wbuffer[BUFFER_LENGTH];
	int wlength;

	RCALLBACK send_callback;

	union {
		RCALLBACK recv_callback;
		RCALLBACK accept_callback;
	} r_action;

	int status;
#if 0 // websocket
	char *payload;
	char mask[4];
#endif
};

typedef int (*msg_handler)(char *msg, int length, char *response);

extern int reactor_entry(unsigned short port, msg_handler handler);
extern int nty_start(unsigned short port, msg_handler handler);
extern int uring_start(unsigned short port, msg_handler handler);

int kvserver_request(char *msg, int length, char *response);

// //// 持久化相关函数
int kvserver_save(const char *filename);
int kvserver_load(const char *filename);
// void kvserver_auto_save(int interval_seconds); 

// //// 增量持久化相关函数
// 操作类型枚举
typedef enum {
    DS_ARRAY = 0,
    DS_RBTREE,
    DS_HASH,
    DS_UNKNOWN
} data_structure_t;

typedef enum {
    OP_SET = 0,
    OP_DEL,
    OP_MOD,
    OP_UNKNOWN
} operation_type_t;

// 操作日志条目结构
typedef struct {
    data_structure_t ds_type;
    operation_type_t op_type;
    char *key;
    char *value;
    time_t timestamp;
} operation_log_t;

// 增量持久化相关函数声明
int kvserver_incremental_init(void);
void kvserver_incremental_close(void);
int kvserver_log_operation(data_structure_t ds_type, operation_type_t op_type, const char *key, const char *value);
int kvserver_incremental_save(void);
int kvserver_load_from_incremental(void);
int kvserver_create_checkpoint(void);

// 持久化文件格式定义
#define KVS_MAGIC_NUMBER 0x4B565354  // "KVST" in hex
#define KVS_VERSION 1

// 文件头结构
typedef struct {
    uint32_t magic;          // 魔数，用于文件识别
    uint32_t version;        // 版本号
    uint64_t timestamp;      // 创建时间戳
} kvs_file_header_t;

// 记录头结构
typedef struct {
    uint32_t key_length;     // 键长度
    uint32_t value_length;   // 值长度
    uint8_t data_type;       // 数据类型（0=array, 1=rbtree, 2=hash）
    uint8_t reserved[3];     // 对齐填充
} kvs_record_header_t;

uint32_t calculate_checksum(const void *data, size_t len);
int safe_write(FILE *file, const void *data, size_t size);
int safe_read(FILE *file, void *data, size_t size);
int kvserver_save(const char *filename);
int kvserver_load(const char *filename);

// 内存池



// 结构体
typedef enum {
    MP_SMALL_BLOCK,    // 小块内存
    MP_LARGE_BLOCK     // 大块内存
} mp_block_type_t;

// 内存块头部信息
typedef struct mp_block_header_s {
    size_t size;                    // 块大小
    mp_block_type_t type;           // 块类型
    struct mp_block_header_s *next; // 下一个块
} mp_block_header_t;

// 内存池结构
typedef struct memory_pool_s {
    void *start;                    // 内存池起始地址
    void *end;                      // 内存池结束地址  
    void *current;                  // 当前分配位置
    size_t total_size;              // 总大小
    size_t used_size;               // 已使用大小
    
    // 空闲链表（用于小块内存回收）
    mp_block_header_t *free_list;
    
    // 大内存块链表
    mp_block_header_t *large_list;
    
    // 线程安全
    pthread_mutex_t lock;
    
    // 统计信息
    size_t alloc_count;
    size_t free_count;
    size_t small_alloc_count;
    size_t large_alloc_count;
    // 添加详细统计
    size_t small_block_count;    // 当前小块内存数量
    size_t large_block_count;    // 当前大块内存数量
    size_t total_small_alloc;    // 小块内存总分配字节数
    size_t total_large_alloc;    // 大块内存总分配字节数
    size_t peak_small_usage;     // 小块内存峰值使用
    size_t peak_large_usage;     // 大块内存峰值使用
} memory_pool_t;

// 函数声明
int memory_pool_init(size_t pool_size);
void memory_pool_destroy(void);
void *kvserver_malloc(size_t size);
void kvserver_free(void *ptr);
void memory_pool_stats(void);

void get_detailed_memory_stats(char *buffer, size_t buffer_size);





#endif


