#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#include "kvstore.h"

server_role_t g_server_role = ROLE_MASTER;
master_config_t g_master = {0};
slave_config_t g_slave = {0};


// 主服务器：接受从服务器连接的线程函数
void* sync_master_accept_thread(void *arg) {
    int sync_port = *(int*)arg;
    
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return NULL;
    }
    
    // 设置端口复用
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(sync_port);
    
    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return NULL;
    }
    
    if (listen(listen_fd, 10) < 0) {
        perror("listen");
        close(listen_fd);
        return NULL;
    }
    
    printf("Master sync server listening on port %d\n", sync_port);
    
    while (1) {
        struct sockaddr_in slave_addr;
        socklen_t addr_len = sizeof(slave_addr);
        int slave_fd = accept(listen_fd, (struct sockaddr*)&slave_addr, &addr_len);
        
        if (slave_fd < 0) {
            perror("accept");
            continue;
        }
        
        // 将新的从服务器添加到列表中
        pthread_mutex_lock(&g_master.lock);
        
        if (g_master.slave_count < g_master.max_slaves) {
            g_master.slaves[g_master.slave_count].fd = slave_fd;
            g_master.slaves[g_master.slave_count].addr = slave_addr;
            g_master.slaves[g_master.slave_count].last_active = time(NULL);
            g_master.slave_count++;
            
            printf("New slave connected: %s:%d, total slaves: %d\n",
                   inet_ntoa(slave_addr.sin_addr), ntohs(slave_addr.sin_port),
                   g_master.slave_count);
        } else {
            printf("Max slaves reached, rejecting connection\n");
            close(slave_fd);
        }
        
        pthread_mutex_unlock(&g_master.lock);
    }
    
    close(listen_fd);
    return NULL;
}

// 初始化主服务器同步功能
int sync_master_init(int max_slaves, int sync_port) {
    g_server_role = ROLE_MASTER;
    
    g_master.slaves = kvserver_malloc(max_slaves * sizeof(slave_info_t));
    if (!g_master.slaves) return -1;
    
    g_master.max_slaves = max_slaves;
    g_master.slave_count = 0;
    g_master.sequence = 0;
    pthread_mutex_init(&g_master.lock, NULL);
    
    // 启动接受从服务器连接的线程
    pthread_t accept_thread;
    int *port_ptr = kvserver_malloc(sizeof(int));
    *port_ptr = sync_port;
    pthread_create(&accept_thread, NULL, sync_master_accept_thread, port_ptr);
    
    printf("Master sync initialized, max slaves: %d, sync port: %d\n", max_slaves, sync_port);
    return 0;
}

// 初始化从服务器同步功能
int sync_slave_init(const char *master_ip, int master_port) {
    g_server_role = ROLE_SLAVE;
    
    strncpy(g_slave.master_ip, master_ip, sizeof(g_slave.master_ip) - 1);
    g_slave.master_port = master_port;
    g_slave.connected = 0;
    g_slave.sync_sequence = 0;
    
    printf("Slave sync initialized, master: %s:%d\n", master_ip, master_port);
    return 0;
}

// 序列化同步消息
int sync_pack_message(sync_operation_t op, const char *key, const char *value, 
                     char *buffer, int buffer_size) {
    if (buffer_size < sizeof(sync_header_t)) return -1;
    
    sync_header_t *header = (sync_header_t*)buffer;
    header->magic = 0x53594E43; // "SYNC"
    header->version = 1;
    header->op = op;
    header->timestamp = time(NULL);
    
    pthread_mutex_lock(&g_master.lock);
    header->sequence = g_master.sequence++;
    pthread_mutex_unlock(&g_master.lock);
    
    char *data = buffer + sizeof(sync_header_t);
    int data_len = 0;
    
    switch (op) {
        case SYNC_SET:
        case SYNC_MOD:
            if (key && value) {
                data_len = snprintf(data, buffer_size - sizeof(sync_header_t),
                                  "%s %s", key, value);
            }
            break;
        case SYNC_DEL:
            if (key) {
                data_len = snprintf(data, buffer_size - sizeof(sync_header_t), "%s", key);
            }
            break;
        case SYNC_PING:
        case SYNC_PONG:
            data_len = 0;
            break;
        default:
            break;
    }
    
    header->data_len = data_len;
    return sizeof(sync_header_t) + data_len;
}

// 解析同步消息
int sync_unpack_message(const char *buffer, int length, 
                       sync_header_t *header, char *key, char *value) {
    if (length < sizeof(sync_header_t)) return -1;
    
    memcpy(header, buffer, sizeof(sync_header_t));
    
    if (header->magic != 0x53594E43) return -1;
    
    const char *data = buffer + sizeof(sync_header_t);
    
    switch (header->op) {
        case SYNC_SET:
        case SYNC_MOD:
            if (sscanf(data, "%s %s", key, value) != 2) return -1;
            break;
        case SYNC_DEL:
            if (sscanf(data, "%s", key) != 1) return -1;
            break;
        case SYNC_PING:
        case SYNC_PONG:
            // 无数据
            break;
        default:
            return -1;
    }
    
    return 0;
}

// 主服务器：广播操作到所有从服务器
void sync_broadcast_to_slaves(sync_operation_t op, const char *key, const char *value) {
    if (g_server_role != ROLE_MASTER) return;
    
    char buffer[SYNC_BUFFER_SIZE];
    int msg_len = sync_pack_message(op, key, value, buffer, sizeof(buffer));
    if (msg_len <= 0) return;
    
    pthread_mutex_lock(&g_master.lock);
    
    for (int i = 0; i < g_master.slave_count; i++) {
        if (g_master.slaves[i].fd > 0) {
            int ret = send(g_master.slaves[i].fd, buffer, msg_len, MSG_NOSIGNAL);
            if (ret <= 0) {
                // 发送失败，标记从服务器断开
                close(g_master.slaves[i].fd);
                g_master.slaves[i].fd = -1;
            }
        }
    }
    
    // 清理断开的从服务器
    int new_count = 0;
    for (int i = 0; i < g_master.slave_count; i++) {
        if (g_master.slaves[i].fd > 0) {
            g_master.slaves[new_count++] = g_master.slaves[i];
        }
    }
    g_master.slave_count = new_count;
    
    pthread_mutex_unlock(&g_master.lock);
}

// 从服务器：连接到主服务器
int sync_connect_to_master() {
    if (g_server_role != ROLE_SLAVE) return -1;
    
    g_slave.master_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_slave.master_fd < 0) {
        perror("socket");
        return -1;
    }
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_slave.master_port);
    inet_pton(AF_INET, g_slave.master_ip, &addr.sin_addr);
    
    if (connect(g_slave.master_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(g_slave.master_fd);
        g_slave.master_fd = -1;
        return -1;
    }
    
    g_slave.connected = 1;
    printf("Connected to master %s:%d\n", g_slave.master_ip, g_slave.master_port);
    return 0;
}

// 从服务器：处理主服务器发送的同步消息
void sync_handle_master_message(const char *buffer, int length) {
    sync_header_t header;
    char key[256] = {0};
    char value[1024] = {0};
    
    if (sync_unpack_message(buffer, length, &header, key, value) < 0) {
        printf("Invalid sync message\n");
        return;
    }
    
    printf("Sync operation: %d, key: %s, value: %s\n", header.op, key, value);
    
    // 在从服务器上执行操作
    switch (header.op) {
        case SYNC_SET:
#if ENABLE_ARRAY
            kvserver_array_set(&global_array, key, value);
#endif
#if ENABLE_RBTREE  
            kvs_rbtree_set(&global_rbtree, key, value);
#endif
#if ENABLE_HASH
            kvs_hash_set(&global_hash, key, value);
#endif
            break;
            
        case SYNC_DEL:
#if ENABLE_ARRAY
            kvserver_array_del(&global_array, key);
#endif
#if ENABLE_RBTREE
            kvs_rbtree_del(&global_rbtree, key);
#endif
#if ENABLE_HASH
            kvs_hash_del(&global_hash, key);
#endif
            break;
            
        case SYNC_MOD:
#if ENABLE_ARRAY
            kvserver_array_mod(&global_array, key, value);
#endif
#if ENABLE_RBTREE
            kvs_rbtree_mod(&global_rbtree, key, value);
#endif
#if ENABLE_HASH
            kvs_hash_mod(&global_hash, key, value);
#endif
            break;
            
        default:
            break;
    }
    
    g_slave.sync_sequence = header.sequence;
}

// 从服务器同步线程
void* sync_slave_thread(void *arg) {
    while (1) {
        if (!g_slave.connected) {
            if (sync_connect_to_master() < 0) {
                sleep(5); // 重连间隔
                continue;
            }
        }
        
        char buffer[SYNC_BUFFER_SIZE];
        int length = recv(g_slave.master_fd, buffer, sizeof(buffer), 0);
        
        if (length <= 0) {
            printf("Master disconnected, reconnecting...\n");
            close(g_slave.master_fd);
            g_slave.connected = 0;
            sleep(5);
            continue;
        }
        
        sync_handle_master_message(buffer, length);
    }
    return NULL;
}

// 启动从服务器同步
int sync_slave_start() {
    if (g_server_role != ROLE_SLAVE) return -1;
    
    return pthread_create(&g_slave.sync_thread, NULL, sync_slave_thread, NULL);
}
