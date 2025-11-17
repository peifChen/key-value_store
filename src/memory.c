#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "kvstore.h"  

#if MEMORY_ALLOCATOR == ALLOCATOR_JEMALLOC
  #include <jemalloc/jemalloc.h>

  /* 你的系统 libjemalloc 只导出无前缀的符号（如 mallctl），
     这里在“未使用 je_ 前缀重命名”的情况下，把 je_* 映射到无前缀版本，
     从而同时兼容两种构建。 */
  #ifndef JEMALLOC_MANGLE
    #ifndef je_malloc
      #define je_malloc  malloc
    #endif
    #ifndef je_free
      #define je_free    free
    #endif
    #ifndef je_mallctl
      #define je_mallctl mallctl
    #endif
  #endif
#endif


// ====== 通用：自定义内存池用到的定义 ======
static memory_pool_t *g_memory_pool = NULL;

#define MP_ALIGN(size, alignment) (((size) + (alignment) - 1) & ~((alignment) - 1))
#define MP_ALIGN_PTR(ptr, alignment) (void *)(((size_t)(ptr) + (alignment) - 1) & ~((alignment) - 1))

static mp_block_header_t *get_block_header(void *ptr) {
    return (mp_block_header_t *)((char *)ptr - sizeof(mp_block_header_t));
}

// =====================================================
// =============== 1) 自定义内存池实现 ==================
// =====================================================
#if MEMORY_ALLOCATOR == ALLOCATOR_CUSTOM

int memory_pool_init(size_t pool_size) {
    if (g_memory_pool != NULL) return 0;
    if (pool_size == 0) pool_size = MP_DEFAULT_SIZE;

    g_memory_pool = (memory_pool_t *)malloc(sizeof(memory_pool_t));
    if (!g_memory_pool) return -1;
    memset(g_memory_pool, 0, sizeof(memory_pool_t));

    g_memory_pool->start = malloc(pool_size);
    if (!g_memory_pool->start) {
        free(g_memory_pool);
        g_memory_pool = NULL;
        return -1;
    }

    g_memory_pool->end = (char *)g_memory_pool->start + pool_size;
    g_memory_pool->current = g_memory_pool->start;
    g_memory_pool->total_size = pool_size;
    g_memory_pool->used_size = 0;
    g_memory_pool->free_list = NULL;
    g_memory_pool->large_list = NULL;

    pthread_mutex_init(&g_memory_pool->lock, NULL);

    printf("Memory pool initialized: %zu bytes\n", pool_size);
    return 0;
}

void memory_pool_destroy(void) {
    if (!g_memory_pool) return;

    pthread_mutex_lock(&g_memory_pool->lock);

    mp_block_header_t *large_block = g_memory_pool->large_list;
    while (large_block) {
        mp_block_header_t *next = large_block->next;
        free(large_block);
        large_block = next;
    }

    free(g_memory_pool->start);

    pthread_mutex_unlock(&g_memory_pool->lock);
    pthread_mutex_destroy(&g_memory_pool->lock);

    free(g_memory_pool);
    g_memory_pool = NULL;

    printf("Memory pool destroyed\n");
}

static void *alloc_from_pool(size_t size) {
    mp_block_header_t **prev = &g_memory_pool->free_list;
    mp_block_header_t *current = g_memory_pool->free_list;

    while (current) {
        if (current->size >= size) {
            *prev = current->next;
            g_memory_pool->free_count--;
            return (void *)((char *)current + sizeof(mp_block_header_t));
        }
        prev = &current->next;
        current = current->next;
    }

    size_t required_size = MP_ALIGN(size + sizeof(mp_block_header_t), MP_ALIGNMENT);
    if ((char *)g_memory_pool->current + required_size > (char *)g_memory_pool->end) {
        return NULL;
    }

    mp_block_header_t *new_block = (mp_block_header_t *)g_memory_pool->current;
    new_block->size = size;
    new_block->type = MP_SMALL_BLOCK;
    new_block->next = NULL;

    g_memory_pool->current = (char *)g_memory_pool->current + required_size;
    g_memory_pool->used_size += required_size;

    return (void *)((char *)new_block + sizeof(mp_block_header_t));
}

static void *alloc_large(size_t size) {
    size_t total_size = sizeof(mp_block_header_t) + size;
    mp_block_header_t *block = (mp_block_header_t *)malloc(total_size);
    if (!block) return NULL;

    block->size = size;
    block->type = MP_LARGE_BLOCK;
    block->next = g_memory_pool->large_list;
    g_memory_pool->large_list = block;

    g_memory_pool->large_alloc_count++;
    return (void *)((char *)block + sizeof(mp_block_header_t));
}

void *kvserver_malloc(size_t size) {
    if (!g_memory_pool) return malloc(size);
    if (size == 0) return NULL;

    pthread_mutex_lock(&g_memory_pool->lock);

    void *ptr = NULL;
    if (size <= MP_LARGE_THRESHOLD){
        ptr = alloc_from_pool(size);
        if (ptr){ 
            g_memory_pool->small_alloc_count++; 
            g_memory_pool->alloc_count++; 
        } else{
            ptr = alloc_large(size);
            // if (ptr) { g_memory_pool->large_alloc_count++; g_memory_pool->alloc_count++; }
            if (ptr) { g_memory_pool->alloc_count++; }
        }
    } else{
        ptr = alloc_large(size);
        if (ptr) {
            g_memory_pool->alloc_count++;
        }
    }

    if (ptr) {
        if (size <= MP_LARGE_THRESHOLD) {
            g_memory_pool->small_block_count++;
            g_memory_pool->total_small_alloc += size;
            if (g_memory_pool->total_small_alloc > g_memory_pool->peak_small_usage)
                g_memory_pool->peak_small_usage = g_memory_pool->total_small_alloc;
        } else {
            g_memory_pool->large_block_count++;
            g_memory_pool->total_large_alloc += size;
            if (g_memory_pool->total_large_alloc > g_memory_pool->peak_large_usage)
                g_memory_pool->peak_large_usage = g_memory_pool->total_large_alloc;
        }
    }

    pthread_mutex_unlock(&g_memory_pool->lock);

    // if (!ptr && size <= MP_LARGE_THRESHOLD) {
    //     ptr = malloc(size);
    // }
    return ptr;
}

void kvserver_free(void *ptr) {
    if (!ptr) return;
    if (!g_memory_pool) { free(ptr); return; }

    pthread_mutex_lock(&g_memory_pool->lock);

    mp_block_header_t *block = get_block_header(ptr);
    if (block->type == MP_SMALL_BLOCK) {
        block->next = g_memory_pool->free_list;
        g_memory_pool->free_list = block;
        g_memory_pool->free_count++;
        g_memory_pool->small_block_count--;
        g_memory_pool->total_small_alloc -= block->size;
    } else {
        mp_block_header_t **prev = &g_memory_pool->large_list;
        mp_block_header_t *cur  = g_memory_pool->large_list;
        while (cur) {
            if (cur == block) {
                *prev = cur->next;
                g_memory_pool->large_block_count--;
                g_memory_pool->total_large_alloc -= block->size;
                pthread_mutex_unlock(&g_memory_pool->lock);
                free(block);
                pthread_mutex_lock(&g_memory_pool->lock);
                break;
            }
            prev = &cur->next;
            cur  = cur->next;
        }
    }
    g_memory_pool->alloc_count--;
    pthread_mutex_unlock(&g_memory_pool->lock);
}

void get_detailed_memory_stats(char *buffer, size_t buffer_size) {
    if (!g_memory_pool || !buffer) {
        snprintf(buffer, buffer_size, "Memory pool not initialized");
        return;
    }

    pthread_mutex_lock(&g_memory_pool->lock);

    double usage_percent = (double)g_memory_pool->used_size / g_memory_pool->total_size * 100.0;
    double small_usage_percent = (double)g_memory_pool->total_small_alloc / g_memory_pool->total_size * 100.0;
    double large_usage_percent = (double)g_memory_pool->total_large_alloc / g_memory_pool->total_size * 100.0;

    snprintf(buffer, buffer_size,
        "=== 详细内存统计（阈值: %d KB） ===\n"
        "分配器: custom-pool\n"
        "总池大小: %zu bytes (%.2f MB)\n"
        "总使用量(线性推进): %zu bytes (%.2f MB) [%.2f%%]\n"
        "\n小块内存（<= %d KB）:\n"
        "  当前块数: %zu\n"
        "  当前使用: %zu bytes (%.2f MB) [%.2f%%]\n"
        "  峰值使用: %zu bytes (%.2f MB)\n"
        "\n大块内存（> %d KB）:\n"
        "  当前块数: %zu\n"
        "  当前使用: %zu bytes (%.2f MB) [%.2f%%]\n"
        "  峰值使用: %zu bytes (%.2f MB)\n"
        "\n分配统计:\n"
        "  总分配次数: %zu\n"
        "  空闲块数: %zu\n"
        "  小块分配次数: %zu\n"
        "  大块分配次数: %zu",
        MP_LARGE_THRESHOLD/1024,
        g_memory_pool->total_size, g_memory_pool->total_size/(1024.0*1024.0),
        g_memory_pool->used_size, g_memory_pool->used_size/(1024.0*1024.0), usage_percent,
        MP_LARGE_THRESHOLD/1024,
        g_memory_pool->small_block_count,
        g_memory_pool->total_small_alloc, g_memory_pool->total_small_alloc/(1024.0*1024.0), small_usage_percent,
        g_memory_pool->peak_small_usage, g_memory_pool->peak_small_usage/(1024.0*1024.0),
        MP_LARGE_THRESHOLD/1024,
        g_memory_pool->large_block_count,
        g_memory_pool->total_large_alloc, g_memory_pool->total_large_alloc/(1024.0*1024.0), large_usage_percent,
        g_memory_pool->peak_large_usage, g_memory_pool->peak_large_usage/(1024.0*1024.0),
        g_memory_pool->alloc_count,
        g_memory_pool->free_count,
        g_memory_pool->small_alloc_count,
        g_memory_pool->large_alloc_count
    );

    pthread_mutex_unlock(&g_memory_pool->lock);
}

void memory_pool_stats(void) {
    if (!g_memory_pool) { printf("Memory pool not initialized\n"); return; }

    pthread_mutex_lock(&g_memory_pool->lock);
    printf("=== Memory Pool Statistics ===\n");
    printf("Total size: %zu bytes\n", g_memory_pool->total_size);
    printf("Used size(linear advanced): %zu bytes\n", g_memory_pool->used_size);
    printf("Alloc count: %zu, Free-list count: %zu\n",
           g_memory_pool->alloc_count, g_memory_pool->free_count);
    printf("Small blocks: %zu, Large blocks: %zu\n",
           g_memory_pool->small_block_count, g_memory_pool->large_block_count);
    pthread_mutex_unlock(&g_memory_pool->lock);
}

// =====================================================
// ================= 2) 系统 malloc 实现 =================
// =====================================================
#elif MEMORY_ALLOCATOR == ALLOCATOR_SYSTEM

// 为统计能力，给系统 malloc 包一层 size 头
typedef struct sys_hdr_s {
    size_t sz;
} sys_hdr_t;

static struct {
    pthread_mutex_t lock;
    size_t alloc_count;
    size_t free_count;
    size_t current_bytes;
    size_t peak_bytes;
} g_sys_stats = { .lock = PTHREAD_MUTEX_INITIALIZER };

int memory_pool_init(size_t pool_size) {
    (void)pool_size;
    printf("Using system malloc\n");
    return 0;
}

void memory_pool_destroy(void) {
    printf("System malloc cleanup\n");
}

static void sys_on_alloc(size_t sz) {
    pthread_mutex_lock(&g_sys_stats.lock);
    g_sys_stats.alloc_count++;
    g_sys_stats.current_bytes += sz;
    if (g_sys_stats.current_bytes > g_sys_stats.peak_bytes)
        g_sys_stats.peak_bytes = g_sys_stats.current_bytes;
    pthread_mutex_unlock(&g_sys_stats.lock);
}

static void sys_on_free(size_t sz) {
    pthread_mutex_lock(&g_sys_stats.lock);
    g_sys_stats.free_count++;
    if (g_sys_stats.current_bytes >= sz) g_sys_stats.current_bytes -= sz;
    else g_sys_stats.current_bytes = 0;
    pthread_mutex_unlock(&g_sys_stats.lock);
}

void *kvserver_malloc(size_t size) {
    if (size == 0) return NULL;
    size_t total = sizeof(sys_hdr_t) + size;
    sys_hdr_t *hdr = (sys_hdr_t *)malloc(total);
    if (!hdr) return NULL;
    hdr->sz = size;
    sys_on_alloc(size);
    return (void *)(hdr + 1);
}

void kvserver_free(void *ptr) {
    if (!ptr) return;
    sys_hdr_t *hdr = ((sys_hdr_t *)ptr) - 1;
    size_t sz = hdr->sz;
    sys_on_free(sz);
    free(hdr);
}

void get_detailed_memory_stats(char *buffer, size_t buffer_size) {
    if (!buffer) return;
    pthread_mutex_lock(&g_sys_stats.lock);
    snprintf(buffer, buffer_size,
        "=== 详细内存统计（系统 malloc） ===\n"
        "分配器: system-malloc\n"
        "当前占用: %zu bytes (%.2f MB)\n"
        "峰值占用: %zu bytes (%.2f MB)\n"
        "分配次数: %zu\n"
        "释放次数: %zu\n",
        g_sys_stats.current_bytes, g_sys_stats.current_bytes/(1024.0*1024.0),
        g_sys_stats.peak_bytes, g_sys_stats.peak_bytes/(1024.0*1024.0),
        g_sys_stats.alloc_count, g_sys_stats.free_count
    );
    pthread_mutex_unlock(&g_sys_stats.lock);
}

void memory_pool_stats(void) {
    pthread_mutex_lock(&g_sys_stats.lock);
    printf("=== System Malloc Statistics ===\n");
    printf("Current Bytes: %zu, Peak Bytes: %zu\n",
           g_sys_stats.current_bytes, g_sys_stats.peak_bytes);
    printf("Alloc Count: %zu, Free Count: %zu\n",
           g_sys_stats.alloc_count, g_sys_stats.free_count);
    pthread_mutex_unlock(&g_sys_stats.lock);
}

// =====================================================
// =================== 3) jemalloc 实现 =================
// =====================================================
#elif MEMORY_ALLOCATOR == ALLOCATOR_JEMALLOC

// 同样包一层 size 头便于对比统计（jemalloc 自身也有 stats，我们两者都提供）
typedef struct je_hdr_s {
    size_t sz;
} je_hdr_t;

static struct {
    pthread_mutex_t lock;
    size_t alloc_count;
    size_t free_count;
    size_t current_bytes;
    size_t peak_bytes;
} g_je_stats = { .lock = PTHREAD_MUTEX_INITIALIZER };

int memory_pool_init(size_t pool_size) {
    (void)pool_size;
    printf("Using jemalloc\n");
    return 0;
}

void memory_pool_destroy(void) {
    printf("Jemalloc cleanup\n");
}

static void je_on_alloc(size_t sz) {
    pthread_mutex_lock(&g_je_stats.lock);
    g_je_stats.alloc_count++;
    g_je_stats.current_bytes += sz;
    if (g_je_stats.current_bytes > g_je_stats.peak_bytes)
        g_je_stats.peak_bytes = g_je_stats.current_bytes;
    pthread_mutex_unlock(&g_je_stats.lock);
}

static void je_on_free(size_t sz) {
    pthread_mutex_lock(&g_je_stats.lock);
    g_je_stats.free_count++;
    if (g_je_stats.current_bytes >= sz) g_je_stats.current_bytes -= sz;
    else g_je_stats.current_bytes = 0;
    pthread_mutex_unlock(&g_je_stats.lock);
}

void *kvserver_malloc(size_t size) {
    if (size == 0) return NULL;
    size_t total = sizeof(je_hdr_t) + size;
    je_hdr_t *hdr = (je_hdr_t *)je_malloc(total);
    if (!hdr) return NULL;
    hdr->sz = size;
    je_on_alloc(size);
    return (void *)(hdr + 1);
}

void kvserver_free(void *ptr) {
    if (!ptr) return;
    je_hdr_t *hdr = ((je_hdr_t *)ptr) - 1;
    size_t sz = hdr->sz;
    je_on_free(sz);
    je_free(hdr);
}

void get_detailed_memory_stats(char *buffer, size_t buffer_size) {
    if (!buffer) return;

    // 我们自己的统计（可与 system/custom 对比）
    pthread_mutex_lock(&g_je_stats.lock);
    size_t cur = g_je_stats.current_bytes;
    size_t peak = g_je_stats.peak_bytes;
    size_t ac = g_je_stats.alloc_count;
    size_t fc = g_je_stats.free_count;
    pthread_mutex_unlock(&g_je_stats.lock);

    // jemalloc 内部统计（更底层的视角）
    size_t allocated = 0, active = 0, resident = 0, mapped = 0;
    size_t sz = sizeof(size_t);
    je_mallctl("stats.allocated", &allocated, &sz, NULL, 0);
    je_mallctl("stats.active", &active, &sz, NULL, 0);
    je_mallctl("stats.resident", &resident, &sz, NULL, 0);
    je_mallctl("stats.mapped", &mapped, &sz, NULL, 0);

    snprintf(buffer, buffer_size,
        "=== 详细内存统计（jemalloc） ===\n"
        "分配器: jemalloc\n"
        "【本程序计数】\n"
        "  当前占用: %zu bytes (%.2f MB)\n"
        "  峰值占用: %zu bytes (%.2f MB)\n"
        "  分配次数: %zu\n"
        "  释放次数: %zu\n"
        "【jemalloc原生】\n"
        "  allocated: %zu (%.2f MB)\n"
        "  active   : %zu (%.2f MB)\n"
        "  resident : %zu (%.2f MB)\n"
        "  mapped   : %zu (%.2f MB)\n",
        cur,  cur/(1024.0*1024.0),
        peak, peak/(1024.0*1024.0),
        ac, fc,
        allocated, allocated/(1024.0*1024.0),
        active,    active/(1024.0*1024.0),
        resident,  resident/(1024.0*1024.0),
        mapped,    mapped/(1024.0*1024.0)
    );
}

void memory_pool_stats(void) {
    // 简要打印；详细看 MEMINFO/STATS
    pthread_mutex_lock(&g_je_stats.lock);
    printf("=== Jemalloc Statistics (program counters) ===\n");
    printf("Current Bytes: %zu, Peak Bytes: %zu\n", g_je_stats.current_bytes, g_je_stats.peak_bytes);
    printf("Alloc Count: %zu, Free Count: %zu\n", g_je_stats.alloc_count, g_je_stats.free_count);
    pthread_mutex_unlock(&g_je_stats.lock);
}

#endif
