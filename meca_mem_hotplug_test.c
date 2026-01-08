#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#include <termios.h>
#include <dirent.h>
#include <sys/mman.h>

#define DEFAULT_ZONEINFO_PATH "/proc/zoneinfo"
#define PAGE_SIZE 4096
#define BAR_WIDTH 60
#define MEMORY_PROBE_PATH "/sys/devices/system/memory/probe"
#define MEMORY_BLOCK_SIZE_PATH "/sys/devices/system/memory/block_size_bytes"
#define MEMORY_BASE_ADDR 0x200000000UL
#define MEMORY_MAX_SIZE (8UL * 1024 * 1024 * 1024)
#define ALLOC_SIZE (100 * 1024 * 1024)
#define MAX_ALLOCS 1024

typedef struct {
    long managed;
    long free_pages;
    long inactive_file;
    long active_file;
    long inactive_anon;
    long active_anon;
} ZoneInfo;

typedef struct {
    long total;
    long used;
    long cached;
    long free;
} MemoryStats;

static struct termios orig_termios;
static bool terminal_raw = false;
static int added_memory_blocks[MAX_ALLOCS];
static int num_memory_blocks = 0;
static void *allocated_blocks[MAX_ALLOCS];
static int num_allocs = 0;
static char status_msg[256] = "";

static void restore_terminal(void)
{
    if (terminal_raw) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
        terminal_raw = false;
    }
}

static void set_raw_mode(void)
{
    struct termios raw;

    tcgetattr(STDIN_FILENO, &orig_termios);
    atexit(restore_terminal);

    raw = orig_termios;
    raw.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    terminal_raw = true;
}

static unsigned long get_block_size(void)
{
    FILE *fp;
    unsigned long block_size = 0;

    fp = fopen(MEMORY_BLOCK_SIZE_PATH, "r");
    if (fp) {
        if (fscanf(fp, "%lx", &block_size) != 1)
            block_size = 0;
        fclose(fp);
    }
    return block_size;
}

static int compare_int(const void *a, const void *b)
{
    return (*(int *)a - *(int *)b);
}

static void scan_existing_memory_blocks(void)
{
    DIR *dir;
    struct dirent *entry;
    unsigned long block_size;
    int start_block;
    int block_num;
    char state_path[320];
    char state[32];
    FILE *fp;

    block_size = get_block_size();
    if (block_size == 0)
        return;

    start_block = (int)(MEMORY_BASE_ADDR / block_size);

    dir = opendir("/sys/devices/system/memory");
    if (!dir)
        return;

    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "memory", 6) != 0)
            continue;

        if (sscanf(entry->d_name, "memory%d", &block_num) != 1)
            continue;

        /* Only consider blocks at or after MEMORY_BASE_ADDR */
        if (block_num < start_block)
            continue;

        /* Check if this block is online */
        snprintf(state_path, sizeof(state_path),
                 "/sys/devices/system/memory/%s/state", entry->d_name);
        fp = fopen(state_path, "r");
        if (!fp)
            continue;

        if (fscanf(fp, "%31s", state) == 1 &&
            strncmp(state, "online", 6) == 0) {
            if (num_memory_blocks < MAX_ALLOCS) {
                added_memory_blocks[num_memory_blocks++] = block_num;
            }
        }
        fclose(fp);
    }

    closedir(dir);

    /* Sort blocks so we remove them in order (highest first when removing) */
    if (num_memory_blocks > 0) {
        qsort(added_memory_blocks, num_memory_blocks, sizeof(int), compare_int);
    }
}

static bool add_memory(void)
{
    FILE *fp;
    int block_num;
    char state_path[128];
    unsigned long block_size;
    unsigned long addr;

    printf("Status: Adding memory...\n");
    fflush(stdout);

    if (num_memory_blocks >= MAX_ALLOCS) {
        snprintf(status_msg, sizeof(status_msg),
                 "Max memory blocks reached (%d)", MAX_ALLOCS);
        return false;
    }

    block_size = get_block_size();
    if (block_size == 0) {
        snprintf(status_msg, sizeof(status_msg), "Failed to get block size");
        return false;
    }

    /* Calculate address for next block (after highest existing block) */
    if (num_memory_blocks > 0) {
        block_num = added_memory_blocks[num_memory_blocks - 1] + 1;
    } else {
        block_num = (int)(MEMORY_BASE_ADDR / block_size);
    }
    addr = (unsigned long)block_num * block_size;

    /* Check if address exceeds MECA memory limit (8GB from base) */
    if (addr + block_size > MEMORY_BASE_ADDR + MEMORY_MAX_SIZE) {
        snprintf(status_msg, sizeof(status_msg),
                 "MECA memory limit reached (8GB max)");
        return false;
    }

    /* Probe the memory */
    fp = fopen(MEMORY_PROBE_PATH, "w");
    if (!fp) {
        snprintf(status_msg, sizeof(status_msg),
                 "Failed to open %s (need root)", MEMORY_PROBE_PATH);
        return false;
    }
    fprintf(fp, "0x%lx", addr);
    fclose(fp);

    /* Online the memory as movable */
    snprintf(state_path, sizeof(state_path),
             "/sys/devices/system/memory/memory%d/state", block_num);
    fp = fopen(state_path, "w");
    if (!fp) {
        snprintf(status_msg, sizeof(status_msg),
                 "Failed to open %s", state_path);
        return false;
    }
    fprintf(fp, "online_movable");
    fclose(fp);

    added_memory_blocks[num_memory_blocks++] = block_num;
    snprintf(status_msg, sizeof(status_msg),
             "Added MECA Memory 128 MB (total: %d MB)", num_memory_blocks*128);
    return true;
}

static bool remove_memory(void)
{
    FILE *fp;
    char state_path[128];
    int block_num;

    printf("Status: Removing memory...\n");
    fflush(stdout);

    if (num_memory_blocks <= 0) {
        snprintf(status_msg, sizeof(status_msg), "No memory to remove");
        return false;
    }

    /* Get the last added block */
    block_num = added_memory_blocks[num_memory_blocks - 1];

    /* Offline the memory */
    snprintf(state_path, sizeof(state_path),
             "/sys/devices/system/memory/memory%d/state", block_num);
    fp = fopen(state_path, "w");
    if (!fp) {
        snprintf(status_msg, sizeof(status_msg),
                 "Failed to open %s", state_path);
        return false;
    }
    fprintf(fp, "offline");
    fclose(fp);

    num_memory_blocks--;
    snprintf(status_msg, sizeof(status_msg),
             "Offlined memory block %d (remaining: %d blocks)", block_num, num_memory_blocks);
    return true;
}

static void allocate_memory(void)
{
    void *mem;

    if (num_allocs >= MAX_ALLOCS) {
        snprintf(status_msg, sizeof(status_msg),
                 "Max allocations reached (%d)", MAX_ALLOCS);
        return;
    }

    printf("Status: Allocating 100 MB...\n");
    fflush(stdout);

    mem = malloc(ALLOC_SIZE);
    if (!mem) {
        snprintf(status_msg, sizeof(status_msg),
                 "Failed to allocate 100 MB");
        return;
    }

    int i;
    char * a = mem;
    for (i=0; i<ALLOC_SIZE; i+=PAGE_SIZE) {
        a[i] = '\0';
    }
#if 0
    /* Use mlock to verify memory is actually available */
    if (mlock(mem, ALLOC_SIZE) != 0) {
        free(mem);
        snprintf(status_msg, sizeof(status_msg),
                 "Not enough memory available for 100 MB");
        return;
    }

    /* Unlock but keep the memory allocated */
    munlock(mem, ALLOC_SIZE);
#endif
    allocated_blocks[num_allocs++] = mem;
    snprintf(status_msg, sizeof(status_msg),
             "Allocated total %d MB",
             num_allocs * 100);
}

static void free_memory(void)
{
    if (num_allocs <= 0) {
        snprintf(status_msg, sizeof(status_msg), "No memory to free");
        return;
    }

    num_allocs--;
    free(allocated_blocks[num_allocs]);
    allocated_blocks[num_allocs] = NULL;

    snprintf(status_msg, sizeof(status_msg),
             "Freed 100 MB (remaining: %d blocks, %d MB)",
             num_allocs, num_allocs * 100);
}

static void parse_zone(FILE *fp, ZoneInfo *zone)
{
    char line[256];

    memset(zone, 0, sizeof(ZoneInfo));

    while (fgets(line, sizeof(line), fp)) {
        /* Stop when we hit the next zone */
        if (strncmp(line, "Node", 4) == 0)
            break;

        if (strstr(line, "managed"))
            sscanf(line, " managed %ld", &zone->managed);
        else if (strstr(line, "nr_free_pages"))
            sscanf(line, " nr_free_pages %ld", &zone->free_pages);
        else if (strstr(line, "nr_zone_inactive_file"))
            sscanf(line, " nr_zone_inactive_file %ld", &zone->inactive_file);
        else if (strstr(line, "nr_zone_active_file"))
            sscanf(line, " nr_zone_active_file %ld", &zone->active_file);
        else if (strstr(line, "nr_zone_inactive_anon"))
            sscanf(line, " nr_zone_inactive_anon %ld", &zone->inactive_anon);
        else if (strstr(line, "nr_zone_active_anon"))
            sscanf(line, " nr_zone_active_anon %ld", &zone->active_anon);
    }
}

static bool find_zone(FILE *fp, const char *zone_name)
{
    char line[256];
    char *p;

    rewind(fp);

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Node", 4) != 0)
            continue;

        p = strstr(line, "zone");
        if (!p)
            continue;

        p += 4;  /* skip "zone" */
        while (*p && isspace((unsigned char)*p))
            p++;

        if (strncmp(p, zone_name, strlen(zone_name)) == 0)
            return true;
    }
    return false;
}

static MemoryStats calculate_stats(const ZoneInfo *zone)
{
    MemoryStats stats;

    stats.total = zone->managed;
    stats.free = zone->free_pages;
    stats.cached = zone->inactive_file + zone->active_file;
    stats.used = stats.total - stats.free - stats.cached;

    if (stats.used < 0)
        stats.used = 0;

    return stats;
}

static void format_size(long pages, char *buf, size_t buflen)
{
    double bytes = (double)pages * PAGE_SIZE;

    if (bytes >= 1024L * 1024 * 1024)
        snprintf(buf, buflen, "%.1f GB", bytes / (1024.0 * 1024 * 1024));
    else if (bytes >= 1024L * 1024)
        snprintf(buf, buflen, "%.1f MB", bytes / (1024.0 * 1024));
    else if (bytes >= 1024)
        snprintf(buf, buflen, "%.1f KB", bytes / 1024.0);
    else
        snprintf(buf, buflen, "%.0f B", bytes);
}

static void draw_bar(const char *label, const MemoryStats *stats, int width,
                     const char *free_color)
{
    char total_str[32], used_str[32], cached_str[32], free_str[32];
    int used_chars, cached_chars, free_chars;
    int i;

    if (stats->total == 0) {
        printf("%s: (no memory)\n", label);
        return;
    }

    format_size(stats->total, total_str, sizeof(total_str));
    format_size(stats->used, used_str, sizeof(used_str));
    format_size(stats->cached, cached_str, sizeof(cached_str));
    format_size(stats->free, free_str, sizeof(free_str));

    used_chars = (int)((double)stats->used / stats->total * width);
    cached_chars = (int)((double)stats->cached / stats->total * width);
    free_chars = width - used_chars - cached_chars;

    if (free_chars < 0)
        free_chars = 0;

    printf("%s [Total: %s]\n", label, total_str);
    printf("[");

    /* Used (red) */
    printf("\033[41m");
    for (i = 0; i < used_chars; i++)
        printf(" ");

    /* Cached (yellow) */
    printf("\033[43m");
    for (i = 0; i < cached_chars; i++)
        printf(" ");

    /* Free (specified color) */
    printf("\033[%sm", free_color);
    for (i = 0; i < free_chars; i++)
        printf(" ");

    printf("\033[0m]\n");

    printf("  \033[41m  \033[0m Used: %-12s  "
           "\033[43m  \033[0m Cached: %-12s  "
           "\033[%sm  \033[0m Free: %s\n\n",
           used_str, cached_str, free_color, free_str);
}

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [zoneinfo_path]\n", prog);
    fprintf(stderr, "  zoneinfo_path: path to zoneinfo file (default: %s)\n",
            DEFAULT_ZONEINFO_PATH);
}

int main(int argc, char *argv[])
{
    FILE *fp;
    ZoneInfo dma32_zone, movable_zone;
    MemoryStats dma32_stats, movable_stats;
    bool has_dma32, has_movable;
    const char *zoneinfo_path = DEFAULT_ZONEINFO_PATH;
    int ch, i;

    if (argc > 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (argc == 2) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        zoneinfo_path = argv[1];
    }

    set_raw_mode();

    /* Detect existing hotplugged memory blocks */
    scan_existing_memory_blocks();

    while (1) {
        has_dma32 = false;
        has_movable = false;

        fp = fopen(zoneinfo_path, "r");
        if (!fp) {
            restore_terminal();
            perror(zoneinfo_path);
            return 1;
        }

        /* Find and parse DMA32 zone (always show) */
        if (find_zone(fp, "DMA32")) {
            parse_zone(fp, &dma32_zone);
            dma32_stats = calculate_stats(&dma32_zone);
            has_dma32 = true;
        }

        /* Find and parse Movable zone (show only if free > 0) */
        if (find_zone(fp, "Movable")) {
            parse_zone(fp, &movable_zone);
            movable_stats = calculate_stats(&movable_zone);
            has_movable = (movable_zone.managed > 0);
        }

        fclose(fp);

        /* Clear screen and move cursor to top-left */
        printf("\033[2J\033[H");

        printf("\n=== Memory Usage Information ===\n\n");

        /* Total Memory = DMA32 + Movable */
        if (has_dma32) {
            MemoryStats total_stats;
            total_stats.total = dma32_stats.total;
            total_stats.used = dma32_stats.used;
            total_stats.cached = dma32_stats.cached;
            total_stats.free = dma32_stats.free;
            if (has_movable) {
                total_stats.total += movable_stats.total;
                total_stats.used += movable_stats.used;
                total_stats.cached += movable_stats.cached;
                total_stats.free += movable_stats.free;
            }
            draw_bar("Total Memory", &total_stats, BAR_WIDTH, "42");
        }

        if (has_dma32) {
            draw_bar("Local Memory", &dma32_stats, BAR_WIDTH, "42");
        } else {
            printf("DMA32 Zone not found.\n\n");
        }

        if (has_movable) {
            draw_bar("MECA Memory", &movable_stats, BAR_WIDTH, "46");
        }

        /* Display allocated memory blocks */
        printf("User Allocated Memory [%d MB]\n", num_allocs * 100);
        printf("[");
        for (i = 0; i < num_allocs; i++)
            printf("\033[41m \033[0m");
        for (i = num_allocs; i < BAR_WIDTH; i++)
            printf(" ");
        printf("]\n\n");

        printf("---\n");
        printf("Commands: [q]uit  [a]hotplug MECA  [r]emove MECA  [s]alloc 100MB  [d]ealloc\n");

        if (status_msg[0]) {
            printf("Status: %s\n", status_msg);
        }

        fflush(stdout);

        /* Flush any input that was typed during display update */
        tcflush(STDIN_FILENO, TCIFLUSH);

        /* Wait for keypress */
        ch = getchar();
        if (ch == 'q' || ch == 'Q')
            break;
        else if (ch == 'a' || ch == 'A')
            add_memory();
        else if (ch == 'r' || ch == 'R')
            remove_memory();
        else if (ch == 's' || ch == 'S')
            allocate_memory();
        else if (ch == 'd' || ch == 'D')
            free_memory();
    }

    while (num_allocs > 0) {
        num_allocs--;
        free(allocated_blocks[num_allocs]);
    }

    restore_terminal();
    return 0;
}
