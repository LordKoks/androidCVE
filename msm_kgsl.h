/**
 * msm_kgsl.h - Исправленный заголовочный файл для KGSL
 * Исправлены типы данных для 64-битных систем (ARM64)
 */

#ifndef _MSM_KGSL_H
#define _MSM_KGSL_H

#include <stdint.h>
#include <sys/ioctl.h>

#define KGSL_IOC_TYPE 0x09

// Основные IOCTL
#define IOCTL_KGSL_DEVICE_GETPROPERTY    _IOWR(KGSL_IOC_TYPE, 0x01, struct kgsl_device_getproperty)
#define IOCTL_KGSL_DEVICE_REGREAD       _IOWR(KGSL_IOC_TYPE, 0x02, struct kgsl_device_regread)
#define IOCTL_KGSL_DRAWCTXT_CREATE      _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)
#define IOCTL_KGSL_DRAWCTXT_DESTROY     _IOW(KGSL_IOC_TYPE, 0x14, struct kgsl_drawctxt_destroy)
#define IOCTL_KGSL_MAP_USER_MEM          _IOWR(KGSL_IOC_TYPE, 0x15, struct kgsl_map_user_mem)
#define IOCTL_KGSL_GPUMEM_ALLOC         _IOWR(KGSL_IOC_TYPE, 0x2a, struct kgsl_gpumem_alloc)
#define IOCTL_KGSL_GPUMEM_ALLOC_ID      _IOWR(KGSL_IOC_TYPE, 0x2b, struct kgsl_gpumem_alloc_id)
#define IOCTL_KGSL_GPUMEM_GET_INFO      _IOWR(KGSL_IOC_TYPE, 0x2d, struct kgsl_gpumem_get_info)

// GPUOBJ variants (used in newer KGSL exploits)
#define IOCTL_KGSL_GPUOBJ_ALLOC _IOWR(KGSL_IOC_TYPE, 0x45, struct kgsl_gpuobj_alloc)
#define IOCTL_KGSL_GPUOBJ_FREE _IOW(KGSL_IOC_TYPE, 0x46, struct kgsl_gpuobj_free)
#define IOCTL_KGSL_GPUOBJ_INFO _IOWR(KGSL_IOC_TYPE, 0x47, struct kgsl_gpuobj_info)
#define IOCTL_KGSL_GPU_COMMAND _IOWR(KGSL_IOC_TYPE, 0x4A, struct kgsl_gpu_command)
#define IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID _IOWR(KGSL_IOC_TYPE, 0x16, struct kgsl_cmdstream_readtimestamp_ctxtid)

// Флаги памяти
#define KGSL_MEMFLAGS_SECURE         0x00000001
#define KGSL_MEMFLAGS_GPUREADONLY    0x00000004
#define KGSL_MEMFLAGS_GPUREADWRITE   0x00000010
#define KGSL_MEMFLAGS_CACHED         0x00000100
#define KGSL_MEMFLAGS_UNCACHED       0x00000200
#define KGSL_MEMFLAGS_USE_CPU_MAP    0x10000000ULL

// Структуры
struct kgsl_device_getproperty {
    unsigned int type;
    void __user *value;
    size_t sizebytes;
};

struct kgsl_device_regread {
    unsigned int offsetwords;
    unsigned int value;
};

struct kgsl_drawctxt_create {
    unsigned int flags;
    unsigned int drawctxt_id;
};

struct kgsl_drawctxt_destroy {
    unsigned int drawctxt_id;
};

struct kgsl_map_user_mem {
    int fd;
    unsigned long gpuaddr;
    size_t len;
    size_t offset;
    unsigned long hostptr;
    unsigned int memtype;
    unsigned int flags;
};

struct kgsl_gpumem_alloc {
    uint64_t gpuaddr;
    size_t size;
    unsigned int flags;
};

struct kgsl_gpumem_alloc_id {
    unsigned int id;
    uint64_t gpuaddr;
    size_t size;
    unsigned int flags;
    unsigned int mmapsize;
};

struct kgsl_gpumem_get_info {
    unsigned int id;
    uint64_t gpuaddr;
    size_t size;
    unsigned int flags;
    unsigned int mmapsize;
};

struct kgsl_gpuobj_alloc {
    uint64_t size;
    uint64_t flags;
    uint64_t va_len;
    uint64_t mmapsize;
    unsigned int id;
    unsigned int metadata_len;
    uint64_t metadata;
};

struct kgsl_gpuobj_free {
    uint64_t flags;
    uint64_t priv;
    unsigned int id;
    unsigned int type;
    unsigned int len;
};

struct kgsl_gpuobj_info {
    uint64_t gpuaddr, flags, size, va_len, va_addr;
    unsigned id;
};

struct kgsl_command_object {
    uint64_t offset, gpuaddr, size;
    unsigned flags, id;
};

struct kgsl_gpu_command {
    uint64_t flags, cmdlist;
    unsigned cmdsize, numcmds;
    uint64_t objlist;
    unsigned objsize, numobjs;
    uint64_t synclist;
    unsigned syncsize, numsyncs, context_id, timestamp;
};

struct kgsl_cmdstream_readtimestamp_ctxtid {
    unsigned context_id, type, timestamp;
};

// Типы пропсов
#define KGSL_PROP_DEVICE_INFO         0x01
#define KGSL_PROP_DEVICE_SHADOW       0x02
#define KGSL_PROP_DEVICE_POWER        0x03
#define KGSL_PROP_SHMEM               0x04
#define KGSL_PROP_SHMEM_PHYSADDR      0x05
#define KGSL_PROP_SHMEM_SIZE          0x06
#define KGSL_PROP_SHMEM_BASE          0x07
#define KGSL_PROP_MMU_ENABLE          0x08
#define KGSL_PROP_INTERRUPT_COUNT     0x09
#define KGSL_PROP_HWTYPE              0x0A
#define KGSL_PROP_VERSION             0x0B
#define KGSL_PROP_TIMESTAMP           0x0C

#endif // _MSM_KGSL_H
