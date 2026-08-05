/**
 * msm_kgsl_minimal.h - Минимальный заголовок для KGSL
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

// Флаги
#define KGSL_MEMFLAGS_SECURE         0x00000001
#define KGSL_MEMFLAGS_GPUREADONLY    0x00000004
#define KGSL_MEMFLAGS_GPUREADWRITE   0x00000010
#define KGSL_MEMFLAGS_CACHED         0x00000100
#define KGSL_MEMFLAGS_UNCACHED       0x00000200

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
    unsigned int gpuaddr;
    unsigned int len;
    unsigned int offset;
    unsigned int hostptr;
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

// Prop types
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
