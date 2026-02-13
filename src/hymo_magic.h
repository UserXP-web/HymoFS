/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HymoFS ioctl protocol definitions.
 * Shared between kernel module and userspace tools.
 */
#ifndef _HYMO_MAGIC_H
#define _HYMO_MAGIC_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/bits.h>
#else
#include <sys/ioctl.h>
#include <stddef.h>
#include <stdint.h>
#endif

#define HYMO_MAGIC1 0x48594D4F  /* "HYMO" */
#define HYMO_MAGIC2 0x524F4F54  /* "ROOT" */
#define HYMO_PROTOCOL_VERSION 12

#define HYMO_MAX_LEN_PATHNAME 256
#define HYMO_FAKE_CMDLINE_SIZE 4096

/* Inode marking bits in inode->i_mapping->flags (high bits to avoid conflict) */
#ifdef __KERNEL__
#define AS_FLAGS_HYMO_HIDE 40
#define BIT_HYMO_HIDE BIT(40)
#define AS_FLAGS_HYMO_DIR_HAS_HIDDEN 41
#define BIT_HYMO_DIR_HAS_HIDDEN BIT(41)
#define AS_FLAGS_HYMO_SPOOF_KSTAT 42
#define BIT_HYMO_SPOOF_KSTAT BIT(42)
#endif

/* Magic file position for injected entries */
#define HYMO_MAGIC_POS 0x7000000000000000ULL

/* Internal command IDs */
#define HYMO_CMD_CLEAR_ALL          100
#define HYMO_CMD_GET_VERSION        101
#define HYMO_CMD_SET_DEBUG          102
#define HYMO_CMD_REORDER_MNT_ID    103
#define HYMO_CMD_SET_STEALTH       104
#define HYMO_CMD_SET_ENABLED       105
#define HYMO_CMD_LIST_RULES        106
#define HYMO_CMD_SET_MIRROR_PATH   107
#define HYMO_CMD_ADD_MERGE_RULE    108
#define HYMO_CMD_ADD_RULE          109
#define HYMO_CMD_HIDE_RULE         110
#define HYMO_CMD_HIDE_OVERLAY_XATTRS 111
#define HYMO_CMD_DEL_RULE          112
#define HYMO_CMD_SET_UNAME         115
#define HYMO_CMD_GET_FD            0x48021

/* Syscall argument structures */
struct hymo_syscall_arg {
    const char *src;
    const char *target;
    int type;
};

struct hymo_syscall_list_arg {
    char *buf;
    size_t size;
};

struct hymo_uid_list_arg {
    __u32 count;
    __u32 reserved;
    __aligned_u64 uids;
};

/* Feature flags */
#define HYMO_FEATURE_KSTAT_SPOOF    (1 << 0)
#define HYMO_FEATURE_UNAME_SPOOF    (1 << 1)
#define HYMO_FEATURE_CMDLINE_SPOOF  (1 << 2)
#define HYMO_FEATURE_SELINUX_BYPASS (1 << 4)
#define HYMO_FEATURE_MERGE_DIR      (1 << 5)

/* ioctl definitions (fd-based mode) */
#define HYMO_IOC_MAGIC 'H'
#define HYMO_IOC_ADD_RULE           _IOW(HYMO_IOC_MAGIC, 1, struct hymo_syscall_arg)
#define HYMO_IOC_DEL_RULE           _IOW(HYMO_IOC_MAGIC, 2, struct hymo_syscall_arg)
#define HYMO_IOC_HIDE_RULE          _IOW(HYMO_IOC_MAGIC, 3, struct hymo_syscall_arg)
#define HYMO_IOC_CLEAR_ALL          _IO(HYMO_IOC_MAGIC, 5)
#define HYMO_IOC_GET_VERSION        _IOR(HYMO_IOC_MAGIC, 6, int)
#define HYMO_IOC_LIST_RULES         _IOWR(HYMO_IOC_MAGIC, 7, struct hymo_syscall_list_arg)
#define HYMO_IOC_SET_DEBUG          _IOW(HYMO_IOC_MAGIC, 8, int)
#define HYMO_IOC_REORDER_MNT_ID    _IO(HYMO_IOC_MAGIC, 9)
#define HYMO_IOC_SET_STEALTH        _IOW(HYMO_IOC_MAGIC, 10, int)
#define HYMO_IOC_HIDE_OVERLAY_XATTRS _IOW(HYMO_IOC_MAGIC, 11, struct hymo_syscall_arg)
#define HYMO_IOC_ADD_MERGE_RULE     _IOW(HYMO_IOC_MAGIC, 12, struct hymo_syscall_arg)
#define HYMO_IOC_SET_MIRROR_PATH    _IOW(HYMO_IOC_MAGIC, 14, struct hymo_syscall_arg)
#define HYMO_IOC_SET_ENABLED        _IOW(HYMO_IOC_MAGIC, 20, int)

#endif /* _HYMO_MAGIC_H */
