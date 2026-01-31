#ifndef _LINUX_HYMOFS_H
#define _LINUX_HYMOFS_H

#include <linux/atomic.h>
#include <linux/kernel.h> /* For system_state */
#include <linux/list.h>
#include <linux/sched.h>       /* For current */
#include <linux/thread_info.h> /* For thread_info flags */
#include <linux/types.h>

#ifndef CONFIG_HYMOFS
#define CONFIG_HYMOFS 1
#endif // #ifndef CONFIG_HYMOFS
#ifndef CONFIG_HYMOFS_REVERSE_LOOKUP
#define CONFIG_HYMOFS_REVERSE_LOOKUP 1
#endif // #ifndef CONFIG_HYMOFS_REVERSE_LOOKUP
#ifndef CONFIG_HYMOFS_FORWARD_REDIRECT
#define CONFIG_HYMOFS_FORWARD_REDIRECT 1
#endif // #ifndef CONFIG_HYMOFS_FORWARD_REDIRECT
#ifndef CONFIG_HYMOFS_HIDE_ENTRIES
#define CONFIG_HYMOFS_HIDE_ENTRIES 1
#endif // #ifndef CONFIG_HYMOFS_HIDE_ENTRIES
#ifndef CONFIG_HYMOFS_INJECT_ENTRIES
#define CONFIG_HYMOFS_INJECT_ENTRIES 0
#endif // #ifndef CONFIG_HYMOFS_INJECT_ENTRIES
#ifndef CONFIG_HYMOFS_STAT_SPOOF
#define CONFIG_HYMOFS_STAT_SPOOF 1
#endif // #ifndef CONFIG_HYMOFS_STAT_SPOOF
#ifndef CONFIG_HYMOFS_XATTR_FILTER
#define CONFIG_HYMOFS_XATTR_FILTER 1
#endif // #ifndef CONFIG_HYMOFS_XATTR_FILTER
#ifndef CONFIG_HYMOFS_UNAME_SPOOF
#define CONFIG_HYMOFS_UNAME_SPOOF 1
#endif // #ifndef CONFIG_HYMOFS_UNAME_SPOOF
#ifndef CONFIG_HYMOFS_CMDLINE_SPOOF
#define CONFIG_HYMOFS_CMDLINE_SPOOF 1
#endif // #ifndef CONFIG_HYMOFS_CMDLINE_SPOOF

#ifdef CONFIG_HYMOFS

#define HYMO_MAGIC_POS 0x7000000000000000ULL

#define HYMO_DEFAULT_MIRROR_NAME "hymo_mirror"
#define HYMO_DEFAULT_MIRROR_PATH "/dev/" HYMO_DEFAULT_MIRROR_NAME

/* Internal command definitions (not exposed to userspace, used within
 * hymo_dispatch_cmd) */
#define HYMO_CMD_CLEAR_ALL 100
#define HYMO_CMD_GET_VERSION 101
#define HYMO_CMD_SET_DEBUG 102
#define HYMO_CMD_REORDER_MNT_ID 103
#define HYMO_CMD_SET_STEALTH 104
#define HYMO_CMD_SET_ENABLED 105
#define HYMO_CMD_LIST_RULES 106
#define HYMO_CMD_SET_MIRROR_PATH 107
#define HYMO_CMD_ADD_MERGE_RULE 108
#define HYMO_CMD_ADD_RULE 109
#define HYMO_CMD_HIDE_RULE 110
#define HYMO_CMD_HIDE_OVERLAY_XATTRS 111
#define HYMO_CMD_DEL_RULE 112
#define HYMO_CMD_ADD_SPOOF_KSTAT 113
#define HYMO_CMD_UPDATE_SPOOF_KSTAT 114
#define HYMO_CMD_SET_UNAME 115
#define HYMO_CMD_SET_CMDLINE 116

struct hymo_merge_target_node {
  struct list_head list;
  char *target;
  struct dentry *target_dentry; /* Cached dentry for fast lookup */
};

/* Bloom filter for merge target filenames - ultra fast O(1) check */
#define HYMO_BLOOM_BITS 10 /* 1024 bits = 128 bytes */
#define HYMO_BLOOM_SIZE (1 << HYMO_BLOOM_BITS)
#define HYMO_BLOOM_MASK (HYMO_BLOOM_SIZE - 1)

/* Hash table for merge target filenames - O(1) lookup */
#define HYMO_MERGE_HASH_BITS 6
#define HYMO_MERGE_HASH_SIZE (1 << HYMO_MERGE_HASH_BITS)

struct hymo_merge_file_entry {
  struct hlist_node node;
  char *name;
  int namlen;
};

struct hymo_readdir_context {
  uint64_t magic;
  struct file *file;
  char *path_buf;
  char *dir_path;
  int dir_path_len;
  bool entry_written;
  struct list_head merge_targets;
  bool is_replace_mode;
  bool dir_has_hidden;  /* Fast path: skip hide check if false */
  bool has_merge_files; /* Fast path: skip merge check if false */
  unsigned long
      bloom_filter[HYMO_BLOOM_SIZE /
                   BITS_PER_LONG]; /* Bloom filter for merge filenames */
  struct hlist_head
      merge_files[HYMO_MERGE_HASH_SIZE]; /* Pre-built hash of merge target
                                            filenames */
};

extern bool hymofs_enabled;
extern bool hymofs_uname_spoofing_enabled;

/* Syscall hook for legacy mode */
extern int (*hymo_dispatch_cmd_hook)(unsigned int cmd, void __user *arg);

/* ========== Directory entry hiding/injection ========== */
#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
void __hymofs_prepare_readdir(struct hymo_readdir_context *ctx,
                              struct file *file);
void __hymofs_cleanup_readdir(struct hymo_readdir_context *ctx);
bool __hymofs_check_filldir(struct hymo_readdir_context *ctx, const char *name,
                            int namlen);
#endif // #ifdef CONFIG_HYMOFS_HIDE_ENTRIES

/* ========== Stat spoofing ========== */
#ifdef CONFIG_HYMOFS_STAT_SPOOF
void hymofs_spoof_stat(const struct path *path, struct kstat *stat);
void hymofs_spoof_kstat_by_ino(unsigned long ino, struct kstat *stat);
bool hymofs_is_kstat_spoofed(struct inode *inode);
void hymofs_post_getattr(const struct path *path, struct inode *inode,
                         struct kstat *stat, int ret);
#endif // #ifdef CONFIG_HYMOFS_STAT_SPOOF

/* ========== Extended attributes filtering ========== */
#ifdef CONFIG_HYMOFS_XATTR_FILTER
ssize_t hymofs_filter_xattrs(struct dentry *dentry, char *klist, ssize_t len);
bool hymofs_is_overlay_xattr(struct dentry *dentry, const char *name);
#endif // #ifdef CONFIG_HYMOFS_XATTR_FILTER

/* ========== Uname spoofing ========== */
#ifdef CONFIG_HYMOFS_UNAME_SPOOF
struct new_utsname;
void hymofs_spoof_uname(struct new_utsname *name);
#endif // #ifdef CONFIG_HYMOFS_UNAME_SPOOF

/* ========== Cmdline spoofing ========== */
#ifdef CONFIG_HYMOFS_CMDLINE_SPOOF
struct seq_file;
int hymofs_spoof_cmdline(struct seq_file *m);
bool hymofs_is_cmdline_spoofed(void);
#endif // #ifdef CONFIG_HYMOFS_CMDLINE_SPOOF

struct hymo_name_list {
  char *name;
  unsigned char type;
  struct list_head list;
};

/* Performance information structure */
struct hymofs_perf_info {
  u64 total_checks;
  u64 fast_path_skips;
  u64 bloom_rejects;
  u64 rule_hits;
};

/* ========== Forward redirection (namei) ========== */
#ifdef CONFIG_HYMOFS_FORWARD_REDIRECT
struct filename;
struct filename *hymofs_handle_getname(struct filename *result);
struct filename *hymofs_resolve_relative(int dfd, const char *name);
char *__hymofs_resolve_target(const char *pathname);
#endif // #ifdef CONFIG_HYMOFS_FORWARD_REDIRECT

/* ========== Reverse lookup (d_path) ========== */
#ifdef CONFIG_HYMOFS_REVERSE_LOOKUP
int __hymofs_reverse_lookup(const char *pathname, char *buf, size_t buflen);
char *hymofs_process_d_path(char *res, char *buf, int buflen);
#endif // #ifdef CONFIG_HYMOFS_REVERSE_LOOKUP

/* ========== Path hiding ========== */
#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
bool __hymofs_should_hide(const char *pathname, size_t len);
bool __hymofs_is_inode_hidden(struct inode *inode);
#endif // #ifdef CONFIG_HYMOFS_HIDE_ENTRIES

/*
 * Inline wrapper with fast-path checks
 *
 * HymoFS design: Only privileged processes are marked
 * Default (unmarked) = hidden, Marked = can see everything
 */
static __always_inline bool hymofs_is_inode_hidden(struct inode *inode) {
#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
  /* Fast path: NULL checks */
  if (unlikely(!inode || !inode->i_mapping))
    return false;

  /* Fast path: Root sees everything */
  if (uid_eq(current_uid(), GLOBAL_ROOT_UID))
    return false;

  /* Fast path: No rules loaded */
  if (!hymofs_enabled)
    return false;

  return __hymofs_is_inode_hidden(inode);
#else
  return false;
#endif // #ifdef CONFIG_HYMOFS_HIDE_ENTRIES
}

static inline void hymofs_prepare_readdir(struct hymo_readdir_context *ctx,
                                          struct file *file) {
#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
  ctx->path_buf = NULL;
  ctx->file = file;
  if (!hymofs_enabled)
    return;
  __hymofs_prepare_readdir(ctx, file);
#endif // #ifdef CONFIG_HYMOFS_HIDE_ENTRIES
}

static inline void hymofs_cleanup_readdir(struct hymo_readdir_context *ctx) {
#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
  if (ctx->path_buf)
    __hymofs_cleanup_readdir(ctx);
#endif // #ifdef CONFIG_HYMOFS_HIDE_ENTRIES
}

static inline bool hymofs_check_filldir(struct hymo_readdir_context *ctx,
                                        const char *name, int namlen) {
#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
  if (!ctx->path_buf)
    return false;
  return __hymofs_check_filldir(ctx, name, namlen);
#else
  return false;
#endif // #ifdef CONFIG_HYMOFS_HIDE_ENTRIES
}

static inline char *hymofs_resolve_target(const char *pathname) {
#ifdef CONFIG_HYMOFS_FORWARD_REDIRECT
  if (!hymofs_enabled)
    return NULL;
  return __hymofs_resolve_target(pathname);
#else
  return NULL;
#endif // #ifdef CONFIG_HYMOFS_FORWARD_REDIRECT
}

static inline int hymofs_reverse_lookup(const char *pathname, char *buf,
                                        size_t buflen) {
#ifdef CONFIG_HYMOFS_REVERSE_LOOKUP
  if (!hymofs_enabled)
    return -1;
  return __hymofs_reverse_lookup(pathname, buf, buflen);
#else
  return -1;
#endif // #ifdef CONFIG_HYMOFS_REVERSE_LOOKUP
}

static inline bool hymofs_should_hide(const char *pathname) {
#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
  if (!hymofs_enabled)
    return false;
  /* Fast path: check for NULL or empty */
  if (!pathname || !*pathname)
    return false;
  return __hymofs_should_hide(pathname, strlen(pathname));
#else
  return false;
#endif // #ifdef CONFIG_HYMOFS_HIDE_ENTRIES
}

#else

/* ========== CONFIG_HYMOFS disabled - all stubs ========== */
struct hymo_readdir_context {};
static inline void hymofs_prepare_readdir(struct hymo_readdir_context *ctx,
                                          struct file *file) {}
static inline void hymofs_cleanup_readdir(struct hymo_readdir_context *ctx) {}
static inline bool hymofs_check_filldir(struct hymo_readdir_context *ctx,
                                        const char *name, int namlen) {
  return false;
}
static inline void hymofs_spoof_stat(const struct path *path,
                                     struct kstat *stat) {}
static inline ssize_t hymofs_filter_xattrs(struct dentry *dentry, char *klist,
                                           ssize_t len) {
  return len;
}
static inline bool hymofs_is_overlay_xattr(struct dentry *dentry,
                                           const char *name) {
  return false;
}
static inline struct filename *hymofs_handle_getname(struct filename *result) {
  return result;
}
static inline struct filename *hymofs_resolve_relative(int dfd,
                                                       const char *name) {
  return NULL;
}
static inline char *hymofs_resolve_target(const char *pathname) { return NULL; }
static inline int hymofs_reverse_lookup(const char *pathname, char *buf,
                                        size_t buflen) {
  return -1;
}
static inline bool hymofs_should_hide(const char *pathname) { return false; }
static inline bool hymofs_is_inode_hidden(struct inode *inode) { return false; }
static inline void hymofs_spoof_kstat_by_ino(unsigned long ino,
                                             struct kstat *stat) {}
static inline bool hymofs_is_kstat_spoofed(struct inode *inode) {
  return false;
}
static inline void hymofs_spoof_uname(struct new_utsname *name) {}
static inline int hymofs_spoof_cmdline(struct seq_file *m) { return 1; }
static inline bool hymofs_is_cmdline_spoofed(void) { return false; }

#endif /* CONFIG_HYMOFS */

#endif /* _LINUX_HYMOFS_H */
