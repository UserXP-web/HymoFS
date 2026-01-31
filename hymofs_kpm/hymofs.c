#include "hymofs_compat.h"

#include "mount.h"
#include <asm/ptrace.h>
#include <linux/anon_inodes.h>
#include <linux/backing-dev.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/dirent.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mnt_namespace.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/securebits.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/utsname.h>
#include <linux/vmalloc.h>
#include <linux/xattr.h>
#include <uapi/linux/fcntl.h>

#define _KP_STDINT_H_
#define _KP_KTYPES_H_
#define _KP_COMPILER_H_
#include <hook.h>
#include <kpmodule.h>

#include "hymo_magic.h"
#include "hymofs.h"
#include "hymofs_utils.h"

/* From KernelPatch (avoid including kputils.h due to current_uid() macro
 * conflict) */
extern int compat_copy_to_user(void __user *to, const void *from, int n);

/*
 * IMPORTANT (AArch64 module relocation):
 * KernelPatch allocates module memory from its own ROX heap, which may be far
 * away from kernel/KP text. Direct CALL26/JUMP26 relocations to external
 * kernel/KP symbols can overflow and make the module fail to load.
 *
 * Therefore, never call KernelPatch-exported helpers directly. Take their
 * address into a function pointer and invoke indirectly (blr), which only
 * needs ABS relocations.
 */
/*
 * Use volatile function pointers to force indirect calls.
 * Otherwise, the compiler may devirtualize the call back into a direct CALL26
 * to `hook_wrap`/`unhook`/`compat_copy_to_user` within the same TU.
 */
static hook_err_t (*volatile hymo_kp_hook_wrap)(void *func, int32_t argno,
                                                void *before, void *after,
                                                void *udata);
static void (*volatile hymo_kp_unhook)(void *func);
static int (*volatile hymo_kp_compat_copy_to_user)(void __user *to,
                                                   const void *from, int n);

static void hymo_kp_lazy_init(void) {
  if (!hymo_kp_hook_wrap)
    hymo_kp_hook_wrap = hook_wrap;
  if (!hymo_kp_unhook)
    hymo_kp_unhook = unhook;
  if (!hymo_kp_compat_copy_to_user)
    hymo_kp_compat_copy_to_user = compat_copy_to_user;
}

static hook_err_t hymo_kp_hook_wrap_call(void *func, int32_t argno,
                                         void *before, void *after,
                                         void *udata) {
  hook_err_t (*fn)(void *, int32_t, void *, void *, void *);
  hymo_kp_lazy_init();
  fn = (hook_err_t (*)(void *, int32_t, void *, void *,
                       void *))hymo_kp_hook_wrap;
  if (!fn)
    return HOOK_BAD_ADDRESS;
  return fn(func, argno, before, after, udata);
}

static void hymo_kp_unhook_call(void *func) {
  void (*fn)(void *);
  hymo_kp_lazy_init();
  fn = (void (*)(void *))hymo_kp_unhook;
  if (fn)
    fn(func);
}

static int hymo_kp_compat_copy_to_user_call(void __user *to, const void *from,
                                            int n) {
  int (*fn)(void __user *, const void *, int);
  hymo_kp_lazy_init();
  fn = (int (*)(void __user *, const void *, int))hymo_kp_compat_copy_to_user;
  if (!fn)
    return 0;
  return fn(to, from, n);
}

/* Kernel symbol indirection for KPM build. */
#ifndef NUMA_NO_NODE
#define NUMA_NO_NODE (-1)
#endif // #ifndef NUMA_NO_NODE

struct rw_semaphore;

static unsigned long (*hymo_sym_copy_from_user)(void *, const void __user *,
                                                unsigned long);
static unsigned long (*hymo_sym_copy_to_user)(void __user *, const void *,
                                              unsigned long);
static void *(*hymo_sym_kmalloc)(size_t, gfp_t);
static void (*hymo_sym_kfree)(const void *);
static void (*hymo_sym_kfree_const)(const void *);
static char *(*hymo_sym_kstrdup)(const char *, gfp_t);
static void *(*hymo_sym_kvmalloc_node)(size_t, gfp_t, int);
static void (*hymo_sym_kvfree)(const void *);
static struct file *(*hymo_sym_filp_open)(const char *, int, umode_t);
static int (*hymo_sym_filp_close)(struct file *, fl_owner_t);
static ssize_t (*hymo_sym_kernel_read)(struct file *, void *, size_t, loff_t *);
static struct file *(*hymo_sym_fget)(int);
static void (*hymo_sym_fput)(struct file *);
static char *(*hymo_sym_d_path)(const struct path *, char *, int);
static char *(*hymo_sym_d_absolute_path)(const struct path *, char *, int);
static struct filename *(*hymo_sym_getname_kernel)(const char *);
static void (*hymo_sym_putname)(struct filename *);
static int (*hymo_sym_kern_path)(const char *, unsigned int, struct path *);
static int (*hymo_sym_vfs_listxattr)(struct dentry *, char *, size_t);
static unsigned int (*hymo_sym_full_name_hash)(const struct inode *,
                                               const char *, unsigned int);
static int (*hymo_sym_anon_inode_getfd)(const char *,
                                        const struct file_operations *, void *,
                                        int);
static int (*hymo_sym_vsnprintf)(char *, size_t, const char *, va_list);
static int (*hymo_sym_vscnprintf)(char *, size_t, const char *, va_list);
static char *(*hymo_sym_kvasprintf)(gfp_t, const char *, va_list);
static int (*hymo_sym_vprintk)(const char *, va_list);
static int (*hymo_sym_seq_putc)(struct seq_file *, char);
static int (*hymo_sym_seq_puts)(struct seq_file *, const char *);
static long (*hymo_sym_strnlen_user)(const char __user *, long);
static void (*hymo_sym_raw_spin_lock)(raw_spinlock_t *);
static void (*hymo_sym_raw_spin_unlock)(raw_spinlock_t *);
static int (*hymo_sym_raw_spin_trylock)(raw_spinlock_t *);
static void (*hymo_sym_mutex_lock)(struct mutex *);
static void (*hymo_sym_mutex_unlock)(struct mutex *);
static void (*hymo_sym_rcu_read_lock)(void);
static void (*hymo_sym_rcu_read_unlock)(void);
static void (*hymo_sym_rcu_barrier)(void);
static void (*hymo_sym_down_read)(struct rw_semaphore *);
static void (*hymo_sym_up_read)(struct rw_semaphore *);
static void (*hymo_sym_path_get)(struct path *);
static void (*hymo_sym_path_put)(struct path *);

static int *hymo_sym_system_state;
static struct rw_semaphore *hymo_sym_uts_sem;

static void hymo_resolve_kernel_symbols(void) {
  static const char *const copy_from_user_syms[] = {
      "_copy_from_user",  "copy_from_user",        "raw_copy_from_user",
      "__copy_from_user", "__arch_copy_from_user",
  };
  static const char *const copy_to_user_syms[] = {
      "_copy_to_user",  "copy_to_user",        "raw_copy_to_user",
      "__copy_to_user", "__arch_copy_to_user",
  };
  size_t i;

  hymo_sym_copy_from_user = NULL;
  for (i = 0; i < ARRAY_SIZE(copy_from_user_syms); i++) {
    hymo_sym_copy_from_user =
        (typeof(hymo_sym_copy_from_user))kallsyms_lookup_name(
            copy_from_user_syms[i]);
    if (hymo_sym_copy_from_user) {
      pr_info("kernel function %s addr: %px\n", copy_from_user_syms[i],
              hymo_sym_copy_from_user);
      break;
    }
  }
  if (!hymo_sym_copy_from_user)
    pr_err("hymofs: copy_from_user symbol not found\n");

  hymo_sym_copy_to_user = NULL;
  for (i = 0; i < ARRAY_SIZE(copy_to_user_syms); i++) {
    hymo_sym_copy_to_user = (typeof(hymo_sym_copy_to_user))kallsyms_lookup_name(
        copy_to_user_syms[i]);
    if (hymo_sym_copy_to_user) {
      pr_info("kernel function %s addr: %px\n", copy_to_user_syms[i],
              hymo_sym_copy_to_user);
      break;
    }
  }
  if (!hymo_sym_copy_to_user)
    pr_err("hymofs: copy_to_user symbol not found\n");
  lookup_name_try_sym(hymo_sym_kmalloc, "__kmalloc");
  lookup_name_try_sym(hymo_sym_kfree, "kfree");
  lookup_name_try_sym(hymo_sym_kfree_const, "kfree_const");
  lookup_name_try_sym(hymo_sym_kstrdup, "kstrdup");
  lookup_name_try_sym(hymo_sym_kvmalloc_node, "kvmalloc_node");
  lookup_name_try_sym(hymo_sym_kvfree, "kvfree");
  lookup_name_try_sym(hymo_sym_filp_open, "filp_open");
  lookup_name_try_sym(hymo_sym_filp_close, "filp_close");
  lookup_name_try_sym(hymo_sym_kernel_read, "kernel_read");
  lookup_name_try_sym(hymo_sym_fget, "fget");
  lookup_name_try_sym(hymo_sym_fput, "fput");
  lookup_name_try_sym(hymo_sym_d_path, "d_path");
  lookup_name_try_sym(hymo_sym_d_absolute_path, "d_absolute_path");
  lookup_name_try_sym(hymo_sym_getname_kernel, "getname_kernel");
  lookup_name_try_sym(hymo_sym_putname, "putname");
  lookup_name_try_sym(hymo_sym_kern_path, "kern_path");
  lookup_name_try_sym(hymo_sym_vfs_listxattr, "vfs_listxattr");
  lookup_name_try_sym(hymo_sym_full_name_hash, "full_name_hash");
  lookup_name_try_sym(hymo_sym_anon_inode_getfd, "anon_inode_getfd");
  lookup_name_try_sym(hymo_sym_vsnprintf, "vsnprintf");
  lookup_name_try_sym(hymo_sym_vscnprintf, "vscnprintf");
  lookup_name_try_sym(hymo_sym_kvasprintf, "kvasprintf");
  lookup_name_try_sym(hymo_sym_vprintk, "vprintk");
  lookup_name_try_sym(hymo_sym_seq_putc, "seq_putc");
  lookup_name_try_sym(hymo_sym_seq_puts, "seq_puts");
  lookup_name_try_sym(hymo_sym_strnlen_user, "strnlen_user");
  lookup_name_try_sym(hymo_sym_raw_spin_lock, "_raw_spin_lock");
  lookup_name_try_sym(hymo_sym_raw_spin_unlock, "_raw_spin_unlock");
  lookup_name_try_sym(hymo_sym_raw_spin_trylock, "_raw_spin_trylock");
  lookup_name_try_sym(hymo_sym_mutex_lock, "mutex_lock");
  lookup_name_try_sym(hymo_sym_mutex_unlock, "mutex_unlock");
  lookup_name_try_sym(hymo_sym_rcu_read_lock, "__rcu_read_lock");
  lookup_name_try_sym(hymo_sym_rcu_read_unlock, "__rcu_read_unlock");
  lookup_name_try_sym(hymo_sym_rcu_barrier, "rcu_barrier");
  lookup_name_try_sym(hymo_sym_down_read, "down_read");
  lookup_name_try_sym(hymo_sym_up_read, "up_read");
  lookup_name_try_sym(hymo_sym_path_get, "path_get");
  lookup_name_try_sym(hymo_sym_path_put, "path_put");
  lookup_name_try_sym(hymo_sym_system_state, "system_state");
  lookup_name_try_sym(hymo_sym_uts_sem, "uts_sem");
}

static inline unsigned long
hymo_copy_from_user(void *to, const void __user *from, unsigned long n) {
  if (!hymo_sym_copy_from_user)
    return n;
  return hymo_sym_copy_from_user(to, from, n);
}

static inline unsigned long hymo_copy_to_user(void __user *to, const void *from,
                                              unsigned long n) {
  if (!hymo_sym_copy_to_user)
    return n;
  return hymo_sym_copy_to_user(to, from, n);
}

static inline void *hymo_kmalloc(size_t size, gfp_t flags) {
  if (!hymo_sym_kmalloc)
    return NULL;
  return hymo_sym_kmalloc(size, flags);
}

static inline void *hymo_kzalloc(size_t size, gfp_t flags) {
  void *ptr = hymo_kmalloc(size, flags);
  if (ptr)
    __builtin_memset(ptr, 0, size);
  return ptr;
}

static inline void hymo_kfree(const void *ptr) {
  if (ptr && hymo_sym_kfree)
    hymo_sym_kfree(ptr);
}

static inline void hymo_kfree_const(const void *ptr) {
  if (ptr && hymo_sym_kfree_const)
    hymo_sym_kfree_const(ptr);
  else
    hymo_kfree(ptr);
}

static inline char *hymo_kstrdup(const char *s, gfp_t flags) {
  if (!hymo_sym_kstrdup)
    return NULL;
  return hymo_sym_kstrdup(s, flags);
}

static inline void *hymo_kvmalloc(size_t size, gfp_t flags) {
  if (hymo_sym_kvmalloc_node)
    return hymo_sym_kvmalloc_node(size, flags, NUMA_NO_NODE);
  return hymo_kmalloc(size, flags);
}

static inline void hymo_kvfree(const void *ptr) {
  if (ptr && hymo_sym_kvfree)
    hymo_sym_kvfree(ptr);
  else
    hymo_kfree(ptr);
}

static inline struct file *hymo_filp_open(const char *name, int flags,
                                          umode_t mode) {
  if (!hymo_sym_filp_open)
    return NULL;
  return hymo_sym_filp_open(name, flags, mode);
}

static inline int hymo_filp_close(struct file *file, fl_owner_t id) {
  if (!hymo_sym_filp_close)
    return -ENOENT;
  return hymo_sym_filp_close(file, id);
}

static inline ssize_t hymo_kernel_read(struct file *file, void *buf,
                                       size_t count, loff_t *pos) {
  if (!hymo_sym_kernel_read)
    return -EINVAL;
  return hymo_sym_kernel_read(file, buf, count, pos);
}

static inline struct file *hymo_fget(int fd) {
  if (!hymo_sym_fget)
    return NULL;
  return hymo_sym_fget(fd);
}

static inline void hymo_fput(struct file *file) {
  if (file && hymo_sym_fput)
    hymo_sym_fput(file);
}

static inline struct filename *hymo_getname_kernel(const char *filename) {
  if (!hymo_sym_getname_kernel)
    return NULL;
  return hymo_sym_getname_kernel(filename);
}

static inline void hymo_putname(struct filename *name) {
  if (name && hymo_sym_putname)
    hymo_sym_putname(name);
}

static inline int hymo_kern_path(const char *name, unsigned int flags,
                                 struct path *path) {
  if (!hymo_sym_kern_path)
    return -ENOENT;
  return hymo_sym_kern_path(name, flags, path);
}

static inline int hymo_vfs_listxattr(struct dentry *dentry, char *list,
                                     size_t size) {
  if (!hymo_sym_vfs_listxattr)
    return -ENOTSUPP;
  return hymo_sym_vfs_listxattr(dentry, list, size);
}

static inline unsigned int hymo_full_name_hash(const struct inode *inode,
                                               const char *name,
                                               unsigned int len) {
  if (!hymo_sym_full_name_hash)
    return 0;
  return hymo_sym_full_name_hash(inode, name, len);
}

static inline int hymo_anon_inode_getfd(const char *name,
                                        const struct file_operations *fops,
                                        void *priv, int flags) {
  if (!hymo_sym_anon_inode_getfd)
    return -ENOENT;
  return hymo_sym_anon_inode_getfd(name, fops, priv, flags);
}

static inline int hymo_vsnprintf(char *buf, size_t size, const char *fmt, ...) {
  va_list args;
  int ret = 0;

  if (!hymo_sym_vsnprintf)
    return 0;
  va_start(args, fmt);
  ret = hymo_sym_vsnprintf(buf, size, fmt, args);
  va_end(args);
  return ret;
}

static inline int hymo_vscnprintf(char *buf, size_t size, const char *fmt,
                                  ...) {
  va_list args;
  int ret = 0;

  if (!hymo_sym_vscnprintf)
    return 0;
  va_start(args, fmt);
  ret = hymo_sym_vscnprintf(buf, size, fmt, args);
  va_end(args);
  return ret;
}

static inline char *hymo_kasprintf(gfp_t gfp, const char *fmt, ...) {
  va_list args;
  char *ret = NULL;

  if (!hymo_sym_kvasprintf)
    return NULL;
  va_start(args, fmt);
  ret = hymo_sym_kvasprintf(gfp, fmt, args);
  va_end(args);
  return ret;
}

static inline bool hymo_sym_valid(const void *p);

static inline int hymo_vprintk(const char *fmt, va_list args) {
  if (!hymo_sym_vprintk || !hymo_sym_valid(hymo_sym_vprintk))
    return 0;
  return hymo_sym_vprintk(fmt, args);
}

static inline long hymo_strnlen_user(const char __user *str, long n) {
  if (!hymo_sym_strnlen_user)
    return -EFAULT;
  return hymo_sym_strnlen_user(str, n);
}

static inline char *hymo_strndup_user(const char __user *src, long n) {
  long len;
  char *dst;

  if (n <= 0)
    return ERR_PTR(-EINVAL);
  len = hymo_strnlen_user(src, n);
  if (len <= 0 || len > n)
    return ERR_PTR(-EFAULT);
  dst = hymo_kmalloc(len + 1, GFP_KERNEL);
  if (!dst)
    return ERR_PTR(-ENOMEM);
  if (hymo_copy_from_user(dst, src, len)) {
    hymo_kfree(dst);
    return ERR_PTR(-EFAULT);
  }
  dst[len] = '\0';
  return dst;
}

static inline void hymo_spin_lock(spinlock_t *lock) {
  if (hymo_sym_raw_spin_lock)
    hymo_sym_raw_spin_lock((raw_spinlock_t *)lock);
}

static inline void hymo_spin_unlock(spinlock_t *lock) {
  if (hymo_sym_raw_spin_unlock)
    hymo_sym_raw_spin_unlock((raw_spinlock_t *)lock);
}

static void hymofs_set_xattr_hooks(bool enable);
static void hymofs_set_all_hooks(bool enable);

static inline bool hymo_spin_trylock(spinlock_t *lock) {
  if (!hymo_sym_raw_spin_trylock)
    return false;
  return hymo_sym_raw_spin_trylock((raw_spinlock_t *)lock) != 0;
}

static inline void hymo_mutex_lock(struct mutex *lock) {
  if (hymo_sym_mutex_lock)
    hymo_sym_mutex_lock(lock);
}

static inline void hymo_mutex_unlock(struct mutex *lock) {
  if (hymo_sym_mutex_unlock)
    hymo_sym_mutex_unlock(lock);
}

static inline void hymo_rcu_read_lock(void) {
  if (hymo_sym_rcu_read_lock)
    hymo_sym_rcu_read_lock();
}

static inline void hymo_rcu_read_unlock(void) {
  if (hymo_sym_rcu_read_unlock)
    hymo_sym_rcu_read_unlock();
}

static inline void hymo_rcu_barrier(void) {
  if (hymo_sym_rcu_barrier)
    hymo_sym_rcu_barrier();
}

static inline void hymo_down_read(struct rw_semaphore *sem) {
  if (hymo_sym_down_read)
    hymo_sym_down_read(sem);
}

static inline void hymo_up_read(struct rw_semaphore *sem) {
  if (hymo_sym_up_read)
    hymo_sym_up_read(sem);
}

static inline void hymo_path_get(struct path *path) {
  if (hymo_sym_path_get)
    hymo_sym_path_get(path);
}

static inline void hymo_path_put(struct path *path) {
  if (hymo_sym_path_put)
    hymo_sym_path_put(path);
}

static inline int hymo_system_state(void) {
  if (!hymo_sym_system_state)
    return SYSTEM_RUNNING;
  return *hymo_sym_system_state;
}

static inline void hymo_uts_down_read(void) {
  if (hymo_sym_uts_sem)
    hymo_down_read(hymo_sym_uts_sem);
}

static inline void hymo_uts_up_read(void) {
  if (hymo_sym_uts_sem)
    hymo_up_read(hymo_sym_uts_sem);
}

static inline void *hymo_memcpy(void *dst, const void *src, size_t n) {
  unsigned char *d = (unsigned char *)dst;
  const unsigned char *s = (const unsigned char *)src;
  while (n--)
    *d++ = *s++;
  return dst;
}

static inline void *hymo_memmove(void *dst, const void *src, size_t n) {
  unsigned char *d = (unsigned char *)dst;
  const unsigned char *s = (const unsigned char *)src;
  if (d == s || n == 0)
    return dst;
  if (d < s) {
    while (n--)
      *d++ = *s++;
  } else {
    d += n;
    s += n;
    while (n--)
      *--d = *--s;
  }
  return dst;
}

static inline void *hymo_memset(void *dst, int c, size_t n) {
  unsigned char *d = (unsigned char *)dst;
  while (n--)
    *d++ = (unsigned char)c;
  return dst;
}

static inline int hymo_memcmp(const void *a, const void *b, size_t n) {
  const unsigned char *p = (const unsigned char *)a;
  const unsigned char *q = (const unsigned char *)b;
  while (n--) {
    if (*p != *q)
      return (int)*p - (int)*q;
    p++;
    q++;
  }
  return 0;
}

static inline size_t hymo_strlen(const char *s) {
  const char *p = s;
  while (*p)
    p++;
  return (size_t)(p - s);
}

static inline int hymo_strcmp(const char *a, const char *b) {
  while (*a && *a == *b) {
    a++;
    b++;
  }
  return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

static inline int hymo_strncmp(const char *a, const char *b, size_t n) {
  while (n--) {
    unsigned char ac = (unsigned char)*a;
    unsigned char bc = (unsigned char)*b;
    if (ac != bc)
      return (int)ac - (int)bc;
    if (!ac)
      return 0;
    a++;
    b++;
  }
  return 0;
}

static inline char *hymo_strchr(const char *s, int c) {
  char ch = (char)c;
  while (*s) {
    if (*s == ch)
      return (char *)s;
    s++;
  }
  return ch == '\0' ? (char *)s : NULL;
}

static inline char *hymo_strrchr(const char *s, int c) {
  char ch = (char)c;
  const char *last = NULL;
  while (*s) {
    if (*s == ch)
      last = s;
    s++;
  }
  if (ch == '\0')
    return (char *)s;
  return (char *)last;
}

static inline size_t hymo_strnlen(const char *s, size_t n) {
  size_t i = 0;
  while (i < n && s[i])
    i++;
  return i;
}

#define HYMO_SYM_NEAR_THRESHOLD (0x20000000UL)
static inline bool hymo_addr_near_self(const void *p) {
  unsigned long addr = (unsigned long)p;
  unsigned long self = (unsigned long)&hymo_addr_near_self;
  unsigned long diff = addr > self ? addr - self : self - addr;
  return diff < HYMO_SYM_NEAR_THRESHOLD;
}

static inline bool hymo_sym_valid(const void *p) {
  return p && !hymo_addr_near_self(p);
}

#define HYMO_CTX_MAGIC 0x48594d4f43545831ULL /* "HYMOCTX1" */
static inline bool hymo_ptr_is_kernel(const void *p) {
  return (((unsigned long)p) & 0xffff000000000000ULL) == 0xffff000000000000ULL;
}

static inline bool hymo_ctx_valid(const struct hymo_readdir_context *ctx,
                                  const struct file *file) {
  return ctx && ctx->magic == HYMO_CTX_MAGIC && ctx->file == file;
}

static inline ssize_t hymo_strscpy(char *dst, const char *src, size_t count) {
  size_t i = 0;

  if (!count)
    return -E2BIG;
  while (i + 1 < count && src[i]) {
    dst[i] = src[i];
    i++;
  }
  dst[i] = '\0';
  if (src[i])
    return -E2BIG;
  return (ssize_t)i;
}

static inline unsigned long hymo_simple_strtoul(const char *cp, char **endp,
                                                unsigned int base) {
  unsigned long result = 0;
  const char *s = cp;

  if (base == 0) {
    if (s[0] == '0') {
      if (s[1] == 'x' || s[1] == 'X') {
        base = 16;
        s += 2;
      } else {
        base = 8;
        s += 1;
      }
    } else {
      base = 10;
    }
  }
  while (*s) {
    unsigned int val;
    if (*s >= '0' && *s <= '9')
      val = *s - '0';
    else if (*s >= 'a' && *s <= 'f')
      val = *s - 'a' + 10;
    else if (*s >= 'A' && *s <= 'F')
      val = *s - 'A' + 10;
    else
      break;
    if (val >= base)
      break;
    result = result * base + val;
    s++;
  }
  if (endp)
    *endp = (char *)s;
  return result;
}

#undef copy_from_user
#define copy_from_user(to, from, n) hymo_copy_from_user((to), (from), (n))
#undef copy_to_user
#define copy_to_user(to, from, n) hymo_copy_to_user((to), (from), (n))
#undef kmalloc
#define kmalloc(size, flags) hymo_kmalloc((size), (flags))
#undef kzalloc
#define kzalloc(size, flags) hymo_kzalloc((size), (flags))
#undef kvmalloc
#define kvmalloc(size, flags) hymo_kvmalloc((size), (flags))
#undef kfree
#define kfree(ptr) hymo_kfree((ptr))
#undef kfree_const
#define kfree_const(ptr) hymo_kfree_const((ptr))
#undef kstrdup
#define kstrdup(s, flags) hymo_kstrdup((s), (flags))
#undef kvfree
#define kvfree(ptr) hymo_kvfree((ptr))
#undef filp_open
#define filp_open(name, flags, mode) hymo_filp_open((name), (flags), (mode))
#undef filp_close
#define filp_close(file, id) hymo_filp_close((file), (id))
#undef kernel_read
#define kernel_read(file, buf, count, pos)                                     \
  hymo_kernel_read((file), (buf), (count), (pos))
#undef fget
#define fget(fd) hymo_fget((fd))
#undef fput
#define fput(file) hymo_fput((file))
#undef getname_kernel
#define getname_kernel(name) hymo_getname_kernel((name))
#undef putname
#define putname(name) hymo_putname((name))
#undef kern_path
#define kern_path(name, flags, path) hymo_kern_path((name), (flags), (path))
#undef vfs_listxattr
#define vfs_listxattr(dentry, list, size)                                      \
  hymo_vfs_listxattr((dentry), (list), (size))
#undef full_name_hash
#define full_name_hash(inode, name, len)                                       \
  hymo_full_name_hash((inode), (name), (len))
#undef anon_inode_getfd
#define anon_inode_getfd(name, fops, priv, flags)                              \
  hymo_anon_inode_getfd((name), (fops), (priv), (flags))
#undef snprintf
#define snprintf(buf, size, fmt, ...)                                          \
  hymo_vsnprintf((buf), (size), (fmt), ##__VA_ARGS__)
#undef scnprintf
#define scnprintf(buf, size, fmt, ...)                                         \
  hymo_vscnprintf((buf), (size), (fmt), ##__VA_ARGS__)
#undef kasprintf
#define kasprintf(gfp, fmt, ...) hymo_kasprintf((gfp), (fmt), ##__VA_ARGS__)
#undef vprintk
#define vprintk(fmt, args) hymo_vprintk((fmt), (args))
#undef strndup_user
#define strndup_user(src, n) hymo_strndup_user((src), (n))
#undef strscpy
#define strscpy(dst, src, count) hymo_strscpy((dst), (src), (count))
#undef simple_strtoul
#define simple_strtoul(cp, endp, base) hymo_simple_strtoul((cp), (endp), (base))
#undef spin_lock
#define spin_lock(lock) hymo_spin_lock((lock))
#undef spin_unlock
#define spin_unlock(lock) hymo_spin_unlock((lock))
#undef mutex_lock
#define mutex_lock(lock) hymo_mutex_lock((lock))
#undef mutex_unlock
#define mutex_unlock(lock) hymo_mutex_unlock((lock))
#undef rcu_read_lock
#define rcu_read_lock() hymo_rcu_read_lock()
#undef rcu_read_unlock
#define rcu_read_unlock() hymo_rcu_read_unlock()
#undef rcu_barrier
#define rcu_barrier() hymo_rcu_barrier()
#undef down_read
#define down_read(sem) hymo_down_read((sem))
#undef up_read
#define up_read(sem) hymo_up_read((sem))
#undef path_get
#define path_get(path) hymo_path_get((path))
#undef path_put
#define path_put(path) hymo_path_put((path))

/* Override utils hook helpers to avoid direct CALL26 to KP symbols */
#undef hook_func
#undef hook_func_try
#undef unhook_func
#define hook_func(func, argv, before, after, udata)                            \
  do {                                                                         \
    if (!(func))                                                               \
      return -22;                                                              \
    hook_err_t hook_err_##func =                                               \
        hymo_kp_hook_wrap_call((func), (argv), (before), (after), (udata));    \
    if (hook_err_##func) {                                                     \
      pr_err("hook %s error: %d\n", #func, hook_err_##func);                   \
      return -23;                                                              \
    } else {                                                                   \
      pr_info("hook %s success\n", #func);                                     \
    }                                                                          \
  } while (0)

#define hook_func_try(func, argv, before, after, udata)                        \
  do {                                                                         \
    if (!(func)) {                                                             \
      pr_warn("hook %s skipped (missing symbol)\n", #func);                    \
    } else {                                                                   \
      hook_err_t hook_err_##func =                                             \
          hymo_kp_hook_wrap_call((func), (argv), (before), (after), (udata));  \
      if (hook_err_##func) {                                                   \
        pr_err("hook %s error: %d\n", #func, hook_err_##func);                 \
      } else {                                                                 \
        pr_info("hook %s success\n", #func);                                   \
      }                                                                        \
    }                                                                          \
  } while (0)

#define unhook_func(func)                                                      \
  do {                                                                         \
    if ((func) && !is_bad_address((void *)(func)))                             \
      hymo_kp_unhook_call((void *)(func));                                     \
  } while (0)

#undef memcpy
#undef memmove
#undef memset
#undef memcmp
#undef strlen
#undef strcmp
#undef strncmp
#undef strchr
#undef strrchr
#undef strnlen
#undef d_path
#undef seq_putc
#undef seq_puts

__attribute__((used)) void *memcpy(void *dst, const void *src, size_t n) {
  return hymo_memcpy(dst, src, n);
}

__attribute__((used)) void *memmove(void *dst, const void *src, size_t n) {
  return hymo_memmove(dst, src, n);
}

__attribute__((used)) void *memset(void *dst, int c, size_t n) {
  return hymo_memset(dst, c, n);
}

__attribute__((used)) int memcmp(const void *a, const void *b, size_t n) {
  return hymo_memcmp(a, b, n);
}

__attribute__((used)) size_t strlen(const char *s) { return hymo_strlen(s); }

__attribute__((used)) int strcmp(const char *a, const char *b) {
  return hymo_strcmp(a, b);
}

__attribute__((used)) int strncmp(const char *a, const char *b, size_t n) {
  return hymo_strncmp(a, b, n);
}

__attribute__((used)) char *strchr(const char *s, int c) {
  return hymo_strchr(s, c);
}

__attribute__((used)) char *strrchr(const char *s, int c) {
  return hymo_strrchr(s, c);
}

__attribute__((used)) size_t strnlen(const char *s, size_t n) {
  return hymo_strnlen(s, n);
}

/*
 * d_path recursion guard
 *
 * When we hook d_path(), calling d_path() again from within our own hook path
 * (directly or indirectly) can cause unbounded recursion / deadlock.
 *
 * Avoid percpu/preempt helpers here (CALL26 relocation risk); use a small
 * hashed atomic depth table keyed by `current` pointer (collisions acceptable).
 */
#define HYMO_DPATH_GUARD_SLOTS 1024 /* must be power of 2 */
static atomic_t hymo_dpath_depth[HYMO_DPATH_GUARD_SLOTS];

static __always_inline unsigned int hymo_dpath_idx(void) {
  return ((unsigned long)current >> 4) & (HYMO_DPATH_GUARD_SLOTS - 1);
}

static __always_inline bool hymo_dpath_enter(void) {
  unsigned int idx = hymo_dpath_idx();
  int v = atomic_inc_return(&hymo_dpath_depth[idx]);
  if (likely(v == 1))
    return true;
  atomic_dec(&hymo_dpath_depth[idx]);
  return false;
}

static __always_inline void hymo_dpath_exit(void) {
  unsigned int idx = hymo_dpath_idx();
  atomic_dec(&hymo_dpath_depth[idx]);
}

static __always_inline bool hymo_dpath_active(void) {
  unsigned int idx = hymo_dpath_idx();
  return atomic_read(&hymo_dpath_depth[idx]) > 0;
}

__attribute__((used)) char *d_path(const struct path *path, char *buf,
                                   int buflen) {
  if (!hymo_sym_d_path)
    return ERR_PTR(-ENOENT);
  /*
   * If we are already inside our d_path hook path, bypass d_path() and try
   * d_absolute_path() to avoid self-recursion. This mirrors the original
   * in-tree HYMOFS strategy.
   */
  if (unlikely(hymo_dpath_active() && hymo_sym_d_absolute_path))
    return hymo_sym_d_absolute_path(path, buf, buflen);
  return hymo_sym_d_path(path, buf, buflen);
}

__attribute__((used)) char *d_absolute_path(const struct path *path, char *buf,
                                            int buflen) {
  if (!hymo_sym_d_absolute_path)
    return ERR_PTR(-ENOENT);
  return hymo_sym_d_absolute_path(path, buf, buflen);
}

__attribute__((used)) void seq_putc(struct seq_file *m, char c) {
  if (!hymo_sym_seq_putc)
    return;
  hymo_sym_seq_putc(m, c);
}

__attribute__((used)) void seq_puts(struct seq_file *m, const char *s) {
  if (!hymo_sym_seq_puts)
    return;
  hymo_sym_seq_puts(m, s);
}

__attribute__((used)) bool __list_add_valid_or_report(struct list_head *new,
                                                      struct list_head *prev,
                                                      struct list_head *next) {
  return true;
}

__attribute__((used)) bool
__list_del_entry_valid_or_report(struct list_head *entry) {
  return true;
}

__attribute__((used, noreturn)) void fortify_panic(const char *name) {
  (void)name;
  for (;;)
    ;
}

struct alt_instr;
__attribute__((used)) void alt_cb_patch_nops(struct alt_instr *alt,
                                             __le32 *origptr, __le32 *updptr,
                                             int nr_inst) {
  (void)alt;
  (void)origptr;
  (void)updptr;
  (void)nr_inst;
}

__attribute__((used)) unsigned long __get_free_pages(gfp_t gfp_mask,
                                                     unsigned int order) {
  (void)gfp_mask;
  (void)order;
  return 0;
}

__attribute__((used)) void free_pages(unsigned long addr, unsigned int order) {
  (void)addr;
  (void)order;
}

struct task_struct;
struct pid_namespace;
__attribute__((used)) pid_t __task_pid_nr_ns(struct task_struct *task,
                                             enum pid_type type,
                                             struct pid_namespace *ns) {
  (void)task;
  (void)type;
  (void)ns;
  return 0;
}

void __check_object_size(const void *ptr, unsigned long n, bool is_write) {
  (void)ptr;
  (void)n;
  (void)is_write;
}

void __copy_overflow(int size, unsigned long count) {
  (void)size;
  (void)count;
}

int _printk(const char *fmt, ...) {
  va_list args;
  int ret = 0;

  va_start(args, fmt);
  ret = hymo_vprintk(fmt, args);
  va_end(args);
  return ret;
}

KPM_NAME("HymoFS");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Anatdx");
KPM_DESCRIPTION("HymoFS kernel patch module");

#ifdef CONFIG_HYMOFS

/* HymoFS - Advanced Path Manipulation and Hiding */
/* Increased hash bits to reduce collisions with large number of rules */
#define HYMO_HASH_BITS 12
#define HYMO_ALLOWLIST_UID_MAX 1024
#define HYMO_KSU_ALLOWLIST_PATH "/data/adb/ksu/.allowlist"
#define HYMO_KSU_ALLOWLIST_MAGIC 0x7f4b5355
#define HYMO_KSU_ALLOWLIST_VERSION 3
#define HYMO_KSU_MAX_PACKAGE_NAME 256
#define HYMO_KSU_MAX_GROUPS 32
#define HYMO_KSU_SELINUX_DOMAIN 64

struct hymo_linux_dirent {
  unsigned long d_ino;
  unsigned long d_off;
  unsigned short d_reclen;
  char d_name[];
};

struct hymo_entry {
  char *src;
  char *target;
  unsigned char type;
  struct hlist_node node;
  struct hlist_node target_node;
  struct rcu_head rcu;
};
struct hymo_hide_entry {
  char *path;
  struct hlist_node node;
  struct rcu_head rcu;
};

struct hymo_allow_uid_entry {
  uid_t uid;
  struct hlist_node node;
  struct rcu_head rcu;
};

struct hymo_root_profile {
  s32 uid;
  s32 gid;
  s32 groups_count;
  s32 groups[HYMO_KSU_MAX_GROUPS];
  struct {
    u64 effective;
    u64 permitted;
    u64 inheritable;
  } capabilities;
  char selinux_domain[HYMO_KSU_SELINUX_DOMAIN];
  s32 namespaces;
};

struct hymo_non_root_profile {
  bool umount_modules;
};

struct hymo_app_profile {
  u32 version;
  char key[HYMO_KSU_MAX_PACKAGE_NAME];
  s32 current_uid;
  bool allow_su;
  union {
    struct {
      bool use_default;
      char template_name[HYMO_KSU_MAX_PACKAGE_NAME];
      struct hymo_root_profile profile;
    } rp_config;
    struct {
      bool use_default;
      struct hymo_non_root_profile profile;
    } nrp_config;
  };
};

struct hymo_inject_entry {
  char *dir;
  struct hlist_node node;
  struct rcu_head rcu;
};

struct hymo_xattr_sb_entry {
  struct super_block *sb;
  struct hlist_node node;
  struct rcu_head rcu;
};

struct hymo_merge_entry {
  char *src;
  char *target;
  struct hlist_node node;
  struct rcu_head rcu;
};

static DEFINE_HASHTABLE(hymo_paths, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_targets, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_hide_paths, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_allow_uids, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_inject_dirs, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_xattr_sbs, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_merge_dirs, HYMO_HASH_BITS);
static DEFINE_SPINLOCK(hymo_lock);
static bool hymo_allowlist_loaded = false;
static DEFINE_MUTEX(hymo_allowlist_lock);
bool hymofs_enabled = false;
bool hymofs_uname_spoofing_enabled = false;
static bool hymofs_exiting = false;
static bool hymo_syms_resolved = false;
static bool hymo_hooks_active = false;
static bool hymo_reboot_hooked = false;
static int hymo_reboot_hit_count = 0;
static bool hymo_reboot_use_regs = false;
static int hymo_ioctl_fail_count = 0;
EXPORT_SYMBOL(hymofs_enabled);

/* Use HYMO_BLOOM_BITS from hymofs.h to avoid redefinition */
static DECLARE_BITMAP(hymo_path_bloom, HYMO_BLOOM_SIZE);
static atomic_t hymo_rule_count = ATOMIC_INIT(0);
static atomic_t hymo_hide_count = ATOMIC_INIT(0);
static atomic_t hymo_merge_count = ATOMIC_INIT(0);

/*
 * Bloom filter fast-path (ported from original hymofs patch):
 * - Used only as a quick *negative* check to skip expensive work on hot paths.
 * - False positives are fine; false negatives must not happen.
 * - We never clear bits on rule deletion (safe, but may increase false
 * positives).
 */
static __always_inline void hymo_bloom_add(unsigned long *filter,
                                           const char *name, int namlen) {
  u32 h1;
  if (!name || namlen <= 0)
    return;
  h1 = full_name_hash(NULL, name, namlen);
  __set_bit(h1 & HYMO_BLOOM_MASK, filter);
  __set_bit((h1 >> 16) & HYMO_BLOOM_MASK, filter);
}

static __always_inline bool hymo_bloom_test(const unsigned long *filter,
                                            const char *name, int namlen) {
  u32 h1;
  if (!name || namlen <= 0)
    return true;
  h1 = full_name_hash(NULL, name, namlen);
  return test_bit(h1 & HYMO_BLOOM_MASK, filter) &&
         test_bit((h1 >> 16) & HYMO_BLOOM_MASK, filter);
}

static __always_inline bool hymofs_has_any_rules(void) {
  /*
   * Hot-path helper for getname/d_path/etc.
   * Use atomic counters instead of hash_empty(): cheaper and avoids corner
   * cases when hash tables are non-empty but temporarily not observable.
   */
  return atomic_read(&hymo_rule_count) != 0 ||
         atomic_read(&hymo_hide_count) != 0 ||
         atomic_read(&hymo_merge_count) != 0;
}

static void hymofs_kpm_update_info_description(void);

/* Runtime hook switches for bisecting freezes */
static int hymofs_hook_stage_runtime = HYMOFS_HOOK_STAGE;
static bool hymofs_disable_dirents_runtime =
    HYMOFS_DISABLE_DIRENTS ? true : false;
static bool hymofs_disable_dpath_runtime = HYMOFS_DISABLE_DPATH ? true : false;
static bool hymofs_disable_getname_runtime =
    HYMOFS_DISABLE_GETNAME ? true : false;
static bool hymofs_disable_getattr_runtime =
    HYMOFS_DISABLE_GETATTR ? true : false;
static bool hymofs_disable_filename_lookup_runtime =
    HYMOFS_DISABLE_FILENAME_LOOKUP ? true : false;

static void hymofs_apply_hook_config_locked(void) {
  /*
   * Re-apply hooks immediately. This is intended for debugging:
   * if you change stage/disable flags and the device freezes, you know which
   * hook group is guilty.
   */
  if (!hymo_syms_resolved)
    return;
  hymofs_set_all_hooks(false);
  if (hymofs_enabled && !hymofs_exiting)
    hymofs_set_all_hooks(true);
}

#ifndef HYMOFS_SAFE_DEFAULT
#define HYMOFS_SAFE_DEFAULT 0
#endif // #ifndef HYMOFS_SAFE_DEFAULT
#ifndef HYMOFS_INIT_ONLY
#define HYMOFS_INIT_ONLY 0
#endif // #ifndef HYMOFS_INIT_ONLY
#ifndef HYMOFS_DISABLE_DIRENTS
#define HYMOFS_DISABLE_DIRENTS 0
#endif // #ifndef HYMOFS_DISABLE_DIRENTS
#ifndef HYMOFS_DISABLE_DPATH
#define HYMOFS_DISABLE_DPATH 0
#endif // #ifndef HYMOFS_DISABLE_DPATH
#ifndef HYMOFS_DISABLE_GETNAME
#define HYMOFS_DISABLE_GETNAME 0
#endif // #ifndef HYMOFS_DISABLE_GETNAME
#ifndef HYMOFS_DISABLE_GETATTR
#define HYMOFS_DISABLE_GETATTR 0
#endif // #ifndef HYMOFS_DISABLE_GETATTR
#ifndef HYMOFS_DISABLE_FILENAME_LOOKUP
#define HYMOFS_DISABLE_FILENAME_LOOKUP 0
#endif // #ifndef HYMOFS_DISABLE_FILENAME_LOOKUP
#ifndef HYMOFS_DISABLE_REBOOT_HOOK
#define HYMOFS_DISABLE_REBOOT_HOOK 0
#endif // #ifndef HYMOFS_DISABLE_REBOOT_HOOK
static bool hymo_debug_enabled = false;
static bool hymo_stealth_enabled = true;
static bool hymo_safe_mode = HYMOFS_SAFE_DEFAULT ? true : false;

/* Hook entry for reboot syscall command channel (optional) */
int (*hymo_dispatch_cmd_hook)(unsigned int cmd, void __user *arg) = NULL;
EXPORT_SYMBOL(hymo_dispatch_cmd_hook);

/* Performance counters */
static __attribute__((unused)) struct hymofs_perf_info hymo_perf = {0};

/* Mirror path */
static char hymo_mirror_path_buf[PATH_MAX] = HYMO_DEFAULT_MIRROR_PATH;
static char hymo_mirror_name_buf[NAME_MAX] = HYMO_DEFAULT_MIRROR_NAME;
static char *hymo_current_mirror_path = hymo_mirror_path_buf;
static char *hymo_current_mirror_name = hymo_mirror_name_buf;

/* Daemon process PID */
static pid_t hymo_daemon_pid = -1;
static DEFINE_SPINLOCK(hymo_daemon_lock);

/* Uname spoofing */
#ifdef CONFIG_HYMOFS_UNAME_SPOOF
struct hymo_uname_info {
  bool enabled;
  struct hymo_spoof_uname uname;
};
static struct hymo_uname_info hymo_uname_info = {0};
static DEFINE_SPINLOCK(hymo_uname_lock);
#endif // #ifdef CONFIG_HYMOFS_UNAME_SPOOF

#ifdef CONFIG_HYMOFS_CMDLINE_SPOOF
static bool hymo_cmdline_spoofed = false;
static char *hymo_fake_cmdline = NULL;
#endif // #ifdef CONFIG_HYMOFS_CMDLINE_SPOOF

/* KStat spoofing */
#ifdef CONFIG_HYMOFS_STAT_SPOOF
struct hymo_kstat_entry {
  struct hlist_node node;
  struct rcu_head rcu;
  struct hymo_spoof_kstat kstat;
};
static DEFINE_HASHTABLE(hymo_spoof_kstats, HYMO_HASH_BITS);
static DEFINE_SPINLOCK(hymo_kstat_lock);
#endif // #ifdef CONFIG_HYMOFS_STAT_SPOOF

/* Rule entry types */
enum {
  HYMO_TYPE_REPLACE = 1,
  HYMO_TYPE_REVERSE = 2,
  HYMO_TYPE_RECURSIVE = 3,
};

static inline void hymo_log(const char *fmt, ...) {
  va_list args;
  if (!hymo_debug_enabled)
    return;
  va_start(args, fmt);
  vprintk(fmt, args);
  va_end(args);
}

static bool hymo_is_allowlist_uid(uid_t uid);
static void hymofs_d_path_after(hook_fargs3_t *args, void *udata);
static void hymofs_getname_after(hook_fargs1_t *args, void *udata);
static void hymofs_getname_uflags_after(hook_fargs2_t *args, void *udata);
static void hymofs_vfs_getattr_after(hook_fargs4_t *args, void *udata);
static void hymofs_getdents_before(hook_fargs3_t *args, void *udata);
static void hymofs_getdents_after(hook_fargs3_t *args, void *udata);
static void hymofs_getdents64_before(hook_fargs3_t *args, void *udata);
static void hymofs_getdents64_after(hook_fargs3_t *args, void *udata);
static void hymofs_getdents_regs_before(hook_fargs1_t *args, void *udata);
static void hymofs_getdents_regs_after(hook_fargs1_t *args, void *udata);
static void hymofs_getdents64_regs_before(hook_fargs1_t *args, void *udata);
static void hymofs_getdents64_regs_after(hook_fargs1_t *args, void *udata);
static void hymofs_filename_lookup_before(hook_fargs5_t *args, void *udata);
static void hymofs_filename_lookup_after(hook_fargs5_t *args, void *udata);
static void hymofs_cmdline_show_before(hook_fargs2_t *args, void *udata);
static void hymofs_mountinfo_show_before(hook_fargs2_t *args, void *udata);
static void hymofs_newuname_before(hook_fargs1_t *args, void *udata);
static void hymofs_uname_before(hook_fargs1_t *args, void *udata);
static void hymofs_reboot_before_args4(hook_fargs4_t *args, void *udata);
static void hymofs_reboot_before_regs(hook_fargs1_t *args, void *udata);

static bool hymo_is_privileged_process(void) {
  pid_t current_pid = task_tgid_vnr(current);
  if (uid_eq(current_uid(), GLOBAL_ROOT_UID))
    return true;
  if (hymo_daemon_pid > 0 && current_pid == hymo_daemon_pid)
    return true;
  if (hymo_is_allowlist_uid(current_uid().val))
    return true;
  return false;
}

static bool hymo_should_apply_hide_rules(void) {
  if (unlikely(hymofs_exiting))
    return false;
  if (!hymofs_enabled)
    return false;
  if (hymo_system_state() < SYSTEM_RUNNING)
    return false;
  return true;
}

static void hymo_cleanup_locked(void) {
  int bkt;
  struct hymo_entry *entry;
  struct hymo_hide_entry *hide_entry;
  struct hymo_inject_entry *inject_entry;
  struct hymo_allow_uid_entry *allow_entry;
  struct hymo_xattr_sb_entry *sb_entry;
  struct hymo_merge_entry *merge_entry;
  struct hlist_node *tmp;

  hash_for_each_safe(hymo_paths, bkt, tmp, entry, node) {
    hash_del_rcu(&entry->node);
    hash_del_rcu(&entry->target_node);
    kfree(entry->src);
    kfree(entry->target);
    kfree(entry);
  }
  hash_for_each_safe(hymo_hide_paths, bkt, tmp, hide_entry, node) {
    hash_del_rcu(&hide_entry->node);
    kfree(hide_entry->path);
    kfree(hide_entry);
  }
  hash_for_each_safe(hymo_inject_dirs, bkt, tmp, inject_entry, node) {
    hash_del_rcu(&inject_entry->node);
    kfree(inject_entry->dir);
    kfree(inject_entry);
  }
  hash_for_each_safe(hymo_allow_uids, bkt, tmp, allow_entry, node) {
    hash_del_rcu(&allow_entry->node);
    kfree(allow_entry);
  }
  hash_for_each_safe(hymo_xattr_sbs, bkt, tmp, sb_entry, node) {
    hash_del_rcu(&sb_entry->node);
    kfree(sb_entry);
  }
  hash_for_each_safe(hymo_merge_dirs, bkt, tmp, merge_entry, node) {
    hash_del_rcu(&merge_entry->node);
    kfree(merge_entry->src);
    kfree(merge_entry->target);
    kfree(merge_entry);
  }
#ifdef CONFIG_HYMOFS_STAT_SPOOF
  {
    struct hymo_kstat_entry *kstat_entry;
    hash_for_each_safe(hymo_spoof_kstats, bkt, tmp, kstat_entry, node) {
      hash_del_rcu(&kstat_entry->node);
      kfree(kstat_entry);
    }
  }
#endif // #ifdef CONFIG_HYMOFS_STAT_SPOOF
  atomic_set(&hymo_rule_count, 0);
  atomic_set(&hymo_hide_count, 0);
  atomic_set(&hymo_merge_count, 0);
  bitmap_zero(hymo_path_bloom, HYMO_BLOOM_SIZE);
}

static bool hymo_is_allowlist_uid(uid_t uid) {
  struct hymo_allow_uid_entry *entry;
  bool found = false;
  if (uid == 0)
    return true;
  rcu_read_lock();
  hlist_for_each_entry_rcu(
      entry, &hymo_allow_uids[hash_min(uid, HYMO_HASH_BITS)], node) {
    if (entry->uid == uid) {
      found = true;
      break;
    }
  }
  rcu_read_unlock();
  return found;
}

/* === KSU allowlist parsing === */
#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
struct hymo_ksu_allowlist_header {
  u32 magic;
  u32 version;
  u32 entry_count;
  u32 reserved;
};

struct hymo_ksu_allowlist_entry {
  u32 uid;
  u32 gid;
  u32 groups_count;
  u32 reserved;
};

static void hymo_reload_ksu_allowlist(void) {
  struct file *file;
  loff_t pos = 0;
  ssize_t bytes;
  struct hymo_ksu_allowlist_header hdr;
  int i;
  bool valid = false;

  if (hymo_safe_mode)
    return;
  /* Avoid blocking I/O during early boot. */
  if (hymo_system_state() < SYSTEM_RUNNING)
    return;
  if (!hymo_sym_valid(hymo_sym_mutex_lock) ||
      !hymo_sym_valid(hymo_sym_mutex_unlock) ||
      !hymo_sym_valid(hymo_sym_filp_open) ||
      !hymo_sym_valid(hymo_sym_kernel_read) ||
      !hymo_sym_valid(hymo_sym_filp_close) ||
      !hymo_sym_valid(hymo_sym_kmalloc) || !hymo_sym_valid(hymo_sym_kfree)) {
    return;
  }

  mutex_lock(&hymo_allowlist_lock);
  if (hymo_allowlist_loaded) {
    mutex_unlock(&hymo_allowlist_lock);
    return;
  }

  file = filp_open(HYMO_KSU_ALLOWLIST_PATH, O_RDONLY, 0);
  if (IS_ERR(file)) {
    mutex_unlock(&hymo_allowlist_lock);
    return;
  }

  bytes = kernel_read(file, &hdr, sizeof(hdr), &pos);
  if (bytes != sizeof(hdr)) {
    goto out;
  }

  if (hdr.magic != HYMO_KSU_ALLOWLIST_MAGIC ||
      hdr.version != HYMO_KSU_ALLOWLIST_VERSION)
    goto out;

  if (hdr.entry_count > HYMO_ALLOWLIST_UID_MAX)
    goto out;

  for (i = 0; i < hdr.entry_count; i++) {
    struct hymo_ksu_allowlist_entry entry;
    struct hymo_allow_uid_entry *uid_entry;

    bytes = kernel_read(file, &entry, sizeof(entry), &pos);
    if (bytes != sizeof(entry))
      break;

    uid_entry = kmalloc(sizeof(*uid_entry), GFP_KERNEL);
    if (!uid_entry)
      break;
    uid_entry->uid = entry.uid;
    hash_add_rcu(hymo_allow_uids, &uid_entry->node, uid_entry->uid);
  }

  valid = true;
out:
  filp_close(file, NULL);
  hymo_allowlist_loaded = valid;
  mutex_unlock(&hymo_allowlist_lock);
}
#endif // #ifdef CONFIG_HYMOFS_HIDE_ENTRIES

/* === Utilities === */
static inline u32 hymo_hash_str(const char *str) {
  return jhash(str, strlen(str), 0);
}

static __attribute__((unused)) void hymofs_add_inject_rule(char *dir) {
  struct hymo_inject_entry *inject_entry;
  u32 hash;
  bool found = false;

  if (!dir)
    return;

  hash = full_name_hash(NULL, dir, strlen(dir));
  hlist_for_each_entry(
      inject_entry, &hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
    if (strcmp(inject_entry->dir, dir) == 0) {
      found = true;
      break;
    }
  }
  if (!found) {
    inject_entry = kmalloc(sizeof(*inject_entry), GFP_ATOMIC);
    if (inject_entry) {
      inject_entry->dir = dir;
      hlist_add_head_rcu(&inject_entry->node,
                         &hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)]);
      atomic_inc(&hymo_rule_count);
      hymo_log("auto-inject parent: %s\n", dir);
    } else {
      kfree(dir);
    }
  } else {
    kfree(dir);
  }
}

static void hymofs_reorder_mnt_id(void) {
  struct mnt_namespace *ns = current->nsproxy->mnt_ns;
  struct mount *m;
  int id = 1;
  bool is_hymo_mount;

  // Try to find the starting ID from the first mount
  if (ns && !list_empty(&ns->list)) {
    struct mount *first = list_first_entry(&ns->list, struct mount, mnt_list);
    if (first->mnt_id < 500000)
      id = first->mnt_id;
  }

  if (!ns)
    return;

  list_for_each_entry(m, &ns->list, mnt_list) {
    is_hymo_mount = false;

    if (m->mnt_devname &&
        (strcmp(m->mnt_devname, hymo_current_mirror_path) == 0 ||
         strcmp(m->mnt_devname, hymo_current_mirror_name) == 0)) {
      is_hymo_mount = true;
    }

    if (is_hymo_mount && hymo_stealth_enabled) {
      if (m->mnt_id < 500000) {
        WRITE_ONCE(m->mnt_id, 500000 + (id % 1000));
      }
    } else {
      if (m->mnt_id >= 500000)
        continue;
      WRITE_ONCE(m->mnt_id, id++);
    }
  }
}

static void hymofs_spoof_mounts(void) {
  struct mnt_namespace *ns = current->nsproxy->mnt_ns;
  struct mount *m;
  char *system_devname = NULL;
  struct path sys_path;

  if (!ns)
    return;
  if (!hymo_stealth_enabled)
    return;

  if (kern_path("/system", LOOKUP_FOLLOW, &sys_path) == 0) {
    struct mount *sys_mnt = real_mount(sys_path.mnt);
    if (sys_mnt && sys_mnt->mnt_devname) {
      system_devname = kstrdup(sys_mnt->mnt_devname, GFP_KERNEL);
    }
    path_put(&sys_path);
  }

  if (!system_devname) {
    if (kern_path("/", LOOKUP_FOLLOW, &sys_path) == 0) {
      struct mount *sys_mnt = real_mount(sys_path.mnt);
      if (sys_mnt && sys_mnt->mnt_devname) {
        system_devname = kstrdup(sys_mnt->mnt_devname, GFP_KERNEL);
      }
      path_put(&sys_path);
    }
  }

  if (!system_devname)
    return;

  list_for_each_entry(m, &ns->list, mnt_list) {
    if (m->mnt_devname &&
        (strcmp(m->mnt_devname, hymo_current_mirror_path) == 0 ||
         strcmp(m->mnt_devname, hymo_current_mirror_name) == 0)) {
      const char *old_name = m->mnt_devname;
      m->mnt_devname = kstrdup(system_devname, GFP_KERNEL);
      if (m->mnt_devname) {
        kfree_const(old_name);
      } else {
        m->mnt_devname = old_name;
      }
    }
  }
  kfree(system_devname);
}

static const struct file_operations hymo_anon_fops;

/* === Command dispatch === */
int hymo_dispatch_cmd(unsigned int cmd, void __user *arg) {
  struct hymo_syscall_arg req;
  struct hymo_entry *entry;
  struct hymo_hide_entry *hide_entry;
  struct hymo_inject_entry *inject_entry;
  char *src = NULL, *target = NULL;
  u32 hash;
  bool found = false;
  int ret = 0;

  if (cmd == HYMO_CMD_CLEAR_ALL) {
    spin_lock(&hymo_lock);
    hymo_cleanup_locked();
    strscpy(hymo_mirror_path_buf, HYMO_DEFAULT_MIRROR_PATH, PATH_MAX);
    strscpy(hymo_mirror_name_buf, HYMO_DEFAULT_MIRROR_NAME, NAME_MAX);
    hymo_current_mirror_path = hymo_mirror_path_buf;
    hymo_current_mirror_name = hymo_mirror_name_buf;
    hymofs_enabled = false;
    hymofs_uname_spoofing_enabled = false;
    spin_unlock(&hymo_lock);
    if (hymo_syms_resolved)
      hymofs_set_all_hooks(false);
    hymofs_kpm_update_info_description();
    rcu_barrier();
    return 0;
  }

  if (cmd == HYMO_CMD_GET_VERSION) {
    return HYMO_PROTOCOL_VERSION;
  }

  if (cmd == HYMO_CMD_SET_DEBUG) {
    int val;
    if (copy_from_user(&val, arg, sizeof(val)))
      return -EFAULT;
    hymo_debug_enabled = !!val;
    hymo_log("debug mode %s\n", hymo_debug_enabled ? "enabled" : "disabled");
    return 0;
  }

  if (cmd == HYMO_CMD_REORDER_MNT_ID) {
    /*
     * reorder_mnt_id identifies Hymo mounts by devname (mirror path/name).
     * spoof_mounts may rewrite devname first, making reorder unable to find
     * them. So reorder first, then spoof.
     */
    hymofs_reorder_mnt_id();
    hymofs_spoof_mounts();
    return 0;
  }

  if (cmd == HYMO_CMD_SET_STEALTH) {
    int val;
    if (copy_from_user(&val, arg, sizeof(val)))
      return -EFAULT;
    hymo_stealth_enabled = !!val;
    hymo_log("stealth mode %s\n",
             hymo_stealth_enabled ? "enabled" : "disabled");
    if (hymo_stealth_enabled) {
      hymofs_reorder_mnt_id();
      hymofs_spoof_mounts();
    }
    return 0;
  }

  if (cmd == HYMO_CMD_SET_ENABLED) {
    int val;
    if (copy_from_user(&val, arg, sizeof(val)))
      return -EFAULT;
    spin_lock(&hymo_lock);
    hymofs_enabled = !!val;
    spin_unlock(&hymo_lock);
    if (hymo_syms_resolved)
      hymofs_set_all_hooks(hymofs_enabled);
    hymofs_kpm_update_info_description();
    hymo_log("HymoFS %s\n", hymofs_enabled ? "enabled" : "disabled");
#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
    if (hymofs_enabled) {
      if (!hymo_safe_mode)
        hymo_reload_ksu_allowlist();
    }
#endif // #ifdef CONFIG_HYMOFS_HIDE_ENTRIES
    return 0;
  }

  if (cmd == HYMO_CMD_GET_FD) {
    /* Return anonymous fd - the ONLY way to access HymoFS */
    int fd;
    pid_t pid;
    if (!uid_eq(current_uid(), GLOBAL_ROOT_UID)) {
      return -EPERM;
    }
    fd = anon_inode_getfd("hymo", &hymo_anon_fops, NULL, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
      return fd;
    }

    /* Automatically register this process as the daemon */
    pid = task_tgid_vnr(current);
    spin_lock(&hymo_daemon_lock);
    hymo_daemon_pid = pid;
    spin_unlock(&hymo_daemon_lock);
    hymo_log("Daemon PID auto-registered: %d\n", pid);

    return fd; /* Return fd directly */
  }

  /* LIST_RULES uses a different struct, handle it separately */
  if (cmd == HYMO_CMD_LIST_RULES) {
    struct hymo_syscall_list_arg list_arg;
    char *kbuf;
    size_t buf_size;
    size_t written = 0;
    int bkt;
    struct hymo_xattr_sb_entry *sb_entry;
    struct hymo_merge_entry *merge_entry;

    if (copy_from_user(&list_arg, (void __user *)arg, sizeof(list_arg))) {
      return -EFAULT;
    }

    buf_size = list_arg.size;
    if (buf_size > 16 * 1024)
      buf_size = 16 * 1024;

    kbuf = kzalloc(buf_size, GFP_KERNEL);
    if (!kbuf) {
      return -ENOMEM;
    }

    rcu_read_lock();

    written += scnprintf(kbuf + written, buf_size - written,
                         "HymoFS Protocol: %d\n", HYMO_PROTOCOL_VERSION);
    written += scnprintf(kbuf + written, buf_size - written,
                         "HymoFS Enabled: %d\n", hymofs_enabled ? 1 : 0);

    hash_for_each_rcu(hymo_paths, bkt, entry, node) {
      if (written >= buf_size)
        break;
      written += scnprintf(kbuf + written, buf_size - written, "add %s %s %d\n",
                           entry->src, entry->target, entry->type);
    }
    hash_for_each_rcu(hymo_hide_paths, bkt, hide_entry, node) {
      if (written >= buf_size)
        break;
      written += scnprintf(kbuf + written, buf_size - written, "hide %s\n",
                           hide_entry->path);
    }
    hash_for_each_rcu(hymo_inject_dirs, bkt, inject_entry, node) {
      if (written >= buf_size)
        break;
      written += scnprintf(kbuf + written, buf_size - written, "inject %s\n",
                           inject_entry->dir);
    }
    hash_for_each_rcu(hymo_merge_dirs, bkt, merge_entry, node) {
      if (written >= buf_size)
        break;
      written += scnprintf(kbuf + written, buf_size - written, "merge %s %s\n",
                           merge_entry->src, merge_entry->target);
    }
    hash_for_each_rcu(hymo_xattr_sbs, bkt, sb_entry, node) {
      if (written >= buf_size)
        break;
      written += scnprintf(kbuf + written, buf_size - written,
                           "hide_xattr_sb %p\n", sb_entry->sb);
    }
    rcu_read_unlock();

    if (copy_to_user(list_arg.buf, kbuf, written)) {
      kfree(kbuf);
      return -EFAULT;
    }
    list_arg.size = written;
    if (copy_to_user((void __user *)arg, &list_arg, sizeof(list_arg))) {
      kfree(kbuf);
      return -EFAULT;
    }

    kfree(kbuf);
    return 0;
  }

  if (cmd == HYMO_CMD_SET_UNAME) {
#ifdef CONFIG_HYMOFS_UNAME_SPOOF
    struct hymo_uname_info u_info;

    if (copy_from_user(&u_info, arg, sizeof(u_info)))
      return -EFAULT;

    spin_lock(&hymo_uname_lock);
    memcpy(&hymo_uname_info, &u_info, sizeof(u_info));
    if (hymo_uname_info.uname.release[0] == '\0') {
      hymofs_uname_spoofing_enabled = false;
    } else {
      hymofs_uname_spoofing_enabled = true;
    }
    spin_unlock(&hymo_uname_lock);
    return 0;
#else
    return -EOPNOTSUPP;
#endif // #ifdef CONFIG_HYMOFS_UNAME_SPOOF
  }

  if (cmd == HYMO_CMD_SET_CMDLINE) {
#ifdef CONFIG_HYMOFS_CMDLINE_SPOOF
    struct hymo_spoof_cmdline cl;
    if (copy_from_user(&cl, arg, sizeof(cl)))
      return -EFAULT;
    kfree(hymo_fake_cmdline);
    hymo_fake_cmdline = kstrdup(cl.cmdline, GFP_KERNEL);
    hymo_cmdline_spoofed = !!hymo_fake_cmdline;
    return 0;
#else
    return -EOPNOTSUPP;
#endif // #ifdef CONFIG_HYMOFS_CMDLINE_SPOOF
  }

  if (cmd == HYMO_CMD_ADD_SPOOF_KSTAT) {
#ifdef CONFIG_HYMOFS_STAT_SPOOF
    struct hymo_spoof_kstat ks;
    struct hymo_kstat_entry *kstat_entry;
    struct path path;
    if (copy_from_user(&ks, arg, sizeof(ks)))
      return -EFAULT;

    if (ks.target_ino == 0 && ks.target_pathname[0]) {
      if (kern_path(ks.target_pathname, LOOKUP_FOLLOW, &path) == 0) {
        ks.target_ino = d_inode(path.dentry)->i_ino;
        set_bit(AS_FLAGS_HYMO_SPOOF_KSTAT,
                &d_inode(path.dentry)->i_mapping->flags);
        path_put(&path);
      } else {
        ks.err = -ENOENT;
        copy_to_user(arg, &ks, sizeof(ks));
        return -ENOENT;
      }
    }

    kstat_entry = kmalloc(sizeof(*kstat_entry), GFP_KERNEL);
    if (!kstat_entry)
      return -ENOMEM;
    memcpy(&kstat_entry->kstat, &ks, sizeof(ks));
    spin_lock(&hymo_kstat_lock);
    hash_add_rcu(hymo_spoof_kstats, &kstat_entry->node, ks.target_ino);
    spin_unlock(&hymo_kstat_lock);
    return 0;
#else
    return -EOPNOTSUPP;
#endif // #ifdef CONFIG_HYMOFS_STAT_SPOOF
  }

  if (cmd == HYMO_CMD_UPDATE_SPOOF_KSTAT) {
#ifdef CONFIG_HYMOFS_STAT_SPOOF
    struct hymo_spoof_kstat ks;
    struct hymo_kstat_entry *kstat_entry;
    bool found = false;
    if (copy_from_user(&ks, arg, sizeof(ks)))
      return -EFAULT;

    spin_lock(&hymo_kstat_lock);
    hash_for_each_possible(hymo_spoof_kstats, kstat_entry, node,
                           ks.target_ino) {
      if (kstat_entry->kstat.target_ino == ks.target_ino) {
        memcpy(&kstat_entry->kstat, &ks, sizeof(ks));
        found = true;
        break;
      }
    }
    spin_unlock(&hymo_kstat_lock);
    return found ? 0 : -ENOENT;
#else
    return -EOPNOTSUPP;
#endif // #ifdef CONFIG_HYMOFS_STAT_SPOOF
  }

  if (copy_from_user(&req, arg, sizeof(req))) {
    if (hymo_ioctl_fail_count < 5) {
      pr_err("hymofs: copy_from_user(req) failed arg=%px\n", arg);
      hymo_ioctl_fail_count++;
    }
    return -EFAULT;
  }

  if (cmd == HYMO_CMD_SET_MIRROR_PATH) {
    char *new_path = NULL;
    char *new_name = NULL;

    if (req.src) {
      new_path = strndup_user(req.src, PATH_MAX);
      if (IS_ERR(new_path))
        return PTR_ERR(new_path);
    } else {
      return -EINVAL;
    }

    hymo_log("setting mirror path to: %s\n", new_path);

    new_name = strrchr(new_path, '/');
    if (!new_name || !*(new_name + 1)) {
      kfree(new_path);
      return -EINVAL;
    }
    new_name++;

    spin_lock(&hymo_lock);
    strscpy(hymo_mirror_path_buf, new_path, PATH_MAX);
    strscpy(hymo_mirror_name_buf, new_name, NAME_MAX);
    hymo_current_mirror_path = hymo_mirror_path_buf;
    hymo_current_mirror_name = hymo_mirror_name_buf;
    spin_unlock(&hymo_lock);

    kfree(new_path);

    if (hymo_stealth_enabled) {
      hymofs_spoof_mounts();
      hymofs_reorder_mnt_id();
    }

    return 0;
  }

  if (!req.src)
    return -EINVAL;
  src = strndup_user(req.src, PATH_MAX);
  if (IS_ERR(src)) {
    if (hymo_ioctl_fail_count < 5) {
      pr_err("hymofs: strndup_user(src) failed src=%px err=%ld\n", req.src,
             PTR_ERR(src));
      hymo_ioctl_fail_count++;
    }
    return PTR_ERR(src);
  }
  if (req.target) {
    target = strndup_user(req.target, PATH_MAX);
    if (IS_ERR(target)) {
      if (hymo_ioctl_fail_count < 5) {
        pr_err("hymofs: strndup_user(target) failed target=%px err=%ld\n",
               req.target, PTR_ERR(target));
        hymo_ioctl_fail_count++;
      }
      kfree(src);
      return PTR_ERR(target);
    }
  }

  if (cmd == HYMO_CMD_ADD_RULE) {
    if (!target) {
      ret = -EINVAL;
      goto out;
    }
    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
      ret = -ENOMEM;
      goto out;
    }
    entry->src = src;
    entry->target = target;
    entry->type = req.type;

    hash = full_name_hash(NULL, entry->src, strlen(entry->src));
    spin_lock(&hymo_lock);
    hash_add_rcu(hymo_paths, &entry->node, hash);
    hash_add_rcu(hymo_targets, &entry->target_node,
                 hymo_hash_str(entry->target));
    atomic_inc(&hymo_rule_count);
    spin_unlock(&hymo_lock);

    hymo_bloom_add(hymo_path_bloom, entry->src, (int)strlen(entry->src));
    hymofs_kpm_update_info_description();
    return 0;
  }

  if (cmd == HYMO_CMD_ADD_MERGE_RULE) {
    struct hymo_merge_entry *merge_entry;
    if (!target) {
      ret = -EINVAL;
      goto out;
    }
    merge_entry = kmalloc(sizeof(*merge_entry), GFP_KERNEL);
    if (!merge_entry) {
      ret = -ENOMEM;
      goto out;
    }
    merge_entry->src = src;
    merge_entry->target = target;

    hash = full_name_hash(NULL, merge_entry->src, strlen(merge_entry->src));
    spin_lock(&hymo_lock);
    hash_add_rcu(hymo_merge_dirs, &merge_entry->node, hash);
    atomic_inc(&hymo_merge_count);
    spin_unlock(&hymo_lock);

    hymo_bloom_add(hymo_path_bloom, merge_entry->src,
                   (int)strlen(merge_entry->src));
    hymofs_kpm_update_info_description();
    return 0;
  }

  if (cmd == HYMO_CMD_HIDE_RULE) {
    hide_entry = kmalloc(sizeof(*hide_entry), GFP_KERNEL);
    if (!hide_entry) {
      ret = -ENOMEM;
      goto out;
    }
    hide_entry->path = src;
    hash = full_name_hash(NULL, hide_entry->path, strlen(hide_entry->path));
    spin_lock(&hymo_lock);
    hash_add_rcu(hymo_hide_paths, &hide_entry->node, hash);
    atomic_inc(&hymo_hide_count);
    spin_unlock(&hymo_lock);
    hymo_bloom_add(hymo_path_bloom, hide_entry->path,
                   (int)strlen(hide_entry->path));
    hymofs_kpm_update_info_description();
    return 0;
  }

  if (cmd == HYMO_CMD_HIDE_OVERLAY_XATTRS) {
    struct hymo_xattr_sb_entry *sb_entry;
    struct path path;
    if (kern_path(src, LOOKUP_FOLLOW, &path)) {
      if (hymo_ioctl_fail_count < 5) {
        pr_err("hymofs: hide_xattr kern_path failed src=%s\n", src);
        hymo_ioctl_fail_count++;
      }
      ret = -ENOENT;
      goto out;
    }

    sb_entry = kmalloc(sizeof(*sb_entry), GFP_KERNEL);
    if (!sb_entry) {
      path_put(&path);
      ret = -ENOMEM;
      goto out;
    }
    sb_entry->sb = path.dentry->d_sb;
    hash = hash_min((unsigned long)sb_entry->sb, HYMO_HASH_BITS);
    spin_lock(&hymo_lock);
    hash_add_rcu(hymo_xattr_sbs, &sb_entry->node, hash);
    spin_unlock(&hymo_lock);
    path_put(&path);
    return 0;
  }

  if (cmd == HYMO_CMD_DEL_RULE) {
    hash = full_name_hash(NULL, src, strlen(src));
    spin_lock(&hymo_lock);
    hlist_for_each_entry_rcu(entry, &hymo_paths[hash_min(hash, HYMO_HASH_BITS)],
                             node) {
      if (strcmp(entry->src, src) == 0) {
        hash_del_rcu(&entry->node);
        hash_del_rcu(&entry->target_node);
        kfree(entry->src);
        kfree(entry->target);
        kfree(entry);
        atomic_dec(&hymo_rule_count);
        found = true;
        break;
      }
    }
    spin_unlock(&hymo_lock);
    if (found)
      hymofs_kpm_update_info_description();
    rcu_barrier();
    ret = found ? 0 : -ENOENT;
    goto out;
  }

out:
  if (src)
    kfree(src);
  if (target)
    kfree(target);
  return ret;
}

/* === ioctl handling === */
static long hymo_anon_ioctl(struct file *file, unsigned int cmd,
                            unsigned long arg);

static const struct file_operations hymo_anon_fops = {
    .unlocked_ioctl = hymo_anon_ioctl,
    .compat_ioctl = hymo_anon_ioctl,
};

static long hymo_anon_ioctl(struct file *file, unsigned int cmd,
                            unsigned long arg) {
  int enabled;

  if (cmd == HYMO_IOC_GET_VERSION) {
    int version = HYMO_PROTOCOL_VERSION;
    if (copy_to_user((void __user *)arg, &version, sizeof(version)))
      return -EFAULT;
    return 0;
  }

  if (cmd == HYMO_IOC_GET_FEATURES) {
    int features = 0;
#ifdef CONFIG_HYMOFS_STAT_SPOOF
    features |= HYMO_FEATURE_KSTAT_SPOOF;
#endif // #ifdef CONFIG_HYMOFS_STAT_SPOOF
#ifdef CONFIG_HYMOFS_UNAME_SPOOF
    features |= HYMO_FEATURE_UNAME_SPOOF;
#endif // #ifdef CONFIG_HYMOFS_UNAME_SPOOF
#ifdef CONFIG_HYMOFS_CMDLINE_SPOOF
    features |= HYMO_FEATURE_CMDLINE_SPOOF;
#endif // #ifdef CONFIG_HYMOFS_CMDLINE_SPOOF
    if (copy_to_user((void __user *)arg, &features, sizeof(features)))
      return -EFAULT;
    return 0;
  }

  if (cmd == HYMO_IOC_SET_ENABLED) {
    if (copy_from_user(&enabled, (void __user *)arg, sizeof(enabled)))
      return -EFAULT;
    spin_lock(&hymo_lock);
    hymofs_enabled = enabled ? true : false;
    spin_unlock(&hymo_lock);
    if (hymo_syms_resolved)
      hymofs_set_all_hooks(hymofs_enabled);
    hymofs_kpm_update_info_description();
#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
    if (hymofs_enabled) {
      hymo_reload_ksu_allowlist();
    }
#endif // #ifdef CONFIG_HYMOFS_HIDE_ENTRIES
    return 0;
  }

  /* Map ioctl to internal command and dispatch */
  switch (cmd) {
  case HYMO_IOC_ADD_RULE:
    return hymo_dispatch_cmd(HYMO_CMD_ADD_RULE, (void __user *)arg);
  case HYMO_IOC_DEL_RULE:
    return hymo_dispatch_cmd(HYMO_CMD_DEL_RULE, (void __user *)arg);
  case HYMO_IOC_HIDE_RULE:
    return hymo_dispatch_cmd(HYMO_CMD_HIDE_RULE, (void __user *)arg);
  case HYMO_IOC_CLEAR_ALL:
    return hymo_dispatch_cmd(HYMO_CMD_CLEAR_ALL, (void __user *)arg);
  case HYMO_IOC_LIST_RULES:
    return hymo_dispatch_cmd(HYMO_CMD_LIST_RULES, (void __user *)arg);
  case HYMO_IOC_SET_DEBUG:
    return hymo_dispatch_cmd(HYMO_CMD_SET_DEBUG, (void __user *)arg);
  case HYMO_IOC_REORDER_MNT_ID:
    return hymo_dispatch_cmd(HYMO_CMD_REORDER_MNT_ID, (void __user *)arg);
  case HYMO_IOC_SET_STEALTH:
    return hymo_dispatch_cmd(HYMO_CMD_SET_STEALTH, (void __user *)arg);
  case HYMO_IOC_HIDE_OVERLAY_XATTRS:
    return hymo_dispatch_cmd(HYMO_CMD_HIDE_OVERLAY_XATTRS, (void __user *)arg);
  case HYMO_IOC_ADD_MERGE_RULE:
    return hymo_dispatch_cmd(HYMO_CMD_ADD_MERGE_RULE, (void __user *)arg);
  case HYMO_IOC_SET_MIRROR_PATH:
    return hymo_dispatch_cmd(HYMO_CMD_SET_MIRROR_PATH, (void __user *)arg);
  case HYMO_IOC_ADD_SPOOF_KSTAT:
    return hymo_dispatch_cmd(HYMO_CMD_ADD_SPOOF_KSTAT, (void __user *)arg);
  case HYMO_IOC_UPDATE_SPOOF_KSTAT:
    return hymo_dispatch_cmd(HYMO_CMD_UPDATE_SPOOF_KSTAT, (void __user *)arg);
  case HYMO_IOC_SET_UNAME:
    return hymo_dispatch_cmd(HYMO_CMD_SET_UNAME, (void __user *)arg);
  case HYMO_IOC_SET_CMDLINE:
    return hymo_dispatch_cmd(HYMO_CMD_SET_CMDLINE, (void __user *)arg);
  default:
    return -EINVAL;
  }
}

static int __init hymofs_init(void) {
  spin_lock_init(&hymo_lock);
  hash_init(hymo_paths);
  hash_init(hymo_targets);
  hash_init(hymo_hide_paths);
  hash_init(hymo_allow_uids);
  hash_init(hymo_inject_dirs);
  hash_init(hymo_xattr_sbs);
  hash_init(hymo_merge_dirs);
#ifdef CONFIG_HYMOFS_STAT_SPOOF
  hash_init(hymo_spoof_kstats);
#endif // #ifdef CONFIG_HYMOFS_STAT_SPOOF

  if (hymo_dispatch_cmd_hook) {
    pr_err("HymoFS: hook already set?\n");
  } else {
    hymo_dispatch_cmd_hook = hymo_dispatch_cmd;
  }

  pr_info("HymoFS: initialized (Anonymous FD Mode Only)\n");
  return 0;
}

#ifdef CONFIG_HYMOFS_FORWARD_REDIRECT
char *__hymofs_resolve_target(const char *pathname) {
  struct hymo_entry *entry;
  struct hymo_merge_entry *merge_entry;
  u32 hash;
  char *target = NULL;
  const char *p;
  size_t path_len;
  struct list_head candidates;
  struct hymo_merge_target_node *cand, *tmp;
  pid_t current_pid;

  if (unlikely(!hymofs_enabled))
    return NULL;
  if (unlikely(!pathname))
    return NULL;

  /* Allow daemon process to bypass path resolution */
  current_pid = task_tgid_vnr(current);
  if (hymo_daemon_pid > 0 && current_pid == hymo_daemon_pid) {
    return NULL;
  }

  INIT_LIST_HEAD(&candidates);
  path_len = strlen(pathname);
  /* Fast negative: definitely not in bloom => no redirect/merge match */
  if (!hymo_bloom_test(hymo_path_bloom, pathname, (int)path_len))
    return NULL;
  hash = full_name_hash(NULL, pathname, path_len);

  rcu_read_lock();
  hlist_for_each_entry_rcu(entry, &hymo_paths[hash_min(hash, HYMO_HASH_BITS)],
                           node) {
    if (unlikely(strcmp(entry->src, pathname) == 0)) {
      target = kstrdup(entry->target, GFP_ATOMIC);
      rcu_read_unlock();
      return target;
    }
  }

  p = pathname + path_len;
  while (p > pathname) {
    while (p > pathname && *p != '/')
      p--;
    if (p == pathname && *p != '/')
      break;

    size_t current_len = p - pathname;
    if (current_len == 0) {
      break;
    }

    hash = full_name_hash(NULL, pathname, current_len);
    hlist_for_each_entry_rcu(
        merge_entry, &hymo_merge_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
      if (strlen(merge_entry->src) == current_len &&
          strncmp(merge_entry->src, pathname, current_len) == 0) {

        const char *suffix = pathname + current_len;
        if (suffix[0] == '\0' || strcmp(suffix, "/.") == 0 ||
            strcmp(suffix, "/..") == 0) {
          continue;
        }

        cand = kmalloc(sizeof(*cand), GFP_ATOMIC);
        if (!cand)
          continue;
        cand->target =
            kasprintf(GFP_ATOMIC, "%s%s", merge_entry->target, suffix);
        cand->target_dentry = NULL;
        if (cand->target) {
          list_add_tail(&cand->list, &candidates);
        } else {
          kfree(cand);
        }
      }
    }
  }
  rcu_read_unlock();

  list_for_each_entry_safe(cand, tmp, &candidates, list) {
    if (cand->target) {
      struct path path;
      if (kern_path(cand->target, LOOKUP_FOLLOW, &path) == 0) {
        target = kstrdup(cand->target, GFP_KERNEL);
        path_put(&path);
      }
      kfree(cand->target);
    }
    list_del(&cand->list);
    kfree(cand);
    if (target)
      return target;
  }

  return NULL;
}

struct filename *hymofs_handle_getname(struct filename *result) {
  char *target = NULL;
  bool is_absolute;

  if (unlikely(IS_ERR(result)))
    return result;

  if (unlikely(!hymofs_enabled))
    return result;

  if (likely(!hymofs_has_any_rules()))
    return result;

  is_absolute = (result->name[0] == '/');

  if (unlikely(hymofs_should_hide(result->name))) {
    putname(result);
    return ERR_PTR(-ENOENT);
  }

  if (likely(is_absolute)) {
    target = hymofs_resolve_target(result->name);
    if (unlikely(target)) {
      putname(result);
      result = getname_kernel(target);
      kfree(target);
    }
    return result;
  }

  /* Handle relative paths - optimized slow path */
  {
    char *buf = NULL;
    struct path pwd;
    char *cwd;
    int cwd_len, name_len;
    const char *name = result->name;

    /* Skip ./ prefix */
    if (name[0] == '.' && name[1] == '/') {
      name += 2;
    }

    /*
     * Get current working directory safely.
     *
     * Do NOT call kernel inline get_fs_pwd(): it was compiled against the
     * original kernel spin_lock()/path_get() and will introduce direct
     * CALL26 relocations to _raw_spin_lock/path_get (may overflow -> load
     * failure). Use our indirection helpers instead.
     */
    if (unlikely(!current->fs)) {
      goto fallback_absolute;
    }
    hymo_spin_lock(&current->fs->lock);
    pwd = current->fs->pwd;
    hymo_path_get(&pwd);
    hymo_spin_unlock(&current->fs->lock);

    /* Allocate buffer only after we have pwd */
    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buf) {
      path_put(&pwd);
      goto fallback_absolute;
    }

    /* Use d_path (hooked) to get the virtual path of CWD */
    cwd = d_path(&pwd, buf, PAGE_SIZE);
    path_put(&pwd);

    if (IS_ERR(cwd)) {
      kfree(buf);
      goto fallback_absolute;
    }

    cwd_len = strlen(cwd);
    name_len = strlen(name);

    /* Move to beginning of buffer to allow appending */
    if (cwd != buf) {
      memmove(buf, cwd, cwd_len + 1);
      cwd = buf;
    }

    if (cwd_len + 1 + name_len < PAGE_SIZE) {
      /* Construct absolute path: cwd + / + name */
      if (cwd_len > 0 && cwd[cwd_len - 1] != '/') {
        cwd[cwd_len++] = '/';
        cwd[cwd_len] = '\0';
      }
      memcpy(cwd + cwd_len, name, name_len + 1);

      /* Try to resolve the constructed absolute path */
      target = hymofs_resolve_target(cwd);
    }

    kfree(buf);
  }

fallback_absolute:
  /* If relative path resolution failed, try the original name */
  if (!target) {
    target = hymofs_resolve_target(result->name);
  }

  if (target) {
    putname(result);
    result = getname_kernel(target);
    kfree(target);
  }

  return result;
}
EXPORT_SYMBOL(hymofs_handle_getname);

/* Resolve relative path with dirfd for fstatat() merge support */
struct filename *hymofs_resolve_relative(int dfd, const char *name) {
  struct file *file;
  struct filename *result = NULL;
  char *buf, *dir_path, *target;
  size_t dir_len, name_len;

  file = fget(dfd);
  if (!file)
    return NULL;

  buf = kmalloc(PATH_MAX, GFP_KERNEL);
  if (!buf)
    goto out_fput;

  dir_path = d_path(&file->f_path, buf, PATH_MAX);
  if (IS_ERR(dir_path))
    goto out_free;

  dir_len = strlen(dir_path);
  name_len = strlen(name);
  if (dir_len + 1 + name_len >= PATH_MAX)
    goto out_free;

  /* Build full path in-place */
  if (dir_path != buf)
    memmove(buf, dir_path, dir_len);
  if (dir_len > 0 && buf[dir_len - 1] != '/')
    buf[dir_len++] = '/';
  memcpy(buf + dir_len, name, name_len + 1);

  target = __hymofs_resolve_target(buf);
  if (target) {
    result = getname_kernel(target);
    if (IS_ERR(result))
      result = NULL;
    kfree(target);
  }

out_free:
  kfree(buf);
out_fput:
  fput(file);
  return result;
}
#endif /* CONFIG_HYMOFS_FORWARD_REDIRECT */

/* Reverse lookup and path filtering */
#ifdef CONFIG_HYMOFS_REVERSE_LOOKUP
int __hymofs_reverse_lookup(const char *pathname, char *buf, size_t buflen) {
  struct hymo_entry *entry;
  struct hymo_merge_entry *merge_entry;
  u32 hash;
  const char *p;
  size_t path_len;

  if (!pathname || !buf || buflen == 0)
    return -1;

  if (!hymofs_enabled)
    return -1;

  path_len = strlen(pathname);
  hash = full_name_hash(NULL, pathname, path_len);

  rcu_read_lock();
  hlist_for_each_entry_rcu(entry, &hymo_targets[hash_min(hash, HYMO_HASH_BITS)],
                           target_node) {
    if (strcmp(entry->target, pathname) == 0) {
      strscpy(buf, entry->src, buflen);
      rcu_read_unlock();
      return 0;
    }
  }
  rcu_read_unlock();

  /* Try merge targets */
  p = pathname + path_len;
  while (p > pathname) {
    while (p > pathname && *p != '/')
      p--;
    if (p == pathname && *p != '/')
      break;
    size_t current_len = p - pathname;
    if (current_len == 0)
      break;
    hash = full_name_hash(NULL, pathname, current_len);
    rcu_read_lock();
    hlist_for_each_entry_rcu(
        merge_entry, &hymo_merge_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
      if (strlen(merge_entry->target) == current_len &&
          strncmp(merge_entry->target, pathname, current_len) == 0) {
        const char *suffix = pathname + current_len;
        if (suffix[0] == '\0' || strcmp(suffix, "/.") == 0 ||
            strcmp(suffix, "/..") == 0) {
          continue;
        }
        snprintf(buf, buflen, "%s%s", merge_entry->src, suffix);
        rcu_read_unlock();
        return 0;
      }
    }
    rcu_read_unlock();
    p--;
  }

  return -1;
}

char *hymofs_process_d_path(char *res, char *buf, int buflen) {
  /*
   * d_path() may return ERR_PTR(-errno) (e.g. -ENAMETOOLONG when the buffer
   * is too small). Never treat error pointers as C-strings.
   */
  if (!res || IS_ERR(res) || !buf || buflen <= 0)
    return res;

  if (!hymofs_enabled)
    return res;

  /*
   * Fast path: when there are no rules/hides/merges, do not pay the cost of
   * reverse lookup on the very hot d_path path (can trigger watchdog resets).
   */
  if (likely(!hymofs_has_any_rules()))
    return res;

  if (hymofs_reverse_lookup(res, buf, buflen) == 0)
    return buf;
  return res;
}
EXPORT_SYMBOL(hymofs_process_d_path);
#endif /* CONFIG_HYMOFS_REVERSE_LOOKUP */

/* === Hide entries and merge === */
#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
bool __hymofs_should_hide(const char *pathname, size_t len) {
  struct hymo_hide_entry *entry;
  u32 hash;

  if (!hymofs_enabled || !pathname)
    return false;
  if (hymo_is_privileged_process())
    return false;

  /* Always hide the mirror node (name or full path) */
  {
    size_t name_len = strlen(hymo_current_mirror_name);
    size_t path_len = strlen(hymo_current_mirror_path);
    if ((len == name_len && strcmp(pathname, hymo_current_mirror_name) == 0) ||
        (len == path_len && strcmp(pathname, hymo_current_mirror_path) == 0)) {
      return true;
    }
  }

  if (!hymo_should_apply_hide_rules())
    return false;

  /* Fast negative: definitely not in bloom => no hide match */
  if (!hymo_bloom_test(hymo_path_bloom, pathname, (int)len))
    return false;

  hash = full_name_hash(NULL, pathname, len);
  rcu_read_lock();
  hlist_for_each_entry_rcu(
      entry, &hymo_hide_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
    if (strcmp(entry->path, pathname) == 0) {
      rcu_read_unlock();
      return true;
    }
  }
  rcu_read_unlock();
  return false;
}

bool __hymofs_should_spoof_mtime(const char *pathname) {
  struct hymo_inject_entry *entry;
  u32 hash;
  bool found = false;
  pid_t current_pid;

  if (!hymofs_enabled || !pathname)
    return false;
  current_pid = task_tgid_vnr(current);
  if (hymo_daemon_pid > 0 && current_pid == hymo_daemon_pid)
    return false;

  hash = full_name_hash(NULL, pathname, strlen(pathname));
  rcu_read_lock();
  hlist_for_each_entry_rcu(
      entry, &hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
    if (strcmp(entry->dir, pathname) == 0) {
      found = true;
      break;
    }
  }
  rcu_read_unlock();
  return found;
}

bool __hymofs_is_inode_hidden(struct inode *inode) {
  if (!inode || !inode->i_mapping)
    return false;
  return test_bit(AS_FLAGS_HYMO_HIDE, &inode->i_mapping->flags);
}

int hymofs_populate_injected_list(const char *dir_path, struct dentry *parent,
                                  struct list_head *head) {
  struct hymo_entry *entry;
  struct hymo_inject_entry *inject_entry;
  struct hymo_name_list *item;
  u32 hash;
  int bkt;
  bool should_inject = false;
  size_t dir_len;

  if (!hymofs_enabled || !dir_path)
    return 0;

  dir_len = strlen(dir_path);
  hash = full_name_hash(NULL, dir_path, dir_len);

  rcu_read_lock();
  hlist_for_each_entry_rcu(
      inject_entry, &hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
    if (strcmp(inject_entry->dir, dir_path) == 0) {
      should_inject = true;
      break;
    }
  }

  if (should_inject) {
    hash_for_each_rcu(hymo_paths, bkt, entry, node) {
      if (strncmp(entry->src, dir_path, dir_len) == 0) {
        char *name = NULL;
        if (dir_len == 1 && dir_path[0] == '/') {
          name = entry->src + 1;
        } else if (entry->src[dir_len] == '/') {
          name = entry->src + dir_len + 1;
        }
        if (name && *name && strchr(name, '/') == NULL) {
          bool exists = false;
          struct hymo_name_list *pos;
          list_for_each_entry(pos, head, list) {
            if (strcmp(pos->name, name) == 0) {
              exists = true;
              break;
            }
          }
          if (!exists) {
            item = kmalloc(sizeof(*item), GFP_ATOMIC);
            if (item) {
              item->name = kstrdup(name, GFP_ATOMIC);
              item->type = entry->type;
              if (item->name) {
                list_add(&item->list, head);
              } else {
                kfree(item);
              }
            }
          }
        }
      }
    }
  }
  rcu_read_unlock();

  return 0;
}

void __hymofs_prepare_readdir(struct hymo_readdir_context *ctx,
                              struct file *file) {
  if (!ctx)
    return;
  ctx->file = file;
  ctx->path_buf = NULL;
  ctx->dir_path = NULL;
  ctx->dir_path_len = 0;
  INIT_LIST_HEAD(&ctx->merge_targets);
  ctx->is_replace_mode = false;
  ctx->dir_has_hidden = false;
  ctx->has_merge_files = false;

  if (!file)
    return;

  ctx->path_buf = (char *)__get_free_page(GFP_NOFS);
  if (!ctx->path_buf)
    return;

  {
    char *p = d_path(&file->f_path, ctx->path_buf, PAGE_SIZE);
    if (!IS_ERR(p)) {
      int len = strlen(p);
      memmove(ctx->path_buf, p, len + 1);
      ctx->dir_path = ctx->path_buf;
      ctx->dir_path_len = len;
    } else {
      free_page((unsigned long)ctx->path_buf);
      ctx->path_buf = NULL;
    }
  }
}

void __hymofs_cleanup_readdir(struct hymo_readdir_context *ctx) {
  if (!ctx)
    return;
  if (ctx->path_buf)
    free_page((unsigned long)ctx->path_buf);
}

bool __hymofs_check_filldir(struct hymo_readdir_context *ctx, const char *name,
                            int namlen) {
  char full[PATH_MAX];
  pid_t current_pid;

  if (!ctx || !ctx->dir_path || !name)
    return false;

  if (uid_eq(current_uid(), GLOBAL_ROOT_UID))
    return false;

  current_pid = task_tgid_vnr(current);
  if (hymo_daemon_pid > 0 && current_pid == hymo_daemon_pid)
    return false;

  if (ctx->dir_path_len == 4 && strcmp(ctx->dir_path, "/dev") == 0) {
    size_t mirror_name_len = strlen(hymo_current_mirror_name);
    if (namlen == mirror_name_len &&
        memcmp(name, hymo_current_mirror_name, namlen) == 0)
      return true;
  }

  if (snprintf(full, sizeof(full), "%s/%.*s", ctx->dir_path, namlen, name) >=
      (int)sizeof(full))
    return false;

  return hymofs_should_hide(full);
}
#endif /* CONFIG_HYMOFS_HIDE_ENTRIES */

/* === Inject entries (getdents) === */
struct linux_dirent {
  unsigned long d_ino;
  unsigned long d_off;
  unsigned short d_reclen;
  char d_name[];
};

#ifdef CONFIG_HYMOFS_INJECT_ENTRIES
/* Inject virtual entries into getdents system call */
int hymofs_inject_entries(struct hymo_readdir_context *ctx,
                          void __user **dir_ptr, int *count, loff_t *pos) {
  struct linux_dirent __user *current_dir = *dir_ptr;
  struct list_head head;
  struct hymo_name_list *item, *tmp;
  loff_t current_idx = 0;
  loff_t start_idx;
  int injected = 0;
  int error = 0;
  int initial_count = *count;
  bool is_transition = (*pos < HYMO_MAGIC_POS);
  struct dentry *parent;

  if (!ctx || !ctx->dir_path || !dir_ptr || !count || !pos)
    return 0;

  if (!hymofs_enabled)
    return 0;

  INIT_LIST_HEAD(&head);

  parent = ctx->file ? ctx->file->f_path.dentry : NULL;
  hymofs_populate_injected_list(ctx->dir_path, parent, &head);

  if (list_empty(&head))
    return 0;

  if (is_transition) {
    *pos = HYMO_MAGIC_POS;
  }

  start_idx = *pos - HYMO_MAGIC_POS;

  list_for_each_entry_safe(item, tmp, &head, list) {
    if (current_idx++ < start_idx) {
      list_del(&item->list);
      kfree(item->name);
      kfree(item);
      continue;
    }

    if (*count <= 0)
      break;

    int reclen =
        ALIGN(offsetof(struct linux_dirent, d_name) + strlen(item->name) + 1,
              sizeof(long));
    if (reclen > *count)
      break;

    if (copy_to_user(&current_dir->d_ino, &current_idx,
                     sizeof(current_dir->d_ino)) ||
        copy_to_user(&current_dir->d_off, &current_idx,
                     sizeof(current_dir->d_off)) ||
        copy_to_user(&current_dir->d_reclen, &reclen,
                     sizeof(current_dir->d_reclen)) ||
        copy_to_user(current_dir->d_name, item->name, strlen(item->name) + 1)) {
      error = -EFAULT;
      break;
    }

    current_dir = (void __user *)current_dir + reclen;
    *count -= reclen;
    injected += reclen;
    (*pos)++;

    list_del(&item->list);
    kfree(item->name);
    kfree(item);
  }

  list_for_each_entry_safe(item, tmp, &head, list) {
    list_del(&item->list);
    kfree(item->name);
    kfree(item);
  }

  if (error)
    return error;

  if (injected > 0 && *count < initial_count) {
    *dir_ptr = current_dir;
    return injected;
  }
  return 0;
}

int hymofs_inject_entries64(struct hymo_readdir_context *ctx,
                            void __user **dir_ptr, int *count, loff_t *pos) {
  struct linux_dirent64 __user *current_dir = *dir_ptr;
  struct list_head head;
  struct hymo_name_list *item, *tmp;
  loff_t current_idx = 0;
  loff_t start_idx;
  int injected = 0;
  int error = 0;
  int initial_count = *count;
  bool is_transition = (*pos < HYMO_MAGIC_POS);
  struct dentry *parent;

  if (!ctx || !ctx->dir_path || !dir_ptr || !count || !pos)
    return 0;

  if (!hymofs_enabled)
    return 0;

  INIT_LIST_HEAD(&head);

  parent = ctx->file ? ctx->file->f_path.dentry : NULL;
  hymofs_populate_injected_list(ctx->dir_path, parent, &head);

  if (list_empty(&head))
    return 0;

  if (is_transition) {
    *pos = HYMO_MAGIC_POS;
  }

  start_idx = *pos - HYMO_MAGIC_POS;

  list_for_each_entry_safe(item, tmp, &head, list) {
    if (current_idx++ < start_idx) {
      list_del(&item->list);
      kfree(item->name);
      kfree(item);
      continue;
    }

    if (*count <= 0)
      break;

    int reclen =
        ALIGN(offsetof(struct linux_dirent64, d_name) + strlen(item->name) + 1,
              sizeof(u64));
    if (reclen > *count)
      break;

    if (copy_to_user(&current_dir->d_ino, &current_idx,
                     sizeof(current_dir->d_ino)) ||
        copy_to_user(&current_dir->d_off, &current_idx,
                     sizeof(current_dir->d_off)) ||
        copy_to_user(&current_dir->d_reclen, &reclen,
                     sizeof(current_dir->d_reclen)) ||
        copy_to_user(current_dir->d_name, item->name, strlen(item->name) + 1)) {
      error = -EFAULT;
      break;
    }

    current_dir = (void __user *)current_dir + reclen;
    *count -= reclen;
    injected += reclen;
    (*pos)++;

    list_del(&item->list);
    kfree(item->name);
    kfree(item);
  }

  list_for_each_entry_safe(item, tmp, &head, list) {
    list_del(&item->list);
    kfree(item->name);
    kfree(item);
  }

  if (error)
    return error;

  if (injected > 0 && *count < initial_count) {
    *dir_ptr = current_dir;
    return injected;
  }
  return 0;
}
#endif /* CONFIG_HYMOFS_INJECT_ENTRIES */

#ifdef CONFIG_HYMOFS_STAT_SPOOF
static inline void hymofs_mark_inode_hidden(struct inode *inode) {
  if (!inode || !inode->i_mapping)
    return;
  set_bit(AS_FLAGS_HYMO_HIDE, &inode->i_mapping->flags);
  if (inode->i_mapping->host)
    set_bit(AS_FLAGS_HYMO_DIR_HAS_HIDDEN, &inode->i_mapping->flags);
}

void hymofs_spoof_kstat_by_ino(unsigned long ino, struct kstat *stat) {
  struct hymo_kstat_entry *entry;
  u32 hash = hash_min(ino, HYMO_HASH_BITS);
  if (!stat)
    return;

  rcu_read_lock();
  hlist_for_each_entry_rcu(entry, &hymo_spoof_kstats[hash], node) {
    if (entry->kstat.target_ino == ino) {
      stat->ino = entry->kstat.spoofed_ino;
      stat->dev = entry->kstat.spoofed_dev;
      stat->nlink = entry->kstat.spoofed_nlink;
      stat->size = entry->kstat.spoofed_size;
      stat->atime = (struct timespec64){entry->kstat.spoofed_atime_sec,
                                        entry->kstat.spoofed_atime_nsec};
      stat->mtime = (struct timespec64){entry->kstat.spoofed_mtime_sec,
                                        entry->kstat.spoofed_mtime_nsec};
      stat->ctime = (struct timespec64){entry->kstat.spoofed_ctime_sec,
                                        entry->kstat.spoofed_ctime_nsec};
      stat->blksize = entry->kstat.spoofed_blksize;
      stat->blocks = entry->kstat.spoofed_blocks;
      rcu_read_unlock();
      return;
    }
  }
  rcu_read_unlock();
}

bool hymofs_is_kstat_spoofed(struct inode *inode) {
  if (!inode || !inode->i_mapping)
    return false;
  return test_bit(AS_FLAGS_HYMO_SPOOF_KSTAT, &inode->i_mapping->flags);
}

void hymofs_spoof_stat(const struct path *path, struct kstat *stat) {
  if (!path || !stat)
    return;
  if (hymofs_is_kstat_spoofed(d_inode(path->dentry)))
    hymofs_spoof_kstat_by_ino(stat->ino, stat);
}

void hymofs_post_getattr(const struct path *path, struct inode *inode,
                         struct kstat *stat, int ret) {
  if (ret)
    return;
  if (!path || !inode || !stat)
    return;
  if (hymofs_is_kstat_spoofed(inode))
    hymofs_spoof_kstat_by_ino(stat->ino, stat);
}
#endif // #ifdef CONFIG_HYMOFS_STAT_SPOOF

#ifdef CONFIG_HYMOFS_UNAME_SPOOF
void hymofs_spoof_uname(struct new_utsname *name) {
  struct hymo_uname_info tmp;
  if (!name)
    return;

  if (!hymofs_uname_spoofing_enabled)
    return;

  spin_lock(&hymo_uname_lock);
  memcpy(&tmp, &hymo_uname_info, sizeof(tmp));
  spin_unlock(&hymo_uname_lock);

  if (!tmp.enabled)
    return;

  if (tmp.uname.sysname[0])
    strscpy(name->sysname, tmp.uname.sysname, sizeof(name->sysname));
  if (tmp.uname.nodename[0])
    strscpy(name->nodename, tmp.uname.nodename, sizeof(name->nodename));
  if (tmp.uname.release[0])
    strscpy(name->release, tmp.uname.release, sizeof(name->release));
  if (tmp.uname.version[0])
    strscpy(name->version, tmp.uname.version, sizeof(name->version));
  if (tmp.uname.machine[0])
    strscpy(name->machine, tmp.uname.machine, sizeof(name->machine));
  if (tmp.uname.domainname[0])
    strscpy(name->domainname, tmp.uname.domainname, sizeof(name->domainname));
}
EXPORT_SYMBOL(hymofs_spoof_uname);
#endif /* CONFIG_HYMOFS_UNAME_SPOOF */

#ifdef CONFIG_HYMOFS_CMDLINE_SPOOF
/*
 * ==================== cmdline Spoofing Implementation ====================
 * Allows spoofing /proc/cmdline content
 */

bool hymofs_is_cmdline_spoofed(void) {
  return hymo_cmdline_spoofed && hymo_fake_cmdline != NULL;
}

int hymofs_spoof_cmdline(struct seq_file *m) {
  if (!hymo_cmdline_spoofed || !hymo_fake_cmdline)
    return 1; /* Return 1 to indicate "not spoofed, use original" */

  /* Root sees real cmdline */
  if (uid_eq(current_uid(), GLOBAL_ROOT_UID))
    return 1;

  seq_puts(m, hymo_fake_cmdline);
  seq_putc(m, '\n');
  hymo_log("cmdline: spoofed\n");
  return 0; /* Return 0 to indicate "spoofed successfully" */
}
EXPORT_SYMBOL(hymofs_spoof_cmdline);
#endif /* CONFIG_HYMOFS_CMDLINE_SPOOF */

#ifdef CONFIG_HYMOFS_XATTR_FILTER
bool hymofs_is_overlay_xattr(struct dentry *dentry, const char *name) {
  struct hymo_xattr_sb_entry *sb_entry;
  bool found = false;

  if (!name)
    return false;
  if (strncmp(name, "trusted.overlay.", 16) != 0)
    return false;

  if (!dentry)
    return false;

  rcu_read_lock();
  hlist_for_each_entry_rcu(
      sb_entry,
      &hymo_xattr_sbs[hash_min((unsigned long)dentry->d_sb, HYMO_HASH_BITS)],
      node) {
    if (sb_entry->sb == dentry->d_sb) {
      found = true;
      break;
    }
  }
  rcu_read_unlock();

  return found;
}
EXPORT_SYMBOL(hymofs_is_overlay_xattr);

ssize_t hymofs_filter_xattrs(struct dentry *dentry, char *klist, ssize_t len) {
  struct hymo_xattr_sb_entry *sb_entry;
  bool should_filter = false;
  char *p = klist;
  char *end = klist + len;
  char *out = klist;
  ssize_t new_len = 0;

  if (!dentry)
    return len;

  rcu_read_lock();
  hlist_for_each_entry_rcu(
      sb_entry,
      &hymo_xattr_sbs[hash_min((unsigned long)dentry->d_sb, HYMO_HASH_BITS)],
      node) {
    if (sb_entry->sb == dentry->d_sb) {
      should_filter = true;
      break;
    }
  }
  rcu_read_unlock();

  if (!should_filter)
    return len;

  while (p < end) {
    size_t slen = strlen(p);
    if (strncmp(p, "trusted.overlay.", 16) != 0) {
      if (out != p)
        memmove(out, p, slen + 1);
      out += slen + 1;
      new_len += slen + 1;
    }
    p += slen + 1;
  }
  return new_len;
}
EXPORT_SYMBOL(hymofs_filter_xattrs);
#endif /* CONFIG_HYMOFS_XATTR_FILTER */

#endif /* CONFIG_HYMOFS */

/* ==================== KPM Hooking Layer ==================== */

static char *(*k_d_path)(const struct path *path, char *buf, int buflen);
static struct filename *(*k_getname)(const char __user *filename);
static struct filename *(*k_getname_uflags)(const char __user *filename,
                                            int flags);
static int (*k_filename_lookup)(int dfd, struct filename *name,
                                unsigned int flags, struct path *path,
                                struct path *root);
static int (*k_vfs_getattr_nosec)(const struct path *path, struct kstat *stat,
                                  u32 request_mask, unsigned int query_flags);
static long (*k_sys_reboot)(int magic1, int magic2, unsigned int cmd,
                            void __user *arg);
static long (*k_sys_getdents)(unsigned int fd,
                              struct linux_dirent __user *dirent,
                              unsigned int count);
static long (*k_sys_getdents64)(unsigned int fd,
                                struct linux_dirent64 __user *dirent,
                                unsigned int count);
/* If the resolved syscall symbol is __arm64_sys_* (syscall wrapper), it takes
 * pt_regs*. */
static bool hymo_getdents_use_regs = false;
static bool hymo_getdents64_use_regs = false;
/* Matched symbol name (for debugging / policy decisions). */
static const char *hymo_getdents_sym_name = NULL;
static const char *hymo_getdents64_sym_name = NULL;
static long (*k_sys_newuname)(struct new_utsname __user *name);
static long (*k_sys_uname)(struct old_utsname __user *name);
static int (*k_cmdline_proc_show)(struct seq_file *m, void *v);
static int (*k_show_mountinfo)(struct seq_file *m, void *v);
static ssize_t (*k_vfs_getxattr)(struct mnt_idmap *idmap, struct dentry *dentry,
                                 const char *name, void *value, size_t size);
static ssize_t (*k_listxattr)(struct dentry *d, char __user *list, size_t size);
static bool hymo_xattr_hooked = false;
static void hymofs_listxattr_before(hook_fargs3_t *args, void *udata);
static void hymofs_getxattr_before(hook_fargs5_t *args, void *udata);

/*
 * getname hook recursion guard
 *
 * IMPORTANT:
 * Do NOT use percpu/preempt helpers (get_cpu_var/put_cpu_var, etc.) here.
 * They may introduce external CALL26/JUMP26 relocations to `preempt_schedule`,
 * and since KPM code is allocated far from kernel text, this can overflow and
 * make the module "嵌入假象/加载失败".
 *
 * We use a small hashed atomic depth table keyed by `current` pointer.
 * Collisions are acceptable (worst case: skip filtering for that call).
 */
#define HYMOFS_GETNAME_GUARD_SLOTS 1024 /* must be power of 2 */
static atomic_t hymofs_getname_depth_tbl[HYMOFS_GETNAME_GUARD_SLOTS];

static __always_inline unsigned int hymofs_getname_guard_idx(void) {
  return ((unsigned long)current >> 4) & (HYMOFS_GETNAME_GUARD_SLOTS - 1);
}

static __always_inline bool hymofs_getname_guard_enter(void) {
  unsigned int idx = hymofs_getname_guard_idx();
  int v = atomic_inc_return(&hymofs_getname_depth_tbl[idx]);
  if (likely(v == 1))
    return true;
  atomic_dec(&hymofs_getname_depth_tbl[idx]);
  return false;
}

static __always_inline void hymofs_getname_guard_exit(void) {
  unsigned int idx = hymofs_getname_guard_idx();
  atomic_dec(&hymofs_getname_depth_tbl[idx]);
}

static void hymofs_d_path_after(hook_fargs3_t *args, void *udata) {
#ifdef CONFIG_HYMOFS_REVERSE_LOOKUP
  char *res = (char *)args->ret;
  char *buf = (char *)args->arg1;
  int buflen = (int)args->arg2;
  if (!hymofs_enabled || hymofs_exiting || hymo_safe_mode ||
      likely(!hymofs_has_any_rules()))
    return;
  if (likely(hymo_dpath_enter())) {
    if (res && !IS_ERR(res) && buf)
      args->ret = (uint64_t)hymofs_process_d_path(res, buf, buflen);
    hymo_dpath_exit();
  }
#endif // #ifdef CONFIG_HYMOFS_REVERSE_LOOKUP
}

static void hymofs_getname_after(hook_fargs1_t *args, void *udata) {
#ifdef CONFIG_HYMOFS_FORWARD_REDIRECT
  struct filename *res = (struct filename *)args->ret;
  if (!res)
    return;
  /*
   * Fast path: if hymofs disabled or there are no rules/hides/merges, do NOT
   * touch guard/handle_getname. getname is extremely hot and even a small
   * overhead here can cause visible UI stalls ("卡一屏") when enabling the
   * meta module with empty rule sets.
   */
  if (unlikely(!hymofs_enabled || hymofs_exiting || hymo_safe_mode))
    return;
  if (likely(!hymofs_has_any_rules()))
    return;
  if (hymo_system_state() < SYSTEM_RUNNING)
    return;

  if (likely(hymofs_getname_guard_enter())) {
    args->ret = (uint64_t)hymofs_handle_getname(res);
    hymofs_getname_guard_exit();
  }
#endif // #ifdef CONFIG_HYMOFS_FORWARD_REDIRECT
}

static void hymofs_getname_uflags_after(hook_fargs2_t *args, void *udata) {
#ifdef CONFIG_HYMOFS_FORWARD_REDIRECT
  struct filename *res = (struct filename *)args->ret;
  if (!res)
    return;
  if (unlikely(!hymofs_enabled || hymofs_exiting || hymo_safe_mode))
    return;
  if (likely(!hymofs_has_any_rules()))
    return;
  if (hymo_system_state() < SYSTEM_RUNNING)
    return;

  if (likely(hymofs_getname_guard_enter())) {
    args->ret = (uint64_t)hymofs_handle_getname(res);
    hymofs_getname_guard_exit();
  }
#endif // #ifdef CONFIG_HYMOFS_FORWARD_REDIRECT
}

static void hymofs_filename_lookup_before(hook_fargs5_t *args, void *udata) {
#ifdef CONFIG_HYMOFS_FORWARD_REDIRECT
  /*
   * IMPORTANT:
   * KernelPatch does NOT guarantee hook_fargsX_t.local is zero-initialized
   * for each invocation. If after() blindly consumes local.data0, it may
   * call putname() on garbage and crash the kernel (observed bootloop).
   *
   * So we always clear local slots we use, and pair them with a cookie.
   */
  const uint64_t cookie = 0x48594d4f46534b50ULL; /* "HYMOFSKP" */
  struct filename *name = (struct filename *)args->arg1;
  const char *p;
  char *target;
  struct filename *tmp;

  args->local.data0 = 0;
  args->local.data1 = 0;

  if (!hymofs_enabled || hymofs_exiting || hymo_safe_mode)
    return;
  if (!hymofs_has_any_rules())
    return;
  /* Keep privileged/daemon behavior consistent with original */
  if (hymo_is_privileged_process())
    return;

  if (!name || !name->name)
    return;
  p = name->name;

  /*
   * For absolute paths, we can apply hide/redirect here (before lookup),
   * without hooking getname (which is too hot in KPM).
   */
  if (p[0] != '/')
    return;

  if (unlikely(hymofs_should_hide(p))) {
    args->ret = (uint64_t)-ENOENT;
    args->skip_origin = 1;
    return;
  }

  target = hymofs_resolve_target(p);
  if (!target)
    return;

  tmp = getname_kernel(target);
  kfree(target);
  if (IS_ERR(tmp) || !tmp)
    return;

  /* Save for after() to free */
  args->local.data0 = (uint64_t)tmp;
  args->local.data1 = cookie;
  args->arg1 = (uint64_t)tmp;
#endif // #ifdef CONFIG_HYMOFS_FORWARD_REDIRECT
}

static void hymofs_filename_lookup_after(hook_fargs5_t *args, void *udata) {
#ifdef CONFIG_HYMOFS_FORWARD_REDIRECT
  const uint64_t cookie = 0x48594d4f46534b50ULL; /* "HYMOFSKP" */
  int ret = (int)args->ret;
  int dfd = (int)args->arg0;
  struct filename *name = (struct filename *)args->arg1;
  unsigned int flags = (unsigned int)args->arg2;
  struct path *path = (struct path *)args->arg3;
  struct path *root = (struct path *)args->arg4;

  /* Free temporary filename (if we replaced arg1 in before()) */
  if (args->local.data1 == cookie && args->local.data0) {
    putname((struct filename *)args->local.data0);
  }
  args->local.data0 = 0;
  args->local.data1 = 0;

  /*
   * If lookup succeeded, enforce hide by inode mark (fast).
   * This uses the same marking bit as the original HYMOFS:
   * AS_FLAGS_HYMO_HIDE in inode->i_mapping->flags.
   */
  if (ret == 0 && path && path->dentry) {
    struct inode *inode = d_inode(path->dentry);
    if (inode && hymofs_is_inode_hidden(inode)) {
      args->ret = (uint64_t)-ENOENT;
      return;
    }
  }

  if (ret == -ENOENT && dfd >= 0 && name && name->name &&
      name->name[0] != '/') {
    struct filename *resolved = hymofs_resolve_relative(dfd, name->name);
    if (resolved) {
      int (*orig)(int, struct filename *, unsigned int, struct path *,
                  struct path *) = (void *)wrap_get_origin_func(args);
      int res = orig(AT_FDCWD, resolved, flags, path, root);
      putname(resolved);
      if (res == 0)
        args->ret = 0;
    }
  }
#endif // #ifdef CONFIG_HYMOFS_FORWARD_REDIRECT
}

static void hymofs_vfs_getattr_after(hook_fargs4_t *args, void *udata) {
#ifdef CONFIG_HYMOFS_STAT_SPOOF
  const struct path *path = (const struct path *)args->arg0;
  struct kstat *stat = (struct kstat *)args->arg1;
  struct inode *inode = path ? d_inode(path->dentry) : NULL;
  int ret = (int)args->ret;
  if (path && stat)
    hymofs_post_getattr(path, inode, stat, ret);
#endif // #ifdef CONFIG_HYMOFS_STAT_SPOOF
}

static ssize_t hymofs_kpm_listxattr(struct dentry *d, char __user *list,
                                    size_t size) {
  ssize_t error;
  char *klist = NULL;
  size_t alloc_size = size;

  if (!size) {
    ssize_t res = vfs_listxattr(d, NULL, 0);
    if (res <= 0)
      return res;
    alloc_size = res;
  }

  if (alloc_size > XATTR_LIST_MAX)
    alloc_size = XATTR_LIST_MAX;

  klist = kvmalloc(alloc_size, GFP_KERNEL);
  if (!klist)
    return -ENOMEM;

  error = vfs_listxattr(d, klist, alloc_size);
  if (error > 0) {
#ifdef CONFIG_HYMOFS_XATTR_FILTER
    error = hymofs_filter_xattrs(d, klist, error);
#endif // #ifdef CONFIG_HYMOFS_XATTR_FILTER

    if (size && copy_to_user(list, klist, error))
      error = -EFAULT;
  } else if (error == -ERANGE && size >= XATTR_LIST_MAX) {
    error = -E2BIG;
  }

  kvfree(klist);
  return error;
}

static void hymofs_listxattr_before(hook_fargs3_t *args, void *udata) {
#ifdef CONFIG_HYMOFS_XATTR_FILTER
  if (!hymofs_enabled || hymofs_exiting || hymo_safe_mode)
    return;
  struct dentry *d = (struct dentry *)args->arg0;
  char __user *list = (char __user *)args->arg1;
  size_t size = (size_t)args->arg2;
  args->ret = hymofs_kpm_listxattr(d, list, size);
  args->skip_origin = 1;
#endif // #ifdef CONFIG_HYMOFS_XATTR_FILTER
}

static void hymofs_getxattr_before(hook_fargs5_t *args, void *udata) {
#ifdef CONFIG_HYMOFS_XATTR_FILTER
  if (!hymofs_enabled || hymofs_exiting || hymo_safe_mode)
    return;
  struct dentry *d = (struct dentry *)args->arg1;
  const char *name = (const char *)args->arg2;
  if (hymofs_is_overlay_xattr(d, name)) {
    args->ret = -ENODATA;
    args->skip_origin = 1;
  }
#endif // #ifdef CONFIG_HYMOFS_XATTR_FILTER
}

static void hymofs_set_xattr_hooks(bool enable) {
  if (!k_vfs_getxattr && !k_listxattr)
    return;

  if (enable) {
    if (hymo_xattr_hooked)
      return;
    if (k_vfs_getxattr) {
      hook_err_t err = hymo_kp_hook_wrap_call(k_vfs_getxattr, 5,
                                              hymofs_getxattr_before, NULL, 0);
      if (err)
        pr_warn("hook vfs_getxattr error: %d\n", err);
    }
    if (k_listxattr) {
      hook_err_t err = hymo_kp_hook_wrap_call(k_listxattr, 3,
                                              hymofs_listxattr_before, NULL, 0);
      if (err)
        pr_warn("hook listxattr error: %d\n", err);
    }
    hymo_xattr_hooked = true;
    return;
  }

  if (!hymo_xattr_hooked)
    return;
  unhook_func(k_vfs_getxattr);
  unhook_func(k_listxattr);
  hymo_xattr_hooked = false;
}

/* === Route A: File Operations Hooking === */

static int (*k_vfs_open)(const struct path *path, struct file *file);

struct hymo_fops_proxy {
  struct list_head list;
  const struct file_operations *orig_fops;
  struct file_operations proxy_fops;
};

static LIST_HEAD(hymo_fops_proxies);
static DEFINE_SPINLOCK(hymo_fops_lock);

struct hymo_dir_context_wrapper {
  struct dir_context ctx;
  struct dir_context *orig_ctx;
  struct hymo_readdir_context *hymo_ctx;
};

static bool hymo_filldir_hook(struct dir_context *ctx, const char *name,
                              int namlen, loff_t offset, u64 ino,
                              unsigned int d_type) {
  struct hymo_dir_context_wrapper *wrapper =
      container_of(ctx, struct hymo_dir_context_wrapper, ctx);

  if (__hymofs_check_filldir(wrapper->hymo_ctx, name, namlen))
    return true;

  return wrapper->orig_ctx->actor(wrapper->orig_ctx, name, namlen, offset, ino,
                                  d_type);
}

static struct hymo_fops_proxy *
hymo_get_fops_proxy(const struct file_operations *orig) {
  struct hymo_fops_proxy *proxy;

  spin_lock(&hymo_fops_lock);
  list_for_each_entry(proxy, &hymo_fops_proxies, list) {
    if (proxy->orig_fops == orig) {
      spin_unlock(&hymo_fops_lock);
      return proxy;
    }
  }
  spin_unlock(&hymo_fops_lock);
  return NULL;
}

static int hymo_iterate_shared_proxy(struct file *file,
                                     struct dir_context *ctx) {
  struct hymo_fops_proxy *proxy;
  struct hymo_dir_context_wrapper wrapper;
  struct hymo_readdir_context hymo_ctx;
  int ret;

  proxy = container_of(file->f_op, struct hymo_fops_proxy, proxy_fops);

  if (!hymofs_enabled || hymofs_exiting || hymo_safe_mode ||
      !hymofs_has_any_rules())
    return proxy->orig_fops->iterate_shared(file, ctx);

  memset(&hymo_ctx, 0, sizeof(hymo_ctx));
  hymo_ctx.magic = HYMO_CTX_MAGIC;
  hymo_ctx.file = file;
  hymofs_prepare_readdir(&hymo_ctx, file);

  wrapper.ctx.actor = hymo_filldir_hook;
  wrapper.ctx.pos = ctx->pos;
  wrapper.orig_ctx = ctx;
  wrapper.hymo_ctx = &hymo_ctx;

  ret = proxy->orig_fops->iterate_shared(file, &wrapper.ctx);

  ctx->pos = wrapper.ctx.pos;
  hymofs_cleanup_readdir(&hymo_ctx);
  return ret;
}

static struct hymo_fops_proxy *
hymo_create_fops_proxy(const struct file_operations *orig) {
  struct hymo_fops_proxy *proxy;

  proxy = kzalloc(sizeof(*proxy), GFP_KERNEL);
  if (!proxy)
    return NULL;

  proxy->orig_fops = orig;
  memcpy(&proxy->proxy_fops, orig, sizeof(*orig));

  if (orig->iterate_shared)
    proxy->proxy_fops.iterate_shared = hymo_iterate_shared_proxy;
  /* If iterate is deprecated, we don't hook it. */

  spin_lock(&hymo_fops_lock);
  list_add(&proxy->list, &hymo_fops_proxies);
  spin_unlock(&hymo_fops_lock);

  return proxy;
}

static void hymofs_vfs_open_after(hook_fargs2_t *args, void *udata) {
  struct file *file;
  struct hymo_fops_proxy *proxy;
  const struct file_operations *orig_fops;

  /* Check return value of vfs_open */
  if (args->ret != 0)
    return;

  if (!hymofs_enabled || hymofs_exiting || hymo_safe_mode)
    return;

  file = (struct file *)args->arg1;
  if (!file || !file->f_op)
    return;

  /* Only hook directories */
  if (!S_ISDIR(file_inode(file)->i_mode))
    return;

  /* Check if already hooked */
  if (file->f_op->iterate_shared == hymo_iterate_shared_proxy)
    return;

  orig_fops = file->f_op;

  /* We only support iterate_shared for now as iterate is deprecated */
  if (!orig_fops->iterate_shared)
    return;

  proxy = hymo_get_fops_proxy(orig_fops);
  if (!proxy)
    proxy = hymo_create_fops_proxy(orig_fops);

  if (proxy) {
    /* Atomically replace fops */
    file->f_op = &proxy->proxy_fops;
  }
}

static void hymofs_set_all_hooks(bool enable) {
  int stage = hymofs_hook_stage_runtime;
  if (!hymo_syms_resolved)
    return;

  if (!HYMOFS_DISABLE_REBOOT_HOOK && !hymo_reboot_hooked && k_sys_reboot) {
    hook_err_t err;
    if (hymo_reboot_use_regs)
      err = hymo_kp_hook_wrap_call(k_sys_reboot, 1, hymofs_reboot_before_regs,
                                   NULL, 0);
    else
      err = hymo_kp_hook_wrap_call(k_sys_reboot, 4, hymofs_reboot_before_args4,
                                   NULL, 0);
    if (err)
      pr_err("hook reboot error: %d\n", err);
    else {
      hymo_reboot_hooked = true;
      pr_err("hymofs: reboot hook active (%s)\n",
             hymo_reboot_use_regs ? "regs" : "args");
    }
  }

  if (enable) {
    if (hymo_hooks_active)
      return;
    if (stage <= 0) {
      pr_info("hymofs: hooks deferred (stage %d)\n", stage);
      return;
    }

    if (!hymofs_disable_dpath_runtime) {
      hook_func_try(k_d_path, 3, NULL, hymofs_d_path_after, 0);
    }
    if (!hymofs_disable_getname_runtime) {
      hook_func_try(k_getname, 1, NULL, hymofs_getname_after, 0);
      hook_func_try(k_getname_uflags, 2, NULL, hymofs_getname_uflags_after, 0);
    }
    if (!hymofs_disable_getattr_runtime) {
      hook_func_try(k_vfs_getattr_nosec, 4, NULL, hymofs_vfs_getattr_after, 0);
    }
    if (!hymofs_disable_dirents_runtime) {
      /*
       * Route A: Fops Hooking
       * Use vfs_open hook to intercept file openings and replace f_op.
       * This avoids unstable inline hooks on getdents/readdir.
       */
      if (k_vfs_open) {
        hook_func_try(k_vfs_open, 2, NULL, hymofs_vfs_open_after, 0);
        pr_info("hymofs: vfs_open hook enabled (Route A)\n");
      } else {
        pr_err("hymofs: vfs_open not found, dirents hiding disabled\n");
      }
    }

    if (stage >= 2 && k_filename_lookup &&
        !hymofs_disable_filename_lookup_runtime) {
      hook_err_t err = hymo_kp_hook_wrap_call(k_filename_lookup, 5,
                                              hymofs_filename_lookup_before,
                                              hymofs_filename_lookup_after, 0);
      if (err)
        pr_warn("hook filename_lookup error: %d\n", err);
    }

    if (stage >= 3 && k_cmdline_proc_show) {
      hook_err_t err = hymo_kp_hook_wrap_call(
          k_cmdline_proc_show, 2, hymofs_cmdline_show_before, NULL, 0);
      if (err)
        pr_warn("hook cmdline_proc_show error: %d\n", err);
      pr_info("hymofs: cmdline hook done\n");
    }

    if (stage >= 4) {
      if (k_sys_newuname) {
        hook_err_t err = hymo_kp_hook_wrap_call(
            k_sys_newuname, 1, hymofs_newuname_before, NULL, 0);
        if (err)
          pr_warn("hook newuname error: %d\n", err);
      }
      if (k_sys_uname) {
        hook_err_t err = hymo_kp_hook_wrap_call(k_sys_uname, 1,
                                                hymofs_uname_before, NULL, 0);
        if (err)
          pr_warn("hook uname error: %d\n", err);
      }
      pr_info("hymofs: uname/reboot hooks done\n");
    }

    if (stage >= 5) {
      if (k_show_mountinfo) {
        hook_err_t err = hymo_kp_hook_wrap_call(
            k_show_mountinfo, 2, hymofs_mountinfo_show_before, NULL, 0);
        if (err)
          pr_warn("hook show_mountinfo error: %d\n", err);
        else
          pr_info("hymofs: mountinfo hook enabled\n");
      }
      hymofs_set_xattr_hooks(true);
      pr_info("hymofs: xattr hooks enabled\n");
    }

    hymo_hooks_active = true;
    return;
  }

  if (!hymo_hooks_active && !hymo_xattr_hooked)
    return;
  unhook_func(k_d_path);
  unhook_func(k_getname);
  unhook_func(k_getname_uflags);
  unhook_func(k_filename_lookup);
  unhook_func(k_vfs_getattr_nosec);
  unhook_func(k_vfs_open);
  unhook_func(k_cmdline_proc_show);
  unhook_func(k_show_mountinfo);
  unhook_func(k_sys_newuname);
  unhook_func(k_sys_uname);
  hymofs_set_xattr_hooks(false);
  hymo_hooks_active = false;
}

static void hymofs_cmdline_show_before(hook_fargs2_t *args, void *udata) {
#ifdef CONFIG_HYMOFS_CMDLINE_SPOOF
  struct seq_file *m = (struct seq_file *)args->arg0;
  if (hymofs_spoof_cmdline(m) == 0) {
    args->ret = 0;
    args->skip_origin = 1;
  }
#endif // #ifdef CONFIG_HYMOFS_CMDLINE_SPOOF
}

static __always_inline bool hymo_mount_is_hymo(const struct mount *m) {
  int id;
  if (!m)
    return false;
  /*
   * reorder_mnt_id() moves Hymo mounts into a "high" id range when stealth is
   * enabled. This marker stays valid even if devname is spoofed later.
   */
  id = READ_ONCE(m->mnt_id);
  if (id >= 500000)
    return true;
  if (m->mnt_devname &&
      (strcmp(m->mnt_devname, hymo_current_mirror_path) == 0 ||
       strcmp(m->mnt_devname, hymo_current_mirror_name) == 0))
    return true;
  return false;
}

static void hymofs_mountinfo_show_before(hook_fargs2_t *args, void *udata) {
  void *v = (void *)args->arg1;
  struct mount *m;

  if (!hymo_stealth_enabled)
    return;
  if (!hymofs_enabled || hymofs_exiting || hymo_safe_mode)
    return;
  if (hymo_is_privileged_process())
    return;

  /* seq_file iteration may pass a small start token (often (void *)1). */
  if (unlikely((unsigned long)v <= 1))
    return;

  m = (struct mount *)v;
  if (hymo_mount_is_hymo(m)) {
    args->ret = 0;
    args->skip_origin = 1;
  }
}

static void hymofs_newuname_before(hook_fargs1_t *args, void *udata) {
#ifdef CONFIG_HYMOFS_UNAME_SPOOF
  if (!hymofs_enabled || hymofs_exiting || hymo_safe_mode)
    return;
  struct new_utsname tmp;
  struct new_utsname __user *name = (struct new_utsname __user *)args->arg0;
  hymo_uts_down_read();
  memcpy(&tmp, utsname(), sizeof(tmp));
  hymo_uts_up_read();
  hymofs_spoof_uname(&tmp);
  if (copy_to_user(name, &tmp, sizeof(tmp))) {
    args->ret = -EFAULT;
  } else {
    args->ret = 0;
  }
  args->skip_origin = 1;
#endif // #ifdef CONFIG_HYMOFS_UNAME_SPOOF
}

static void hymofs_uname_before(hook_fargs1_t *args, void *udata) {
#ifdef CONFIG_HYMOFS_UNAME_SPOOF
  if (!hymofs_enabled || hymofs_exiting || hymo_safe_mode)
    return;
  struct new_utsname tmp;
  struct new_utsname __user *name = (struct new_utsname __user *)args->arg0;

  memset(&tmp, 0, sizeof(tmp));

  hymo_uts_down_read();
  memcpy(&tmp, utsname(), sizeof(tmp));
  hymo_uts_up_read();
  hymofs_spoof_uname(&tmp);
  if (copy_to_user(name, &tmp, sizeof(tmp))) {
    args->ret = -EFAULT;
  } else {
    args->ret = 0;
  }
  args->skip_origin = 1;
#endif // #ifdef CONFIG_HYMOFS_UNAME_SPOOF
}

static ssize_t hymofs_filter_dirents(struct hymo_readdir_context *ctx,
                                     void __user *dirent, ssize_t bytes,
                                     bool is64) {
  char *kbuf;
  char *p;
  char *end;
  char *out;
  ssize_t new_len = 0;

  if (!ctx || bytes <= 0 || !dirent)
    return bytes;

  kbuf = kvmalloc(bytes, GFP_KERNEL);
  if (!kbuf)
    return bytes;

  if (copy_from_user(kbuf, dirent, bytes)) {
    kvfree(kbuf);
    return -EFAULT;
  }

  p = kbuf;
  end = kbuf + bytes;
  out = kbuf;

  while (p < end) {
    unsigned short reclen;
    char *name;
    int namlen;

    if (is64) {
      struct linux_dirent64 *d = (struct linux_dirent64 *)p;
      reclen = d->d_reclen;
      if (!reclen || p + reclen > end)
        break;
      name = d->d_name;
      namlen = strnlen(name, reclen - offsetof(struct linux_dirent64, d_name));
    } else {
      struct linux_dirent *d = (struct linux_dirent *)p;
      reclen = d->d_reclen;
      if (!reclen || p + reclen > end)
        break;
      name = d->d_name;
      namlen = strnlen(name, reclen - offsetof(struct linux_dirent, d_name));
    }

    if (!hymofs_check_filldir(ctx, name, namlen)) {
      if (out != p)
        memmove(out, p, reclen);
      out += reclen;
      new_len += reclen;
    }
    p += reclen;
  }

  if (copy_to_user(dirent, kbuf, new_len)) {
    kvfree(kbuf);
    return -EFAULT;
  }

  kvfree(kbuf);
  return new_len;
}

static void hymofs_getdents_before(hook_fargs3_t *args, void *udata) {
#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
  unsigned int fd = (unsigned int)args->arg0;
  struct file *file;
  struct hymo_readdir_context *ctx;

  args->local.data0 = 0;
  args->local.data1 = 0;

  /*
   * getdents is hot during boot (init, vold, zygote scanning /proc and /).
   * Keep behavior consistent with getname/d_path: if disabled/safe/no rules,
   * do nothing and let origin run untouched.
   */
  if (!hymofs_enabled || hymofs_exiting || hymo_safe_mode)
    return;
  if (hymo_system_state() < SYSTEM_RUNNING)
    return;
  if (likely(!hymofs_has_any_rules()))
    return;

  file = fget(fd);
  if (!file) {
    args->ret = -EBADF;
    args->skip_origin = 1;
    return;
  }

  ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
  if (!ctx) {
    fput(file);
    return;
  }
  ctx->magic = HYMO_CTX_MAGIC;
  ctx->file = file;
  hymofs_prepare_readdir(ctx, file);

#ifdef CONFIG_HYMOFS_INJECT_ENTRIES
  if (file->f_pos >= HYMO_MAGIC_POS) {
    void __user *dir_ptr = (void __user *)args->arg1;
    int count = (int)args->arg2;
    int res = hymofs_inject_entries(ctx, &dir_ptr, &count, &file->f_pos);
    if (res >= 0)
      args->ret = (int)args->arg2 - count;
    else
      args->ret = res;
    hymofs_cleanup_readdir(ctx);
    ctx->magic = 0;
    kfree(ctx);
    fput(file);
    args->local.data0 = 0;
    args->local.data1 = 0;
    args->skip_origin = 1;
    return;
  }
#endif // #ifdef CONFIG_HYMOFS_INJECT_ENTRIES

  args->local.data0 = (uint64_t)ctx;
  args->local.data1 = (uint64_t)file;
#endif // #ifdef CONFIG_HYMOFS_HIDE_ENTRIES
}

static void hymofs_getdents_after(hook_fargs3_t *args, void *udata) {
#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
  struct hymo_readdir_context *ctx =
      (struct hymo_readdir_context *)args->local.data0;
  struct file *file = (struct file *)args->local.data1;
  ssize_t ret = (ssize_t)args->ret;
  unsigned int count = (unsigned int)args->arg2;

  if (!ctx || !file) {
    return;
  }
  if (!hymo_ptr_is_kernel(ctx) || !hymo_ptr_is_kernel(file)) {
    pr_warn("hymofs: getdents ctx ptr invalid, skip cleanup\n");
    return;
  }
  if (!hymo_ctx_valid(ctx, file)) {
    pr_warn("hymofs: getdents ctx invalid, skip cleanup\n");
    return;
  }

  if (ret > 0) {
    ssize_t filtered =
        hymofs_filter_dirents(ctx, (void __user *)args->arg1, ret, false);
    if (filtered < 0) {
      args->ret = filtered;
      goto out;
    }
    args->ret = filtered;

#ifdef CONFIG_HYMOFS_INJECT_ENTRIES
    if (filtered >= 0 && filtered < count && file->f_pos < HYMO_MAGIC_POS &&
        !signal_pending(current)) {
      void __user *dir_ptr = (char __user *)args->arg1 + filtered;
      int remain = (int)count - (int)filtered;
      int res = hymofs_inject_entries(ctx, &dir_ptr, &remain, &file->f_pos);
      if (res > 0)
        args->ret = count - remain;
    }
#endif // #ifdef CONFIG_HYMOFS_INJECT_ENTRIES
  }

out:
  hymofs_cleanup_readdir(ctx);
  ctx->magic = 0;
  kfree(ctx);
  fput(file);
#endif // #ifdef CONFIG_HYMOFS_HIDE_ENTRIES
}

/* syscall-wrapper variant: __arm64_sys_getdents*(const struct pt_regs *regs) */
static void hymofs_getdents_regs_before(hook_fargs1_t *args, void *udata) {
#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
  struct pt_regs *regs = (struct pt_regs *)args->arg0;
  unsigned int fd;
  struct file *file;
  struct hymo_readdir_context *ctx;

  args->local.data0 = 0;
  args->local.data1 = 0;

  if (!regs)
    return;

  if (!hymofs_enabled || hymofs_exiting || hymo_safe_mode)
    return;
  if (hymo_system_state() < SYSTEM_RUNNING)
    return;
  if (likely(!hymofs_has_any_rules()))
    return;

  fd = (unsigned int)regs->regs[0];
  file = fget(fd);
  if (!file) {
    /* Override syscall return via pt_regs */
    regs->regs[0] = (unsigned long)-EBADF;
    args->ret = (uint64_t)-EBADF;
    args->skip_origin = 1;
    return;
  }

  ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
  if (!ctx) {
    fput(file);
    return;
  }
  ctx->magic = HYMO_CTX_MAGIC;
  ctx->file = file;
  hymofs_prepare_readdir(ctx, file);

  args->local.data0 = (uint64_t)ctx;
  args->local.data1 = (uint64_t)file;
#endif // #ifdef CONFIG_HYMOFS_HIDE_ENTRIES
}

static void hymofs_getdents_regs_after(hook_fargs1_t *args, void *udata) {
#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
  struct pt_regs *regs = (struct pt_regs *)args->arg0;
  struct hymo_readdir_context *ctx =
      (struct hymo_readdir_context *)args->local.data0;
  struct file *file = (struct file *)args->local.data1;
  ssize_t ret = (ssize_t)args->ret;

  if (!regs || !ctx || !file)
    return;
  if (!hymo_ptr_is_kernel(ctx) || !hymo_ptr_is_kernel(file)) {
    pr_warn("hymofs: getdents(regs) ctx ptr invalid, skip cleanup\n");
    return;
  }
  if (!hymo_ctx_valid(ctx, file)) {
    pr_warn("hymofs: getdents(regs) ctx invalid, skip cleanup\n");
    return;
  }

  if (ret > 0) {
    void __user *dirent = (void __user *)regs->regs[1];
    unsigned int count = (unsigned int)regs->regs[2];
    ssize_t filtered = hymofs_filter_dirents(ctx, dirent, ret, false);
    if (filtered < 0) {
      regs->regs[0] = (unsigned long)filtered;
      args->ret = (uint64_t)filtered;
      goto out;
    }
    regs->regs[0] = (unsigned long)filtered;
    args->ret = (uint64_t)filtered;

#ifdef CONFIG_HYMOFS_INJECT_ENTRIES
    if (filtered >= 0 && filtered < (ssize_t)count &&
        file->f_pos < HYMO_MAGIC_POS && !signal_pending(current)) {
      void __user *dir_ptr = (char __user *)dirent + filtered;
      int remain = (int)count - (int)filtered;
      int res = hymofs_inject_entries(ctx, &dir_ptr, &remain, &file->f_pos);
      if (res > 0) {
        regs->regs[0] = (unsigned long)(count - remain);
        args->ret = (uint64_t)(count - remain);
      }
    }
#endif // #ifdef CONFIG_HYMOFS_INJECT_ENTRIES
  }

out:
  hymofs_cleanup_readdir(ctx);
  ctx->magic = 0;
  kfree(ctx);
  fput(file);
#endif // #ifdef CONFIG_HYMOFS_HIDE_ENTRIES
}

static void hymofs_getdents64_before(hook_fargs3_t *args, void *udata) {
#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
  unsigned int fd = (unsigned int)args->arg0;
  struct file *file;
  struct hymo_readdir_context *ctx;

  args->local.data0 = 0;
  args->local.data1 = 0;

  /* Same fast-path policy as hymofs_getdents_before() */
  if (!hymofs_enabled || hymofs_exiting || hymo_safe_mode)
    return;
  if (hymo_system_state() < SYSTEM_RUNNING)
    return;
  if (likely(!hymofs_has_any_rules()))
    return;

  file = fget(fd);
  if (!file) {
    args->ret = -EBADF;
    args->skip_origin = 1;
    return;
  }

  ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
  if (!ctx) {
    fput(file);
    return;
  }
  ctx->magic = HYMO_CTX_MAGIC;
  ctx->file = file;
  hymofs_prepare_readdir(ctx, file);

#ifdef CONFIG_HYMOFS_INJECT_ENTRIES
  if (file->f_pos >= HYMO_MAGIC_POS) {
    void __user *dir_ptr = (void __user *)args->arg1;
    int count = (int)args->arg2;
    int res = hymofs_inject_entries64(ctx, &dir_ptr, &count, &file->f_pos);
    if (res >= 0)
      args->ret = (int)args->arg2 - count;
    else
      args->ret = res;
    hymofs_cleanup_readdir(ctx);
    ctx->magic = 0;
    kfree(ctx);
    fput(file);
    args->local.data0 = 0;
    args->local.data1 = 0;
    args->skip_origin = 1;
    return;
  }
#endif // #ifdef CONFIG_HYMOFS_INJECT_ENTRIES

  args->local.data0 = (uint64_t)ctx;
  args->local.data1 = (uint64_t)file;
#endif // #ifdef CONFIG_HYMOFS_HIDE_ENTRIES
}

static void hymofs_getdents64_after(hook_fargs3_t *args, void *udata) {
#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
  struct hymo_readdir_context *ctx =
      (struct hymo_readdir_context *)args->local.data0;
  struct file *file = (struct file *)args->local.data1;
  ssize_t ret = (ssize_t)args->ret;
  unsigned int count = (unsigned int)args->arg2;

  if (!ctx || !file) {
    return;
  }
  if (!hymo_ptr_is_kernel(ctx) || !hymo_ptr_is_kernel(file)) {
    pr_warn("hymofs: getdents64 ctx ptr invalid, skip cleanup\n");
    return;
  }
  if (!hymo_ctx_valid(ctx, file)) {
    pr_warn("hymofs: getdents64 ctx invalid, skip cleanup\n");
    return;
  }

  if (ret > 0) {
    ssize_t filtered =
        hymofs_filter_dirents(ctx, (void __user *)args->arg1, ret, true);
    if (filtered < 0) {
      args->ret = filtered;
      goto out;
    }
    args->ret = filtered;

#ifdef CONFIG_HYMOFS_INJECT_ENTRIES
    if (filtered >= 0 && filtered < count && file->f_pos < HYMO_MAGIC_POS &&
        !signal_pending(current)) {
      void __user *dir_ptr = (char __user *)args->arg1 + filtered;
      int remain = (int)count - (int)filtered;
      int res = hymofs_inject_entries64(ctx, &dir_ptr, &remain, &file->f_pos);
      if (res > 0)
        args->ret = count - remain;
    }
#endif // #ifdef CONFIG_HYMOFS_INJECT_ENTRIES
  }

out:
  hymofs_cleanup_readdir(ctx);
  ctx->magic = 0;
  kfree(ctx);
  fput(file);
#endif // #ifdef CONFIG_HYMOFS_HIDE_ENTRIES
}

static void hymofs_getdents64_regs_before(hook_fargs1_t *args, void *udata) {
#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
  struct pt_regs *regs = (struct pt_regs *)args->arg0;
  unsigned int fd;
  struct file *file;
  struct hymo_readdir_context *ctx;

  args->local.data0 = 0;
  args->local.data1 = 0;

  if (!regs)
    return;

  if (!hymofs_enabled || hymofs_exiting || hymo_safe_mode)
    return;
  if (hymo_system_state() < SYSTEM_RUNNING)
    return;
  if (likely(!hymofs_has_any_rules()))
    return;

  fd = (unsigned int)regs->regs[0];
  file = fget(fd);
  if (!file) {
    regs->regs[0] = (unsigned long)-EBADF;
    args->ret = (uint64_t)-EBADF;
    args->skip_origin = 1;
    return;
  }

  ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
  if (!ctx) {
    fput(file);
    return;
  }
  ctx->magic = HYMO_CTX_MAGIC;
  ctx->file = file;
  hymofs_prepare_readdir(ctx, file);

  args->local.data0 = (uint64_t)ctx;
  args->local.data1 = (uint64_t)file;
#endif // #ifdef CONFIG_HYMOFS_HIDE_ENTRIES
}

static void hymofs_getdents64_regs_after(hook_fargs1_t *args, void *udata) {
#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
  struct pt_regs *regs = (struct pt_regs *)args->arg0;
  struct hymo_readdir_context *ctx =
      (struct hymo_readdir_context *)args->local.data0;
  struct file *file = (struct file *)args->local.data1;
  ssize_t ret = (ssize_t)args->ret;

  if (!regs || !ctx || !file)
    return;
  if (!hymo_ptr_is_kernel(ctx) || !hymo_ptr_is_kernel(file)) {
    pr_warn("hymofs: getdents64(regs) ctx ptr invalid, skip cleanup\n");
    return;
  }
  if (!hymo_ctx_valid(ctx, file)) {
    pr_warn("hymofs: getdents64(regs) ctx invalid, skip cleanup\n");
    return;
  }

  if (ret > 0) {
    void __user *dirent = (void __user *)regs->regs[1];
    unsigned int count = (unsigned int)regs->regs[2];
    ssize_t filtered = hymofs_filter_dirents(ctx, dirent, ret, true);
    if (filtered < 0) {
      regs->regs[0] = (unsigned long)filtered;
      args->ret = (uint64_t)filtered;
      goto out;
    }
    regs->regs[0] = (unsigned long)filtered;
    args->ret = (uint64_t)filtered;

#ifdef CONFIG_HYMOFS_INJECT_ENTRIES
    if (filtered >= 0 && filtered < (ssize_t)count &&
        file->f_pos < HYMO_MAGIC_POS && !signal_pending(current)) {
      void __user *dir_ptr = (char __user *)dirent + filtered;
      int remain = (int)count - (int)filtered;
      int res = hymofs_inject_entries64(ctx, &dir_ptr, &remain, &file->f_pos);
      if (res > 0) {
        regs->regs[0] = (unsigned long)(count - remain);
        args->ret = (uint64_t)(count - remain);
      }
    }
#endif // #ifdef CONFIG_HYMOFS_INJECT_ENTRIES
  }

out:
  hymofs_cleanup_readdir(ctx);
  ctx->magic = 0;
  kfree(ctx);
  fput(file);
#endif // #ifdef CONFIG_HYMOFS_HIDE_ENTRIES
}

static void hymofs_reboot_before_args4(hook_fargs4_t *args, void *udata) {
  int magic1 = (int)args->arg0;
  int magic2 = (int)args->arg1;
  unsigned int cmd = (unsigned int)args->arg2;
  void __user *arg = (void __user *)args->arg3;
  if (hymo_reboot_hit_count < 5) {
    pr_err("hymofs: reboot hook hit m1=0x%x m2=0x%x cmd=0x%x arg=%px\n", magic1,
           magic2, cmd, arg);
    hymo_reboot_hit_count++;
  }
  if (magic1 == HYMO_MAGIC1 && magic2 == HYMO_MAGIC2) {
    if (hymo_reboot_hit_count < 5) {
      pr_err("hymofs: reboot magic matched\n");
      hymo_reboot_hit_count++;
    }
    args->ret = hymo_dispatch_cmd(cmd, arg);
    args->skip_origin = 1;
  }
}

static void hymofs_reboot_before_regs(hook_fargs1_t *args, void *udata) {
  struct pt_regs *regs = (struct pt_regs *)args->arg0;
  int magic1;
  int magic2;
  unsigned int cmd;
  void __user *arg;

  if (!regs)
    return;

  magic1 = (int)regs->regs[0];
  magic2 = (int)regs->regs[1];
  cmd = (unsigned int)regs->regs[2];
  arg = (void __user *)regs->regs[3];

  if (hymo_reboot_hit_count < 5) {
    pr_err("hymofs: reboot hook hit m1=0x%x m2=0x%x cmd=0x%x arg=%px\n", magic1,
           magic2, cmd, arg);
    hymo_reboot_hit_count++;
  }
  if (magic1 == HYMO_MAGIC1 && magic2 == HYMO_MAGIC2) {
    if (hymo_reboot_hit_count < 5) {
      pr_err("hymofs: reboot magic matched\n");
      hymo_reboot_hit_count++;
    }
    args->ret = hymo_dispatch_cmd(cmd, arg);
    args->skip_origin = 1;
  }
}

static void *hymofs_lookup_any(const char *const *names, size_t count) {
  size_t i;
  void *addr = NULL;

  for (i = 0; i < count; i++) {
    addr = (void *)kallsyms_lookup_name(names[i]);
    if (addr) {
      pr_info("kernel function %s addr: %px\n", names[i], addr);
      return addr;
    }
  }
  return NULL;
}

static void *hymofs_lookup_any_with_name(const char *const *names, size_t count,
                                         const char **matched) {
  size_t i;
  void *addr = NULL;

  if (matched)
    *matched = NULL;

  for (i = 0; i < count; i++) {
    addr = (void *)kallsyms_lookup_name(names[i]);
    if (addr) {
      if (matched)
        *matched = names[i];
      pr_info("kernel function %s addr: %px\n", names[i], addr);
      return addr;
    }
  }
  return NULL;
}

static void hymofs_kpm_format_status(char *msg, size_t msg_sz) {
  const char *emoji = hymofs_enabled ? "😋" : "😴";
  int rules = atomic_read(&hymo_rule_count);
  int hides = atomic_read(&hymo_hide_count);
  int merges = atomic_read(&hymo_merge_count);
  (void)scnprintf(
      msg, msg_sz,
      "HymoFS %s %s | merge=%d rules=%d hide=%d | stealth=%d safe=%d",
      MYKPM_VERSION, emoji, merges, rules, hides, hymo_stealth_enabled ? 1 : 0,
      hymo_safe_mode ? 1 : 0);
}

static void hymofs_kpm_update_info_description(void) {
  /*
   * Keep `.kpm.info` in the standard macro-generated format for compatibility
   * with loaders/managers. Dynamic status is still available via ctl0 out_msg.
   */
}

static long hymofs_kpm_ctl0(const char *ctl_args, char *__user out_msg,
                            int outlen) {
  if (ctl_args) {
    if (!strncmp(ctl_args, "debug=", 6)) {
      hymo_debug_enabled = !!simple_strtoul(ctl_args + 6, NULL, 10);
    } else if (!strncmp(ctl_args, "stealth=", 8)) {
      hymo_stealth_enabled = !!simple_strtoul(ctl_args + 8, NULL, 10);
    } else if (!strncmp(ctl_args, "safe=", 5)) {
      hymo_safe_mode = !!simple_strtoul(ctl_args + 5, NULL, 10);
      pr_info("hymofs: safe mode %s\n",
              hymo_safe_mode ? "enabled" : "disabled");
    } else if (!strncmp(ctl_args, "stage=", 6)) {
      hymofs_hook_stage_runtime = (int)simple_strtoul(ctl_args + 6, NULL, 10);
      pr_info("hymofs: hook stage set to %d\n", hymofs_hook_stage_runtime);
      hymofs_apply_hook_config_locked();
    } else if (!strncmp(ctl_args, "no_dirents=", 11)) {
      hymofs_disable_dirents_runtime =
          !!simple_strtoul(ctl_args + 11, NULL, 10);
      pr_info("hymofs: disable dirents=%d\n",
              hymofs_disable_dirents_runtime ? 1 : 0);
      hymofs_apply_hook_config_locked();
    } else if (!strncmp(ctl_args, "no_getname=", 11)) {
      hymofs_disable_getname_runtime =
          !!simple_strtoul(ctl_args + 11, NULL, 10);
      pr_info("hymofs: disable getname=%d\n",
              hymofs_disable_getname_runtime ? 1 : 0);
      hymofs_apply_hook_config_locked();
    } else if (!strncmp(ctl_args, "no_dpath=", 9)) {
      hymofs_disable_dpath_runtime = !!simple_strtoul(ctl_args + 9, NULL, 10);
      pr_info("hymofs: disable d_path=%d\n",
              hymofs_disable_dpath_runtime ? 1 : 0);
      hymofs_apply_hook_config_locked();
    } else if (!strncmp(ctl_args, "no_getattr=", 11)) {
      hymofs_disable_getattr_runtime =
          !!simple_strtoul(ctl_args + 11, NULL, 10);
      pr_info("hymofs: disable getattr=%d\n",
              hymofs_disable_getattr_runtime ? 1 : 0);
      hymofs_apply_hook_config_locked();
    } else if (!strncmp(ctl_args, "no_flookup=", 11)) {
      hymofs_disable_filename_lookup_runtime =
          !!simple_strtoul(ctl_args + 11, NULL, 10);
      pr_info("hymofs: disable filename_lookup=%d\n",
              hymofs_disable_filename_lookup_runtime ? 1 : 0);
      hymofs_apply_hook_config_locked();
    }
  }

  if (out_msg && outlen > 0) {
    char msg[256];
    size_t len;
    /*
     * Include hook config in the status line so we can debug freezes quickly.
     */
    {
      char base[192];
      hymofs_kpm_format_status(base, sizeof(base));
      (void)scnprintf(msg, sizeof(msg),
                      "%s | stage=%d hooks=%d syms=%d no_dirents=%d "
                      "no_getname=%d no_dpath=%d no_getattr=%d no_flookup=%d",
                      base, hymofs_hook_stage_runtime,
                      hymo_hooks_active ? 1 : 0, hymo_syms_resolved ? 1 : 0,
                      hymofs_disable_dirents_runtime ? 1 : 0,
                      hymofs_disable_getname_runtime ? 1 : 0,
                      hymofs_disable_dpath_runtime ? 1 : 0,
                      hymofs_disable_getattr_runtime ? 1 : 0,
                      hymofs_disable_filename_lookup_runtime ? 1 : 0);
    }
    hymofs_kpm_update_info_description();
    len = strnlen(msg, sizeof(msg));
    if (len + 1 > (size_t)outlen)
      len = outlen - 1;
    msg[len] = '\0';
    /* Keep consistent with KernelPatch demos */
    if (hymo_kp_compat_copy_to_user_call(out_msg, msg, (int)len + 1) <= 0)
      copy_to_user(out_msg, msg, len + 1);
  }
  return 0;
}

static long hymofs_kpm_ctl1(void *a1, void *a2, void *a3) {
  (void)a1;
  (void)a2;
  (void)a3;
  return -ENOSYS;
}

static long hymofs_kpm_init(const char *args, const char *event,
                            void *__user reserved) {
  int rc;
  static const char *const getdents_syms[] = {
      /* Prefer ksys_* helpers (stable args ABI, avoid syscall wrapper traps) */
      "ksys_getdents", "__se_sys_getdents",    "__do_sys_getdents",
      "sys_getdents",  "__arm64_sys_getdents",
  };
  static const char *const getdents64_syms[] = {
      "ksys_getdents64", "__se_sys_getdents64",    "__do_sys_getdents64",
      "sys_getdents64",  "__arm64_sys_getdents64",
  };
  const char *getdents_sym = NULL;
  const char *getdents64_sym = NULL;
  static const char *const newuname_syms[] = {
      "__arm64_sys_newuname",
      "sys_newuname",
      "__se_sys_newuname",
      "__do_sys_newuname",
  };
  static const char *const uname_syms[] = {
      "__arm64_sys_uname",
      "sys_uname",
      "__se_sys_uname",
      "__do_sys_uname",
  };
  static const char *const reboot_syms[] = {
      "__do_sys_reboot",
      "__se_sys_reboot",
      "__arm64_sys_reboot",
      "sys_reboot",
  };
  const char *reboot_sym = NULL;

  if (hymo_safe_mode)
    return 0;

  /* Resolve KP exported helpers into function pointers (avoid CALL26). */
  hymo_kp_lazy_init();

  pr_info("hymofs: init begin, args=%s, event=%s\n", args ? args : "(null)",
          event ? event : "(null)");
  hymofs_kpm_update_info_description();

  rc = hymofs_kpm_ctl0(args, NULL, 0);
  if (rc)
    return rc;
  pr_info("hymofs: ctl0 parsed\n");

  rc = hymofs_init();
  if (rc)
    return rc;
  pr_info("hymofs: core init done\n");

#if HYMOFS_INIT_ONLY
  pr_info("hymofs: init-only, skip symbol resolve/hooks\n");
  return 0;
#endif // #if HYMOFS_INIT_ONLY

  hymo_resolve_kernel_symbols();
  pr_info("hymofs: resolve symbols done\n");

  lookup_name_try_sym(k_d_path, "d_path");
  lookup_name_try_sym(k_getname, "getname");
  lookup_name_try_sym(k_getname_uflags, "getname_uflags");
  lookup_name_try_sym(k_vfs_getattr_nosec, "vfs_getattr_nosec");

  {
    static const char *const vfs_open_syms[] = {
        "vfs_open",
        "do_dentry_open",
    };
    const char *vfs_open_sym = NULL;
    k_vfs_open = (typeof(k_vfs_open))hymofs_lookup_any_with_name(
        vfs_open_syms, ARRAY_SIZE(vfs_open_syms), &vfs_open_sym);
    if (k_vfs_open)
      pr_info("hymofs: vfs_open target=%s\n", vfs_open_sym);
    else
      pr_warn("hymofs: vfs_open not found\n");
  }

  k_sys_getdents = (typeof(k_sys_getdents))hymofs_lookup_any_with_name(
      getdents_syms, ARRAY_SIZE(getdents_syms), &getdents_sym);
  if (!k_sys_getdents)
    pr_warn("kernel function getdents not found\n");
  k_sys_getdents64 = (typeof(k_sys_getdents64))hymofs_lookup_any_with_name(
      getdents64_syms, ARRAY_SIZE(getdents64_syms), &getdents64_sym);
  if (!k_sys_getdents64)
    pr_warn("kernel function getdents64 not found\n");
  hymo_getdents_use_regs =
      (getdents_sym && !strcmp(getdents_sym, "__arm64_sys_getdents"));
  hymo_getdents64_use_regs =
      (getdents64_sym && !strcmp(getdents64_sym, "__arm64_sys_getdents64"));
  hymo_getdents_sym_name = getdents_sym;
  hymo_getdents64_sym_name = getdents64_sym;
  if (k_sys_getdents)
    pr_info("hymofs: getdents target=%s ABI=%s\n",
            hymo_getdents_sym_name ? hymo_getdents_sym_name : "(unknown)",
            hymo_getdents_use_regs ? "pt_regs" : "args");
  if (k_sys_getdents64)
    pr_info("hymofs: getdents64 target=%s ABI=%s\n",
            hymo_getdents64_sym_name ? hymo_getdents64_sym_name : "(unknown)",
            hymo_getdents64_use_regs ? "pt_regs" : "args");

  /*
   * Device-specific stability:
   * Some vendor kernels only expose syscall-wrapper __arm64_sys_getdents* via
   * kallsyms, and hooking those wrappers has been observed to cause early-boot
   * crashes. In that case, disable dirents hooks entirely (keep other hooks).
   */
  if (hymo_getdents_use_regs || hymo_getdents64_use_regs) {
    pr_err(
        "hymofs: dirents hooks disabled (wrapper-only symbols are unstable)\n");
    k_sys_getdents = NULL;
    k_sys_getdents64 = NULL;
    hymofs_disable_dirents_runtime = true;
  }

  lookup_name_continue_sym(k_filename_lookup, "filename_lookup");

  lookup_name_continue_sym(k_cmdline_proc_show, "cmdline_proc_show");
  lookup_name_continue_sym(k_show_mountinfo, "show_mountinfo");

  k_sys_newuname = (typeof(k_sys_newuname))hymofs_lookup_any(
      newuname_syms, ARRAY_SIZE(newuname_syms));

  k_sys_uname = (typeof(k_sys_uname))hymofs_lookup_any(uname_syms,
                                                       ARRAY_SIZE(uname_syms));

  k_sys_reboot = (typeof(k_sys_reboot))hymofs_lookup_any_with_name(
      reboot_syms, ARRAY_SIZE(reboot_syms), &reboot_sym);
  if (k_sys_reboot) {
#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
    if (reboot_sym && !strcmp(reboot_sym, "__arm64_sys_reboot"))
      hymo_reboot_use_regs = true;
    else
      hymo_reboot_use_regs = false;
#else
    hymo_reboot_use_regs = false;
#endif // #ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
  }
  if (!k_sys_reboot)
    pr_err("kernel function reboot not found\n");

  lookup_name_continue_sym(k_vfs_getxattr, "vfs_getxattr");

  lookup_name_continue_sym(k_listxattr, "listxattr");
  hymo_syms_resolved = true;
#if HYMOFS_SKIP_HOOKS
  pr_info("hymofs: skip hooks (resolve-only)\n");
  return 0;
#endif // #if HYMOFS_SKIP_HOOKS
  hymofs_set_all_hooks(hymofs_enabled);
  return 0;
}

static long hymofs_kpm_exit(void *__user reserved) {
  bool cleaned = false;
  hymofs_exiting = true;
  hymofs_enabled = false;
  hymofs_set_all_hooks(false);
  if (hymo_reboot_hooked) {
    unhook_func(k_sys_reboot);
    hymo_reboot_hooked = false;
  }
  if (hymo_spin_trylock(&hymo_lock)) {
    hymo_cleanup_locked();
    hymo_spin_unlock(&hymo_lock);
    cleaned = true;
  } else {
    pr_warn("hymofs: exit lock busy, skip cleanup\n");
  }
  if (cleaned) {
    kfree(hymo_fake_cmdline);
    hymo_fake_cmdline = NULL;
    hymo_cmdline_spoofed = false;
  }
  return 0;
}

KPM_INIT(hymofs_kpm_init);
KPM_CTL0(hymofs_kpm_ctl0);
KPM_CTL1(hymofs_kpm_ctl1);
KPM_EXIT(hymofs_kpm_exit);
