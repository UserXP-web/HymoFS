// SPDX-License-Identifier: GPL-2.0
/*
 * HymoFS LKM - Loadable Kernel Module for filesystem path manipulation.
 *
 * Uses ftrace hooks on key VFS functions to intercept path resolution,
 * stat, directory listing, and d_path. Provides a miscdevice (/dev/hymofs)
 * for userspace communication via ioctl.
 *
 * Hooks:
 *   getname_flags  - forward path redirection (open/stat/access/...)
 *   vfs_getattr    - stat result spoofing (mtime, inode, dev)
 *   d_path         - reverse lookup (physical -> virtual path)
 *   iterate_dir    - directory entry hiding (filldir filter)
 *
 * Author: Anatdx
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/jhash.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/sched/task.h>
#include <linux/fs_struct.h>
#include <linux/dirent.h>
#include <linux/stat.h>
#include <linux/time.h>

#include "hymofs_lkm.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anatdx");
MODULE_DESCRIPTION("HymoFS ftrace-based LKM");
MODULE_VERSION("0.1.0");

/* ======================================================================
 * Part 1: Ftrace Hook Infrastructure
 * ====================================================================== */

/* Global state needed early for ftrace thunk fast-path.
 * Moved above ftrace code so the thunk can access them. */
static bool hymofs_enabled;  /* false by default; daemon enables via ioctl */
static atomic_t hymo_rule_count = ATOMIC_INIT(0);
static atomic_t hymo_hide_count = ATOMIC_INIT(0);

#ifdef CONFIG_FUNCTION_TRACER
static int hymofs_resolve_hook_addr(struct hymofs_ftrace_hook *hook);

/* Ftrace callback: redirect function entry to our wrapper.
 *
 * CRITICAL OPTIMIZATION: Check global state BEFORE redirecting.
 * When hymofs is disabled or no rules exist, we return immediately
 * without modifying the instruction pointer. This means the original
 * kernel function runs with only ONE ftrace trampoline entry instead
 * of TWO (our hook calling orig_* would trigger ftrace again).
 * This eliminates ~50% of ftrace overhead for the no-rules case.
 */
static void notrace hymofs_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
					struct ftrace_ops *ops,
					struct ftrace_regs *fregs)
{
	struct hymofs_ftrace_hook *hook =
		container_of(ops, struct hymofs_ftrace_hook, ops);
	struct pt_regs *regs = ftrace_get_regs(fregs);

	if (!regs)
		return;

	/* Anti-recursion: skip hooks from within this module */
	if (within_module(parent_ip, THIS_MODULE))
		return;

	/* Global fast path: skip redirect entirely when nothing to do.
	 * The original function runs unmodified - no double ftrace entry. */
	if (likely(!READ_ONCE(hymofs_enabled)))
		return;
	if (likely(atomic_read(&hymo_rule_count) == 0 &&
		   atomic_read(&hymo_hide_count) == 0))
		return;

	/* Redirect execution to our hook function */
	instruction_pointer_set(regs, (unsigned long)hook->function);
}

static int hymofs_install_hook(struct hymofs_ftrace_hook *hook)
{
	int ret;

	ret = hymofs_resolve_hook_addr(hook);
	if (ret)
		return ret;

	*((unsigned long *)hook->original) = hook->address;

	hook->ops.func = hymofs_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION
			| FTRACE_OPS_FL_IPMODIFY;

	ret = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (ret) {
		pr_err("hymofs: ftrace_set_filter_ip(%s) failed: %d\n",
		       hook->name, ret);
		return ret;
	}

	ret = register_ftrace_function(&hook->ops);
	if (ret) {
		pr_err("hymofs: register_ftrace_function(%s) failed: %d\n",
		       hook->name, ret);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return ret;
	}

	return 0;
}

static void hymofs_remove_hook(struct hymofs_ftrace_hook *hook)
{
	int ret;

	ret = unregister_ftrace_function(&hook->ops);
	if (ret)
		pr_warn("hymofs: unregister(%s) failed: %d\n", hook->name, ret);

	ret = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (ret)
		pr_warn("hymofs: filter_ip remove(%s) failed: %d\n",
			hook->name, ret);
}

static int hymofs_install_hooks(struct hymofs_ftrace_hook *hooks, size_t count)
{
	size_t i;
	int ret;

	for (i = 0; i < count; i++) {
		ret = hymofs_install_hook(&hooks[i]);
		if (ret)
			goto rollback;
		pr_info("hymofs: hooked %s @0x%lx\n",
			hooks[i].name, hooks[i].address);
	}
	return 0;

rollback:
	while (i--)
		hymofs_remove_hook(&hooks[i]);
	return ret;
}

static void hymofs_remove_hooks(struct hymofs_ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		hymofs_remove_hook(&hooks[i]);
}

/* ======================================================================
 * Part 2: Symbol Resolution
 * ====================================================================== */

/* Try kallsyms first, fall back to kprobe trick */
static unsigned long hymofs_lookup_name(const char *name)
{
	unsigned long addr;

#ifdef CONFIG_KALLSYMS
	addr = kallsyms_lookup_name(name);
	if (addr)
		return addr;
#endif
	{
		struct kprobe kp = { .symbol_name = name };
		if (register_kprobe(&kp) < 0)
			return 0;
		addr = (unsigned long)kp.addr;
		unregister_kprobe(&kp);
	}
	return addr;
}

static int hymofs_resolve_hook_addr(struct hymofs_ftrace_hook *hook)
{
	hook->address = hymofs_lookup_name(hook->name);
	if (!hook->address) {
		pr_err("hymofs: symbol not found: %s\n", hook->name);
		return -ENOENT;
	}
	return 0;
}
#endif /* CONFIG_FUNCTION_TRACER */

/* Constants & data structures are in hymofs_lkm.h */

/* ======================================================================
 * Part 5: Global State
 * ====================================================================== */

static struct hymo_merge_trie_node *hymo_merge_trie_root __rcu;
static DEFINE_SPINLOCK(hymo_merge_trie_lock);

static DEFINE_HASHTABLE(hymo_paths, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_targets, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_hide_paths, HYMO_HASH_BITS);
static DEFINE_XARRAY(hymo_allow_uids_xa);
static DEFINE_HASHTABLE(hymo_inject_dirs, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_xattr_sbs, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_merge_dirs, HYMO_HASH_BITS);

static DEFINE_SPINLOCK(hymo_cfg_lock);
static DEFINE_SPINLOCK(hymo_rules_lock);
static DEFINE_SPINLOCK(hymo_hide_lock);
static DEFINE_SPINLOCK(hymo_allow_uids_lock);
static DEFINE_SPINLOCK(hymo_xattr_sbs_lock);
static DEFINE_SPINLOCK(hymo_merge_lock);
static DEFINE_SPINLOCK(hymo_inject_lock);

static bool hymo_allowlist_loaded;
static DEFINE_MUTEX(hymo_allowlist_lock);

/* hymofs_enabled declared above ftrace thunk */
bool hymo_debug_enabled;
static bool hymo_stealth_enabled = true;

static char hymo_mirror_path_buf[PATH_MAX] = HYMO_DEFAULT_MIRROR_PATH;
static char hymo_mirror_name_buf[NAME_MAX] = HYMO_DEFAULT_MIRROR_NAME;
static char *hymo_current_mirror_path = hymo_mirror_path_buf;
static char *hymo_current_mirror_name = hymo_mirror_name_buf;

static pid_t hymo_daemon_pid;
static DEFINE_SPINLOCK(hymo_daemon_lock);

static DECLARE_BITMAP(hymo_path_bloom, HYMO_BLOOM_SIZE);
static DECLARE_BITMAP(hymo_hide_bloom, HYMO_BLOOM_SIZE);
/* hymo_rule_count and hymo_hide_count declared above ftrace thunk */

/* hymo_log macro is in hymofs_lkm.h */

/* ======================================================================
 * Part 6: RCU Free Callbacks
 * ====================================================================== */

static void hymo_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_entry *e = container_of(head, struct hymo_entry, rcu);
	kfree(e->src);
	kfree(e->target);
	kfree(e);
}

static void hymo_hide_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_hide_entry *e = container_of(head, struct hymo_hide_entry, rcu);
	kfree(e->path);
	kfree(e);
}

static void hymo_inject_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_inject_entry *e = container_of(head, struct hymo_inject_entry, rcu);
	kfree(e->dir);
	kfree(e);
}

static void hymo_xattr_sb_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_xattr_sb_entry *e = container_of(head, struct hymo_xattr_sb_entry, rcu);
	kfree(e);
}

static void hymo_merge_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_merge_entry *e = container_of(head, struct hymo_merge_entry, rcu);
	kfree(e->src);
	kfree(e->target);
	kfree(e);
}

/* ======================================================================
 * Part 7: Merge Trie
 * ====================================================================== */

static void hymo_merge_trie_free_node(struct hymo_merge_trie_node *n)
{
	struct hymo_merge_trie_node *c, *next;

	if (!n)
		return;
	for (c = n->first_child; c; c = next) {
		next = c->next_sibling;
		hymo_merge_trie_free_node(c);
	}
	kfree(n->comp);
	kfree(n);
}

static void hymo_merge_trie_free_rcu(struct rcu_head *head)
{
	struct hymo_merge_trie_node *root =
		container_of(head, struct hymo_merge_trie_node, rcu);
	hymo_merge_trie_free_node(root);
}

/* Build trie from hymo_merge_dirs. Must hold hymo_merge_lock. */
static void hymo_merge_trie_build_locked(void)
{
	struct hymo_merge_trie_node *new_root, *old_root, *cur, **slot;
	struct hymo_merge_entry *me;
	const char *path, *start;
	char *comp;
	size_t comp_len;
	int bkt;

	spin_lock(&hymo_merge_trie_lock);
	new_root = kzalloc(sizeof(*new_root), GFP_ATOMIC);
	if (!new_root) {
		spin_unlock(&hymo_merge_trie_lock);
		return;
	}

	hash_for_each(hymo_merge_dirs, bkt, me, node) {
		if (!me->src)
			continue;
		path = me->src;
		while (*path == '/')
			path++;
		cur = new_root;
		while (*path) {
			start = path;
			while (*path && *path != '/')
				path++;
			comp_len = (size_t)(path - start);
			if (comp_len == 0) {
				if (*path) path++;
				continue;
			}
			comp = kmalloc(comp_len + 1, GFP_ATOMIC);
			if (!comp)
				break;
			memcpy(comp, start, comp_len);
			comp[comp_len] = '\0';
			for (slot = &cur->first_child; *slot;
			     slot = &(*slot)->next_sibling) {
				if ((*slot)->comp_len == comp_len &&
				    memcmp((*slot)->comp, comp, comp_len) == 0)
					break;
			}
			if (!*slot) {
				*slot = kzalloc(sizeof(struct hymo_merge_trie_node),
						GFP_ATOMIC);
				if (!*slot) {
					kfree(comp);
					break;
				}
				(*slot)->comp = comp;
				(*slot)->comp_len = comp_len;
			} else {
				kfree(comp);
			}
			cur = *slot;
			if (*path == '/')
				path++;
		}
		cur->entry = me;
	}

	old_root = rcu_dereference_protected(hymo_merge_trie_root,
				lockdep_is_held(&hymo_merge_trie_lock));
	rcu_assign_pointer(hymo_merge_trie_root, new_root);
	if (old_root)
		call_rcu(&old_root->rcu, hymo_merge_trie_free_rcu);
	spin_unlock(&hymo_merge_trie_lock);
}

/* Longest-prefix lookup; caller must hold rcu_read_lock. */
static struct hymo_merge_entry *
hymo_merge_trie_lookup_longest(const char *pathname)
{
	struct hymo_merge_trie_node *root, *cur, *child;
	const char *path, *start;
	size_t comp_len;
	struct hymo_merge_entry *last = NULL;

	root = rcu_dereference(hymo_merge_trie_root);
	if (!root)
		return NULL;
	path = pathname;
	while (*path == '/')
		path++;
	cur = root;
	while (*path) {
		start = path;
		while (*path && *path != '/')
			path++;
		comp_len = (size_t)(path - start);
		if (comp_len == 0) {
			if (*path) path++;
			continue;
		}
		for (child = rcu_dereference(cur->first_child); child;
		     child = rcu_dereference(child->next_sibling)) {
			if (child->comp_len == comp_len &&
			    memcmp(child->comp, start, comp_len) == 0)
				break;
		}
		if (!child)
			return last;
		cur = child;
		if (cur->entry)
			last = cur->entry;
		if (*path == '/')
			path++;
	}
	return last;
}

/* ======================================================================
 * Part 8: Inode Marking
 * ====================================================================== */

static inline void hymofs_mark_inode_hidden(struct inode *inode)
{
	if (inode && inode->i_mapping)
		set_bit(AS_FLAGS_HYMO_HIDE, &inode->i_mapping->flags);
}

static inline bool hymofs_is_inode_hidden_bit(struct inode *inode)
{
	if (!inode || !inode->i_mapping)
		return false;
	return test_bit(AS_FLAGS_HYMO_HIDE, &inode->i_mapping->flags);
}

/* ======================================================================
 * Part 9: Cleanup
 * ====================================================================== */

static void hymo_cleanup_locked(void)
{
	struct hymo_entry *entry;
	struct hymo_hide_entry *hide_entry;
	struct hymo_inject_entry *inject_entry;
	struct hymo_xattr_sb_entry *sb_entry;
	struct hymo_merge_entry *merge_entry;
	struct hlist_node *tmp;
	struct hymo_merge_trie_node *old_trie;
	int bkt;

	hash_for_each_safe(hymo_paths, bkt, tmp, entry, node) {
		hlist_del_rcu(&entry->node);
		hlist_del_rcu(&entry->target_node);
		call_rcu(&entry->rcu, hymo_entry_free_rcu);
	}
	hash_for_each_safe(hymo_hide_paths, bkt, tmp, hide_entry, node) {
		hlist_del_rcu(&hide_entry->node);
		call_rcu(&hide_entry->rcu, hymo_hide_entry_free_rcu);
	}
	xa_destroy(&hymo_allow_uids_xa);
	hash_for_each_safe(hymo_inject_dirs, bkt, tmp, inject_entry, node) {
		hlist_del_rcu(&inject_entry->node);
		call_rcu(&inject_entry->rcu, hymo_inject_entry_free_rcu);
	}
	hash_for_each_safe(hymo_xattr_sbs, bkt, tmp, sb_entry, node) {
		hlist_del_rcu(&sb_entry->node);
		call_rcu(&sb_entry->rcu, hymo_xattr_sb_entry_free_rcu);
	}
	hash_for_each_safe(hymo_merge_dirs, bkt, tmp, merge_entry, node) {
		hlist_del_rcu(&merge_entry->node);
		call_rcu(&merge_entry->rcu, hymo_merge_entry_free_rcu);
	}

	spin_lock(&hymo_merge_trie_lock);
	old_trie = rcu_dereference_protected(hymo_merge_trie_root,
				lockdep_is_held(&hymo_merge_trie_lock));
	rcu_assign_pointer(hymo_merge_trie_root, NULL);
	if (old_trie)
		call_rcu(&old_trie->rcu, hymo_merge_trie_free_rcu);
	spin_unlock(&hymo_merge_trie_lock);

	bitmap_zero(hymo_path_bloom, HYMO_BLOOM_SIZE);
	bitmap_zero(hymo_hide_bloom, HYMO_BLOOM_SIZE);
	atomic_set(&hymo_rule_count, 0);
	atomic_set(&hymo_hide_count, 0);
	hymo_allowlist_loaded = false;
}

/* ======================================================================
 * Part 10: Inject Rule Helper
 * ====================================================================== */

static void hymofs_add_inject_rule(char *dir)
{
	struct hymo_inject_entry *ie;
	u32 hash;
	bool found = false;

	if (!dir)
		return;

	hash = full_name_hash(NULL, dir, strlen(dir));
	spin_lock(&hymo_inject_lock);
	hlist_for_each_entry(ie, &hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (strcmp(ie->dir, dir) == 0) {
			found = true;
			break;
		}
	}
	if (!found) {
		ie = kmalloc(sizeof(*ie), GFP_ATOMIC);
		if (ie) {
			ie->dir = dir;
			hlist_add_head_rcu(&ie->node,
				&hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)]);
			atomic_inc(&hymo_rule_count);
		} else {
			kfree(dir);
		}
	} else {
		kfree(dir);
	}
	spin_unlock(&hymo_inject_lock);
}

/* ======================================================================
 * Part 11: Core Logic - Privileged Check / Allowlist
 * ====================================================================== */

static inline bool hymo_is_privileged_process(void)
{
	pid_t pid = task_tgid_vnr(current);

	if (unlikely(uid_eq(current_uid(), GLOBAL_ROOT_UID)))
		return true;
	if (hymo_daemon_pid > 0 && pid == hymo_daemon_pid)
		return true;
	return false;
}

static bool hymo_uid_in_allowlist(uid_t uid)
{
	void *p;

	rcu_read_lock();
	p = xa_load(&hymo_allow_uids_xa, uid);
	rcu_read_unlock();
	return p != NULL;
}

static bool hymo_should_apply_hide_rules(void)
{
	if (!hymo_allowlist_loaded)
		return true;
	if (xa_empty(&hymo_allow_uids_xa))
		return true;
	return !hymo_uid_in_allowlist(__kuid_val(current_uid()));
}

/* Simplified KSU allowlist reload */
static bool hymo_should_umount_profile(const struct hymo_app_profile *p)
{
	if (p->allow_su)
		return false;
	if (p->nrp_config.use_default)
		return true;
	return p->nrp_config.profile.umount_modules;
}

static void hymo_add_allow_uid(uid_t uid)
{
	spin_lock(&hymo_allow_uids_lock);
	xa_store(&hymo_allow_uids_xa, uid, HYMO_UID_ALLOW_MARKER, GFP_KERNEL);
	spin_unlock(&hymo_allow_uids_lock);
}

static bool hymo_reload_ksu_allowlist(void)
{
	struct file *fp;
	loff_t off = 0;
	u32 magic = 0, version = 0;
	ssize_t ret;
	struct hymo_app_profile profile;
	int count = 0;

	if (!mutex_trylock(&hymo_allowlist_lock))
		return false;

	fp = filp_open(HYMO_KSU_ALLOWLIST_PATH, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		spin_lock(&hymo_allow_uids_lock);
		xa_destroy(&hymo_allow_uids_xa);
		hymo_allowlist_loaded = false;
		spin_unlock(&hymo_allow_uids_lock);
		mutex_unlock(&hymo_allowlist_lock);
		return false;
	}

	ret = kernel_read(fp, &magic, sizeof(magic), &off);
	if (ret != sizeof(magic) || magic != HYMO_KSU_ALLOWLIST_MAGIC)
		goto bad;
	ret = kernel_read(fp, &version, sizeof(version), &off);
	if (ret != sizeof(version))
		goto bad;

	spin_lock(&hymo_allow_uids_lock);
	xa_destroy(&hymo_allow_uids_xa);
	hymo_allowlist_loaded = true;
	spin_unlock(&hymo_allow_uids_lock);

	while (kernel_read(fp, &profile, sizeof(profile), &off) == sizeof(profile)) {
		if (!hymo_should_umount_profile(&profile) && profile.current_uid > 0) {
			hymo_add_allow_uid((uid_t)profile.current_uid);
			if (++count >= HYMO_ALLOWLIST_UID_MAX)
				break;
		}
	}

	filp_close(fp, NULL);
	mutex_unlock(&hymo_allowlist_lock);
	return true;

bad:
	filp_close(fp, NULL);
	spin_lock(&hymo_allow_uids_lock);
	xa_destroy(&hymo_allow_uids_xa);
	hymo_allowlist_loaded = false;
	spin_unlock(&hymo_allow_uids_lock);
	mutex_unlock(&hymo_allowlist_lock);
	return false;
}

/* ======================================================================
 * Part 12: Forward Redirect (resolve_target)
 * ====================================================================== */

static char * __maybe_unused hymofs_resolve_target(const char *pathname)
{
	struct hymo_entry *entry;
	struct hymo_merge_entry *me;
	u32 hash;
	char *target = NULL;
	size_t path_len;
	pid_t pid;

	if (unlikely(!hymofs_enabled || !pathname))
		return NULL;

	pid = task_tgid_vnr(current);
	if (hymo_daemon_pid > 0 && pid == hymo_daemon_pid)
		return NULL;

	path_len = strlen(pathname);
	hash = full_name_hash(NULL, pathname, path_len);

	rcu_read_lock();

	/* Bloom filter fast-path for exact match rules */
	if (atomic_read(&hymo_rule_count) != 0) {
		unsigned long bh1 = jhash(pathname, (u32)path_len, 0) & (HYMO_BLOOM_SIZE - 1);
		unsigned long bh2 = jhash(pathname, (u32)path_len, 1) & (HYMO_BLOOM_SIZE - 1);

		if (test_bit(bh1, hymo_path_bloom) && test_bit(bh2, hymo_path_bloom)) {
			hlist_for_each_entry_rcu(entry,
				&hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
				if (entry->src_hash == hash &&
				    strcmp(entry->src, pathname) == 0) {
					target = kstrdup(entry->target, GFP_ATOMIC);
					rcu_read_unlock();
					return target;
				}
			}
		}
	}

	/* Longest-prefix merge match via trie */
	me = hymo_merge_trie_lookup_longest(pathname);
	if (me) {
		size_t src_len = strlen(me->src);
		const char *suffix = pathname + src_len;

		if (suffix[0] != '\0' &&
		    strcmp(suffix, "/.") != 0 &&
		    strcmp(suffix, "/..") != 0) {
			size_t target_len = strlen(me->target);
			size_t suffix_len = path_len - src_len;

			target = kmalloc(target_len + suffix_len + 1, GFP_ATOMIC);
			if (target) {
				memcpy(target, me->target, target_len);
				memcpy(target + target_len, suffix, suffix_len);
				target[target_len + suffix_len] = '\0';
			}
		}
	}

	rcu_read_unlock();

	/* Validate merge target exists */
	if (target) {
		struct path p;
		if (kern_path(target, LOOKUP_FOLLOW, &p) == 0) {
			path_put(&p);
		} else {
			kfree(target);
			target = NULL;
		}
	}

	return target;
}

/* ======================================================================
 * Part 13: Reverse Lookup
 * ====================================================================== */

static int __maybe_unused hymofs_reverse_lookup(const char *pathname, char *buf, size_t buflen)
{
	struct hymo_entry *entry;
	struct hymo_merge_entry *me;
	u32 hash;
	int bkt, ret = -1;

	if (unlikely(!hymofs_enabled || !pathname || !buf))
		return -1;

	hash = full_name_hash(NULL, pathname, strlen(pathname));

	rcu_read_lock();

	/* Check 1-to-1 mappings */
	hlist_for_each_entry_rcu(entry,
		&hymo_targets[hash_min(hash, HYMO_HASH_BITS)], target_node) {
		if (strcmp(entry->target, pathname) == 0) {
			ret = strscpy(buf, entry->src, buflen);
			if (ret < 0)
				ret = -ENAMETOOLONG;
			else
				ret = strlen(buf);
			goto out;
		}
	}

	/* Check merge directory mappings */
	hash_for_each_rcu(hymo_merge_dirs, bkt, me, node) {
		size_t target_len = strlen(me->target);

		if (strncmp(pathname, me->target, target_len) == 0 &&
		    (pathname[target_len] == '/' || pathname[target_len] == '\0')) {
			size_t src_len = strlen(me->src);
			size_t suffix_len = strlen(pathname) - target_len;

			if (src_len + suffix_len + 1 > buflen) {
				ret = -ENAMETOOLONG;
			} else {
				memcpy(buf, me->src, src_len);
				memcpy(buf + src_len, pathname + target_len, suffix_len);
				buf[src_len + suffix_len] = '\0';
				ret = src_len + suffix_len;
			}
			goto out;
		}
	}

out:
	rcu_read_unlock();
	return ret;
}

/* ======================================================================
 * Part 14: Hide Logic
 * ====================================================================== */

static bool __maybe_unused hymofs_should_hide(const char *pathname)
{
	struct hymo_hide_entry *he;
	u32 hash;
	size_t len;

	if (unlikely(!hymofs_enabled || !pathname || !*pathname))
		return false;
	if (unlikely(hymo_is_privileged_process()))
		return false;

	len = strlen(pathname);

	/* Stealth: always hide the mirror device */
	if (likely(hymo_stealth_enabled)) {
		size_t name_len = strlen(hymo_current_mirror_name);
		size_t path_len = strlen(hymo_current_mirror_path);

		if ((len == name_len && strcmp(pathname, hymo_current_mirror_name) == 0) ||
		    (len == path_len && strcmp(pathname, hymo_current_mirror_path) == 0))
			return true;
	}

	if (!hymo_should_apply_hide_rules())
		return false;

	/* Bloom fast-path */
	if (atomic_read(&hymo_hide_count) == 0)
		return false;

	{
		unsigned long bh1 = jhash(pathname, (u32)len, 0) & (HYMO_BLOOM_SIZE - 1);
		unsigned long bh2 = jhash(pathname, (u32)len, 1) & (HYMO_BLOOM_SIZE - 1);

		if (!test_bit(bh1, hymo_hide_bloom) || !test_bit(bh2, hymo_hide_bloom))
			return false;
	}

	hash = full_name_hash(NULL, pathname, len);
	rcu_read_lock();
	hlist_for_each_entry_rcu(he,
		&hymo_hide_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (he->path_hash == hash && strcmp(he->path, pathname) == 0) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

static bool __maybe_unused hymofs_should_spoof_mtime(const char *pathname)
{
	struct hymo_inject_entry *ie;
	u32 hash;
	bool found = false;
	pid_t pid;

	if (unlikely(!hymofs_enabled || !pathname))
		return false;

	pid = task_tgid_vnr(current);
	if (hymo_daemon_pid > 0 && pid == hymo_daemon_pid)
		return false;

	hash = full_name_hash(NULL, pathname, strlen(pathname));
	rcu_read_lock();
	hlist_for_each_entry_rcu(ie,
		&hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (strcmp(ie->dir, pathname) == 0) {
			found = true;
			break;
		}
	}
	rcu_read_unlock();
	return found;
}

static bool __maybe_unused hymofs_should_replace(const char *pathname)
{
	struct hymo_entry *entry;
	u32 hash;
	size_t path_len;
	pid_t pid;

	if (unlikely(!hymofs_enabled || !pathname))
		return false;

	pid = task_tgid_vnr(current);
	if (hymo_daemon_pid > 0 && pid == hymo_daemon_pid)
		return false;
	if (atomic_read(&hymo_rule_count) == 0)
		return false;

	path_len = strlen(pathname);
	{
		unsigned long bh1 = jhash(pathname, (u32)path_len, 0) & (HYMO_BLOOM_SIZE - 1);
		unsigned long bh2 = jhash(pathname, (u32)path_len, 1) & (HYMO_BLOOM_SIZE - 1);

		if (!test_bit(bh1, hymo_path_bloom) || !test_bit(bh2, hymo_path_bloom))
			return false;
	}

	hash = full_name_hash(NULL, pathname, path_len);
	rcu_read_lock();
	hlist_for_each_entry_rcu(entry,
		&hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (entry->src_hash == hash && strcmp(entry->src, pathname) == 0) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

/* ======================================================================
 * Part 15: Dispatch Handler (all HYMO_CMD_* commands)
 * ====================================================================== */

static int hymo_dispatch_cmd(unsigned int cmd, void __user *arg)
{
	struct hymo_syscall_arg req;
	struct hymo_entry *entry;
	struct hymo_hide_entry *hide_entry;
	struct hymo_inject_entry *inject_entry;
	char *src = NULL, *target = NULL;
	u32 hash;
	bool found = false;
	int ret = 0;

	if (cmd == HYMO_CMD_CLEAR_ALL) {
		spin_lock(&hymo_cfg_lock);
		spin_lock(&hymo_rules_lock);
		spin_lock(&hymo_hide_lock);
		spin_lock(&hymo_allow_uids_lock);
		spin_lock(&hymo_xattr_sbs_lock);
		spin_lock(&hymo_merge_lock);
		spin_lock(&hymo_inject_lock);
		hymo_cleanup_locked();
		strscpy(hymo_mirror_path_buf, HYMO_DEFAULT_MIRROR_PATH, PATH_MAX);
		strscpy(hymo_mirror_name_buf, HYMO_DEFAULT_MIRROR_NAME, NAME_MAX);
		hymo_current_mirror_path = hymo_mirror_path_buf;
		hymo_current_mirror_name = hymo_mirror_name_buf;
		spin_unlock(&hymo_inject_lock);
		spin_unlock(&hymo_merge_lock);
		spin_unlock(&hymo_xattr_sbs_lock);
		spin_unlock(&hymo_allow_uids_lock);
		spin_unlock(&hymo_hide_lock);
		spin_unlock(&hymo_rules_lock);
		spin_unlock(&hymo_cfg_lock);
		rcu_barrier();
		return 0;
	}

	if (cmd == HYMO_CMD_GET_VERSION)
		return HYMO_PROTOCOL_VERSION;

	if (cmd == HYMO_CMD_SET_DEBUG) {
		int val;
		if (copy_from_user(&val, arg, sizeof(val)))
			return -EFAULT;
		hymo_debug_enabled = !!val;
		return 0;
	}

	if (cmd == HYMO_CMD_SET_STEALTH) {
		int val;
		if (copy_from_user(&val, arg, sizeof(val)))
			return -EFAULT;
		hymo_stealth_enabled = !!val;
		return 0;
	}

	if (cmd == HYMO_CMD_SET_ENABLED) {
		int val;
		if (copy_from_user(&val, arg, sizeof(val)))
			return -EFAULT;
		spin_lock(&hymo_cfg_lock);
		hymofs_enabled = !!val;
		spin_unlock(&hymo_cfg_lock);
		if (hymofs_enabled)
			hymo_reload_ksu_allowlist();
		return 0;
	}

	if (cmd == HYMO_CMD_REORDER_MNT_ID) {
		/* Mount operations not supported in LKM (needs internal mount.h) */
		return -EOPNOTSUPP;
	}

	if (cmd == HYMO_CMD_LIST_RULES) {
		struct hymo_syscall_list_arg list_arg;
		struct hymo_xattr_sb_entry *sb_entry;
		struct hymo_merge_entry *merge_entry;
		char *kbuf;
		size_t buf_size, written = 0;
		int bkt;

		if (copy_from_user(&list_arg, arg, sizeof(list_arg)))
			return -EFAULT;

		buf_size = list_arg.size;
		if (buf_size > 16 * 1024)
			buf_size = 16 * 1024;

		kbuf = kzalloc(buf_size, GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;

		rcu_read_lock();
		written += scnprintf(kbuf + written, buf_size - written,
				     "HymoFS Protocol: %d\n", HYMO_PROTOCOL_VERSION);
		written += scnprintf(kbuf + written, buf_size - written,
				     "HymoFS Enabled: %d\n", hymofs_enabled ? 1 : 0);
		hash_for_each_rcu(hymo_paths, bkt, entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "add %s %s %d\n", entry->src,
					     entry->target, entry->type);
		}
		hash_for_each_rcu(hymo_hide_paths, bkt, hide_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "hide %s\n", hide_entry->path);
		}
		hash_for_each_rcu(hymo_inject_dirs, bkt, inject_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "inject %s\n", inject_entry->dir);
		}
		hash_for_each_rcu(hymo_merge_dirs, bkt, merge_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "merge %s %s\n", merge_entry->src,
					     merge_entry->target);
		}
		hash_for_each_rcu(hymo_xattr_sbs, bkt, sb_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "hide_xattr_sb %p\n", sb_entry->sb);
		}
		rcu_read_unlock();

		if (copy_to_user(list_arg.buf, kbuf, written)) {
			kfree(kbuf);
			return -EFAULT;
		}
		list_arg.size = written;
		if (copy_to_user(arg, &list_arg, sizeof(list_arg))) {
			kfree(kbuf);
			return -EFAULT;
		}
		kfree(kbuf);
		return 0;
	}

	if (cmd == HYMO_CMD_SET_MIRROR_PATH) {
		char *new_path, *new_name, *slash;
		size_t len;

		if (copy_from_user(&req, arg, sizeof(req)))
			return -EFAULT;
		if (!req.src)
			return -EINVAL;
		new_path = strndup_user(req.src, PATH_MAX);
		if (IS_ERR(new_path))
			return PTR_ERR(new_path);

		len = strlen(new_path);
		if (len > 1 && new_path[len - 1] == '/')
			new_path[len - 1] = '\0';

		slash = strrchr(new_path, '/');
		new_name = kstrdup(slash ? slash + 1 : new_path, GFP_KERNEL);
		if (!new_name) {
			kfree(new_path);
			return -ENOMEM;
		}

		spin_lock(&hymo_cfg_lock);
		strscpy(hymo_mirror_path_buf, new_path, PATH_MAX);
		strscpy(hymo_mirror_name_buf, new_name, NAME_MAX);
		hymo_current_mirror_path = hymo_mirror_path_buf;
		hymo_current_mirror_name = hymo_mirror_name_buf;
		spin_unlock(&hymo_cfg_lock);

		kfree(new_path);
		kfree(new_name);
		return 0;
	}

	if (cmd == HYMO_CMD_SET_UNAME)
		return -EOPNOTSUPP; /* TODO: uname spoofing */

	/* Commands that use hymo_syscall_arg */
	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;

	if (req.src) {
		src = strndup_user(req.src, PAGE_SIZE);
		if (IS_ERR(src))
			return PTR_ERR(src);
	}
	if (req.target) {
		target = strndup_user(req.target, PAGE_SIZE);
		if (IS_ERR(target)) {
			kfree(src);
			return PTR_ERR(target);
		}
	}

	switch (cmd) {
	case HYMO_CMD_ADD_MERGE_RULE: {
		struct hymo_merge_entry *me;

		if (!src || !target) { ret = -EINVAL; break; }

		hash = full_name_hash(NULL, src, strlen(src));
		spin_lock(&hymo_merge_lock);
		spin_lock(&hymo_inject_lock);

		hlist_for_each_entry(me,
			&hymo_merge_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
			if (strcmp(me->src, src) == 0 &&
			    strcmp(me->target, target) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			me = kmalloc(sizeof(*me), GFP_ATOMIC);
			if (me) {
				me->src = src;
				me->target = target;
				hlist_add_head_rcu(&me->node,
					&hymo_merge_dirs[hash_min(hash, HYMO_HASH_BITS)]);
				src = NULL;
				target = NULL;
				hymo_merge_trie_build_locked();
			} else {
				ret = -ENOMEM;
			}
		} else {
			ret = -EEXIST;
		}
		spin_unlock(&hymo_inject_lock);
		spin_unlock(&hymo_merge_lock);
		if (!found && !ret)
			hymofs_add_inject_rule(kstrdup(me->src, GFP_ATOMIC));
		spin_lock(&hymo_cfg_lock);
		hymofs_enabled = true;
		spin_unlock(&hymo_cfg_lock);
		break;
	}

	case HYMO_CMD_ADD_RULE: {
		char *parent_dir = NULL;
		char *resolved_src = NULL;
		struct path path;
		struct inode *src_inode = NULL;
		struct inode *parent_inode = NULL;
		char *tmp_buf;

		if (!src || !target) { ret = -EINVAL; break; }

		tmp_buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!tmp_buf) { ret = -ENOMEM; break; }

		/* Try to resolve full path */
		if (kern_path(src, LOOKUP_FOLLOW, &path) == 0) {
			char *res = d_path(&path, tmp_buf, PATH_MAX);
			if (!IS_ERR(res)) {
				resolved_src = kstrdup(res, GFP_KERNEL);
				{
					char *ls = strrchr(res, '/');
					if (ls) {
						if (ls == res)
							parent_dir = kstrdup("/", GFP_KERNEL);
						else {
							size_t l = ls - res;
							parent_dir = kmalloc(l + 1, GFP_KERNEL);
							if (parent_dir) {
								memcpy(parent_dir, res, l);
								parent_dir[l] = '\0';
							}
						}
					}
				}
			}
			if (d_inode(path.dentry)) {
				src_inode = d_inode(path.dentry);
				ihold(src_inode);
			}
			if (path.dentry->d_parent && d_inode(path.dentry->d_parent)) {
				parent_inode = d_inode(path.dentry->d_parent);
				ihold(parent_inode);
			}
			path_put(&path);
		} else {
			char *ls = strrchr(src, '/');
			if (ls && ls != src) {
				size_t l = ls - src;
				char *p_str = kmalloc(l + 1, GFP_KERNEL);
				if (p_str) {
					memcpy(p_str, src, l);
					p_str[l] = '\0';
					if (kern_path(p_str, LOOKUP_FOLLOW, &path) == 0) {
						char *res = d_path(&path, tmp_buf, PATH_MAX);
						if (!IS_ERR(res)) {
							size_t rl = strlen(res);
							size_t nl = strlen(ls);
							resolved_src = kmalloc(rl + nl + 1, GFP_KERNEL);
							if (resolved_src) {
								strcpy(resolved_src, res);
								strcat(resolved_src, ls);
							}
							parent_dir = kstrdup(res, GFP_KERNEL);
						}
						path_put(&path);
					}
					kfree(p_str);
				}
			}
		}
		kfree(tmp_buf);

		if (resolved_src) {
			kfree(src);
			src = resolved_src;
		}

		hash = full_name_hash(NULL, src, strlen(src));
		spin_lock(&hymo_rules_lock);

		hlist_for_each_entry(entry,
			&hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
			if (entry->src_hash == hash && strcmp(entry->src, src) == 0) {
				char *old_t = entry->target;
				char *new_t = kstrdup(target, GFP_ATOMIC);
				if (new_t) {
					hlist_del_rcu(&entry->target_node);
					rcu_assign_pointer(entry->target, new_t);
					entry->type = req.type;
					hlist_add_head_rcu(&entry->target_node,
						&hymo_targets[hash_min(
							full_name_hash(NULL, new_t, strlen(new_t)),
							HYMO_HASH_BITS)]);
					kfree(old_t);
				}
				found = true;
				break;
			}
		}
		if (!found) {
			entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
			if (entry) {
				entry->src = kstrdup(src, GFP_ATOMIC);
				entry->target = kstrdup(target, GFP_ATOMIC);
				entry->type = req.type;
				entry->src_hash = hash;
				if (entry->src && entry->target) {
					unsigned long h1, h2;
					hlist_add_head_rcu(&entry->node,
						&hymo_paths[hash_min(hash, HYMO_HASH_BITS)]);
					hlist_add_head_rcu(&entry->target_node,
						&hymo_targets[hash_min(
							full_name_hash(NULL, entry->target,
								strlen(entry->target)),
							HYMO_HASH_BITS)]);
					h1 = jhash(src, strlen(src), 0) & (HYMO_BLOOM_SIZE - 1);
					h2 = jhash(src, strlen(src), 1) & (HYMO_BLOOM_SIZE - 1);
					set_bit(h1, hymo_path_bloom);
					set_bit(h2, hymo_path_bloom);
					atomic_inc(&hymo_rule_count);
				} else {
					kfree(entry->src);
					kfree(entry->target);
					kfree(entry);
				}
			}
		}
		spin_unlock(&hymo_rules_lock);

		if (parent_dir)
			hymofs_add_inject_rule(parent_dir);
		if (src_inode) {
			hymofs_mark_inode_hidden(src_inode);
			iput(src_inode);
		}
		if (parent_inode) {
			if (parent_inode->i_mapping)
				set_bit(AS_FLAGS_HYMO_DIR_HAS_HIDDEN,
					&parent_inode->i_mapping->flags);
			iput(parent_inode);
		}

		spin_lock(&hymo_cfg_lock);
		hymofs_enabled = true;
		spin_unlock(&hymo_cfg_lock);
		break;
	}

	case HYMO_CMD_HIDE_RULE: {
		char *resolved_src = NULL;
		struct path path;
		struct inode *target_inode = NULL;
		struct inode *parent_inode = NULL;
		char *tmp_buf;

		if (!src) { ret = -EINVAL; break; }

		tmp_buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!tmp_buf) { ret = -ENOMEM; break; }

		if (kern_path(src, LOOKUP_FOLLOW, &path) == 0) {
			char *res = d_path(&path, tmp_buf, PATH_MAX);
			if (!IS_ERR(res))
				resolved_src = kstrdup(res, GFP_KERNEL);
			if (d_inode(path.dentry)) {
				target_inode = d_inode(path.dentry);
				ihold(target_inode);
			}
			if (path.dentry->d_parent && d_inode(path.dentry->d_parent)) {
				parent_inode = d_inode(path.dentry->d_parent);
				ihold(parent_inode);
			}
			path_put(&path);
		}
		kfree(tmp_buf);

		if (resolved_src) {
			kfree(src);
			src = resolved_src;
		}

		if (target_inode) {
			hymofs_mark_inode_hidden(target_inode);
			iput(target_inode);
		}
		if (parent_inode) {
			if (parent_inode->i_mapping)
				set_bit(AS_FLAGS_HYMO_DIR_HAS_HIDDEN,
					&parent_inode->i_mapping->flags);
			iput(parent_inode);
		}

		hash = full_name_hash(NULL, src, strlen(src));
		spin_lock(&hymo_hide_lock);
		hlist_for_each_entry(hide_entry,
			&hymo_hide_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
			if (hide_entry->path_hash == hash &&
			    strcmp(hide_entry->path, src) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			hide_entry = kmalloc(sizeof(*hide_entry), GFP_ATOMIC);
			if (hide_entry) {
				hide_entry->path = kstrdup(src, GFP_ATOMIC);
				hide_entry->path_hash = hash;
				if (hide_entry->path) {
					unsigned long h1 = jhash(src, strlen(src), 0) & (HYMO_BLOOM_SIZE - 1);
					unsigned long h2 = jhash(src, strlen(src), 1) & (HYMO_BLOOM_SIZE - 1);
					set_bit(h1, hymo_hide_bloom);
					set_bit(h2, hymo_hide_bloom);
					atomic_inc(&hymo_hide_count);
					hlist_add_head_rcu(&hide_entry->node,
						&hymo_hide_paths[hash_min(hash, HYMO_HASH_BITS)]);
				} else {
					kfree(hide_entry);
				}
			}
		}
		spin_unlock(&hymo_hide_lock);

		spin_lock(&hymo_cfg_lock);
		hymofs_enabled = true;
		spin_unlock(&hymo_cfg_lock);
		break;
	}

	case HYMO_CMD_HIDE_OVERLAY_XATTRS: {
		struct path path;
		struct hymo_xattr_sb_entry *sb_entry;
		bool xfound = false;

		if (!src) { ret = -EINVAL; break; }

		if (kern_path(src, LOOKUP_FOLLOW, &path) == 0) {
			struct super_block *sb = path.dentry->d_sb;

			spin_lock(&hymo_xattr_sbs_lock);
			hlist_for_each_entry(sb_entry,
				&hymo_xattr_sbs[hash_min((unsigned long)sb, HYMO_HASH_BITS)], node) {
				if (sb_entry->sb == sb) {
					xfound = true;
					break;
				}
			}
			if (!xfound) {
				sb_entry = kmalloc(sizeof(*sb_entry), GFP_ATOMIC);
				if (sb_entry) {
					sb_entry->sb = sb;
					hlist_add_head_rcu(&sb_entry->node,
						&hymo_xattr_sbs[hash_min((unsigned long)sb,
							HYMO_HASH_BITS)]);
				}
			}
			spin_unlock(&hymo_xattr_sbs_lock);
			spin_lock(&hymo_cfg_lock);
			hymofs_enabled = true;
			spin_unlock(&hymo_cfg_lock);
			path_put(&path);
		} else {
			ret = -ENOENT;
		}
		break;
	}

	case HYMO_CMD_DEL_RULE:
		if (!src) { ret = -EINVAL; break; }
		hash = full_name_hash(NULL, src, strlen(src));
		spin_lock(&hymo_rules_lock);
		spin_lock(&hymo_hide_lock);
		spin_lock(&hymo_inject_lock);

		hlist_for_each_entry(entry,
			&hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
			if (entry->src_hash == hash && strcmp(entry->src, src) == 0) {
				hlist_del_rcu(&entry->node);
				hlist_del_rcu(&entry->target_node);
				atomic_dec(&hymo_rule_count);
				call_rcu(&entry->rcu, hymo_entry_free_rcu);
				goto del_done;
			}
		}
		hlist_for_each_entry(hide_entry,
			&hymo_hide_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
			if (hide_entry->path_hash == hash &&
			    strcmp(hide_entry->path, src) == 0) {
				hlist_del_rcu(&hide_entry->node);
				atomic_dec(&hymo_hide_count);
				call_rcu(&hide_entry->rcu, hymo_hide_entry_free_rcu);
				goto del_done;
			}
		}
		hlist_for_each_entry(inject_entry,
			&hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
			if (strcmp(inject_entry->dir, src) == 0) {
				hlist_del_rcu(&inject_entry->node);
				atomic_dec(&hymo_rule_count);
				call_rcu(&inject_entry->rcu, hymo_inject_entry_free_rcu);
				goto del_done;
			}
		}
del_done:
		spin_unlock(&hymo_inject_lock);
		spin_unlock(&hymo_hide_lock);
		spin_unlock(&hymo_rules_lock);
		break;

	default:
		ret = -EINVAL;
		break;
	}

	kfree(src);
	kfree(target);
	return ret;
}

/* ======================================================================
 * Part 16: Ioctl Handler
 * ====================================================================== */

static long hymofs_dev_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	if (cmd == HYMO_IOC_GET_VERSION) {
		int ver = HYMO_PROTOCOL_VERSION;
		if (copy_to_user((void __user *)arg, &ver, sizeof(ver)))
			return -EFAULT;
		return 0;
	}

	if (cmd == HYMO_IOC_SET_ENABLED) {
		int enabled;
		if (copy_from_user(&enabled, (void __user *)arg, sizeof(enabled)))
			return -EFAULT;
		spin_lock(&hymo_cfg_lock);
		hymofs_enabled = !!enabled;
		spin_unlock(&hymo_cfg_lock);
		if (hymofs_enabled)
			hymo_reload_ksu_allowlist();
		return 0;
	}

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
	default:
		return -EINVAL;
	}
}

/* ======================================================================
 * Part 17: Miscdevice
 * ====================================================================== */

static int hymofs_dev_open(struct inode *inode, struct file *file)
{
	pid_t pid;

	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return -EPERM;

	pid = task_tgid_vnr(current);
	spin_lock(&hymo_daemon_lock);
	hymo_daemon_pid = pid;
	spin_unlock(&hymo_daemon_lock);
	hymo_log("daemon registered: pid=%d\n", pid);
	return 0;
}

static const struct file_operations hymofs_dev_fops = {
	.owner          = THIS_MODULE,
	.open           = hymofs_dev_open,
	.unlocked_ioctl = hymofs_dev_ioctl,
	.compat_ioctl   = hymofs_dev_ioctl,
	.llseek         = noop_llseek,
};

static struct miscdevice hymofs_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "hymofs",
	.fops  = &hymofs_dev_fops,
	.mode  = 0600,
};

/* ======================================================================
 * Part 18: Hook Wrappers - Original Function Pointers
 * ====================================================================== */

#ifdef CONFIG_FUNCTION_TRACER
static struct filename *(*orig_getname_flags)(const char __user *, int, int *);
static int (*orig_vfs_getattr)(const struct path *, struct kstat *, u32, unsigned int);
static char *(*orig_d_path)(const struct path *, char *, int);
static int (*orig_iterate_dir)(struct file *, struct dir_context *);

/* ======================================================================
 * Part 19: Hook - getname_flags (Forward Path Redirection)
 * ====================================================================== */

static struct filename *hook_getname_flags(const char __user *filename,
					   int flags, int *empty)
{
	struct filename *result;
	char *target;
	bool is_absolute;

	result = orig_getname_flags(filename, flags, empty);

	/* The thunk already checked hymofs_enabled and rule counts,
	 * but keep a safety check for IS_ERR and early exits. */
	if (IS_ERR(result))
		return result;

	/* Aligned with original hymofs.c hymofs_handle_getname:
	 * bail out when all hash tables are empty. */
	if (likely(hash_empty(hymo_paths) &&
		   hash_empty(hymo_hide_paths) &&
		   hash_empty(hymo_merge_dirs)))
		return result;

	is_absolute = (result->name[0] == '/');

	/* Check hide rules (bloom filter fast-path inside) */
	if (unlikely(hymofs_should_hide(result->name))) {
		putname(result);
		return ERR_PTR(-ENOENT);
	}

	/* Try forward redirect (only absolute paths) */
	if (likely(is_absolute)) {
		target = hymofs_resolve_target(result->name);
		if (unlikely(target)) {
			putname(result);
			result = getname_kernel(target);
			kfree(target);
		}
	}
	return result;
}

/* ======================================================================
 * Part 20: Hook - vfs_getattr (Stat Spoofing)
 * ====================================================================== */

/*
 * Fast path check: skip common system paths that never have HymoFS rules.
 * Uses dentry name for O(1) prefix check - no path allocation needed.
 */
static inline bool hymofs_needs_stat_check(const struct path *path)
{
	const char *name;

	if (!path || !path->dentry)
		return false;

	name = path->dentry->d_name.name;

	/* Skip /dev, /proc, /sys - never have hymofs rules */
	if (name[0] == 'd' && !strncmp(name, "dev", 3))
		return false;
	if (name[0] == 'p' && !strncmp(name, "proc", 4))
		return false;
	if (name[0] == 's' && !strncmp(name, "sys", 3))
		return false;

	return true;
}

static int hook_vfs_getattr(const struct path *path, struct kstat *stat,
			    u32 request_mask, unsigned int query_flags)
{
	int ret;
	struct inode *inode;

	ret = orig_vfs_getattr(path, stat, request_mask, query_flags);

	/* Fast bailout: error or stealth not needed */
	if (likely(ret != 0 || !hymo_stealth_enabled))
		return ret;
	if (!hymofs_needs_stat_check(path))
		return ret;

	/* Root/daemon: no spoofing needed */
	if (unlikely(uid_eq(current_uid(), GLOBAL_ROOT_UID)))
		return ret;
	if (hymo_daemon_pid > 0 &&
	    task_tgid_vnr(current) == hymo_daemon_pid)
		return ret;

	/* O(1) inode-bit checks. No path allocation. */
	if (!path->dentry)
		return ret;
	inode = d_inode(path->dentry);
	if (!inode || !inode->i_mapping)
		return ret;

	if (test_bit(AS_FLAGS_HYMO_HIDE, &inode->i_mapping->flags))
		stat->ino ^= 0x48594D4F;

	if (S_ISDIR(inode->i_mode) &&
	    test_bit(AS_FLAGS_HYMO_DIR_HAS_HIDDEN, &inode->i_mapping->flags)) {
		ktime_get_real_ts64(&stat->mtime);
		stat->ctime = stat->mtime;
	}

	return ret;
}

/* ======================================================================
 * Part 21: Hook - d_path (Reverse Lookup)
 * ====================================================================== */

static char *hook_d_path(const struct path *path, char *buf, int bufsize)
{
	char *res = orig_d_path(path, buf, bufsize);

	/* Thunk already checked enabled + rule counts.
	 * Keep IS_ERR check and hash_empty as secondary fast path. */
	if (IS_ERR(res))
		return res;

	/* Root/daemon: show real paths */
	if (unlikely(uid_eq(current_uid(), GLOBAL_ROOT_UID)))
		return res;
	if (hymo_daemon_pid > 0 &&
	    task_tgid_vnr(current) == hymo_daemon_pid)
		return res;

	/* Only allocate if we actually have targets/merge rules */
	if (likely(hash_empty(hymo_targets) && hash_empty(hymo_merge_dirs)))
		return res;

	{
		char *temp = kmalloc(bufsize, GFP_KERNEL);
		if (temp) {
			int len = hymofs_reverse_lookup(res, temp, bufsize);
			if (len > 0 && len < bufsize) {
				memcpy(buf, temp, len + 1);
				res = buf;
			}
			kfree(temp);
		}
	}
	return res;
}

/* ======================================================================
 * Part 22: Hook - iterate_dir (Directory Entry Hiding)
 * ====================================================================== */

static HYMO_FILLDIR_RET_TYPE
hymofs_filldir_filter(struct dir_context *ctx, const char *name,
		      int namlen, loff_t offset, u64 ino, unsigned int d_type)
{
	struct hymofs_filldir_wrapper *w =
		container_of(ctx, struct hymofs_filldir_wrapper, wrap_ctx);

	/* Skip . and .. immediately - most common entries */
	if (unlikely(namlen <= 2 && name[0] == '.')) {
		if (namlen == 1 || (namlen == 2 && name[1] == '.'))
			goto passthrough;
	}

	/* Stealth: hide mirror device in /dev (cheap string compare) */
	if (hymo_stealth_enabled && w->dir_path_len == 4) {
		size_t mlen = strlen(hymo_current_mirror_name);
		if ((unsigned int)namlen == mlen &&
		    memcmp(name, hymo_current_mirror_name, namlen) == 0)
			return HYMO_FILLDIR_CONTINUE;
	}

	/*
	 * Hide check using dcache lookup (from original hymofs.c):
	 * O(1) d_hash_and_lookup on parent dentry -> check inode bit.
	 * NO string allocation, NO path building, NO hash table walk.
	 */
	if (w->dir_has_hidden && w->parent_dentry) {
		struct dentry *child;

		child = d_hash_and_lookup(w->parent_dentry,
				&(struct qstr)QSTR_INIT(name, namlen));
		if (child) {
			struct inode *cinode = d_inode(child);
			if (cinode && cinode->i_mapping &&
			    test_bit(AS_FLAGS_HYMO_HIDE,
				     &cinode->i_mapping->flags)) {
				dput(child);
				return HYMO_FILLDIR_CONTINUE;
			}
			dput(child);
		}
	}

passthrough:
	return w->orig_ctx->actor(w->orig_ctx, name, namlen, offset, ino, d_type);
}

static int hook_iterate_dir(struct file *file, struct dir_context *ctx)
{
	struct hymofs_filldir_wrapper wrapper;
	struct inode *dir_inode;
	bool need_filter = false;
	bool is_dev_dir = false;
	int ret;

	/* These checks mirror the thunk, but are kept as safety net
	 * in case the hook is entered through an indirect path. */
	if (likely(!READ_ONCE(hymofs_enabled)))
		return orig_iterate_dir(file, ctx);

	/* Root/daemon: no filtering */
	if (unlikely(uid_eq(current_uid(), GLOBAL_ROOT_UID)))
		return orig_iterate_dir(file, ctx);
	if (hymo_daemon_pid > 0 &&
	    task_tgid_vnr(current) == hymo_daemon_pid)
		return orig_iterate_dir(file, ctx);

	/* Check inode bit: does this directory have hidden entries? */
	wrapper.dir_has_hidden = false;
	wrapper.parent_dentry = NULL;
	wrapper.dir_path = NULL;
	wrapper.dir_path_len = 0;

	if (file && file->f_path.dentry) {
		dir_inode = d_inode(file->f_path.dentry);
		if (dir_inode && dir_inode->i_mapping)
			wrapper.dir_has_hidden = test_bit(
				AS_FLAGS_HYMO_DIR_HAS_HIDDEN,
				&dir_inode->i_mapping->flags);
		wrapper.parent_dentry = file->f_path.dentry;
	}

	/* Determine if we actually need filtering.
	 * Aligned with original hymofs.c __hymofs_check_filldir:
	 *   - dir_has_hidden: need to filter hidden entries (inode bit check)
	 *   - /dev stealth: only for /dev directory, hide mirror device
	 * Do NOT wrap ALL directories when stealth is enabled! */
	if (wrapper.dir_has_hidden)
		need_filter = true;

	if (!need_filter && hymo_stealth_enabled && wrapper.parent_dentry) {
		const char *dname = wrapper.parent_dentry->d_name.name;
		if (dname[0] == 'd' && dname[1] == 'e' && dname[2] == 'v' &&
		    dname[3] == '\0') {
			is_dev_dir = true;
			need_filter = true;
		}
	}

	/* Fast path: nothing to filter -> run original directly */
	if (likely(!need_filter))
		return orig_iterate_dir(file, ctx);

	if (is_dev_dir)
		wrapper.dir_path_len = 4;

	wrapper.wrap_ctx.actor = hymofs_filldir_filter;
	wrapper.wrap_ctx.pos = ctx->pos;
	wrapper.orig_ctx = ctx;

	ret = orig_iterate_dir(file, &wrapper.wrap_ctx);
	ctx->pos = wrapper.wrap_ctx.pos;

	return ret;
}

/* ======================================================================
 * Part 23: Hook Table
 * ====================================================================== */

static struct hymofs_ftrace_hook hymofs_hooks[] = {
	HYMOFS_HOOK("getname_flags", hook_getname_flags, orig_getname_flags),
	HYMOFS_HOOK("vfs_getattr",   hook_vfs_getattr,   orig_vfs_getattr),
	HYMOFS_HOOK("d_path",        hook_d_path,        orig_d_path),
	HYMOFS_HOOK("iterate_dir",   hook_iterate_dir,   orig_iterate_dir),
};
#define HYMOFS_HOOK_COUNT ARRAY_SIZE(hymofs_hooks)
#endif /* CONFIG_FUNCTION_TRACER */

/* ======================================================================
 * Part 24: Module Init / Exit
 * ====================================================================== */

static int __init hymofs_lkm_init(void)
{
	int ret;

	pr_info("hymofs: initializing LKM v%s\n", "0.1.0");

	/* Initialize hash tables */
	hash_init(hymo_paths);
	hash_init(hymo_targets);
	hash_init(hymo_hide_paths);
	hash_init(hymo_inject_dirs);
	hash_init(hymo_xattr_sbs);
	hash_init(hymo_merge_dirs);

	/* Register miscdevice */
	ret = misc_register(&hymofs_miscdev);
	if (ret) {
		pr_err("hymofs: misc_register failed: %d\n", ret);
		return ret;
	}
	pr_info("hymofs: /dev/hymofs registered\n");

	/* Install ftrace hooks */
#ifdef CONFIG_FUNCTION_TRACER
	ret = hymofs_install_hooks(hymofs_hooks, HYMOFS_HOOK_COUNT);
	if (ret) {
		pr_err("hymofs: hook installation failed: %d\n", ret);
		misc_deregister(&hymofs_miscdev);
		return ret;
	}
	pr_info("hymofs: initialized (%zu hooks active)\n", HYMOFS_HOOK_COUNT);
#else
	pr_warn("hymofs: CONFIG_FUNCTION_TRACER not set, hooks disabled\n");
#endif
	return 0;
}

static void __exit hymofs_lkm_exit(void)
{
	pr_info("hymofs: shutting down\n");

	/* Remove hooks first to stop interception */
#ifdef CONFIG_FUNCTION_TRACER
	hymofs_remove_hooks(hymofs_hooks, HYMOFS_HOOK_COUNT);
#endif

	/* Deregister miscdevice */
	misc_deregister(&hymofs_miscdev);

	/* Clean up all rules and wait for RCU grace period */
	spin_lock(&hymo_cfg_lock);
	spin_lock(&hymo_rules_lock);
	spin_lock(&hymo_hide_lock);
	spin_lock(&hymo_allow_uids_lock);
	spin_lock(&hymo_xattr_sbs_lock);
	spin_lock(&hymo_merge_lock);
	spin_lock(&hymo_inject_lock);
	hymo_cleanup_locked();
	spin_unlock(&hymo_inject_lock);
	spin_unlock(&hymo_merge_lock);
	spin_unlock(&hymo_xattr_sbs_lock);
	spin_unlock(&hymo_allow_uids_lock);
	spin_unlock(&hymo_hide_lock);
	spin_unlock(&hymo_rules_lock);
	spin_unlock(&hymo_cfg_lock);

	rcu_barrier();
	pr_info("hymofs: unloaded\n");
}

module_init(hymofs_lkm_init);
module_exit(hymofs_lkm_exit);
