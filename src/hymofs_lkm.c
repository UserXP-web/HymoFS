// SPDX-License-Identifier: GPL-2.0
/*
 * HymoFS LKM skeleton (ftrace-based).
 *
 * Thin wrapper: sets up an ftrace hook framework to intercept kernel
 * functions (getattr, d_path, xattr, etc.) and delegate to hymofs.c.
 * This skeleton only logs on hook hit; real logic will call hymofs_* helpers.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/errno.h>
#include <linux/ptrace.h>
#ifdef CONFIG_FUNCTION_TRACER
#include <linux/ftrace.h>
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HymoFS");
MODULE_DESCRIPTION("HymoFS ftrace-based LKM skeleton");
MODULE_VERSION("0.0.1");

/* Test hook target; replace with vfs_statx / d_path etc. when wiring real logic. */
static const char * const hymofs_test_target = "vfs_getattr";
static unsigned long __maybe_unused hymofs_test_ip;

#ifdef CONFIG_FUNCTION_TRACER
/* Ftrace callback: log only; later parse pt_regs and call hymofs_* helpers. */
static void notrace hymofs_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
					struct ftrace_ops *op, struct ftrace_regs *fregs)
{
#if defined(CONFIG_ARM64)
	struct pt_regs *regs;

	if (unlikely(ip != hymofs_test_ip))
		return;

	regs = ftrace_get_regs(fregs);
	if (!regs)
		return;

	pr_debug("hymofs_lkm: ftrace hit %s @0x%lx from 0x%lx\n",
		 hymofs_test_target, ip, parent_ip);
	(void)regs;
#endif
}

static struct ftrace_ops hymofs_ftrace_ops = {
	.func  = hymofs_ftrace_thunk,
	.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION,
};
#endif /* CONFIG_FUNCTION_TRACER */

static int __init hymofs_lkm_init(void)
{
	pr_info("hymofs_lkm: init (ftrace skeleton)\n");

#ifdef CONFIG_FUNCTION_TRACER
	{
		int ret;

		hymofs_test_ip = kallsyms_lookup_name(hymofs_test_target);
		if (!hymofs_test_ip) {
			pr_err("hymofs_lkm: failed to resolve %s\n", hymofs_test_target);
			return -ENOENT;
		}

		ret = ftrace_set_filter_ip(&hymofs_ftrace_ops, hymofs_test_ip, 0, 0);
		if (ret) {
			pr_err("hymofs_lkm: ftrace_set_filter_ip failed: %d\n", ret);
			return ret;
		}

		ret = register_ftrace_function(&hymofs_ftrace_ops);
		if (ret) {
			pr_err("hymofs_lkm: register_ftrace_function failed: %d\n", ret);
			ftrace_set_filter_ip(&hymofs_ftrace_ops, hymofs_test_ip, 1, 0);
			return ret;
		}

		pr_info("hymofs_lkm: ftrace hook on %s @0x%lx\n",
			hymofs_test_target, hymofs_test_ip);
	}
#else
	pr_info("hymofs_lkm: CONFIG_FUNCTION_TRACER not set, hook disabled\n");
#endif
	return 0;
}

static void __exit hymofs_lkm_exit(void)
{
#ifdef CONFIG_FUNCTION_TRACER
	{
		int ret;

		ret = unregister_ftrace_function(&hymofs_ftrace_ops);
		if (ret)
			pr_warn("hymofs_lkm: unregister_ftrace_function failed: %d\n", ret);

		if (hymofs_test_ip) {
			ftrace_set_filter_ip(&hymofs_ftrace_ops, hymofs_test_ip, 1, 0);
		}
	}
#endif
	pr_info("hymofs_lkm: exit\n");
}

module_init(hymofs_lkm_init);
module_exit(hymofs_lkm_exit);

