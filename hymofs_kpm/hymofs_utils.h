/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _HYMOFS_UTILS_H
#define _HYMOFS_UTILS_H

#include <hook.h>
#include <ksyms.h>
#include <linux/printk.h>
#include <log.h>

#undef pr_info
#undef pr_warn
#undef pr_err
#undef pr_debug
#define pr_info(fmt, ...) logki(fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...) logkw(fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...) logke(fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...) logkd(fmt, ##__VA_ARGS__)

#define lookup_name(func)                                                      \
  func = (typeof(func))kallsyms_lookup_name(#func);                            \
  pr_info("kernel function %s addr: %px\n", #func, func);                      \
  if (!func)                                                                   \
    return -21;

#define lookup_name_continue(func)                                             \
  func = (typeof(func))kallsyms_lookup_name(#func);                            \
  pr_info("kernel function %s addr: %px\n", #func, func);

#define lookup_name_sym(func, sym)                                             \
  func = (typeof(func))kallsyms_lookup_name(sym);                              \
  pr_info("kernel function %s addr: %px\n", sym, func);                        \
  if (!func)                                                                   \
    return -21;

#define lookup_name_continue_sym(func, sym)                                    \
  func = (typeof(func))kallsyms_lookup_name(sym);                              \
  pr_info("kernel function %s addr: %px\n", sym, func);

#define lookup_name_try_sym(func, sym)                                         \
  func = (typeof(func))kallsyms_lookup_name(sym);                              \
  pr_info("kernel function %s addr: %px\n", sym, func);                        \
  if (!func)                                                                   \
    pr_warn("kernel function %s not found\n", sym);

#define hook_func(func, argv, before, after, udata)                            \
  if (!func)                                                                   \
    return -22;                                                                \
  hook_err_t hook_err_##func = hook_wrap(func, argv, before, after, udata);    \
  if (hook_err_##func) {                                                       \
    pr_err("hook %s error: %d\n", #func, hook_err_##func);                     \
    return -23;                                                                \
  } else {                                                                     \
    pr_info("hook %s success\n", #func);                                       \
  }

#define hook_func_try(func, argv, before, after, udata)                        \
  if (!func) {                                                                 \
    pr_warn("hook %s skipped (missing symbol)\n", #func);                      \
  } else {                                                                     \
    hook_err_t hook_err_##func = hook_wrap(func, argv, before, after, udata);  \
    if (hook_err_##func) {                                                     \
      pr_err("hook %s error: %d\n", #func, hook_err_##func);                   \
    } else {                                                                   \
      pr_info("hook %s success\n", #func);                                     \
    }                                                                          \
  }

#define unhook_func(func)                                                      \
  if (func && !is_bad_address(func))                                           \
    unhook(func);

#endif // #ifndef _HYMOFS_UTILS_H
