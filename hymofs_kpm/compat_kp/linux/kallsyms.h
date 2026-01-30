#ifndef _LINUX_KALLSYMS_H
#define _LINUX_KALLSYMS_H

#include <kallsyms.h>

/* Keep minimal compat for kernel headers that expect this helper. */
#ifndef dereference_symbol_descriptor
static inline void *dereference_symbol_descriptor(void *ptr) { return ptr; }
#endif // #ifndef dereference_symbol_descriptor

#endif // #ifndef _LINUX_KALLSYMS_H
