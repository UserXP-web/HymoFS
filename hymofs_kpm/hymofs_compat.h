#ifndef _HYMOFS_COMPAT_H
#define _HYMOFS_COMPAT_H

/* Fallbacks for Android kernel headers outside build system. */
#ifndef __no_sanitize_or_inline
#define __no_sanitize_or_inline __attribute__((__always_inline__)) inline
#endif // #ifndef __no_sanitize_or_inline

/*
 * Newer kernels define __no_kasan_or_inline themselves; keep our fallback only
 * when it isn't already present, to avoid -Wmacro-redefined noise.
 */
#ifndef __no_kasan_or_inline
#define __no_kasan_or_inline __attribute__((__always_inline__)) inline
#endif // #ifndef __no_kasan_or_inline

#endif // #ifndef _HYMOFS_COMPAT_H
