HymoFS KPM module

This module ports the HymoFS kernel patch to a KernelPatch KPM module
for Android GKI 6.6.x. It keeps the original anonymous-fd ioctl control
interface and injects behavior via inline hooks.

Build:
  make KP_DIR=../KernelPatch KERNEL_SRC=/path/to/kernel
  # KERNEL_SRC auto-detects ../patch_workspace/android15-6.6/common when present

Load:
  Use APatch manager to load the generated .kpm file.
