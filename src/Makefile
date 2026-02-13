#
# Out-of-tree build for HymoFS LKM.
# From kernel source root (e.g. patch_workspace/lkm/common):
#   make ARCH=arm64 M=/path/to/HymoFS/src modules
#

obj-m += hymofs_lkm.o
# When linking hymofs.o: ccflags-y += -DCONFIG_HYMOFS -I$(srctree)/fs

# Override -gz=zstd when host compiler does not support it.
ccflags-y += -gz=none
