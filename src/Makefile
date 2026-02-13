#
# Out-of-tree build for HymoFS LKM.
# From kernel source root:
#   make ARCH=arm64 LLVM=1 M=/path/to/HymoFS/src modules
#

obj-m += hymofs_lkm.o

# Override -gz=zstd when host compiler does not support it.
ccflags-y += -gz=none
