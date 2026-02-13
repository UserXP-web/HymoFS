#
# Out-of-tree build for HymoFS LKM.
# From kernel source root:
#   make ARCH=arm64 LLVM=1 M=/path/to/HymoFS/src modules
#
# From this directory (src):
#   make clean   - remove build artifacts
#

obj-m += hymofs_lkm.o

# Override -gz=zstd when host compiler does not support it.
ccflags-y += -gz=none

clean:
	rm -f hymofs_lkm.ko hymofs_lkm.o hymofs_lkm.mod hymofs_lkm.mod.c hymofs_lkm.mod.o
	rm -f .hymofs_lkm.ko.cmd .hymofs_lkm.o.cmd .hymofs_lkm.mod.cmd .hymofs_lkm.mod.o.cmd
	rm -rf .tmp_versions
	rm -f Module.symvers modules.order
.PHONY: clean
