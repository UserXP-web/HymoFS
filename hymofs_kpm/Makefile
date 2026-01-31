MYKPM_VERSION := v0.0.8

ifndef KP_DIR
    KP_DIR = ../KernelPatch
endif

ifeq ($(wildcard $(CURDIR)/../patch_workspace/android15-6.6/common/Makefile),$(CURDIR)/../patch_workspace/android15-6.6/common/Makefile)
    KERNEL_SRC ?= $(CURDIR)/../patch_workspace/android15-6.6/common
endif

OS_NAME = $(shell uname | tr A-Z a-z)
MACHINE = $(shell uname -m)
HOST_TAG = $(OS_NAME)-$(MACHINE)
ifeq ($(HOST_TAG), darwin-arm64)
    HOST_TAG = darwin-x86_64
endif
NDK_BIN_DIR := toolchains/llvm/prebuilt/$(HOST_TAG)/bin
ifdef ANDROID_NDK_LATEST_HOME
    NDK_PATH ?= $(ANDROID_NDK_LATEST_HOME)/$(NDK_BIN_DIR)
else ifdef ANDROID_NDK
    NDK_PATH ?= $(ANDROID_NDK)/$(NDK_BIN_DIR)
endif

ifdef TARGET_COMPILE
    CC := $(TARGET_COMPILE)gcc
    LD := $(TARGET_COMPILE)ld
    OBJCOPY := $(TARGET_COMPILE)objcopy
else ifdef NDK_PATH
    CC := $(NDK_PATH)/aarch64-linux-android31-clang
    LD := $(NDK_PATH)/ld.lld
    OBJCOPY := $(NDK_PATH)/llvm-objcopy
endif

OBJCOPY ?= objcopy
LD ?= ld.lld
STRIP_SECTIONS = \
	--remove-section=.eh_frame \
	--remove-section=.rela.eh_frame \
	--remove-section=.altinstructions \
	--remove-section=.rela.altinstructions

HYMOFS_SAFE_DEFAULT ?= 0
HYMOFS_INIT_ONLY ?= 0
HYMOFS_SKIP_HOOKS ?= 0
# Default to minimal core hooks; enable more via ctl0 for debugging
HYMOFS_HOOK_STAGE ?= 1
HYMOFS_DISABLE_DIRENTS ?= 0
HYMOFS_DISABLE_DPATH ?= 0
HYMOFS_DISABLE_GETNAME ?= 0
HYMOFS_DISABLE_GETATTR ?= 0
HYMOFS_DISABLE_FILENAME_LOOKUP ?= 0
HYMOFS_DISABLE_REBOOT_HOOK ?= 0

CFLAGS = -Wall -O2 -fno-builtin -fno-builtin-memset -fno-builtin-memcpy -fno-builtin-memmove -fno-builtin-memcmp -fno-builtin-strlen -fno-builtin-strcmp -fno-builtin-strncmp -fno-builtin-strchr -fno-builtin-strrchr -fno-builtin-strnlen -fno-PIC -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common -DMYKPM_VERSION=\"$(MYKPM_VERSION)\" -D__KERNEL__ -DCONFIG_64BIT -DCONFIG_ARM64 -DHYMOFS_SAFE_DEFAULT=$(HYMOFS_SAFE_DEFAULT) -DHYMOFS_INIT_ONLY=$(HYMOFS_INIT_ONLY) -DHYMOFS_SKIP_HOOKS=$(HYMOFS_SKIP_HOOKS) -DHYMOFS_HOOK_STAGE=$(HYMOFS_HOOK_STAGE) -DHYMOFS_DISABLE_DIRENTS=$(HYMOFS_DISABLE_DIRENTS) -DHYMOFS_DISABLE_DPATH=$(HYMOFS_DISABLE_DPATH) -DHYMOFS_DISABLE_GETNAME=$(HYMOFS_DISABLE_GETNAME) -DHYMOFS_DISABLE_GETATTR=$(HYMOFS_DISABLE_GETATTR) -DHYMOFS_DISABLE_FILENAME_LOOKUP=$(HYMOFS_DISABLE_FILENAME_LOOKUP)
CFLAGS += -DHYMOFS_DISABLE_REBOOT_HOOK=$(HYMOFS_DISABLE_REBOOT_HOOK)

# Kernel headers may trigger warnings under clang; keep output clean.
CFLAGS += -Wno-macro-redefined -Wno-pointer-sign -Wno-gnu-variable-sized-type-not-at-end

ifdef KERNEL_SRC
KP_INCLUDE_DIRS := . include patch/include
else
KP_INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
endif

INCLUDE_FLAGS := $(foreach dir,$(KP_INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))
INCLUDE_FLAGS += -I$(CURDIR)/compat_kp

IS_CLANG := $(findstring clang,$(notdir $(CC)))
ifdef KERNEL_SRC
INCLUDE_FLAGS += -I$(KERNEL_SRC)/include -I$(KERNEL_SRC)/include/uapi -I$(KERNEL_SRC)/arch/arm64/include -I$(KERNEL_SRC)/arch/arm64/include/uapi -I$(KERNEL_SRC)/arch/arm64/include/generated -I$(KERNEL_SRC)/tools/arch/arm64/include -I$(KERNEL_SRC)/fs
ifneq ($(IS_CLANG),)
CFLAGS += -target aarch64-linux-android
endif
INCLUDE_FLAGS += -I$(CURDIR)/compat
CFLAGS += -include $(KERNEL_SRC)/include/linux/kconfig.h
endif

ASFLAGS := $(filter-out -include,$(CFLAGS))
ifdef KERNEL_SRC
ASFLAGS := $(filter-out $(KERNEL_SRC)/include/linux/kconfig.h,$(ASFLAGS))
endif

objs := hymofs.o kpm_plt.o

OUT_DIR ?= $(abspath $(CURDIR)/..)
FLAVOR ?=
OUT_KPM = $(OUT_DIR)/hymofs_$(MYKPM_VERSION)$(if $(FLAVOR),_$(FLAVOR),).kpm
OUT_KPM_DEBUG = $(OUT_DIR)/hymofs_$(MYKPM_VERSION)$(if $(FLAVOR),_$(FLAVOR),)_debug.kpm

.PHONY: all build debug build_debug
all: build
build: $(OUT_KPM)

debug: build_debug
build_debug: CFLAGS += -DCONFIG_DEBUG
build_debug: HYMO_VER := _d
build_debug: $(OUT_KPM_DEBUG)

#
# Convenience build targets for bisecting "stage1 freeze"
# Usage examples:
#   make s1_nodirents
#   make s1_nogetname
#   make s1_nodpath
#   make s1_nogetattr
#
.PHONY: s1 s1_nodirents s1_nogetname s1_nodpath s1_nogetattr
s1:
	$(MAKE) FLAVOR=s1 HYMOFS_HOOK_STAGE=1 build

s1_nodirents:
	$(MAKE) FLAVOR=s1_nodirents HYMOFS_HOOK_STAGE=1 HYMOFS_DISABLE_DIRENTS=1 build

s1_nogetname:
	$(MAKE) FLAVOR=s1_nogetname HYMOFS_HOOK_STAGE=1 HYMOFS_DISABLE_GETNAME=1 build

s1_nodpath:
	$(MAKE) FLAVOR=s1_nodpath HYMOFS_HOOK_STAGE=1 HYMOFS_DISABLE_DPATH=1 build

s1_nogetattr:
	$(MAKE) FLAVOR=s1_nogetattr HYMOFS_HOOK_STAGE=1 HYMOFS_DISABLE_GETATTR=1 build

# Short aliases (keep legacy targets above intact)
.PHONY: s1nd s1ng s1np s1na
s1nd: s1_nodirents
s1ng: s1_nogetname
s1np: s1_nodpath
s1na: s1_nogetattr

# Stage2: avoid hooking getname (too hot for KPM), use filename_lookup instead
.PHONY: s2_nodirents_nogetname s2_nodirents_nogetname_nodpath s2_nodirents_nogetname_nogetattr s2_nodirents_nogetname_nodpath_nogetattr s2_nodirents_nogetname_nofilename
s2_nodirents_nogetname:
	$(MAKE) FLAVOR=s2_nodirents_nogetname HYMOFS_HOOK_STAGE=2 HYMOFS_DISABLE_GETNAME=1 HYMOFS_DISABLE_DIRENTS=1 build

# Stage2 bisect variants (for "卡一屏但没 pstore" watchdog resets)
s2_nodirents_nogetname_nodpath:
	$(MAKE) FLAVOR=s2_nodirents_nogetname_nodpath HYMOFS_HOOK_STAGE=2 HYMOFS_DISABLE_GETNAME=1 HYMOFS_DISABLE_DIRENTS=1 HYMOFS_DISABLE_DPATH=1 build

s2_nodirents_nogetname_nogetattr:
	$(MAKE) FLAVOR=s2_nodirents_nogetname_nogetattr HYMOFS_HOOK_STAGE=2 HYMOFS_DISABLE_GETNAME=1 HYMOFS_DISABLE_DIRENTS=1 HYMOFS_DISABLE_GETATTR=1 build

s2_nodirents_nogetname_nodpath_nogetattr:
	$(MAKE) FLAVOR=s2_nodirents_nogetname_nodpath_nogetattr HYMOFS_HOOK_STAGE=2 HYMOFS_DISABLE_GETNAME=1 HYMOFS_DISABLE_DIRENTS=1 HYMOFS_DISABLE_DPATH=1 HYMOFS_DISABLE_GETATTR=1 build

s2_nodirents_nogetname_nofilename:
	$(MAKE) FLAVOR=s2_nodirents_nogetname_nofilename HYMOFS_HOOK_STAGE=2 HYMOFS_DISABLE_GETNAME=1 HYMOFS_DISABLE_DIRENTS=1 HYMOFS_DISABLE_FILENAME_LOOKUP=1 build

# Stage2 quick targets (shorter names)
.PHONY: s2nd s2ndng s2ndngnp s2ndngna s2ndngnpna s2ndngnf
# s2 + nodirents (getname enabled; useful to re-test with guards)
s2nd:
	$(MAKE) FLAVOR=s2nd HYMOFS_HOOK_STAGE=2 HYMOFS_DISABLE_DIRENTS=1 build
# s2 + nodirents + nogetname (recommended default)
s2ndng: s2_nodirents_nogetname
s2ndngnp: s2_nodirents_nogetname_nodpath
s2ndngna: s2_nodirents_nogetname_nogetattr
s2ndngnpna: s2_nodirents_nogetname_nodpath_nogetattr
s2ndngnf: s2_nodirents_nogetname_nofilename

# Stage2 extra bisect targets:
# - s2ng: keep dirents enabled but disable getname (to isolate dirents)
.PHONY: s2ng
s2ng:
	$(MAKE) FLAVOR=s2ng HYMOFS_HOOK_STAGE=2 HYMOFS_DISABLE_GETNAME=1 HYMOFS_DISABLE_DIRENTS=0 build

# Higher stages (more stealth hooks)
.PHONY: s3 s4 s5 s3ndng s4ndng s5ndng s5ndngdp
s3:
	$(MAKE) FLAVOR=s3 HYMOFS_HOOK_STAGE=3 build
s4:
	$(MAKE) FLAVOR=s4 HYMOFS_HOOK_STAGE=4 build
s5:
	$(MAKE) FLAVOR=s5 HYMOFS_HOOK_STAGE=5 build

# Safer higher-stage presets (keep stage but disable the hottest hooks)
s3ndng:
	$(MAKE) FLAVOR=s3ndng HYMOFS_HOOK_STAGE=3 HYMOFS_DISABLE_DIRENTS=1 HYMOFS_DISABLE_GETNAME=1 build
s4ndng:
	$(MAKE) FLAVOR=s4ndng HYMOFS_HOOK_STAGE=4 HYMOFS_DISABLE_DIRENTS=1 HYMOFS_DISABLE_GETNAME=1 build
s5ndng:
	$(MAKE) FLAVOR=s5ndng HYMOFS_HOOK_STAGE=5 HYMOFS_DISABLE_DIRENTS=1 HYMOFS_DISABLE_GETNAME=1 HYMOFS_DISABLE_DPATH=1 build

# Stage5 variant with d_path enabled (may cause heavy stalls / watchdog on some devices)
s5ndngdp:
	$(MAKE) FLAVOR=s5ndngdp HYMOFS_HOOK_STAGE=5 HYMOFS_DISABLE_DIRENTS=1 HYMOFS_DISABLE_GETNAME=1 HYMOFS_DISABLE_DPATH=0 build

# Emergency recovery builds (to avoid bootloop)
.PHONY: s0 s0_noreboot
s0:
	$(MAKE) FLAVOR=s0 HYMOFS_HOOK_STAGE=0 build

s0_noreboot:
	$(MAKE) FLAVOR=s0_noreboot HYMOFS_HOOK_STAGE=0 HYMOFS_DISABLE_REBOOT_HOOK=1 build

$(OUT_KPM): ${objs}
	@mkdir -p "$(OUT_DIR)"
	${LD} -r -o "$@" $^
	${OBJCOPY} $(STRIP_SECTIONS) "$@"

$(OUT_KPM_DEBUG): ${objs}
	@mkdir -p "$(OUT_DIR)"
	${LD} -r -o "$@" $^
	${OBJCOPY} $(STRIP_SECTIONS) "$@"

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

%.o: %.S
	${CC} $(ASFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f "$(OUT_KPM)" "$(OUT_KPM_DEBUG)"
	# Keep clean deterministic and portable (avoid find|xargs quirks).
	rm -f ./*.o

.PHONY: cleanall
cleanall:
	rm -f "$(OUT_DIR)"/hymofs_*.kpm "$(OUT_DIR)"/hymofs_*.kpm.sig "$(OUT_DIR)"/hymofs_*.kpm.asc
	rm -f ./*.o
