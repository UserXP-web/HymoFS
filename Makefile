# Root Makefile for ddk build. ddk mounts workspace as /build and sets KDIR.
MDIR := $(CURDIR)/src

all:
	$(MAKE) -C $(KDIR) ARCH=arm64 M=$(MDIR) modules

clean:
	$(MAKE) -C $(KDIR) ARCH=arm64 M=$(MDIR) clean

.PHONY: all clean
