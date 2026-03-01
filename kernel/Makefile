# SPDX-License-Identifier: GPL-2.0
#
# CryptoFS - Out-of-tree kernel module Makefile
#
# Usage:
#   make                  - build against running kernel
#   make KDIR=/path/to/kernel  - build against specific kernel
#   make clean            - remove build artifacts
#   make install          - install module to /lib/modules/...
#   make check            - run sparse static analysis
#

obj-m := cryptofs.o

cryptofs-objs := main.o super.o dentry.o lookup.o file.o inode.o \
                 crypto.o mmap.o policy.o netlink.o audit.o

# Kernel source / build directory
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# Compiler flags
ccflags-y := -Wall -Werror -DDEBUG

# Default target
all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f Module.symvers modules.order

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

# Static analysis with sparse
check:
	$(MAKE) -C $(KDIR) M=$(PWD) C=2 CF="-D__CHECK_ENDIAN__" modules

# Load module (convenience)
load: modules
	insmod cryptofs.ko

unload:
	rmmod cryptofs

reload: unload load

.PHONY: all modules clean install check load unload reload
