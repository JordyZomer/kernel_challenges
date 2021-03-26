# SPDX-License-Identifier: GPL-2.0
obj-m += shell.o

KERNELVER	?= $(shell uname -r)
KERNELDIR	?= /lib/modules/$(KERNELVER)/build
PWD		:= $(shell pwd)

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
