obj-m += ./src/netfilter.o
KERNEL_DIR = /lib/modules/$(shell uname -r)/build
SRC_DIR = ./src

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(shell pwd) SRCDIR=$(SRC_DIR) modules

clean:
	rm  -rf *.o *.ko    *.mod.* *.symvers   *.order
