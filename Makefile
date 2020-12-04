obj-m += src/firewall.o
KERNEL_DIR = /lib/modules/$(shell uname -r)/build
PWD = $(shell pwd)
SRC_DIR = ./src

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) SRCDIR=$(SRC_DIR) modules

clean:
	rm -rf *.o *.ko *.mod.* *.symvers *.order
