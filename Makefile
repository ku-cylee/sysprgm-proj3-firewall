obj-m := firewall.o

KDIR = /lib/modules/$(shell uname -r)/build
PWD = $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) SUBDIRS=$(PWD) modules

load:
	sudo insmod firewall.ko

unload:
	sudo rmmod firewall

clean:
	rm -rf *.o *.ko *.mod.* *.symvers *.order .*.*.cmd .tmp_versions
