obj-m:=test_netfilter.o

# 下面的这个路径要改成自己的 Linux 内核地址
KDIR:=/lib/modules/$(shell uname -r)/build
PWD:=$(shell pwd)
CFLAGS:=-std=gnu99 -Wall -pedantic

all:
	@$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) modules clean
