obj-m:=myfirewall.o

KDIR:=/lib/modules/$(shell uname -r)/build
PWD:=$(shell pwd)

export NOSTDINC_FLAGS
NOSTDINC_FLAGS += -I$(pwd)$(realpath ../)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) modules clean
