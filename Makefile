obj-m:=test_netfilter.o

MODPATH := kmodule
USRPATH := user

all:
	$(MAKE) -C $(MODPATH) && $(MAKE) -C $(USRPATH)
clean:
	$(MAKE) -C $(MODPATH) clean && $(MAKE) -C $(USRPATH) clean
load:
	sudo insmod test_netfilter.ko
unload:
	sudo rmmod test_netfilter
