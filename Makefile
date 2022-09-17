MODULE := myfirewall

MODPATH := kmodule
USRPATH := user

.PHONY = load, unload, clean

all:
	$(MAKE) -C $(MODPATH) && $(MAKE) -C $(USRPATH)
clean:
	$(MAKE) -C $(MODPATH) clean && $(MAKE) -C $(USRPATH) clean
load:
	sudo insmod kmodule/$(MODULE).ko
unload:
	sudo rmmod $(MODULE)
