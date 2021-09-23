

obj-m	+= uoa.o

CFLAGS_uoa.o := -DDEBUG

ifeq ($(KERNDIR), )
KDIR	:= /lib/modules/$(shell uname -r)/build
else
KDIR	:= $(KERNDIR)
endif
PWD	:= $(shell pwd)


.PHONY: insmod rmmod 
# default: insmod 

build: uoa.ko
uoa.ko: uoa.c uoa.h uoa_opp.h
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) modules clean


insmod: rmmod uoa.ko
	sudo insmod uoa.ko v6_to_v4_enable=1 v6_to_v4_prefix_str=fdbd:dc00::

rmmod:
	-sudo rmmod uoa
