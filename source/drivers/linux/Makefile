KERNEL_SRC_DIR = /lib/modules/`uname -r`/build ##/usr/src/android/3.0-mid
EXTRA_CFLAGS = 
VERSION=

obj-m += chipsec$(VERSION).o
chipsec$(VERSION)-objs := chipsec_km.o 

all:	clean chipsec$(VERSION)

chipsec$(VERSION) : clean
	make -C $(KERNEL_SRC_DIR) SUBDIRS=`pwd` modules
	cd ../../tool/chipsec/helper/linux; make

install:
	./run.sh

uninstall:
	rmmod chipsec

clean : 
	rm -f *.o *.ko *.mod.c Module.symvers Module.markers modules.order \.*.o.cmd \.*.ko.cmd \.*.o.d
	rm -rf \.tmp_versions
	cd ../../tool/chipsec/helper/linux; make clean

