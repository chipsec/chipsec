KERNEL_SRC_DIR = /lib/modules/`uname -r`/build 
##KERNEL_SRC_DIR = /usr/src/android/3.0-mid

EXTRA_CFLAGS = 
VERSION=

obj-m += chipsec$(VERSION).o

ifeq ($(shell uname -m),x86_64)
	chipsec$(VERSION)-objs := chipsec_km.o amd64/cpu.o
else
	chipsec$(VERSION)-objs := chipsec_km.o i386/cpu.o
	#chipsec$(VERSION)-objs := chipsec_km.o 
endif

all:	clean chipsec$(VERSION)

ifeq ($(shell uname -m),x86_64)
chipsec$(VERSION) : clean
	nasm -f elf64 -o amd64/cpu.o amd64/cpu.asm;
	make -C $(KERNEL_SRC_DIR) SUBDIRS=`pwd` modules
	cd ../../tool/chipsec/helper/linux; make
else
chipsec$(VERSION) : clean
	nasm -f elf32 -o i386/cpu.o i386/cpu.asm;
	make -C $(KERNEL_SRC_DIR) SUBDIRS=`pwd` modules
	cd ../../tool/chipsec/helper/linux; make
endif

install:
	./run.sh

uninstall:
	rmmod chipsec

clean : 
	rm -f *.o *.ko *.mod.c Module.symvers Module.markers modules.order \.*.o.cmd \.*.ko.cmd \.*.o.d
	rm -rf \.tmp_versions
	rm -rf amd64/cpu.o i386/cpu.o
	cd ../../tool/chipsec/helper/linux; make clean

