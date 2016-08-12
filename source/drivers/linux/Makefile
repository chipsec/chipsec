KERNEL_SRC_DIR = /lib/modules/`uname -r`/build 
##KERNEL_SRC_DIR = /usr/src/android/3.0-mid

EXTRA_CFLAGS = 
VERSION=

#obj-m += chipsec.o

ifeq ($(ARCH),i386)
obj-m += chipsec.o
chipsec-objs := chipsec_km.o i386/cpu.o
all:	clean chipsec32
else
obj-m += chipsec.o
chipsec-objs := chipsec_km.o amd64/cpu.o
all:	clean chipsec64
endif

chipsec64: clean
	nasm -f elf64 -o amd64/cpu.o amd64/cpu.asm;
	make -C $(KERNEL_SRC_DIR) SUBDIRS=`pwd` modules
	make -C ../../tool/chipsec/helper/linux

chipsec32: clean
	nasm -f elf32 -o i386/cpu.o i386/cpu.asm;
	make -C $(KERNEL_SRC_DIR) SUBDIRS=`pwd` modules
	make -C ../../tool/chipsec/helper/linux

install:
	./run.sh

uninstall:
	rmmod chipsec

clean:
	rm -f *.o *.ko *.mod.c Module.symvers Module.markers modules.order \.*.o.cmd \.*.ko.cmd \.*.o.d
	rm -rf \.tmp_versions
	rm -rf amd64/cpu.o i386/cpu.o

