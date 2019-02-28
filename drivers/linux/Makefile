KERNEL_SRC_DIR ?= /lib/modules/`uname -r`/build
#KERNEL_SRC_DIR = /usr/src/android/3.0-mid

MACHINE ?= $(shell uname -m)

ifeq (,$(filter %i686 %i386 %i586,$(MACHINE)))
	elf-size := elf64
	asm-path := amd64
else
	elf-size := elf32
	asm-path := i386
endif

chipsec-objs := chipsec_km.o $(asm-path)/cpu.o
obj-m += chipsec.o

all: chipsec

check_kernel_dir:
	@if [ ! -d $(KERNEL_SRC_DIR) ]; then \
		echo "Unable to find the Linux source tree."; \
		exit 1; \
	fi

chipsec: check_kernel_dir clean
	nasm -f $(elf-size) -o $(asm-path)/cpu.o $(asm-path)/cpu.asm
	@if [ `grep -c 'D efi' /proc/kallsyms` != "0" ]; then \
	    make CFLAGS_MODULE=-DHAS_EFI=1 -C $(KERNEL_SRC_DIR) M=${CURDIR} modules; \
	else \
	    make -C $(KERNEL_SRC_DIR) M=${CURDIR} modules; \
	fi

clean: check_kernel_dir
	make -C $(KERNEL_SRC_DIR) M=${CURDIR} clean
	rm -f ${asm-path}/cpu.o

