MACHINE ?= $(shell uname -m)

DESTDIR	=
MODDIR	= $(DESTDIR)/lib/modules
KVERS	= $(shell uname -r)
KVER	= $(KVERS)
VMODDIR = $(MODDIR)/$(KVER)
KSRC	= $(VMODDIR)/build

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
	@if [ ! -d $(KSRC) ]; then \
	    echo "Unable to find the Linux source tree."; \
	    exit 1; \
	fi

chipsec: check_kernel_dir clean 
	nasm -f $(elf-size) -o $(asm-path)/cpu.o $(asm-path)/cpu.asm
	touch $(asm-path)/.cpu.o.cmd
	@if [ `grep -c 'efi_call' /proc/kallsyms` != "0" ]; then \
	    make CFLAGS_MODULE=-DHAS_EFI=1 -C $(KSRC) M=$(CURDIR) modules; \
	else \
	    make -C $(KSRC) M=$(CURDIR) modules; \
	fi

clean: check_kernel_dir
	make -C $(KSRC) M=$(CURDIR) clean
	rm -f ${asm-path}/cpu.o
