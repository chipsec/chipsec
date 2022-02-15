DESTDIR	=
MODDIR	= $(DESTDIR)/lib/modules
KVERS	= $(shell uname -r)
KVER	= $(KVERS)
VMODDIR = $(MODDIR)/$(KVER)
KSRC	?= $(VMODDIR)/build

obj-m += chipsec.o
chipsec-objs-y := chipsec_km.o
chipsec-objs-$(CONFIG_X86_32) += i386/cpu.o
chipsec-objs-$(CONFIG_X86_64) += amd64/cpu.o
chipsec-objs := $(chipsec-objs-y)

quiet_cmd_nasm32 = NASM_32 $@
      cmd_nasm32 = nasm -f elf32 -o $@ $<

quiet_cmd_nasm64 = NASM_64 $@
      cmd_nasm64 = nasm -f elf64 -o $@ $<


all: chipsec

check_kernel_dir:
	@if [ ! -d $(KSRC) ]; then \
	    echo "Unable to find the Linux source tree."; \
	    exit 1; \
	fi

chipsec: check_kernel_dir clean
	make -C $(KSRC) M=$(CURDIR) modules

clean: check_kernel_dir
	make -C $(KSRC) M=$(CURDIR) clean

$(obj)/i386/cpu.o: $(src)/i386/cpu.asm FORCE
	$(call if_changed,nasm32)

$(obj)/amd64/cpu.o: $(src)/amd64/cpu.asm FORCE
	$(call if_changed,nasm64)
