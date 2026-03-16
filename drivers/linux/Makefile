DESTDIR	=
MODDIR	= $(DESTDIR)/lib/modules
KVERS	= $(shell uname -r)
KVER	= $(KVERS)
VMODDIR = $(MODDIR)/$(KVER)
KSRC	?= $(VMODDIR)/build

# Optional: set to 1 to bypass objtool stack validation on problematic builds.
# Default is 0 now that assembly stubs are thunked for modern mitigations.
SKIP_STACK_VALIDATION ?= 0

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
	$(MAKE) -C $(KSRC) M=$(CURDIR) SKIP_STACK_VALIDATION=$(SKIP_STACK_VALIDATION) modules

clean: check_kernel_dir
	$(MAKE) -C $(KSRC) M=$(CURDIR) SKIP_STACK_VALIDATION=$(SKIP_STACK_VALIDATION) clean

$(obj)/i386/cpu.o: $(src)/i386/cpu.asm FORCE
	$(call if_changed,nasm32)

$(obj)/amd64/cpu.o: $(src)/amd64/cpu.asm FORCE
	$(call if_changed,nasm64)
