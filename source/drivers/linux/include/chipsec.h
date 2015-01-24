#ifndef CHIPSEC_H
#define CHIPSEC_H

#define MSR_IA32_BIOS_UPDT_TRIG 0x79
#define MSR_IA32_BIOS_SIGN_ID   0x8b

#define IOCTL_BASE  _IO(0, 0)
#define IOCTL_RDIO  _IOWR(0, 0x1, int*)
#define IOCTL_WRIO  _IOWR(0, 0x2, int*)
#define IOCTL_RDPCI _IOWR(0, 0x3, int*)
#define IOCTL_WRPCI _IOWR(0, 0x4, int*)
#define IOCTL_RDMSR _IOWR(0, 0x5, int*) 
#define IOCTL_WRMSR _IOWR(0, 0x6, int*) 
#define IOCTL_CPUID _IOWR(0, 0x7, int*) 
#define IOCTL_GET_CPU_DESCRIPTOR_TABLE _IOWR(0, 0x8, int*)
#define IOCTL_SWSMI _IOWR(0, 0xA, int*)
#define IOCTL_LOAD_UCODE_PATCH _IOWR(0, 0xB, int*)
#define IOCTL_ALLOC_PHYSMEM _IOWR(0, 0xC, int*)
#define IOCTL_GET_EFIVAR _IOWR(0, 0xD, int*)
#define IOCTL_SET_EFIVAR _IOWR(0, 0xE, int*)
        
#define IOCTL_RDCR _IOWR(0, 0x10, int*) 
#define IOCTL_WRCR _IOWR(0, 0x11, int*) 

/// if defined debug is enabled
#define DEBUG
#ifdef DEBUG 
/// Macro for debug print
#define dbgprint(format, args...) \
	do {            \
		printk(KERN_DEBUG "%s %s %d: "format"\n", program_name, __FUNCTION__, __LINE__, ## args);\
	} while ( 0 )
#else
#define dbgprint(format, args...) do {} while( 0 );
#endif
#endif	

#ifdef __x86_64__
typedef u64 physaddr_t;
#else
typedef __u32 physaddr_t;
#endif

#ifdef __x86_64__
#define PUSH_REGS asm volatile ("push %rax\n\t" "push %rbx\n\t" "push %rcx\n\t" "push %rdx\n\t" "push %rsi\n\t" "push %rdi\n\t" );
#define POP_REGS asm volatile ("pop %rdi\n\t" "pop %rsi\n\t" "pop %rdx\n\t" "pop %rcx\n\t" "pop %rbx\n\t" "pop %rax\n\t");
#define GET_RETURN_VALUE asm volatile ( "mov %%rax, %%rbx" : "=b"(ret) : );
#else
#define PUSH_REGS asm volatile ("push %eax\n\t" "push %ebx\n\t" "push %ecx\n\t" "push %edx\n\t" "push %esi\n\t" "push %edi\n\t" );
#define POP_REGS asm volatile ("pop %edi\n\t" "pop %esi\n\t" "pop %edx\n\t" "pop %ecx\n\t" "pop %ebx\n\t" "pop %eax\n\t");
#define GET_RETURN_VALUE asm volatile ( "mov %%eax, %%ebx" : "=b"(ret) : );
#endif

typedef enum {
  CPU_DT_CODE_IDTR = 0x0,
  CPU_DT_CODE_GDTR = 0x1,
  CPU_DT_CODE_LDTR = 0x2,
} DTR_CODE;

#pragma pack(1)
typedef union {
   struct {
       uint32_t low;
       int32_t high;
   } u;
   physaddr_t quadpart;
} PHYSICAL_ADDRESS;
#pragma pack()

#pragma pack(1)
typedef struct _DESCRIPTOR_TABLE_RECORD {
  uint16_t    limit;
  physaddr_t base;
} DESCRIPTOR_TABLE_RECORD, *PDESCRIPTOR_TABLE_RECORD;
#pragma pack()

