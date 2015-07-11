/* 
CHIPSEC: Platform Security Assessment Framework
Copyright (c) 2010-2014, Intel Corporation
 
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; Version 2.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

Contact information:
chipsec@intel.com
*/ 

#include <linux/module.h>
#include <linux/device.h>
#include <linux/highmem.h>
#include <linux/kallsyms.h>
#include <linux/tty.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <asm/io.h>
#include "include/chipsec.h"
#include <linux/smp.h>
#include <linux/efi.h>
#include <linux/proc_fs.h>

#define _GNU_SOURCE 
#define CHIPSEC_VER_ 		1
#define CHIPSEC_VER_MINOR	2


MODULE_LICENSE("GPL");

int chipsec_mem_major = -1;

// function page_is_ram is not exported 
// for modules, but is available in kallsyms.
// So we need determine this address using dirty tricks
int (*guess_page_is_ram)(unsigned long pagenr);
int (*guess_raw_pci_read)(unsigned int domain, unsigned int bus, unsigned int devfn, int reg, int len, uint32_t *val);
int (*guess_raw_pci_write)(unsigned int domain, unsigned int bus, unsigned int devfn, int reg, int len, uint32_t val);

unsigned long a1=0;
module_param(a1,ulong,0); //a1 is addr of page_is_ram function
unsigned long a2=0;
module_param(a2,ulong,0); //a2 is addr of raw_pci_read function
unsigned long a3=0;
module_param(a3,ulong,0); //a3 is addr of raw_pci_write function

/// Char we show before each debug print
const char program_name[] = "chipsec";

typedef struct tagCONTEXT {
   unsigned int a;   // rax - 0x00; eax - 0x0
   unsigned int b;   // rbx - 0x08; ebx - 0x4
   unsigned int c;   // rcx - 0x10; ecx - 0x8
   unsigned int d;   // rdx - 0x18; edx - 0xc
} CONTEXT, *PCONTEXT;
typedef CONTEXT CPUID_CTX, *PCPUID_CTX;

  void __cpuid__(CPUID_CTX * ctx);

typedef struct tagSMI_CONTEXT {
   unsigned int c;     // rcx - 0x00;
   unsigned int d;     // rdx - 0x08;
   unsigned int r8;     // r8 - 0x10;
   unsigned int r9;     // r9 - 0x18;
   unsigned int r10;   // r10 - 0x20;
   unsigned int r11;   // r11 - 0x28;
   unsigned int r12;   // r12 - 0x30;
} SMI_CONTEXT, *SMI_PCONTEXT;

typedef SMI_CONTEXT SMI_CTX, *PSMI_CTX; 

 void __swsmi__(SMI_CTX * ctx); 

  void _rdmsr( 
    unsigned long msr_num, // rdi
    unsigned long * msr_lo, // rsi
    unsigned long * msr_hi  // rdx
    );

  void _wrmsr( 
    unsigned long msr_num, // rdi
    unsigned long msr_hi, // rsi
    unsigned long msr_lo  // rdx
    );

  unsigned int
  ReadPortDword (
    unsigned short	port_num           // rdi
    );

  unsigned short
  ReadPortWord (
    unsigned short	port_num           // rdi
    );

  unsigned char
  ReadPortByte (
    unsigned short	port_num           // rdi
    );

  void
  WritePortByte (
    unsigned char	out_value,          // rdi
    unsigned short	port_num           // rsi
    );

  void
  WritePortWord (
    unsigned short	out_value,          // rdi 
    unsigned short	port_num           // rsi
    );

  void
  WritePortDword (
    unsigned int	out_value,          // rdi
    unsigned short	port_num           // rsi
    );

  void
  WritePCIByte (
    unsigned int	pci_reg,          // rdi
    unsigned short	cfg_data_port,    // rsi
    unsigned char	byte_value       // rdx
    );

  void
  WritePCIWord (
    unsigned int	pci_reg,          // rdi
    unsigned short	cfg_data_port,    // rsi
    unsigned short	word_value       // rdx
    );

  void
  WritePCIDword (
    unsigned int	pci_reg,          // rdi
    unsigned short	cfg_data_port,    // rsi
    unsigned int	dword_value      // rdx
    );

  unsigned char
  ReadPCIByte (
    unsigned int	pci_reg,          // rdi
    unsigned short	cfg_data_port    // rsi
    );

  unsigned short
  ReadPCIWord (
    unsigned int	pci_reg,          // rdi
    unsigned short	cfg_data_port    // rsi
    );

  unsigned int
  ReadPCIDword (
    unsigned int	pci_reg,          // rdi
    unsigned short	cfg_data_port    // rsi
    );

    unsigned int ReadCR0(void);
    unsigned int ReadCR2(void);
    unsigned int ReadCR3(void);
    unsigned int ReadCR4(void);
#ifdef __x86_64__
    unsigned int ReadCR8(void);
#endif

    void WriteCR0( unsigned int );
    void WriteCR2( unsigned int );
    void WriteCR3( unsigned int );
    void WriteCR4( unsigned int );
#ifdef __x86_64__
    void WriteCR8( unsigned int );
#endif

    void __cpuid__(CPUID_CTX * ctx);
   
  void _store_idtr(
    uint16_t *address // rdi
    );

 void _store_gdtr(
   uint16_t *address // rdi
   );

 void _store_ldtr(
   uint16_t *address // rdi
   );

uint32_t
ReadPCICfg(
  uint8_t bus,
  uint8_t dev,
  uint8_t fun,
  uint8_t off,
  uint8_t len // 1, 2, 4 bytes
  )
{
  unsigned int result = 0;
  unsigned int pci_addr = (0x80000000 | (bus << 16) | (dev << 11) | (fun << 8) | (off & ~3));
  unsigned short cfg_data_port = (uint16_t)(0xCFC + ( off & 0x3 ));
  if     ( 1 == len ) result = (ReadPCIByte ( pci_addr, cfg_data_port ) & 0xFF);
  else if( 2 == len ) result = (ReadPCIWord ( pci_addr, cfg_data_port ) & 0xFFFF);
  else if( 4 == len ) result =  ReadPCIDword( pci_addr, cfg_data_port );
  return result;
}

void
WritePCICfg(
  uint8_t bus,
  uint8_t dev,
  uint8_t fun,
  uint8_t off,
  uint8_t len, // 1, 2, 4 bytes
  uint32_t val
  )
{
  uint32_t pci_addr = (0x80000000 | (bus << 16) | (dev << 11) | (fun << 8) | (off & ~3));
  uint16_t cfg_data_port = (uint16_t)(0xCFC + ( off & 0x3 ));
  if     ( 1 == len ) WritePCIByte ( pci_addr, cfg_data_port, (uint8_t)(val&0xFF) );
  else if( 2 == len ) WritePCIWord ( pci_addr, cfg_data_port, (uint16_t)(val&0xFFFF) );
  else if( 4 == len ) WritePCIDword( pci_addr, cfg_data_port, val );
}

void
WriteIOPort(
  uint32_t value,
  uint16_t io_port,
  uint8_t len // 1, 2, 4 bytes
  )
{
  if     ( 1 == len ) WritePortByte ( (uint8_t)(value&0xFF), io_port );
  else if( 2 == len ) WritePortWord ( (uint16_t)(value&0xFFFF), io_port );
  else if( 4 == len ) WritePortDword( value, io_port );
}

uint32_t
ReadIOPort(
  uint16_t io_port,
  uint8_t len // 1, 2, 4 bytes
  )
{
  if     ( 1 == len ) return (ReadPortByte( io_port ) & 0xFF);
  else if( 2 == len ) return (ReadPortWord( io_port ) & 0xFFFF);
  else if( 4 == len ) return ReadPortDword( io_port );
  return 0;
}

/* Own implementation of xlate_dev_mem_ptr
 * (so we can read highmem and other)
 * 
 * Input:  physical address
 * Output: pointer to virtual address where requested 
 *         physical address is mapped
 */

void *my_xlate_dev_mem_ptr(unsigned long phys)
{

	void *addr=NULL;
	unsigned long start = phys & PAGE_MASK;
	unsigned long pfn = PFN_DOWN(phys);
	
        /* If page is RAM, we can use __va. Otherwise ioremap and unmap. */
        if ((*guess_page_is_ram)(start >> PAGE_SHIFT)) {

		if (PageHighMem(pfn_to_page(pfn))) {
                /* The buffer does not have a mapping.  Map it! */
		        addr = kmap(pfn_to_page(pfn));	
			return addr;
		}
		return __va(phys);
	}

	// Not RAM, so it is some device (can be bios for example)
	addr = (void __force *)ioremap_nocache(start, PAGE_SIZE);
    
    if (addr)
    {
        addr = (void *)((unsigned long)addr | (phys & ~PAGE_MASK));
        return addr;
    }
    
    addr = (void __force *)ioremap_prot(start, PAGE_SIZE,0);
    
	if (addr)
		addr = (void *)((unsigned long)addr | (phys & ~PAGE_MASK));
	return addr;
}

// Our own implementation of unxlate_dev_mem_ptr
// (so we can read highmem and other)
void my_unxlate_dev_mem_ptr(unsigned long phys,void *addr)
{
	unsigned long pfn = PFN_DOWN(phys); //get page number

	/* If page is RAM, check for highmem, and eventualy do nothing. 
	   Otherwise need to iounmap. */
	if ((*guess_page_is_ram)(phys >> PAGE_SHIFT)) {
	
		if (PageHighMem(pfn_to_page(pfn))) { 
		/* Need to kunmap kmaped memory*/
		        kunmap(pfn_to_page(pfn));
			dbgprint ("unxlate: Highmem detected");
		}
		return;
	}
	
	// Not RAM, so it is some device (can be bios for example)
	iounmap((void __iomem *)((unsigned long)addr & PAGE_MASK));
}

/*-- original (stripped) linux/drivers/char/mem.c starts here ---
   only one mem device (fmem) was left
   only read operation is supported
   some not necessary pieces may survived, feel free to clean them
  --------------------------------------------------------------*/

/*
 * Architectures vary in how they handle caching for addresses
 * outside of main memory.
 *
 */
static inline int uncached_access(struct file *file, unsigned long addr)
{
#if defined(CONFIG_IA64)
	/*
	 * On ia64, we ignore O_SYNC because we cannot tolerate memory attribute aliases.
	 */
	return !(efi_mem_attributes(addr) & EFI_MEMORY_WB);
#elif defined(CONFIG_MIPS)
	{
		extern int __uncached_access(struct file *file, unsigned long addr);

		return __uncached_access(file, addr);
	}
#else
	/*
	 * Accessing memory above the top the kernel knows about or through a file pointer
	 * that was marked O_SYNC will be done non-cached.
	 */
	if (file->f_flags & O_SYNC)
		return 1;
	return addr >= __pa(high_memory);
#endif
}

/*
 * This function reads the *physical* memory. The f_pos points directly to the 
 * memory location. 
 */
static ssize_t read_mem(struct file * file, char __user * buf, size_t count, loff_t *ppos)
{
	unsigned long p = *ppos;
	ssize_t read, sz;
	char *ptr;
        
	read = 0;

#ifdef __ARCH_HAS_NO_PAGE_ZERO_MAPPED
	/* we don't have page 0 mapped on sparc and m68k.. */
	if (p < PAGE_SIZE) {
		sz = PAGE_SIZE - p;
		if (sz > count) 
			sz = count; 
		if (sz > 0) {
			if (clear_user(buf, sz))
				return -EFAULT;
			buf += sz; 
			p += sz; 
			count -= sz; 
			read += sz; 
		}
	}
#endif
    
	while (count > 0) {
		/*
		 * Handle first page in case it's not aligned
		 */
		if (-p & (PAGE_SIZE - 1))
			sz = -p & (PAGE_SIZE - 1);
		else
			sz = PAGE_SIZE;

		sz = min_t(unsigned long, sz, count);

		/*
		 * On ia64 if a page has been mapped somewhere as
		 * uncached, then it must also be accessed uncached
		 * by the kernel or data corruption may occur
		 */
		ptr = my_xlate_dev_mem_ptr(p);

		if (!ptr){
			dbgprint ("xlate FAIL, p: %lX",p);
			return -EFAULT;
		}

		if (copy_to_user(buf, ptr, sz)) {
			dbgprint ("copy_to_user FAIL, ptr: %p",ptr);
			my_unxlate_dev_mem_ptr(p, ptr);
			return -EFAULT;
		}

		my_unxlate_dev_mem_ptr(p, ptr);

		buf += sz;
		p += sz;
		count -= sz;
		read += sz;
	}

	*ppos += read;
	return read;
}

static ssize_t write_mem(struct file * file, const char __user * buf, size_t count, loff_t *ppos)
{
	unsigned long p = *ppos;
	ssize_t read, sz;
	char *ptr;

	read = 0;
#ifdef __ARCH_HAS_NO_PAGE_ZERO_MAPPED
	/* we don't have page 0 mapped on sparc and m68k.. */
	if (p < PAGE_SIZE) {
		sz = PAGE_SIZE - p;
		if (sz > count) 
			sz = count; 
		if (sz > 0) {
			//if (clear_user(buf, sz))
			//	return -EFAULT;
			buf += sz; 
			p += sz; 
			count -= sz; 
			read += sz; 
		}
	}
#endif

	while (count > 0) {
		/*
		 * Handle first page in case it's not aligned
		 */
		if (-p & (PAGE_SIZE - 1))
			sz = -p & (PAGE_SIZE - 1);
		else
			sz = PAGE_SIZE;

		sz = min_t(unsigned long, sz, count);

		/*
		 * On ia64 if a page has been mapped somewhere as
		 * uncached, then it must also be accessed uncached
		 * by the kernel or data corruption may occur
		 */
		ptr = my_xlate_dev_mem_ptr(p);

		if (!ptr){
			dbgprint ("xlate FAIL, p: %lX",p);
			return -EFAULT;
		}

		if (copy_from_user(ptr, buf, sz)) {
			dbgprint ("copy_from_user FAIL, ptr: %p",ptr);
			my_unxlate_dev_mem_ptr(p, ptr);
			return -EFAULT;
		}

		my_unxlate_dev_mem_ptr(p, ptr);

		buf += sz;
		p += sz;
		count -= sz;
		read += sz;
	}

	*ppos += read;
	return read;
}

#ifndef CONFIG_MMU
static unsigned long get_unmapped_area_mem(struct file *file,
					   unsigned long addr,
					   unsigned long len,
					   unsigned long pgoff,
					   unsigned long flags)
{
	if (!valid_mmap_phys_addr_range(pgoff, len))
		return (unsigned long) -EINVAL;
	return pgoff << PAGE_SHIFT;
}

/* can't do an in-place private mapping if there's no MMU */
static inline int private_mapping_ok(struct vm_area_struct *vma)
{
	return vma->vm_flags & VM_MAYSHARE;
}
#else
#define get_unmapped_area_mem	NULL

static inline int private_mapping_ok(struct vm_area_struct *vma)
{
	return 1;
}
#endif

static int mmap_mem(struct file * file, struct vm_area_struct * vma)
{
	return 0;
}

/*
 * The memory devices use the full 32/64 bits of the offset, and so we cannot
 * check against negative addresses: they are ok. The return value is weird,
 * though, in that case (0).
 *
 * also note that seeking relative to the "end of file" isn't supported:
 * it has no meaning, so it returns -EINVAL.
 */
static loff_t memory_lseek(struct file * file, loff_t offset, int orig)
{
	loff_t ret;
//Older kernels (<20) uses f_dentry instead of f_path.dentry
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
	mutex_lock(&file->f_dentry->d_inode->i_mutex);
#else
	mutex_lock(&file->f_path.dentry->d_inode->i_mutex);
#endif 

	switch (orig) {
		case 0:
			file->f_pos = offset;
			ret = file->f_pos;
			force_successful_syscall_return();
			break;
		case 1:
			file->f_pos += offset;
			ret = file->f_pos;
			force_successful_syscall_return();
			break;
		default:
			ret = -EINVAL;
	}
//Older kernels (<20) uses f_dentry instead of f_path.dentry
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
	mutex_unlock(&file->f_dentry->d_inode->i_mutex);
#else
	mutex_unlock(&file->f_path.dentry->d_inode->i_mutex);
#endif 

	return ret;
}


void * patch_apply_ucode(void * ucode_buf)
{
	unsigned long long ucode_start;

	printk(KERN_INFO "[chipsec] [patch_apply_ucode] Applying patch in the processor id: %d", smp_processor_id());

	ucode_start=(unsigned long long) ucode_buf;
	asm volatile("wrmsr" :  : "c"(MSR_IA32_BIOS_UPDT_TRIG),"d"((unsigned int)((ucode_start >> 32) & 0xffffffff)),"a"((unsigned int)(ucode_start & 0xffffffff))); // lo is in eax


	return NULL;
}

void * patch_bios_sign(void * ucode_buf)
{
	asm volatile("wrmsr" :  : "c"(MSR_IA32_BIOS_SIGN_ID),"a"((unsigned int)0),"d"((unsigned int)0));
	return NULL;
}

void * patch_cpuid_0(void * CPUInfo)
{
	int *pointer;
	pointer=(int *) CPUInfo;
	asm volatile( "cpuid" : "=a"(pointer[0]),"=b"(pointer[1]),"=c"(pointer[2]),"=d"(pointer[3]) : "a"((unsigned int)(1)));
	return NULL;
}

void * patch_read_msr(void * CPUInfo)
{
	int *pointer;
	pointer=(int *) CPUInfo;
	asm volatile("rdmsr" : "=a"(pointer[0]), "=d"(pointer[3]) : "c"(MSR_IA32_BIOS_SIGN_ID));
	return NULL;
}

void print_stat(efi_status_t stat)
{
    switch (stat) {
        case EFI_SUCCESS:
            printk( KERN_DEBUG "EFI_SUCCESS\n");
            break;
        case EFI_LOAD_ERROR:
            printk( KERN_DEBUG "EFI_LOAD_ERROR\n");
            break;        
        case EFI_INVALID_PARAMETER:
            printk( KERN_DEBUG "EFI_INVALID_PARAMETER\n");
            break;
        case EFI_UNSUPPORTED:
            printk( KERN_DEBUG "EFI_UNSUPPORTED\n");
            break;
        case EFI_BAD_BUFFER_SIZE:
            printk( KERN_DEBUG "EFI_BAD_BUFFER_SIZE\n");
            break;
        case EFI_BUFFER_TOO_SMALL:
            printk( KERN_DEBUG "EFI_BUFFER_TOO_SMALL\n");
            break;
        case EFI_NOT_READY:
            printk( KERN_DEBUG "EFI_NOT_READY\n");
            break;
        case EFI_DEVICE_ERROR:
            printk( KERN_DEBUG "EFI_DEVICE_ERROR\n");
            break;
        case EFI_WRITE_PROTECTED:
            printk( KERN_DEBUG "EFI_WRITE_PROTECTED\n");
            break;
        case EFI_OUT_OF_RESOURCES:
            printk( KERN_DEBUG "EFI_OUT_OF_RESOURCES\n");
            break;
        case EFI_NOT_FOUND:
            printk( KERN_DEBUG "EFI_NOT_FOUND\n");
            break;
        case EFI_SECURITY_VIOLATION:
            printk( KERN_DEBUG "EFI_SECURITY_VIOLATION\n");
            break;
        default:
            printk( KERN_DEBUG "Unknown status\n");
            break;
    }
}

static long d_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param)
{
	int numargs = 0;
	long ptrbuf[16];
	long *ptr = ptrbuf;
	unsigned short ucode_size;
	unsigned short thread_id;
	char *ucode_buf;
	//unsigned int counter;
	char small_buffer[6]; //32 bits + char + \0
	int CPUInfo[4]={-1};
	void (*apply_ucode_patch_p)(void *info);

	switch(ioctl_num)
	{
	case IOCTL_BASE:
	{
		return ((IOCTL_RDIO & 0xfffffff0) >> 4);
	}
	case IOCTL_RDIO:
	{
		//IN  params: addr, size
		//OUT params: val
#ifdef CONFIG_X86
		numargs = 3;
		if( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs) ) > 0)
			return -EFAULT;

		switch( ptr[1] )
		{
			case 1:
				ptr[2] = ReadPortByte(ptr[0]);
				// BUGFIX: eax is returning more than a byte of data ??
				ptr[2] = ptr[2] & 0xff;
				break;
			case 2:
				ptr[2] = ReadPortWord(ptr[0]);
				break;
			default: // 4
				ptr[2] = ReadPortDword(ptr[0]);
				break;
		}

		if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
			return -EFAULT;
		break;
#else
		return -EFAULT;
#endif
	}

	case IOCTL_WRIO:
	{
		//IN params: addr, size, val
#ifdef CONFIG_X86

		numargs = 3;
		if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
			return -EFAULT;

		switch(ptr[1])
		{
			case 1:
				WritePortByte(ptr[2],ptr[0]);
				break;
			case 2:
				WritePortWord(ptr[2],ptr[0]);
				break;
			default:
				WritePortDword(ptr[2],ptr[0]);
				break;
		}

		if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
			return -EFAULT;
		break;
#else
		return -EFAULT;
#endif
	}

	case IOCTL_LOAD_UCODE_PATCH:
	{

#ifdef CONFIG_X86
		ucode_size=0;

		printk(KERN_INFO "[chipsec][IOCTL_LOAD_UCODE_UPDATE] Initializing update routine\n");

		/* we just check if the first bytes are in the ok range */
		if (!access_ok(VERIFY_READ, ioctl_param, sizeof(unsigned short))) {
			printk("\n address not in user-mode\n");
			return -EFAULT;
		}
	
		/* first byte: thread_id */
		memset(small_buffer, 0x00, 6);

		if ( copy_from_user(&small_buffer, (char *) ioctl_param, sizeof(unsigned char)) > 0 )
			return -EFAULT;

		thread_id=(unsigned short) small_buffer[0];	

		memset(small_buffer, 0x00, 6);

		if ( copy_from_user(&small_buffer, (unsigned char *)(ioctl_param+sizeof(unsigned char)), sizeof(unsigned short)) > 0 )
			return -EFAULT;

		ucode_size=(unsigned short) *((unsigned short *) small_buffer);

		ucode_buf=kmalloc(ucode_size, GFP_KERNEL);
		if (!ucode_buf)
			return -EFAULT;

		memset(ucode_buf, 0, ucode_size);
		
		if ( copy_from_user(ucode_buf, (unsigned char *)(ioctl_param+sizeof(unsigned char)+sizeof(unsigned short)), ucode_size) > 0 )
			return -EFAULT;


		/* to confirm the received patch is correct, uncomment */
		/*
		printk(KERN_INFO "\n");
		for (counter=0; counter<40; counter++)
			printk(KERN_INFO "ucode_buf[%d] = 0x%x ",counter, (unsigned char) ucode_buf[counter]);
		printk(KERN_INFO "\n");
		printk(KERN_INFO "ucode_buf[%d] = 0x%x ",ucode_size-1, (unsigned char) ucode_buf[ucode_size-1]);
		*/

		apply_ucode_patch_p=(void *) patch_apply_ucode;
		smp_call_function_single(thread_id, apply_ucode_patch_p, ucode_buf, 0);
		kfree(ucode_buf);

		apply_ucode_patch_p=(void *)patch_bios_sign;
		smp_call_function_single(thread_id, apply_ucode_patch_p, ucode_buf, 0);

		apply_ucode_patch_p=(void *)patch_cpuid_0;
		smp_call_function_single(thread_id, apply_ucode_patch_p, CPUInfo, 0);

		apply_ucode_patch_p=(void *)patch_read_msr;
		smp_call_function_single(thread_id, apply_ucode_patch_p, CPUInfo, 0);

		if (0 != CPUInfo[3])
			printk(KERN_INFO "[chipsec][IOCTL_LOAD_UCODE_UPDATE] Microcode update loaded (ID != 0)"); 
		else
			printk(KERN_INFO "[chipsec][IOCTL_LOAD_UCODE_UPDATE] Microcode update failed"); 


		break;
#else
		return -EFAULT;
#endif
	}

	case IOCTL_RDMSR:
	{
		//IN  params: threadid, msr_addr
		//OUT params: edx, eax
#ifdef CONFIG_X86

		numargs = 4;
		if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
			return -EFAULT;

		_rdmsr(ptr[1],&ptr[3],&ptr[2]);

		if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
			return -EFAULT;
		break;
#else
		return -EFAULT;
#endif
	}

	case IOCTL_WRMSR:
	{
		//IN params: threadid, msr_addr, {e,r}dx, {e,r}ax
#ifdef CONFIG_X86
		numargs = 4;
		if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
			return -EFAULT;

		_wrmsr(ptr[1],ptr[3],ptr[2]);

		if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
			return -EFAULT;
		break;
#else
		return -EFAULT;
#endif
	}

	case IOCTL_CPUID:
	{
		//IN  params: {e,r}ax
		//OUT params: {e,r}ax, {e,r}bx, {e,r}cx, {e,r}dx
#ifdef CONFIG_X86
		numargs = 4;
		if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
			return -EFAULT;

                __cpuid__((CPUID_CTX *)ptr);

		if(copy_to_user( (void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
			return -EFAULT;
		break;
#else
		return -EFAULT;
#endif

	}

	case IOCTL_RDPCI:
	{
		//IN  params: bus, dev, fun, off, len
		//OUT params: value
#ifdef CONFIG_PCI
		
		uint32_t bus, dev, fun, off, len, val;
		numargs = 5;
		if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
			return -EFAULT;
		
		bus = ptr[0] & 0xffff;
		dev = ptr[1] >> 16 & 0xffff;
		fun = ptr[1] & 0xffff;
		off = ptr[2];
		len = ptr[3];

		val = ReadPCICfg( bus, dev, fun, off, len );

		ptr[4] = val;	
		if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
			return -EFAULT;	
		break;
#else
		return -EFAULT;
#endif
	}

	case IOCTL_WRPCI:
	{ 
		//IN params:  bus, dev, fun, off, len, val
#ifdef CONFIG_PCI 

		uint32_t bus, dev, fun, off, len, val;
		numargs = 5;
		if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
			return -EFAULT;

		bus = ptr[0] & 0xffff;
		dev = ptr[1] >> 16 & 0xffff;
		fun = ptr[1] & 0xffff;
		off = ptr[2];
		val = ptr[4];
		len = ptr[3];

		WritePCICfg( bus, dev, fun, off, len, val );

		break;
#else
		return -EFAULT;
#endif
	}
    
	case IOCTL_GET_CPU_DESCRIPTOR_TABLE:
	{
		//IN  params: cpu_thread_id, desc_table_code, 0, 0, 0
		//OUT params: limit, base_hi, base_lo, phys_hi, phys_lo
#ifdef CONFIG_X86
            	DESCRIPTOR_TABLE_RECORD dtr;
            	PDESCRIPTOR_TABLE_RECORD pdtr = &dtr;
            	PHYSICAL_ADDRESS dt_pa;

		numargs = 5;
		if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
			return -EFAULT;

		switch(ptr[1]) 
              	{
                	case CPU_DT_CODE_GDTR: 
			{ 
				_store_gdtr(&pdtr->limit);
				break; 
			}
                	case CPU_DT_CODE_LDTR: 
			{ 
				_store_ldtr(&pdtr->limit);
				break; 
			}
                	case CPU_DT_CODE_IDTR: 
			{ 
				_store_idtr(&pdtr->limit);
				break; 
			}
              	}
		
		dt_pa.quadpart = virt_to_phys((void*)dtr.base);
		ptr[0] = dtr.limit;
		ptr[1] = (uint32_t)(dtr.base >> 32);
		ptr[2] = (uint32_t)dtr.base;

		#pragma GCC diagnostic ignored "-Wuninitialized" dt_pa.u.high
		#pragma GCC diagnostic ignored "-Wuninitialized" dt_pa.u.low
		ptr[3] = dt_pa.u.high;
		ptr[4] = dt_pa.u.low;

		if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
			return -EFAULT;
		break;
#else
		return -EFAULT;
#endif	
	}
    
    	case IOCTL_SWSMI:
	{
		//IN params: SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi 
#ifdef CONFIG_X86

		printk( KERN_INFO "[chipsec] > IOCTL_SWSMI\n");
		numargs = 7;
		if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
		{
			printk( KERN_ALERT "[chipsec] ERROR: STATUS_INVALID_PARAMETER\n" );
			break;
		}
	
		__swsmi__((SMI_CTX *)ptr);

		if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
			return -EFAULT;	
		break;
#else
		return -EFAULT;
#endif
	}
    
	case IOCTL_RDCR:
	{
		//IN  params: number of CR reg
		//OUT params: val
#ifdef CONFIG_X86
		numargs = 3;
		if( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs) ) > 0)
			return -EFAULT;

		switch( ptr[1] )
		{
                    case 0: 
        		ptr[2] = ReadCR0();
                        break;
                    case 2: 
        		ptr[2] = ReadCR2();
                        break;
                    case 3: 
        		ptr[2] = ReadCR3();
                        break;
                    case 4: 
        		ptr[2] = ReadCR4();
                        break;
                    case 8:
#ifdef __x86_64__
                        ptr[2] = ReadCR8();
#endif
                        break;
		}

		if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
			return -EFAULT;
		break;
#else
		return -EFAULT;
#endif
        }
	case IOCTL_WRCR:
	{
		//IN  params: number of CR reg
		//OUT params: val
#ifdef CONFIG_X86
		numargs = 3;
		if( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs) ) > 0)
			return -EFAULT;

		switch( ptr[1] )
		{
                    case 0: 
        		WriteCR0(ptr[2]);
                        break;
                    case 2: 
        		WriteCR2(ptr[2]);
                        break;
                    case 3: 
        		WriteCR3(ptr[2]);
                        break;
                    case 4: 
        		WriteCR4(ptr[2]);
                        break;
                    case 8:
#ifdef __x86_64__
                        WriteCR8(ptr[2]);
#endif
                        break;
		}

		if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
			return -EFAULT;
		break;
#else
        return -EFAULT;
#endif
        }
    case IOCTL_ALLOC_PHYSMEM:
    {
        //IN params: size
        //OUT params: physical address
        uint32_t NumberOfBytes = 0;
        void *va, *pa, *max_pa;
        
        numargs = 2;
        if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
        {
            printk( KERN_ALERT "[chipsec] ERROR: STATUS_INVALID_PARAMETER\n" );
            return -EFAULT;
        }
        
        NumberOfBytes = ptr[0];
        max_pa = (void *)ptr[1];
        
        va = kmalloc(NumberOfBytes, GFP_KERNEL );
        if( !va )
        {
            printk(KERN_ALERT "[chipsec] ERROR: STATUS_UNSUCCESSFUL - could not allocate memory\n" );
            return -EFAULT;
        }
         
        memset(va, 0, NumberOfBytes);
        pa = (void*)virt_to_phys(va);

        if (pa > max_pa)
        {
            //printk(KERN_ALERT "[chipsec] ERROR: STATUS_UNSUCCESSFUL - could not allocate memory below max_pa (%p > %p)\n", pa, max_pa );
            //kfree(va);
            //return -EFAULT;
            printk(KERN_ALERT "[chipsec] WARNING: allocated memory (%p) is not below max_pa (%p) (ignoring)", pa, max_pa);
        }
        //else
        //{
            ptr[0] = (unsigned long)va;
            ptr[1] = (unsigned long)pa;
        //}
		
        if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
			return -EFAULT;
		break;
	}
    
	case IOCTL_GET_EFIVAR:
	{
		//IN  params: data_size, guid, namelen, name
		//OUT params: var_size, stat, data
 
		uint32_t *kbuf;
		static efi_char16_t *name;
		char *cptr, *var;
		efi_guid_t GUID;
		efi_status_t stat;
		long unsigned int data_size, var_size;
		uint32_t data_size_u32;
		unsigned int namelen, index;
		static struct efi *myefi;
		myefi = &efi;
    
		printk( KERN_INFO "[chipsec] > IOCTL_GET_EFIVAR\n");
        
		// get the size (a uint32_t)
		if(copy_from_user((void*)&data_size_u32, (void*)ioctl_param, sizeof(uint32_t)) > 0)
		{
			printk( KERN_ALERT "[chipsec] ERROR: STATUS_INVALID_PARAMETER\n" );
			return -EFAULT;
		}
		data_size = (unsigned long)data_size_u32;

		// check that this is enough memory 
		if (data_size < sizeof(uint32_t) * 13)
		{
			printk(KERN_ALERT "[chipsec] ERROR: INVALID SIZE PARAMETER\n");
			return -EFAULT;
		}
        
		// allocate that much memory
		kbuf = kzalloc(data_size, GFP_KERNEL);
		if (!kbuf)
		{
			printk(KERN_ALERT "[chipsec] ERROR: STATUS_UNSUCCESSFUL - could not allocate memory\n" );
			return -EFAULT;
		}

		// fill kbuf with user's buffer
		if(copy_from_user((void*)kbuf, (void*)ioctl_param, data_size) > 0)
		{
            kfree(kbuf);
			printk( KERN_ALERT "[chipsec] ERROR: STATUS_INVALID_PARAMETER\n" );
			return -EFAULT;
		}
        
		GUID = EFI_GUID( kbuf[1], kbuf[2], kbuf[3], kbuf[4], kbuf[5], kbuf[6], kbuf[7], kbuf[8], kbuf[9], kbuf[10], kbuf[11]);
        
		namelen = kbuf[12]; 
                cptr = (char *)&kbuf[13];

                if (namelen > (data_size - sizeof(uint32_t) * 13))
		{
			printk(KERN_ALERT "[chipsec] ERROR: INVALID SIZE PARAMETER (namelen %u too big for data_size %lu)\n", namelen, data_size);
			return -EFAULT;
		}
        
        // if name overflowed, we only work with the part that fit in kbuf
        name = kzalloc((namelen+1)*sizeof(efi_char16_t), GFP_KERNEL);
        if (!name)
        {
            kfree(kbuf);
            printk(KERN_ALERT "[chipsec] ERROR: STATUS_UNSUCCESSFUL - could not allocate memory\n" );
            return -EFAULT;
        }

		for(index=0; index < namelen; index++)
		{
			// upper byte is 0x0 (for ASCII), the lower byte is ASCII char
			name[index] = (efi_char16_t)(cptr[index] & 0xFF);
		}
		name[index] = (efi_char16_t)(0);
        
		// now we're done with everything in kbuf. use it for get_variable
		// the format for kbuf is:
		//      size, return value, attrs, data
		memset(kbuf, '\0', data_size);

		// For the call to get_variable we reserve space for header information
		var_size = data_size - (sizeof(uint32_t) * 3);
		var = (char *)&kbuf[3];
		stat = myefi->get_variable(name, &GUID, (u32*)&kbuf[2], &var_size, var); 
                     
		if (stat != EFI_SUCCESS)
		{
			print_stat(stat);
			data_size = sizeof(uint32_t) * 2;
		}
        else if (var_size > data_size - (sizeof(uint32_t) * 3))
        {
            printk(KERN_ALERT "[chipsec] ERROR: get_variable runtime service returned EFI_SUCCESS but the variable size was larger than the size passed. Possible corruption? (Should have returned \n" );
        }

		kbuf[0] = var_size;
		kbuf[1] = stat;
		// kbuf[2] = attributes from the get_variable call above
		// kbuf[3..] = contents of the variable
		if(copy_to_user((void*)ioctl_param, (void*)kbuf, data_size) > 0)
		{
            kfree(name);
            kfree(kbuf);
			return -EFAULT;
		}

		kfree(name);
		kfree(kbuf);
        
		break;
	}

    case IOCTL_SET_EFIVAR:
    {
    
        uint32_t *kbuf;
        static efi_char16_t *name;
        char *cptr, *data;
        efi_guid_t GUID;
        efi_status_t stat;
        unsigned long data_size;
        uint32_t data_size_u32, attr, datalen;
        unsigned int namelen, index;
        static struct efi *myefi;
        myefi = &efi;
    
        printk( KERN_INFO "[chipsec] > IOCTL_SET_EFIVAR\n");
        
        //IN  params: data_size, guid, attr, namelen, datalen, name, data
        //OUT params: data_size, status

        // get the size (a uint32_t)
        if(copy_from_user((void*)&data_size_u32, (void*)ioctl_param, sizeof(uint32_t)) > 0)
        {
            printk( KERN_ALERT "[chipsec] ERROR: STATUS_INVALID_PARAMETER\n" );
            return -EFAULT;
        }
        data_size = (unsigned long)data_size_u32;

        // check that this is enough to store what we will expect
        if (data_size < (sizeof(uint32_t) * 14))
        {
            printk(KERN_ALERT "[chipsec] ERROR: INVALID data_size PARAMETER\n");
            return -EFAULT;
        }
        
        // allocate that much memory
        kbuf = kzalloc(data_size, GFP_KERNEL);
        if (!kbuf)
        {
            printk(KERN_ALERT "[chipsec] ERROR: STATUS_UNSUCCESSFUL - could not allocate memory\n" );
            return -EFAULT;
        }

        // fill kbuf with user's buffer
        if(copy_from_user((void*)kbuf, (void*)ioctl_param, data_size) > 0)
        {
            printk( KERN_ALERT "[chipsec] ERROR: STATUS_INVALID_PARAMETER\n" );
            kfree(kbuf);
            return -EFAULT;
        }
        
        GUID = EFI_GUID( kbuf[1], kbuf[2], kbuf[3], kbuf[4], kbuf[5], kbuf[6], kbuf[7], kbuf[8], kbuf[9], kbuf[10], kbuf[11]);

        attr = kbuf[12];
        namelen = kbuf[13];
        datalen = kbuf[14];
        cptr = (char *)&kbuf[15];
                
        // check for namelen underflow
        if (data_size - (namelen) > data_size)
        { 
            printk(KERN_ALERT "[chipsec] ERROR: INVALID name PARAMETER (namelen = %u)\n", namelen);
            kfree(kbuf);
            return -EFAULT;
        }
        
        // make sure size that was passed in actually fits
        if (data_size - (namelen) - sizeof(uint32_t)*15 != datalen)
        {
            printk(KERN_ALERT "[chipsec] ERROR: INVALID datalen PARAMETER (%u != %lu)\n", datalen, data_size - namelen - sizeof(uint32_t)*14);
            kfree(kbuf);
            return -EFAULT;
        }
        
        // if name overflowed, we only work with the part that fit in kbuf
        name = kzalloc((namelen+1)*sizeof(efi_char16_t), GFP_KERNEL);
        if (!name)
        {
            printk(KERN_ALERT "[chipsec] ERROR: STATUS_UNSUCCESSFUL - could not allocate memory\n" );
            kfree(kbuf);
            return -EFAULT;
        }

        for(index=0; index < namelen; index++)
        {
            // upper byte is 0x0 (for ASCII), the lower byte is ASCII char
            name[index] = ((efi_char16_t)cptr[index] & 0xFF);
        }
        name[index] = (efi_char16_t)(0);
        
        data = (char *) &cptr[namelen];

        stat = myefi->set_variable(name, &GUID, attr, datalen, data);
        
        // clear kbuf before using it for output
        memset(kbuf, '\0', data_size);
        
        kbuf[0] = sizeof(uint32_t) * 2;
        kbuf[1] = stat;
        
        if (stat != EFI_SUCCESS)
        {
            print_stat(stat);
        }

        if(copy_to_user((void*)ioctl_param, (void*)kbuf, sizeof(uint32_t) * 2) > 0)
        {
            kfree(kbuf);
            kfree(name);
            return -EFAULT;
        }

        kfree(name);
        kfree(kbuf);
        
        break;

    } 

    case IOCTL_RDMMIO:
	{
        unsigned long addr, first, second;
        char *ioaddr;
		
        numargs = 2;
        printk( KERN_INFO "[chipsec] > IOCTL_RDMMIO\n");
		if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
		{
			printk( KERN_ALERT "[chipsec] ERROR: STATUS_INVALID_PARAMETER\n" );
			return -EFAULT;
		}

        addr = (unsigned long)ptr[0];
        ioaddr = my_xlate_dev_mem_ptr(addr);
        
        switch(ptr[1])
		{
			case 1:
				ptr[0] = ioread8(ioaddr);
				break;
			case 2:
				ptr[0] = ioread16(ioaddr);
				break;
			case 4:
				ptr[0] = ioread32(ioaddr);
				break;
            case 8:
                first = ioread32(ioaddr);
                second = ioread32( ioaddr + 4 );
                ptr[0] = first | (second << 32);
                break;
		}

		my_unxlate_dev_mem_ptr(addr, ioaddr);

		if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
			return -EFAULT;
		break;
	}

        case IOCTL_WRMMIO:
	{
        unsigned long addr, value;
        char *ioaddr;
		
        numargs = 3;
        printk( KERN_INFO "[chipsec] > IOCTL_WRMMIO\n");
		if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
		{
			printk( KERN_ALERT "[chipsec] ERROR: STATUS_INVALID_PARAMETER\n" );
			return -EFAULT;
		}

        addr = (unsigned long)ptr[0];
        value = (unsigned long)ptr[2];
        ioaddr = my_xlate_dev_mem_ptr(addr);
        
        switch(ptr[1])
		{
			case 1:
				iowrite8(value, ioaddr);
				break;
			case 2:
				iowrite16(value, ioaddr);
				break;
			case 4:
				iowrite32(value, ioaddr);
				break;
            case 8:
                iowrite32( ( value >> 32 ) & 0xFFFFFFFF, ioaddr );
                iowrite32( value & 0xFFFFFFFF, ioaddr + 4 );
                break;
		}

		my_unxlate_dev_mem_ptr(addr, ioaddr);

		if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
			return -EFAULT;
		break;
	}
 
	case IOCTL_VA2PA:
	{
		//IN  params: va
		//OUT params: pa
#ifdef CONFIG_X86
		PHYSICAL_ADDRESS pa;
		numargs = 1;
		if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
			return -EFAULT;

		pa.quadpart = virt_to_phys((void*)ptr[0]);
                ptr[0] = pa.quadpart;

		if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
			return -EFAULT;
		break;
#else
		return -EFAULT;
#endif
	}

   
	default:
		return -EFAULT;
	}
	return 0;
}

static int open_port(struct inode * inode, struct file * filp)
{
	return capable(CAP_SYS_RAWIO) ? 0 : -EPERM;
}

#define full_lseek      null_lseek
#define read_full       read_zero
#define open_mem	open_port
#define open_fmem	open_port

static const struct file_operations mem_fops = {
	.llseek		= memory_lseek,
	.read		= read_mem,
	.write		= write_mem,
	.mmap		= mmap_mem,
	.open		= open_mem,
	.unlocked_ioctl	= d_ioctl,
	.get_unmapped_area = get_unmapped_area_mem,
};

static int memory_open(struct inode * inode, struct file * filp)
{
	// no more kernel locking,
	// let's hope it is safe;)
	int ret = 0;

	switch (iminor(inode)) {
		case 1:
			filp->f_op = &mem_fops;

//Older kernels (<2.619) and New 4.X do not have directly_mappable_cdev_bdi
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19) || LINUX_VERSION_CODE > KERNEL_VERSION(4,0,0)
#else
			filp->f_mapping->backing_dev_info =
				&directly_mappable_cdev_bdi;
#endif 
			break;

		default:
			return -ENXIO;
	}
	if (filp->f_op && filp->f_op->open)
		ret = filp->f_op->open(inode,filp);
	return ret;
}

static const struct file_operations memory_fops = {
	.open		= memory_open,	/* just a selector for the real open */
};

static const struct {
	unsigned int		minor;
	char			*name;
	umode_t			mode;
	const struct file_operations	*fops;
} devlist[] = { /* list of minor devices */
	{1, "chipsec",     S_IRUSR | S_IWUSR | S_IRGRP, &mem_fops},
};

static struct class *mem_class;


// This function actually creates device itself.
static int __init chr_dev_init(void)
{
	int i;

	// get dynamic major num
	chipsec_mem_major = register_chrdev(0, "chipsec", &memory_fops);
	if(chipsec_mem_major < 0){
		printk(KERN_ALERT "Registering chipsec dev failed with %d\n", chipsec_mem_major);
		return chipsec_mem_major;
	}

	mem_class = class_create(THIS_MODULE, "chipsec");
	for (i = 0; i < ARRAY_SIZE(devlist); i++){

//Older kernels have one less parameter
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,26)
		device_create(mem_class, NULL,MKDEV(chipsec_mem_major, devlist[i].minor), devlist[i].name);
#else
		device_create(mem_class, NULL,MKDEV(chipsec_mem_major, devlist[i].minor), NULL, devlist[i].name);
#endif 
	}

	return 0;
}


int find_symbols(void) 
{
	//Older kernels don't have kallsyms_lookup_name. Use FMEM method (pass from run.sh)
	#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,33)
		printk("Chipsec warning: Using function addresses provided by run.sh");
		guess_page_is_ram=(void *)a1;
		dbgprint ("set guess_page_is_ram: %p\n",guess_page_is_ram);
		guess_raw_pci_read=(void *)a2;
		printk ("set guess_raw_pci_read: %p\n",guess_raw_pci_read);
		guess_raw_pci_write=(void *)a3;
		printk ("set guess_raw_pci_write: %p\n",guess_raw_pci_write);
	#else
		guess_page_is_ram   = (void *)kallsyms_lookup_name("page_is_ram");
		guess_raw_pci_read  = (void *)kallsyms_lookup_name("raw_pci_read");
		guess_raw_pci_write = (void *)kallsyms_lookup_name("raw_pci_write");

		if(guess_page_is_ram == 0 || guess_raw_pci_read == 0 || guess_raw_pci_write == 0)
		{
			printk("Chipsec find_symbols failed. Unloading module");
			return -1;
		}
	#endif 
	return 0;
}

/// Function executed upon loading module
int __init
init_module (void)
{
	int sym_status = 0;
	printk(KERN_ALERT "Chipsec module loaded \n");
	printk(KERN_ALERT "** This module exposes hardware & memory access, **\n");
	printk(KERN_ALERT "** which can effect the secure operation of      **\n");
	printk(KERN_ALERT "** production systems!! Use for research only!   **\n");

	sym_status = find_symbols();
	chr_dev_init();  
	if(sym_status) 
	{
		printk("Chipsec symbol lookup failed\n");
		cleanup_module();
		return -1;
	}
	return 0;
}

/// Function executed when unloading module
void __exit
cleanup_module (void)
{
	dbgprint ("Destroying chipsec device");
	unregister_chrdev(chipsec_mem_major, "chipsec");
	device_destroy(mem_class, MKDEV(chipsec_mem_major, 1));
	class_destroy(mem_class);
	dbgprint ("exit");
}
