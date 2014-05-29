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

#ifdef CONFIG_IA64
# include <linux/efi.h>
#endif

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

static long d_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param)
{
	int numargs = 0;
	long ptrbuf[8];
	long *ptr = ptrbuf;

	switch(ioctl_num)
	{
	case IOCTL_BASE:
		return ((IOCTL_RDIO & 0xfffffff0) >> 4);

	case IOCTL_RDIO:
		//IN  params: addr, size
		//OUT params: val
#ifdef CONFIG_X86
		numargs = 3;
		if( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs) ) > 0)
			return -EFAULT;

		switch( ptr[1] )
		{
			case 1:
				asm volatile("inb %%dx, %%al" : "=a"(ptr[2]) : "d"(ptr[0]));
				// BUGFIX: eax is returning more than a byte of data ??
				ptr[2] = ptr[2] & 0xff;
				break;
			case 2:
				asm volatile("inw %%dx, %%ax" : "=a"(ptr[2]) : "d"(ptr[0]));
				break;
			default: // 4
				asm volatile("inl %%dx, %%eax" : "=a"(ptr[2]) : "d"(ptr[0]));
				break;
		}

		if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
			return -EFAULT;
		break;
#else
		return -EFAULT;
#endif

	case IOCTL_WRIO:
		//IN params: addr, size, val
#ifdef CONFIG_X86

		numargs = 3;
		if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
			return -EFAULT;

		switch(ptr[1])
		{
			case 1:
				asm volatile("outb %%al, %%dx" : : "a"(ptr[2]),"d"(ptr[0]));
				break;
			case 2:
				asm volatile("outw %%ax, %%dx" : : "a"(ptr[2]),"d"(ptr[0]));
				break;
			default:
				asm volatile("outl %%eax, %%dx" : : "a"(ptr[2]),"d"(ptr[0]));
				break;
		}

		if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
			return -EFAULT;
		break;
#else
		return -EFAULT;
#endif

	case IOCTL_RDMSR:
		//IN  params: threadid, msr_addr
		//OUT params: edx, eax
#ifdef CONFIG_X86

		numargs = 4;
		if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
			return -EFAULT;

		asm volatile("rdmsr" : "=a"(ptr[3]),"=d"(ptr[2]) : "c"(ptr[1]));

		if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
			return -EFAULT;
		break;
#else
		return -EFAULT;
#endif

	case IOCTL_WRMSR:
		//IN params: threadid, msr_addr, edx, eax
#ifdef CONFIG_X86
		numargs = 4;
		if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
			return -EFAULT;

		asm volatile("wrmsr" :  : "a"(ptr[3]),"d"(ptr[2]),"c"(ptr[1]));

		if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
			return -EFAULT;
		break;
#else
		return -EFAULT;
#endif
	case IOCTL_CPUID:
		//IN  params: eax
		//OUT params: eax, ebx, ecx, edx
#ifdef CONFIG_X86
		numargs = 4;
		if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
			return -EFAULT;

		asm volatile( "cpuid" : "=a"(ptr[1]),"=b"(ptr[2]),"=c"(ptr[3]),"=d"(ptr[4]) : "a"(ptr[0]) );

		if(copy_to_user( (void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
			return -EFAULT;
		break;
#else
		return -EFAULT;
#endif

	case IOCTL_RDPCI:
	{
		//IN  params: dombus, devfunc, offset, len, value
		//OUT params: value
#ifdef CONFIG_PCI
		
		uint32_t bus, dev, func, offset, val;
		numargs = 5;
		if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
			return -EFAULT;
		
		bus = ptr[0] & 0xffff;
		dev = ptr[1] >> 16 & 0xffff;
		func = ptr[1] & 0xffff;
		offset = ptr[2];
		outl((0x80000000) | (bus << 16) | (dev << 11) | (func << 8) | (offset), 0xcf8);
		switch( ptr[3] ) //Size in bytes
		{
			case 1: val = inb(0xcfc); break;
			case 2: val = inw(0xcfc); break;
			default:val = inl(0xcfc); break;
		}
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
		//IN params:  dombus, devfunc, offset, len, value
		//OUT params: limit, base, pa
#ifdef CONFIG_PCI

		uint32_t bus, dev, func, offset, val;
		numargs = 5;
		if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
			return -EFAULT;

		bus = ptr[0] & 0xffff;
		dev = ptr[1] >> 16 & 0xffff;
		func = ptr[1] & 0xffff;
		offset = ptr[2];
		val = ptr[4];
		outl((0x80000000) | (bus << 16) | (dev << 11) | (func << 8) | (offset), 0xcf8);
		switch( ptr[3] ) //Size in bytes
		{
			case 1:  outb((char)val, 0xcfc);  break;
			case 2:	 outw((short)val, 0xcfc); break;
			default: outl(val, 0xcfc);        break;
		}

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
                	case CPU_DT_CODE_GDTR: { asm volatile( "sgdt %0" : "=m"( pdtr->limit )); break; }
                	case CPU_DT_CODE_LDTR: { asm volatile( "sldt %0" : "=m"( pdtr->limit )); break; }
                	case CPU_DT_CODE_IDTR: { asm volatile( "sidt %0" : "=m"( pdtr->limit )); break; }
                	default:               { asm volatile( "sidt %0" : "=m"( pdtr->limit )); break; }
              	}
		
		dt_pa.quadpart = virt_to_phys((void*)dtr.base);
		ptr[0] = dtr.limit;
		ptr[1] = (uint32_t)(dtr.base >> 32);
		ptr[2] = (uint32_t)dtr.base;
		ptr[3] = dt_pa.u.high;
		ptr[4] = dt_pa.u.low;

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

//Older kernels (<19) does not have directly_mappable_cdev_bdi
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
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
