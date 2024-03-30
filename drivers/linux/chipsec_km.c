/*
CHIPSEC: Platform Security Assessment Framework
Copyright (c) 2010-2020, Intel Corporation

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

/* grsecurity compatibility: prevent sprint_symbol() from becoming a no-op */
#if defined(CONFIG_KALLSYMS) && defined(CONFIG_GRKERNSEC_HIDESYM)
#define __INCLUDED_BY_HIDESYM 1
#endif

#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/kallsyms.h>
#include <linux/tty.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <asm/io.h>
#include <linux/smp.h>
#include <linux/miscdevice.h>

#include "include/chipsec.h"

#ifdef CONFIG_EFI
    #include <linux/efi.h>
#endif


#define CHIPSEC_VER_         1
#define CHIPSEC_VER_MINOR    2

MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
  /* 'ioremap_nocache' was deprecated in kernels >= 5.6, so instead we use 'ioremap' which
  is no-cache by default since kernels 2.6.25. */
#    define IOREMAP_NO_CACHE(address, size) ioremap(address, size)
#else /* KERNEL_VERSION < 2.6.25 */
#    define IOREMAP_NO_CACHE(address, size) ioremap_nocache(address, size)
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
#include <linux/static_call.h>
#include <linux/kprobes.h>

static unsigned long chipsec_lookup_name_scinit(const char *name);
static int chipsec_page_is_ram_scinit(unsigned long pagenr);
DEFINE_STATIC_CALL(chipsec_lookup_name_sc, chipsec_lookup_name_scinit);
DEFINE_STATIC_CALL(chipsec_page_is_ram_sc, chipsec_page_is_ram_scinit);
#endif

// function page_is_ram is not exported
// for modules, but is available in kallsyms.
// So we need determine this address using dirty tricks
static int (*guess_page_is_ram)(unsigned long pagenr);
static int chipsec_page_is_ram(unsigned long pagenr);
// same with phys_mem_accesss_prot
static
pgprot_t (*guess_phys_mem_access_prot)(struct file *file, unsigned long pfn,
                        unsigned long size, pgprot_t vma_prot);

static unsigned long a1;
static unsigned long a2;
module_param(a1,ulong,0); //a1 is addr of page_is_ram function
module_param(a2,ulong,0); //a2 is addr of phys_mem_access_prot function

/// Char we show before each debug print
static const char program_name[] = "chipsec";

// list of allocated memory
struct allocated_mem_list {
    struct list_head list;
    phys_addr_t pa;
    unsigned long va;
    unsigned int order;
};
static LIST_HEAD(allocated_mem_list);

typedef struct tagCONTEXT {
    unsigned long a;   // rax - 0x00; eax - 0x0
    unsigned long b;   // rbx - 0x08; ebx - 0x4
    unsigned long c;   // rcx - 0x10; ecx - 0x8
    unsigned long d;   // rdx - 0x18; edx - 0xc
} CONTEXT, *PCONTEXT;
typedef CONTEXT CPUID_CTX, *PCPUID_CTX;

  void __cpuid__(CPUID_CTX * ctx);

typedef struct tagSMI_CONTEXT {
    unsigned long smi_code_data; // smi_code_data - 0x00;
    unsigned long rax;           // rax - 0x08; eax - 0x04
    unsigned long rbx;           // rbx - 0x10; ebx - 0x08
    unsigned long rcx;           // rcx - 0x18; ecx - 0x0c
    unsigned long rdx;           // rdx - 0x20; edx - 0x10
    unsigned long rsi;           // rsi - 0x28; edi - 0x14
    unsigned long rdi;           // rdi - 0x30; esi - 0x18
} SMI_CONTEXT, *SMI_PCONTEXT;

typedef SMI_CONTEXT SMI_CTX, *PSMI_CTX; 

 void __swsmi__(SMI_CTX * ctx); 
 void __swsmi_timed__(SMI_CTX * ctx, unsigned long * time);

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
    unsigned short    port_num           // rdi
    );

  unsigned short
  ReadPortWord (
    unsigned short    port_num           // rdi
    );

  unsigned char
  ReadPortByte (
    unsigned short    port_num           // rdi
    );

  void
  WritePortByte (
    unsigned char    out_value,          // rdi
    unsigned short    port_num           // rsi
    );

  void
  WritePortWord (
    unsigned short    out_value,          // rdi 
    unsigned short    port_num           // rsi
    );

  void
  WritePortDword (
    unsigned int    out_value,          // rdi
    unsigned short    port_num           // rsi
    );

  void
  WritePCIByte (
    unsigned int    pci_reg,          // rdi
    unsigned short    cfg_data_port,    // rsi
    unsigned char    byte_value       // rdx
    );

  void
  WritePCIWord (
    unsigned int    pci_reg,          // rdi
    unsigned short    cfg_data_port,    // rsi
    unsigned short    word_value       // rdx
    );

  void
  WritePCIDword (
    unsigned int    pci_reg,          // rdi
    unsigned short    cfg_data_port,    // rsi
    unsigned int    dword_value      // rdx
    );

  unsigned char
  ReadPCIByte (
    unsigned int    pci_reg,          // rdi
    unsigned short    cfg_data_port    // rsi
    );

  unsigned short
  ReadPCIWord (
    unsigned int    pci_reg,          // rdi
    unsigned short    cfg_data_port    // rsi
    );

  unsigned int
  ReadPCIDword (
    unsigned int    pci_reg,          // rdi
    unsigned short    cfg_data_port    // rsi
    );

    unsigned long ReadCR0(void);
    unsigned long ReadCR2(void);
    unsigned long ReadCR3(void);
    unsigned long ReadCR4(void);
#ifdef __x86_64__
    unsigned long ReadCR8(void);
#endif

    void WriteCR0( unsigned long );
    void WriteCR2( unsigned long );
    void WriteCR3( unsigned long );
    void WriteCR4( unsigned long );
#ifdef __x86_64__
    void WriteCR8( unsigned long );
#endif

  unsigned long
  hypercall(
    unsigned long    rcx_val,
    unsigned long    rdx_val,
    unsigned long    r8_val,
    unsigned long    r9_val,
    unsigned long    r10_val,
    unsigned long    r11_val,
    unsigned long    rax_val,
    unsigned long    rbx_val,
    unsigned long    rdi_val,
    unsigned long    rsi_val,
    unsigned long    xmm_buffer,
    unsigned long    hypercall_page
    );

  unsigned long hypercall_page(void);

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

static void *my_xlate_dev_mem_ptr(unsigned long phys)
{

    void *addr=NULL;
    unsigned long start = phys & PAGE_MASK;
    unsigned long pfn = PFN_DOWN(phys);

    /* If page is RAM, we can use __va. Otherwise ioremap and unmap. */
    if (chipsec_page_is_ram(start >> PAGE_SHIFT)) {
        if (PageHighMem(pfn_to_page(pfn))) {
                /* The buffer does not have a mapping.  Map it! */
                addr = kmap(pfn_to_page(pfn));    
            return addr;
        }
        return __va(phys);
    }

    // Not RAM, so it is some device (can be bios for example)
    addr = (void __force *)IOREMAP_NO_CACHE(start, PAGE_SIZE);

    if (!addr)
        addr = (void __force *)ioremap_prot(start, PAGE_SIZE,0);

    if (addr)
        addr = (void *)((unsigned long)addr | (phys & ~PAGE_MASK));

    return addr;
}

// Our own implementation of unxlate_dev_mem_ptr
// (so we can read highmem and other)
static void my_unxlate_dev_mem_ptr(unsigned long phys,void *addr)
{
    unsigned long pfn = PFN_DOWN(phys); //get page number

    /* If page is RAM, check for highmem, and eventualy do nothing.
        Otherwise need to iounmap. */
    if (chipsec_page_is_ram((phys >> PAGE_SHIFT))) {
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)
/* copy_from_kernel_nofault and copy_to_kernel_nofault were introduced in Linux
 * 5.8.0. Before, they were called probe_kernel_read and probe_kernel_write
 * (cf. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=fe557319aa06c23cffc9346000f119547e0f289a).
 *
 * As copy_to_kernel_nofault symbol is not exported, do not use it.
 */
long copy_from_kernel_nofault(void *dst, const void *src, size_t size)
{
    return probe_kernel_read(dst, src, size);
}
#endif

/*
 * This function reads/writes *physical* memory. The f_pos points directly to
 * the memory location.
 */
static ssize_t rw_mem(struct file *file, char __user *buf, size_t count,
                loff_t *ppos, bool read)
{
    unsigned long p = *ppos;
    ssize_t bytes = 0;
    size_t sz;
    void *ptr, *bounce;
    int err;

#ifdef __ARCH_HAS_NO_PAGE_ZERO_MAPPED
    /* we don't have page 0 mapped on sparc and m68k.. */
    if (p < PAGE_SIZE) {
        sz = PAGE_SIZE - p;
        if (sz > count)
            sz = count;
        if (sz > 0) {
            if (read && clear_user(buf, sz))
                return -EFAULT;
            buf += sz;
            p += sz;
            count -= sz;
            bytes += sz;
        }
    }
#endif

    /* Allocate a bounce buffer to chain copy_from_kernel_nofault with copy_to_user */
    bounce = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!bounce) {
        printk(KERN_ALERT "[chipsec] ERROR: STATUS_UNSUCCESSFUL - could not allocate memory\n");
        return -ENOMEM;
    }

    while (count > 0) {
        /*
         * Handle first page in case it's not aligned
         */
        if (-p & (PAGE_SIZE - 1))
            sz = -p & (PAGE_SIZE - 1);
        else
            sz = PAGE_SIZE;

        if (sz > count)
            sz = count;

        /*
         * On ia64 if a page has been mapped somewhere as
         * uncached, then it must also be accessed uncached
         * by the kernel or data corruption may occur
         */
        ptr = my_xlate_dev_mem_ptr(p);
        if (!ptr){
            dbgprint("xlate FAIL, p: %lX", p);
            kfree(bounce);
            return -EFAULT;
        }

        if (read) {
            memset(bounce, 0, sz);
            err = copy_from_kernel_nofault(bounce, ptr, sz);
            if (err) {
                dbgprint("copy_from_kernel_nofault FAIL %d, ptr: %lX / %lx",
                        err, p, (unsigned long)ptr);
                my_unxlate_dev_mem_ptr(p, ptr);
                kfree(bounce);
                return -EFAULT;
            }
            err = copy_to_user(buf, bounce, sz);
            if (err) {
                dbgprint("copy_to_user FAIL %d, ptr: %lX / %lx",
                        err, p, (unsigned long)ptr);
                my_unxlate_dev_mem_ptr(p, ptr);
                kfree(bounce);
                return -EFAULT;
            }
        } else {
            /*
             * It would be safer to use probe_kernel_write() or
             * copy_to_kernel_nofault() but these functions are
             * no longer exported since Linux 5.8.0
             * (cf. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=0493cb086353e786be56010780a0b7025b5db34c)
             */
            if (copy_from_user(bounce, buf, sz)) {
                dbgprint("copy_from_user FAIL, ptr: %lX / %lx",
                        p, (unsigned long)ptr);
                my_unxlate_dev_mem_ptr(p, ptr);
                kfree(bounce);
                return -EFAULT;
            }
            memcpy(ptr, bounce, sz);
        }

        my_unxlate_dev_mem_ptr(p, ptr);

        buf += sz;
        p += sz;
        count -= sz;
        bytes += sz;
    }
    *ppos += bytes;
    kfree(bounce);
    return bytes;
}

static ssize_t read_mem(struct file *file, char __user *buf, size_t count,
            loff_t *ppos)
{
    return rw_mem(file, buf, count, ppos, true);
}

static ssize_t write_mem(struct file *file, const char __user *buf,
                size_t count, loff_t *ppos)
{
    return rw_mem(file, (char __user *)buf, count, ppos, false);
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
#define get_unmapped_area_mem    NULL

static inline int private_mapping_ok(struct vm_area_struct *vma)
{
    return 1;
}
#endif

int __weak phys_mem_access_prot_allowed(struct file *file,
            unsigned long pfn, unsigned long size, pgprot_t *vma_prot)
{
        return 1;
}

#if defined(__HAVE_ARCH_PAX_OPEN_USERLAND)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,14,0) && defined(ARCH_HAS_VALID_PHYS_ADDR_RANGE)
int valid_mmap_phys_addr_range(unsigned long pfn, size_t size)
{
    return 1;
}
#endif

#else

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,12) && defined(ARCH_HAS_VALID_PHYS_ADDR_RANGE)
int valid_mmap_phys_addr_range(unsigned long pfn, size_t size)
{
    return 1;
}
#endif
#endif

#ifndef ARCH_HAS_VALID_PHYS_ADDR_RANGE
static inline int valid_phys_addr_range(phys_addr_t addr, size_t count)
{
    return addr + count <= __pa(high_memory);
}

static inline int valid_mmap_phys_addr_range(unsigned long pfn, size_t size)
{
    return 1;
}
#endif

#ifndef __HAVE_PHYS_MEM_ACCESS_PROT
static pgprot_t cs_phys_mem_access_prot(struct file *file, unsigned long pfn,
                    unsigned long size, pgprot_t vma_prot)
{
#ifdef pgprot_noncached
    phys_addr_t offset = pfn << PAGE_SHIFT;

    if (uncached_access(file, offset))
        return pgprot_noncached(vma_prot);
#endif
    return vma_prot;
}
#endif

static phys_addr_t virt_2_phys(void *vaddr)
{
#if defined(CONFIG_X86) && LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
    if (!virt_addr_valid(vaddr))
    return slow_virt_to_phys(vaddr);
#endif
    return virt_to_phys(vaddr);
}

static const struct vm_operations_struct mmap_mem_ops = {
#ifdef CONFIG_HAVE_IOREMAP_PROT
    .access = generic_access_phys
#endif
};

static int mmap_mem(struct file * file, struct vm_area_struct * vma)
{
    size_t size = vma->vm_end - vma->vm_start;

    if (!valid_mmap_phys_addr_range(vma->vm_pgoff, size)) {
        return -EINVAL;
    }

    if (!private_mapping_ok(vma)) {
        return -ENOSYS;
    }

    if (!phys_mem_access_prot_allowed(file, vma->vm_pgoff, size,
                        &vma->vm_page_prot)) {
        return -EINVAL;
    }

    // We skip devmem_is_allowed / range_is_allowed checking here
    // because we want to be able to mmap MMIO regions
    
    vma->vm_page_prot = guess_phys_mem_access_prot(file, vma->vm_pgoff,
                                 size,
                                vma->vm_page_prot);

    vma->vm_ops = &mmap_mem_ops;

    if (remap_pfn_range(vma,
                vma->vm_start,
                vma->vm_pgoff,
                size,
                vma->vm_page_prot)) {
        return -EAGAIN;
    }

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
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0)
    inode_lock(file->f_path.dentry->d_inode);
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
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0)
    inode_unlock(file->f_path.dentry->d_inode);
#else
    mutex_unlock(&file->f_path.dentry->d_inode->i_mutex);
#endif 

    return ret;
}

#ifdef EFI_NOT_READY
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
#endif

static void apply_ucode_patch(void *info)
{
    CPUID_CTX *cpuinfo = (CPUID_CTX *)info;
    __cpuid__(cpuinfo);
}

static unsigned long hypercall_page_c(void)
{
    return hypercall_page();
}

static long d_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param)
{
    int numargs = 0;
    unsigned long ptrbuf[16];
    unsigned long *ptr = ptrbuf;
    unsigned short ucode_size;
    unsigned short thread_id;
    char *ucode_buf;
    //unsigned int counter;
    char small_buffer[6]; //32 bits + char + \0
    unsigned long CPUInfo[4]={1,0,0,0};

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
        return -EOPNOTSUPP;
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
        return -EOPNOTSUPP;
#endif
    }

    case IOCTL_LOAD_UCODE_PATCH:
    {

#ifdef CONFIG_X86
        unsigned long long ucode_start = 0;
        u32 _eax[2] = {0}, _edx[2] = {0};
        ucode_size=0;

        printk(KERN_INFO "[chipsec][IOCTL_LOAD_UCODE_UPDATE] Initializing update routine\n");

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

        ucode_start = (unsigned long long) ucode_start;
        memset(ucode_buf, 0, ucode_size);

        if ( copy_from_user(ucode_buf, (unsigned char *)(ioctl_param+sizeof(unsigned char)+sizeof(unsigned short)), ucode_size) > 0 )
            return -EFAULT;

        printk(KERN_INFO "[chipsec] [patch_apply_ucode] Checking current patch ID");
        rdmsr_on_cpu(thread_id, MSR_IA32_BIOS_SIGN_ID, (u32*)&_eax[0], (u32*)&_edx[0]);

        printk(KERN_INFO "[chipsec] [patch_apply_ucode] Applying patch in the processor id: %d", thread_id);
        wrmsr_on_cpu(thread_id, MSR_IA32_BIOS_UPDT_TRIG, (u32)ucode_start, (u32)((ucode_start >> 32) & 0xffffffff));

        kfree(ucode_buf);

        printk(KERN_INFO "[chipsec] [patch_apply_ucode] checking ucode update was loaded..\n");
        printk(KERN_INFO "[chipsec] [patch_apply_ucode] clear IA32_BIOS_SIGN_ID, CPUID EAX=1, read back IA32_BIOS_SIGN_ID\n" );

        wrmsr_on_cpu(thread_id, MSR_IA32_BIOS_SIGN_ID, (u32)_eax[1], (u32)_edx[1]);
        smp_call_function_single(thread_id, apply_ucode_patch, (void *)CPUInfo,0);
        rdmsr_on_cpu(thread_id, MSR_IA32_BIOS_SIGN_ID, (u32*)&_eax[1], (u32*)&_edx[1]);

        if (_edx[1] != _edx[0])
            printk(KERN_INFO "[chipsec][IOCTL_LOAD_UCODE_UPDATE] Microcode update loaded (ID != %u)\n", _edx[0]);
        else
            printk(KERN_INFO "[chipsec][IOCTL_LOAD_UCODE_UPDATE] Microcode update failed"); 

        break;
#else
        return -EOPNOTSUPP;
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

        rdmsr_on_cpu(ptr[0], ptr[1], (u32*)&ptr[3], (u32*)&ptr[2]);
        //_rdmsr(ptr[1],&ptr[3],&ptr[2]);

        if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
            return -EFAULT;
        break;
#else
        return -EOPNOTSUPP;
#endif
    }

    case IOCTL_WRMSR:
    {
        //IN params: threadid, msr_addr, {e,r}dx, {e,r}ax
#ifdef CONFIG_X86
        numargs = 4;
        if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
            return -EFAULT;

        wrmsr_on_cpu(ptr[0], ptr[1], (u32)ptr[3], (u32)ptr[2]);
        //_wrmsr(ptr[1],ptr[3],ptr[2]);

        if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
            return -EFAULT;
        break;
#else
        return -EOPNOTSUPP;
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
        return -EOPNOTSUPP;
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
        return -EOPNOTSUPP;
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
        return -EOPNOTSUPP;
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
            default:
                return -EINVAL;
                  }
        
        dt_pa.quadpart = virt_2_phys((void*)dtr.base);
        ptr[0] = dtr.limit;
        #ifdef __x86_64__
        ptr[1] = (uint32_t)(dtr.base >> 32);
        #else
        ptr[1] = 0;
        #endif
        ptr[2] = (uint32_t)dtr.base;

        //#pragma GCC diagnostic ignored "-Wuninitialized" dt_pa.u.high
        //#pragma GCC diagnostic ignored "-Wuninitialized" dt_pa.u.low
        ptr[3] = dt_pa.u.high;
        ptr[4] = dt_pa.u.low;

        if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
            return -EFAULT;
        break;
#else
        return -EOPNOTSUPP;
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
        return -EOPNOTSUPP;
#endif
    }

    case IOCTL_SWSMI_TIMED:
    {
        //IN params: SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi
#ifdef CONFIG_X86

        printk( KERN_INFO "[chipsec] > IOCTL_SWSMI_TIMED\n");
        numargs = 7;
        if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
        {
            printk( KERN_ALERT "[chipsec] ERROR: STATUS_INVALID_PARAMETER\n" );
            break;
        }

        unsigned long m_time;
        preempt_disable();
        __swsmi_timed__((SMI_CTX *)ptr, &m_time);
        preempt_enable();
        ptrbuf[numargs] = m_time;

        if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * (numargs + 1))) > 0)
            return -EFAULT;
        break;
#else
        return -EOPNOTSUPP;
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
        return -EOPNOTSUPP;
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
        return -EOPNOTSUPP;
#endif
        }
    case IOCTL_ALLOC_PHYSMEM:
    {
        //IN params: size
        //OUT params: physical address
        uint32_t NumberOfBytes = 0;
        unsigned int order;
        unsigned long va = 0;
        phys_addr_t pa, max_pa;
        struct allocated_mem_list *tmp = NULL;

        numargs = 2;
        if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
        {
            printk( KERN_ALERT "[chipsec] ERROR: STATUS_INVALID_PARAMETER\n" );
            return -EFAULT;
        }

        NumberOfBytes = ptr[0];
        max_pa = ptr[1];
        order = get_order(NumberOfBytes);

        if (max_pa <= U32_MAX) {
            if (max_pa > 16 * 1024 * 1024)
                va = __get_free_pages(GFP_KERNEL | __GFP_ZERO | __GFP_DMA32, order);
            else
                va = __get_free_pages(GFP_KERNEL | __GFP_ZERO | __GFP_DMA, order);
        }
        if (!va)
            va = __get_free_pages(GFP_KERNEL | __GFP_ZERO, order);
        if (!va) {
            printk(KERN_ALERT "[chipsec] ERROR: STATUS_UNSUCCESSFUL - could not allocate memory\n" );
            return -ENOMEM;
        }

        pa = virt_to_phys((void *)va);
        if (pa > max_pa) {
            printk(KERN_ALERT "[chipsec] ERROR: allocated memory (0x%llx) is not below max_pa (0x%llx)", pa, max_pa);
            free_pages(va, order);
            return -ENOMEM;
        }

        tmp = kmalloc(sizeof(struct allocated_mem_list), GFP_KERNEL);
        if (tmp == NULL) {
            printk(KERN_ALERT "[chipsec] ERROR: STATUS_UNSUCCESSFUL - could not allocate memory\n");
            free_pages(va, order);
            return -ENOMEM;
        }

        tmp->va = va;
        tmp->pa = pa;
        tmp->order = order;
        list_add(&tmp->list, &allocated_mem_list);

        ptr[0] = va;
        ptr[1] = pa;
        
        if (copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
            return -EFAULT;

        break;
    }

    case IOCTL_FREE_PHYSMEM:
    {
        // IN params : physical address
        // OUT params : 0 not freed, 1 freed
        struct allocated_mem_list *e;
        phys_addr_t pa;

        numargs = 1;
        if (copy_from_user((void*) ptrbuf, (void*) ioctl_param, (sizeof(long) * numargs)) > 0) {
            printk( KERN_ALERT "[chipsec] ERROR: STATUS_INVALID_PARAMETER\n" );
            return -EFAULT;
        }

        pa = ptr[0];

        // look for pa inside allocated mem list
        list_for_each_entry(e, &allocated_mem_list, list) {
            if (e->pa == pa) {
                list_del(&e->list);
                break;
            }
        }

        if (&e->list != &allocated_mem_list) {
            // freeing
            printk(KERN_INFO "[chipsec] freeing pa = 0x%llx, va = 0x%lx\n", pa, e->va);
            free_pages(e->va, e->order);
            kfree(e);
            ptr[0] = 1;
        } else {
            printk(KERN_ERR "[chipsec] allocation for pa = 0x%llx not found!\n", pa);
            ptr[0] = 0;
        }

        if (copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
            return -EFAULT;

        break;
    }
   
#ifdef EFI_NOT_READY
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
            return -EINVAL;
        }
        
        // allocate that much memory
        kbuf = kzalloc(data_size, GFP_KERNEL);
        if (!kbuf)
        {
            printk(KERN_ALERT "[chipsec] ERROR: STATUS_UNSUCCESSFUL - could not allocate memory\n" );
            return -ENOMEM;
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
            kfree(kbuf);
            printk(KERN_ALERT "[chipsec] ERROR: INVALID SIZE PARAMETER (namelen %u too big for data_size %lu)\n", namelen, data_size);
            return -EINVAL;
        }
        
        // if name overflowed, we only work with the part that fit in kbuf
        name = kzalloc((namelen+1)*sizeof(efi_char16_t), GFP_KERNEL);
        if (!name)
        {
            kfree(kbuf);
            printk(KERN_ALERT "[chipsec] ERROR: STATUS_UNSUCCESSFUL - could not allocate memory\n" );
            return -ENOMEM;
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
            return -EINVAL;
        }
        
        // allocate that much memory
        kbuf = kzalloc(data_size, GFP_KERNEL);
        if (!kbuf)
        {
            printk(KERN_ALERT "[chipsec] ERROR: STATUS_UNSUCCESSFUL - could not allocate memory\n" );
            return -ENOMEM;
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
            return -EINVAL;
        }
        
        // make sure size that was passed in actually fits
        if (data_size - (namelen) - sizeof(uint32_t)*15 != datalen)
        {
            printk(KERN_ALERT "[chipsec] ERROR: INVALID datalen PARAMETER (%u != %lu)\n", datalen, data_size - namelen - sizeof(uint32_t)*14);
            kfree(kbuf);
            return -EINVAL;
        }
        
        // if name overflowed, we only work with the part that fit in kbuf
        name = kzalloc((namelen+1)*sizeof(efi_char16_t), GFP_KERNEL);
        if (!name)
        {
            printk(KERN_ALERT "[chipsec] ERROR: STATUS_UNSUCCESSFUL - could not allocate memory\n" );
            kfree(kbuf);
            return -ENOMEM;
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
#endif

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
        if (!ioaddr) {
            printk(KERN_ALERT "[chipsec] ERROR: failed to xlate 0x%lx\n", addr);
            return -EIO;
        }

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
            #ifdef __x86_64__
            case 8:
                first = ioread32(ioaddr);
                second = ioread32( ioaddr + 4 );
                ptr[0] = first | (second << 32);
                break;
            #endif
        }

        my_unxlate_dev_mem_ptr(addr, ioaddr);

        if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
            return -EFAULT;
        break;
    }

        case IOCTL_WRMMIO:
    {
        unsigned long addr, value, first, second;
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
        if (!ioaddr) {
            printk(KERN_ALERT "[chipsec] ERROR: failed to xlate 0x%lx\n", addr);
            return -EIO;
        }

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
            #ifdef __x86_64__
                first = value & 0xFFFFFFFF;
                second = (value >> 32) & 0xFFFFFFFF;

                iowrite32(first, ioaddr);
                iowrite32(second, ioaddr + 4);
            #endif
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
        phys_addr_t pa;
        void *va;

        numargs = 1;
        if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
            return -EFAULT;

        va = (void*)ptr[0];
        if (!virt_addr_valid(va))
            return -EINVAL;

        pa = virt_to_phys(va);
        ptr[0] = pa;

        if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
            return -EFAULT;
        break;
#else
        return -EOPNOTSUPP;
#endif
    }

        case IOCTL_HYPERCALL:
        {
        numargs = 11;
        if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(ptrbuf[0]) * numargs)) > 0)
        {
            printk( KERN_ALERT "[chipsec] ERROR: STATUS_INVALID_PARAMETER\n" );
            return -EFAULT;
        }

        #ifdef HYPERCALL_DEBUG
        printk( KERN_DEBUG "[chipsec] > IOCTL_HYPERCALL\n");
        #ifdef __x86_64__
        printk( KERN_DEBUG "    RAX = 0x%016lX  RBX = 0x%016lX\n", ptrbuf[6], ptrbuf[7] );
        printk( KERN_DEBUG "    RCX = 0x%016lX  RDX = 0x%016lX\n", ptrbuf[0], ptrbuf[1] );
        printk( KERN_DEBUG "    RDI = 0x%016lX  RSI = 0x%016lX\n", ptrbuf[8], ptrbuf[9] );
        printk( KERN_DEBUG "    R8  = 0x%016lX  R9  = 0x%016lX\n", ptrbuf[2], ptrbuf[3] );
        printk( KERN_DEBUG "    R10 = 0x%016lX  R11 = 0x%016lX\n", ptrbuf[4], ptrbuf[5] );
        #else
        printk( KERN_DEBUG "    EAX = 0x%08lX  EBX = 0x%08lX  ECX = 0x%08lX\n", ptrbuf[6], ptrbuf[7], ptrbuf[0] );
        printk( KERN_DEBUG "    EDX = 0x%08lX  ESI = 0x%08lX  EDI = 0x%08lX\n", ptrbuf[1], ptrbuf[8], ptrbuf[9] );
        #endif
        printk( KERN_DEBUG "    XMM0-XMM5 buffer VA = 0x%016lX\n", ptrbuf[10] );
        printk( KERN_DEBUG "    Hypercall page VA   = 0x%016lX\n", ptrbuf[11]);
        #endif

        ptrbuf[0]  = hypercall(ptrbuf[0], ptrbuf[1], ptrbuf[2], ptrbuf[3], ptrbuf[4], ptrbuf[5], ptrbuf[6], ptrbuf[7], ptrbuf[8], ptrbuf[9], ptrbuf[10], (unsigned long)&hypercall_page_c);

        #ifdef HYPERCALL_DEBUG
        printk( KERN_DEBUG "    Hypercall status    = 0x%016lX\n", ptrbuf[0]);
        #endif

        if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, sizeof(ptrbuf[0])) > 0)
            return -EFAULT;
        break;
        }

    case IOCTL_MSGBUS_SEND_MESSAGE:
    {
        //IN  params: direction, mcr, mcrx, mdr
        //OUT params: mdr_out
#ifdef CONFIG_X86
        uint32_t direction, mcr, mcrx, mdr, mdr_out;
        numargs = 5;
        printk( KERN_INFO "[chipsec] > IOCTL_MSGBUS_SEND_MESSAGE\n");

        if(copy_from_user((void*)ptrbuf, (void*)ioctl_param, (sizeof(long) * numargs)) > 0)
            return -EFAULT;

        mdr_out   = 0;        
        direction = ptr[0];
        mcr       = ptr[1];
        mcrx      = ptr[2];
        mdr       = ptr[3];

        if (direction & MSGBUS_MDR_IN_MASK)
            // Write data to MDR register
            WritePCICfg( MSGBUS_BUS, MSGBUS_DEV, MSGBUS_FUN, MDR, 4, mdr );

        // Write extended address to MCRX register if address is > 0xFF
        if (mcrx != 0)
            WritePCICfg( MSGBUS_BUS, MSGBUS_DEV, MSGBUS_FUN, MCRX, 4, mcrx );

        // Write to MCR register to send the message on the message bus
        WritePCICfg( MSGBUS_BUS, MSGBUS_DEV, MSGBUS_FUN, MCR, 4, mcr );

        if (direction & MSGBUS_MDR_OUT_MASK) {
            // Read data from MDR register
            mdr_out = ReadPCICfg( MSGBUS_BUS, MSGBUS_DEV, MSGBUS_FUN, MDR, 4 );
            ptr[4] = mdr_out;
        }

        if(copy_to_user((void*)ioctl_param, (void*)ptrbuf, (sizeof(long) * numargs)) > 0)
            return -EFAULT;
        break;
#else
        return -EOPNOTSUPP;
#endif
    }

   
    default:
        return -EINVAL;
    }
    return 0;
}

static int open_port(struct inode * inode, struct file * filp)
{
    return capable(CAP_SYS_RAWIO) ? 0 : -EPERM;
}

static const struct file_operations mem_fops = {
    .llseek        = memory_lseek,
    .read        = read_mem,
    .write        = write_mem,
    .mmap        = mmap_mem,
    .open        = open_port,
    .unlocked_ioctl    = d_ioctl,
    .get_unmapped_area = get_unmapped_area_mem,
};

static struct miscdevice chipsec_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "chipsec",
    .fops = &mem_fops
};

/*
 * 0ld dog never die:
 * https://gist.githubusercontent.com/GoldenOak/a8cd563d671af04a3d387d198aa3ecf8/raw/8dcc90dbbf9b9ffd65cc2c03f1cd48445b84c2b6/obtain_syscall_table_by_proc.c
 *
 * Using kernel_read directly was disabled in Linux 5.10 with commit
 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=4d03e3cc59828c82ee89ea6e27a2f3cdf95aaadf
 * because /proc/kallsyms does not implement ->f_op->read_iter.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0) && LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)

static unsigned long chipsec_lookup_name(const char *name)
{
    unsigned int i = 0, first_space_idx = 0, second_space_idx = 0; /* Read Index and indexes of spaces */
    struct file *proc_ksyms = NULL;
    loff_t pos = 0;
    unsigned long ret = 0;
    ssize_t read = 0;
    int err = 0;
    const size_t name_len = strlen(name);

    /*
     * Buffer for each line of kallsyms file.
     * Linux defines KSYM_NAME_LEN to 512 since 6.1, with a rational documented in commit
     * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/include/linux/kallsyms.h?id=b8a94bfb33952bb17fbc65f8903d242a721c533d
     */
    char proc_ksyms_entry[512] = {0};

    proc_ksyms = filp_open("/proc/kallsyms", O_RDONLY, 0);
    if (proc_ksyms == NULL)
        goto cleanup;

    read = kernel_read(proc_ksyms, proc_ksyms_entry + i, 1, &pos);
    while (read == 1) {
        if (proc_ksyms_entry[i] == '\n' || (size_t)i == sizeof(proc_ksyms_entry) - 1) {
            /* Prefix-match the name with the 3rd field of the line, after the second space */
            if (second_space_idx > 0 &&
                second_space_idx + 1 + name_len <= sizeof(proc_ksyms_entry) &&
                !strncmp(proc_ksyms_entry + second_space_idx + 1, name, name_len)) {
                printk(KERN_INFO "[+] %s: %.*s\n", name,
                        i, proc_ksyms_entry);
                /* Decode the address, which is in hexadecimal */
                proc_ksyms_entry[first_space_idx] = '\0';
                err = kstrtoul(proc_ksyms_entry, 16, &ret);
                if (err) {
                    printk(KERN_ERR "kstrtoul returned error %d while parsing %.*s\n",
                            err, first_space_idx, proc_ksyms_entry);
                    ret = 0;
                    goto cleanup;
                }
                goto cleanup;
            }

            i = 0;
            first_space_idx = 0;
            second_space_idx = 0;
            memset(proc_ksyms_entry, 0, sizeof(proc_ksyms_entry));
        } else {
            if (proc_ksyms_entry[i] == ' ') {
                if (first_space_idx == 0) {
                    first_space_idx = i;
                } else if (second_space_idx == 0) {
                    second_space_idx = i;
                }
            }
            i++;
        }
        read = kernel_read(proc_ksyms, proc_ksyms_entry + i, 1, &pos);
    }
    printk(KERN_ERR "symbol not found in kallsyms: %s\n", name);

cleanup:
    if (proc_ksyms != NULL)
        filp_close(proc_ksyms, 0);
    return ret;
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name",
    .flags = KPROBE_FLAG_DISABLED
};

static unsigned long chipsec_lookup_name_scinit(const char *name)
{
    unsigned long (*chipsec_lookup_name_fp)(const char *name) = NULL;
    int kp_ret;

    // try kprobes first, but have a fallback as they might be disabled
    kp_ret = register_kprobe(&kp);
    if (kp_ret < 0) {
        dbgprint("register_kprobe failed, returned %d", kp_ret);
    } else {
        chipsec_lookup_name_fp = (unsigned long (*) (const char *name))kp.addr;
        unregister_kprobe(&kp);
    }

    // brute force by doing a symbolic search via sprint_symbol
    if (!chipsec_lookup_name_fp) {
        char name[KSYM_NAME_LEN];
        unsigned long search_range = 32 * 1024;    // covers all of kallsyms.o
        unsigned long start = (unsigned long) sprint_symbol + search_range;
        unsigned long end = start - 2 * search_range;
        unsigned long addr, offset;
        char *off_ptr;

        /* gcc's -freorder-functions, which is enabled by default at -O2 / -Os
         * may put kallsyms_lookup_name() after sprint_symbol(). So we have to
         * search in both directions.
         *
         * Do it top down to start with a valid kernel .text address for sure.
         */
        for (addr = start; addr > end; addr--) {
            if (sprint_symbol(name, addr) <= 0)
                break;
            if (!strncmp(name, "0x", 2))
                break;
            off_ptr = strchr(name, '+');
            if (!off_ptr)
                break;
            if (sscanf(off_ptr, "+%lx", &offset) != 1)
                break;
            addr -= offset;
            if (off_ptr - name == 20 &&
                !strncmp(name, "kallsyms_lookup_name", 20))
            {
                chipsec_lookup_name_fp = (void *)addr;
                break;
            }
        }

        if (!chipsec_lookup_name_fp)
            dbgprint("lookup via sprint_symbol() failed, too");
    }

    if (chipsec_lookup_name_fp) {
        static_call_update(chipsec_lookup_name_sc, chipsec_lookup_name_fp);
        return static_call(chipsec_lookup_name_sc)(name);
    }

    return 0;
}

static unsigned long chipsec_lookup_name(const char *name)
{
    return static_call(chipsec_lookup_name_sc)(name);
}

#else

static unsigned long chipsec_lookup_name(const char *name){
    return kallsyms_lookup_name(name);
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)

static int chipsec_page_is_ram_scinit(unsigned long pagenr)
{
    BUG_ON(guess_page_is_ram == NULL);    // resolved in find_symbols()
    static_call_update(chipsec_page_is_ram_sc, guess_page_is_ram);
    return static_call(chipsec_page_is_ram_sc)(pagenr);
}

static int chipsec_page_is_ram(unsigned long pagenr)
{
    return static_call(chipsec_page_is_ram_sc)(pagenr);
}

#else

static int chipsec_page_is_ram(unsigned long pagenr)
{
    BUG_ON(guess_page_is_ram == NULL);    // resolved in find_symbols()
    return guess_page_is_ram(pagenr);
}

#endif

static int find_symbols(void)
{
    //Older kernels don't have kallsyms_lookup_name. Use FMEM method (pass from run.sh)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,33)
    printk("Chipsec warning: Using function addresses provided by run.sh");
    guess_page_is_ram=(void *)a1;
    dbgprint ("set guess_page_is_ram: %p",guess_page_is_ram);
    #ifdef __HAVE_PHYS_MEM_ACCESS_PROT
    guess_phys_mem_access_prot=(void *)a2;
    dbgprint ("set guess_phys_mem_acess_prot: %p",guess_phys_mem_access_prot);
    #else
    guess_phys_mem_access_prot = &cs_phys_mem_access_prot;
    #endif
#else
    guess_page_is_ram = (void *)chipsec_lookup_name("page_is_ram");
    #ifdef __HAVE_PHYS_MEM_ACCESS_PROT
    guess_phys_mem_access_prot = (void *)chipsec_lookup_name("phys_mem_access_prot");
    #else
    guess_phys_mem_access_prot = &cs_phys_mem_access_prot;
    #endif
#endif
    if (guess_page_is_ram == 0 || guess_phys_mem_access_prot == 0) {
        printk("Chipsec find_symbols failed. Unloading module");
        return -1;
    }

    return 0;
}

/// Function executed upon loading module
int __init
init_module (void)
{
    int ret = 0;
    printk(KERN_ALERT "Chipsec module loaded \n");
    printk(KERN_ALERT "** This module exposes hardware & memory access, **\n");
    printk(KERN_ALERT "** which can effect the secure operation of      **\n");
    printk(KERN_ALERT "** production systems!! Use for research only!   **\n");

    ret = find_symbols();
    if (ret)
    {
        printk("Chipsec symbol lookup failed\n");
        return -EOPNOTSUPP;
    }
    ret = misc_register(&chipsec_dev);
    if (ret)
    {
        printk("Unable to register the chipsec device\n");
        return ret;
    }

    return 0;
}

/// Function executed when unloading module
void cleanup_module (void)
{
    struct allocated_mem_list *e, *tmp;

    dbgprint ("Destroying chipsec device");
    misc_deregister(&chipsec_dev);
    dbgprint ("exit");

    // freeing
    list_for_each_entry_safe(e, tmp, &allocated_mem_list, list) {
        printk(KERN_INFO "auto freeing allocated memory (va = 0x%lx, pa = 0x%llx)\n", e->va, e->pa);
        free_pages(e->va, e->order);
        list_del(&e->list);
        kfree(e);
    }
}
