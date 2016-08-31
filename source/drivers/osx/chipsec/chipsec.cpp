// This driver implements a character device that can be used to read physical
// memory from user space. It creates a node "/dev/chipsec", which can be read by
// user "root" and group "wheel".
//
// Copyright 2012, 2016 Google Inc. All Rights Reserved.
// Authors: Thiebaud Weksteen (tweksteen@gmail.com)
//   (pmem) Johannes Stüttgen (johannes.stuettgen@gmail.com)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "chipsec.h"
#include "cpu.h"

// Tagname for memory allocations in the kernel.
static const char * const pmem_tagname = "PMEM";

// Name of the physical memory device in '/dev/'.
static const char * const chipsec_devname = "chipsec";
// Minor numbers for devfs files
static const int chipsec_dev_minor = 0;
// Node <-> Driver mappings.
static int chipsec_dev_major = 0;
static void *pmem_devpmemnode = NULL;

// Tagname to use with the kernel malloc functions.
static OSMallocTag pmem_tag = NULL;
// Global buffer to cache physical pages.
static uint8_t *pmem_zero_page = NULL;

// This is the switch table for the character device.
// It registers callbacks for the device file.
// See: xnu/bsd/sys/conf.h
static struct cdevsw pmem_cdevsw = {
    reinterpret_cast<d_open_t *>(&nulldev),   // d_open
    reinterpret_cast<d_close_t *>(&nulldev),  // d_close
    pmem_read,                                // d_read
    eno_rdwrt,                                // d_write
    pmem_ioctl,                               // d_ioctl
    eno_stop,                                 // d_stop
    eno_reset,                                // d_reset
    0,                                        // d_ttys
    eno_select,                               // handler for select()
    eno_mmap,                                 // handler for mmap()
    eno_strat,                                // d_strategy
    eno_getc,                                 // putc()
    eno_putc,                                 // getc()
    D_TTY                                     // d_type
};

#ifdef DEBUG
void log_addr(uint64_t addr, unsigned int length, const char *name)
{
    int i;
    uint64_t ad = 0;

    for(i=length; i>=0; i--)
    {
        if((addr >> i) & 0x1)
        {
            ad |= 0x1;
        }
        ad <<= 1;
    }
    printf("%s = %llx\n", name, ad);
}
#else
void log_addr(uint64_t addr, unsigned int length, const char *name) {}
#endif

// Prints debug messages to the kernel log buffer (Read with dmesg).
// This function will only be active if pmem_debug_logging is set to TRUE.
//
// args: fmt must be a format string.
// ...: an arbitrary amount of arguments for the format string may follow.
#if DEBUG
static void pmem_log(const char *fmt, ...) {
    va_list argptr;

    va_start(argptr, fmt);
    vprintf(fmt, argptr);
    printf("\n");
    va_end(argptr);
}
#else
static void pmem_log(const char *fmt, ...) { }
#endif

// Prints errors to the kernel log buffer (read with dmesg).
//
// args: fmt musst be a format string.
// ...: an arbitrary amount of arguments for the format string may follow.
#ifdef DEBUG
static void pmem_error(const char *fmt, ...) {
    va_list argptr;

    va_start(argptr, fmt);
    printf("Error: ");
    vprintf(fmt, argptr);
    printf("\n");
    va_end(argptr);
}
#else
static void pmem_error(const char *fmt, ...) { }
#endif

uint32_t ReadPCICfg(uint8_t bus, uint8_t dev, uint8_t fun, uint8_t off,
                    uint8_t len)
{
    unsigned int result = 0;
    unsigned int pci_addr = (0x80000000 | (bus << 16) | (dev << 11) |
                             (fun << 8) | (off & ~3));
    unsigned short cfg_data_port = (uint16_t)(0xCFC + (off & 0x3));
    switch(len) {
        case 1:
            result = (ReadPCIByte (pci_addr, cfg_data_port) & 0xFF);
            break;
        case 2:
            result = (ReadPCIWord (pci_addr, cfg_data_port) & 0xFFFF);
            break;
        case 4:
            result = ReadPCIDword(pci_addr, cfg_data_port);
            break;
    }
    return result;
}

void WritePCICfg(uint8_t bus, uint8_t dev, uint8_t fun, uint8_t off,
                 uint8_t len, uint32_t val)
{
    uint32_t pci_addr = (0x80000000 | (bus << 16) | (dev << 11) |
                         (fun << 8) | (off & ~3));
    uint16_t cfg_data_port = (uint16_t)(0xCFC + (off & 0x3));
    switch(len) {
        case 1:
            WritePCIByte(pci_addr, cfg_data_port, (uint8_t)(val & 0xFF));
            break;
        case 2:
            WritePCIWord(pci_addr, cfg_data_port, (uint16_t)(val & 0xFFFF));
            break;
        case 4:
            WritePCIDword(pci_addr, cfg_data_port, val);
            break;
    }
}

// This function is called whenever a program in user space tries to read from
// the device file. It will dispatch the appropriate function for the file that
// is read by inspecting the given minor number.
//
// args:
//  dev: Device struct [minor(dev) returns minor number]
//  uio: Structure representing the I/O request
//  r:   This will always be UIO_READ, as we only register this function for
//       reads. Do not register for writes, your buffer will get overwritten.
//
// return: KERN_SUCCESS, always.
//
// This function will always succeed, in case of errors the uio is zero padded.
static kern_return_t pmem_read(dev_t dev, struct uio *uio, __unused int rw) {
    if (minor(dev) == chipsec_dev_minor) {
        return pmem_read_memory(uio);
    } else {
        return EFAULT;
    }
}

// This function uses as many pmem_partial_read() calls as necessary,
// to copy uio->resid bytes of physical memory from the physical address, as
// specified in uio->offset to the buffer in the uio.
static kern_return_t pmem_read_memory(struct uio *uio) {
    size_t read_bytes = 0;

    while (uio_resid(uio) > 0) {
        uio_update(uio, 0);
        // Try to read as many times as necessary until the uio is full.
        read_bytes = pmem_partial_read(uio, uio_offset(uio),
                                       uio_offset(uio) + uio_curriovlen(uio));
        uio_update(uio, read_bytes);
    }
    return KERN_SUCCESS;
}

// Copy the requested amount to userspace if it doesn't cross page boundaries
// or memory mapped io. If it does, stop at the boundary. Will copy zeroes
// if the given physical address is not backed by physical memory.
//
// args: uio is the userspace io request object
// return: number of bytes copied successfully
//
static uint64_t pmem_partial_read(struct uio *uio, addr64_t start_addr,
                                  addr64_t end_addr) {
    // Separate page and offset
    uint64_t page_offset = start_addr & PAGE_MASK;
    addr64_t page = trunc_page_64(start_addr);
    // don't copy across page boundaries
    uint32_t chunk_len = (uint32_t)MIN(PAGE_SIZE - page_offset,
                                       end_addr - start_addr);
    // Prepare the page for IOKit
    IOMemoryDescriptor *page_desc = (
                                     IOMemoryDescriptor::withPhysicalAddress(page, PAGE_SIZE, kIODirectionIn));
    if (page_desc == NULL) {
        pmem_error("Can't read from %#016llx, address not in physical memory range",
                   start_addr);
        // Skip this range as it is not even in the physical address space
        return chunk_len;
    } else {
        // Map the page containing address into kernel address space.
        IOMemoryMap *page_map = (
                                 page_desc->createMappingInTask(kernel_task, 0, kIODirectionIn, 0, 0));
        // Check if the mapping succeded.
        if (!page_map) {
            pmem_error("page %#016llx could not be mapped into the kernel, "
                       "zero padding return buffer", page);
            // Zero pad this chunk, as it is not inside a valid page frame.
            uiomove64((addr64_t)pmem_zero_page + page_offset,
                      (uint32_t)chunk_len, uio);
        } else {
            // Successfully mapped page, copy contents...
            pmem_log("partial_read");
            log_addr(page_map->getAddress(), 64, "page_map->getAddress()");
            log_addr(page_offset, 64, "page_offset");
            uiomove64(page_map->getAddress() + page_offset, (uint32_t)chunk_len, uio);
            page_map->release();
        }
        page_desc->release();
    }
    return chunk_len;
}

/*
 * Translate a physical address to an allocated virtual address
 * args:   Physical address
 * return: 0 if successful. The page descriptor and page mapping values are
 *         filled. IT IS THE CALLER RESPONSABILITY to call unxlate_pa_va when
 *         done with it.
 */
static int xlate_pa_va(addr64_t phys, IOMemoryDescriptor **page_desc,
                        IOMemoryMap **page_map)
{
    // Separate page and offset
    //uint64_t page_offset = phys & PAGE_MASK;
    addr64_t page = trunc_page_64(phys);

    *page_desc = (IOMemoryDescriptor::withPhysicalAddress(page, PAGE_SIZE, kIODirectionInOut));
    if (*page_desc == NULL) {
        pmem_error("Can't read from %#016llx, address not in physical memory range",
                   phys);
        // Skip this range as it is not even in the physical address space
        return -1;
    } else {
        // Map the page containing address into kernel address space.
        *page_map = ((*page_desc)->createMappingInTask(kernel_task, 0, kIODirectionInOut, 0, 0));
        // Check if the mapping succeded.
        if (!*page_map) {
            pmem_error("page %#016llx could not be mapped into the kernel, "
                       "zero padding return buffer", page);
            return -1;
        }
    }
    return 0;
}

/*
 * Free the allocated object to access physical memory (see xlate_pa_va)
 */
static void unxlate_pa_va(IOMemoryDescriptor **page_desc, IOMemoryMap **page_map)
{
    if (*page_map) {
        (*page_map)->release();
    }
    if (*page_desc) {
        (*page_desc)->release();
    }
}

static uint64_t ReadMMIO(uint64_t phys, uint8_t length){
    uint64_t value = 0;
    //uint32_t *ioaddr;
    IOMemoryDescriptor* io_desc;
    IOMemoryMap* io_map;
    uint64_t page_offset = phys & PAGE_MASK;

    log_addr((uint64_t) page_offset, 64, "page_offset");

    xlate_pa_va(phys, &io_desc, &io_map);

    if(io_map) {
        log_addr(io_map->getVirtualAddress(), 64, "io_map->getVirtualAddress");

        switch (length) {
            case 1:
                value = *(volatile uint8_t *)((uintptr_t)(io_map->getVirtualAddress()) + page_offset);
                break;
            case 2:
                value = OSReadLittleInt16((void *)io_map->getVirtualAddress(),
                                         page_offset);
                break;
            case 4:
                value = OSReadLittleInt32((void *)io_map->getVirtualAddress(),
                                          page_offset);
                break;
            case 8:
                value = OSReadLittleInt64((void *)io_map->getVirtualAddress(),
                                          page_offset);
            default:
                pmem_error("ReadMMIO Incorrect read length");
                break;
        }

        // DEBUG
        //ioaddr = (uint32_t *) (io_map->getVirtualAddress() + page_offset);
        //log_addr((uint64_t)ioaddr, 64, "ioaddr");
    }

    unxlate_pa_va(&io_desc, &io_map);

    return value;
}

static uint64_t WriteMMIO(uint64_t phys, uint8_t length, uint64_t value){
    IOMemoryDescriptor* io_desc;
    IOMemoryMap* io_map;
    uint64_t page_offset = phys & PAGE_MASK;

    log_addr((uint64_t) page_offset, 64, "page_offset");

    xlate_pa_va(phys, &io_desc, &io_map);

    if(io_map) {
        log_addr(io_map->getVirtualAddress(), 64, "io_map->getVirtualAddress");

        switch (length) {
            case 1:
                *(volatile uint8_t *)((uintptr_t)io_map->getVirtualAddress() + page_offset) = value;
                break;
            case 2:
                 OSWriteLittleInt16((void *)io_map->getVirtualAddress(),
                                          page_offset, (uint16_t) value);
                break;
            case 4:
                 OSWriteLittleInt32((void *)io_map->getVirtualAddress(),
                                          page_offset, (uint32_t) value);
                break;
            case 8:
                 OSWriteLittleInt64((void *)io_map->getVirtualAddress(),
                                          page_offset, value);
            default:
                pmem_error("WriteMMIO Incorrect write length");
                break;
        }
    }

    unxlate_pa_va(&io_desc, &io_map);
    return value;
}


/* Handles ioctl's from userspace.
   See ioctl codes in chipsec-common/chipsec_ioctl.h
 */
static kern_return_t pmem_ioctl(dev_t dev, u_long cmd, caddr_t data, int flag,
                                struct proc *p) {
    //TODO (dynamically allocate these)
    pci_msg_t kpci;
    mmio_msg_t kmmio;
    cr_msg_t kcr;

    pmem_log("cmd = %x", cmd);

    switch (cmd) {

        case CHIPSEC_IOC_RDPCI:
            pmem_log("RDPCI");
            log_addr((uint64_t) data, 64, "data");
            log_addr((uint64_t) &kpci, 64, "&krdpci");
            bcopy(data, &kpci, sizeof(pci_msg_t));
            pmem_log("ReadPCICfg(%lx, %lx, %lx, %lx, %lx)",
                     kpci.bus, kpci.device, kpci.function,
                     kpci.offset, kpci.length);

            kpci.value = ReadPCICfg(kpci.bus, kpci.device, kpci.function,
                             kpci.offset, kpci.length);
            pmem_log("kpci.value = %08x", kpci.value);

            bcopy(&kpci, data, sizeof(pci_msg_t));
            break;

        case CHIPSEC_IOC_WRPCI:
            pmem_log("WRPCI");
            bcopy(data, &kpci, sizeof(pci_msg_t));
            pmem_log("WritePCICfg(%lx, %lx, %lx, %lx, %lx, %lx)",
                     kpci.bus, kpci.device, kpci.function,
                     kpci.offset, kpci.length, kpci.value);

            WritePCICfg(kpci.bus, kpci.device, kpci.function,
                        kpci.offset, kpci.length, kpci.value);
            break;

        case CHIPSEC_IOC_RDMMIO:
            pmem_log("RDMMIO");
            bcopy(data, &kmmio, sizeof(mmio_msg_t));
            pmem_log("ReadMMIO(%lx, %x)", kmmio.addr, kmmio.length);
            kmmio.value = ReadMMIO(kmmio.addr, kmmio.length);
            pmem_log("val = %08llx", kmmio.value);

            bcopy(&kmmio, data, sizeof(mmio_msg_t));
            break;

        case CHIPSEC_IOC_WRMMIO:
            pmem_log("WRMMIO");
            bcopy(data, &kmmio, sizeof(mmio_msg_t));
            pmem_log("WriteMMIO(%lx, %x, %x)", kmmio.addr, kmmio.length,
                     (uint32_t) kmmio.value);

            WriteMMIO(kmmio.addr, kmmio.length, kmmio.value);
            break;

        case CHIPSEC_IOC_RDCR:
            pmem_log("RDCR");
            bcopy(data, &kcr, sizeof(cr_msg_t));
            pmem_log("ReadCR%d()", kcr.register_number);

            switch(kcr.register_number) {
                case 0:
                    kcr.value = ReadCR0();
                    break;
                case 2:
                    kcr.value = ReadCR2();
                    break;
                case 3:
                    kcr.value = ReadCR3();
                    break;
                case 4:
                    kcr.value = ReadCR4();
                    break;
                case 8:
                    kcr.value = ReadCR8();
                    break;
                default:
                    pmem_error("Incorrect CR number");
                    break;
            }
            bcopy(&kcr, data, sizeof(cr_msg_t));
            break;

        case CHIPSEC_IOC_WRCR:
            pmem_log("WRCR");
            bcopy(data, &kcr, sizeof(cr_msg_t));
            pmem_log("WriteCR%d(%x)", kcr.register_number, kcr.value);

            switch(kcr.register_number) {
                case 0:
                    WriteCR0(kcr.value);
                    break;
                case 2:
                    WriteCR2(kcr.value);
                    break;
                case 3:
                    WriteCR3(kcr.value);
                    break;
                case 4:
                    WriteCR4(kcr.value);
                    break;
                case 8:
                    WriteCR8(kcr.value);
                    break;
                default:
                    pmem_error("Incorrect CR number");
                    break;
            }
            bcopy(&kcr, data, sizeof(cr_msg_t));
            break;

        default:
            pmem_error("Illegal ioctl %08lx", cmd);
            return -EFAULT;
    }
    return KERN_SUCCESS;
}




// Tries to free all resources and also passes through any errors
//
// args: the error arg will be overwritten with KERN_FAILURE in case of an error
//       or returned unmodified in case everything went well.
// return: the given error argument or KERN_FAILURE if anything went wrong
static int pmem_cleanup(int error) {
    if (pmem_zero_page) {
        OSFree(pmem_zero_page, PAGE_SIZE, pmem_tag);
    }
    if (pmem_tag) {
        OSMalloc_Tagfree(pmem_tag);
    }
    if (pmem_devpmemnode) {
        devfs_remove(pmem_devpmemnode);
    }
    if (chipsec_dev_major != -1) {
        int devindex = 0;
        devindex = cdevsw_remove(chipsec_dev_major, &pmem_cdevsw);
        if (devindex != chipsec_dev_major) {
            pmem_error("Failed to remove cdevsw, cdevsw_remove() returned %d,"
                       "should be %d", devindex, chipsec_dev_major);
            pmem_error("Kext will not be unloaded as an uio could result"
                       " in calling non-existent code");
            error = KERN_FAILURE;
        }
    }
    return error;
}

// Driver entry point. Initializes globals and registers driver node in /dev.
kern_return_t chipsec_start(kmod_info_t * ki, void *d) {
    int error = 0;

    pmem_log("Loading /dev/%s driver", chipsec_devname);
    // Memory allocations are tagged to prevent leaks
    pmem_tag = OSMalloc_Tagalloc(pmem_tagname, OSMT_DEFAULT);
    // Allocate one page for zero padding of illegal read requests
    pmem_zero_page = static_cast<uint8_t *>(OSMalloc(PAGE_SIZE, pmem_tag));
    if (pmem_zero_page == NULL) {
        pmem_error("Failed to allocate memory for page buffer");
        return pmem_cleanup(KERN_FAILURE);
    }
    bzero(pmem_zero_page, PAGE_SIZE);

    // Install the character device
    chipsec_dev_major = cdevsw_add(-1, &pmem_cdevsw);
    if (chipsec_dev_major == -1) {
        pmem_error("Failed to create character device");
        return pmem_cleanup(KERN_FAILURE);
    }
    // Create physical memory device file
    pmem_log("Adding node /dev/%s", chipsec_devname);
    pmem_devpmemnode = devfs_make_node(makedev(chipsec_dev_major,
                                               chipsec_dev_minor),
                                       DEVFS_CHAR,
                                       UID_ROOT,
                                       GID_WHEEL,
                                       0660,
                                       chipsec_devname);
    if (pmem_devpmemnode == NULL) {
        pmem_error("Failed to create /dev/%s node", chipsec_devname);
        return pmem_cleanup(KERN_FAILURE);
    }
    pmem_log("pmem driver loaded, physical memory available in /dev/%s",
             chipsec_devname);
    return error;
}

// Driver cleanup function, frees all memory and removes device nodes.
kern_return_t chipsec_stop(kmod_info_t *ki, void *d) {
    pmem_log("Unloading /dev/%s driver", chipsec_devname);
    return pmem_cleanup(KERN_SUCCESS);
}
