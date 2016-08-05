CHIPSEC: Platform Security Assessment Framework
===============================================

CHIPSEC is a framework for analyzing the security of PC platforms including hardware, system firmware (BIOS/UEFI), and platform components. It includes a security test suite, tools for accessing various low level interfaces, and forensic capabilities. It can be run on Windows, Linux, and UEFI shell. Instructions for installing and using CHIPSEC can be found in the [manual](chipsec-manual.pdf).

NOTE: This software is for security testing purposes. Use at your own risk. Read [WARNING.txt](source/tool/WARNING.txt) before using.

Questions? Enter a new issue labeled as question, or e-mail chipsec@intel.com.

Status: [![Build Status](https://travis-ci.org/chipsec/chipsec.svg?branch=master)](https://travis-ci.org/chipsec/chipsec)

Announcements
-------------

June 2016: Version 1.2.3 released! 

This version includes the following new or updated modules:

1. tools.vmm.vbox_crash_apicbase -- test for CVE-2015-0377
2. udated common.bios_ts, common.uefi.s3bootscript, remap
3. added template config file smm_config.ini for tools.smm.smm_ptr SMI fuzzer
4. added template config file te.cfg for tools.secureboot.te tool

This version includes the following new functionality:

1. Added basic TPM access and TPM 1.2 support
   * hal/tpm.py and hal/tpm12_commands.py HAL components
2. Added basic Embedded Controller (EC) support
   * hal/ec.py HAL component and ``chipsec_util ec`` util
3. Added processing of x86 paging hierarchy
   * hal/paging.py and hal/cpu.py HAL components and ``chipsec_util cpu pt`` util 
4. Added processing of Second Level Address Translation paging hierarchy (EPT)
   * hal/vmm.py HAL component and ``chipsec_util vmm pt`` util 
5. Added processing of IOMMU (VT-d) paging hierarchy
   * hal/iommu.py HAL component and ``chipsec_util iommu pt`` util 
6. Basic support for hypervisor hypercall interfaces
   * hal/vmm.py HAL component and ``chipsec_util vmm hypercall`` util
7. Added message bus interface for Atom SoC (Linux)
   * hal/msgbus.py HAL component and ``chipsec_util msgbus`` util
8. CPUID functionality moved from hal/cpuid.py to hal/cpu.py HAL component
   * Use ``chipsec_util cpu cpuid`` util
9. Added parsing of RAW images in UEFI firmware volumes
10. Updated smbus and SPD HAL components to use XML config
11. Added qrk.xml configuration file for Quark CPUs, updated configuration for Haswell Server (hsx.xml)

This version includes the following fixes:

1. Fixed location of MMCFG in server platforms. Results from prior versions may need to be recollected on server platforms.

This version has the following known issues/litimations:

1. Decompression of images in SPI flash parsing is not available in UEFI shell.
2. UEFI shell environment does not support ``get_thread_count``. There are functions that simply warn that they are not supported.
3. Size of MMCFG (PCIEXBAR) is calculated incorrectly
4. ``chipsec_util mmcfg`` and calculation of MMCFG (ECBASE) does not work on Atom SoCs
5. Atom SoC message bus interface is not implemented on Windows and in UEFI shell
6. Hypercall support is not implemented on Linux and UEFI shell



Oct 2015: Version 1.2.2 released! 

This version includes the following new or updated modules:

1. Updated tools.smm.smm_ptr to perform exhaustive fuzzing of SMI handler for insufficient input validation pointer vulnerabilities
2. Updated smm_dma to remove TSEGMB 8MB alignment check and to use XML "controls". Please recheck failures in smm_dma.py with the new version.
3. Updated common.bios_smi, common.spi_lock, and common.bios_wp to use XML "controls"
4. Updated common.uefi.s3bootscript which automatically tests protections of UEFI S3 Resume Boot Script table
5. Updated tools.uefi.s3script_modify which allows further manual testing of protections of UEFI S3 Resume Boot Script table
6. Added the following VMM security testing modules:
    * tools.vmm.cpuid_fuzz to test CPUID instruction emulation by VMMs
    * tools.vmm.iofuzz to test port I/O emulation by VMMs
    * tools.vmm.msr_fuzz to test CPU Model Specific Registers (MSR) emulation by VMMs
    * tools.vmm.pcie_fuzz to test PCIe device memory-mapped I/O (MMIO) and I/O ranges emulation by VMMs
    * tools.vmm.pcie_overlap_fuzz to test handling of overlapping PCIe device MMIO ranges by VMMs
7. Added tools.vmm.venom to test for VENOM vulnerability

This version includes the following new functionality:

1. Added hal.cpu component to access x86 CPU functionality. Removed hal.cr which merged to hal.cpu
2. Added ``chipsec_util cpu`` utility, removed ``chipsec_util cr``
3. Added S3 boot script opcodes encoding functionality in hal.uefi_platform
4. Added hal.iommu, cfg/iommu.xml and ``chipsec_util iommu`` to access IOMMU/VT-d hardware
5. Added ``chipsec_util io list`` to list predefined I/O BARs
6. Added support for Broadwell, Skylake, IvyTown, Jaketown and Haswell Server CPU families
7. Added ability to define I/O BARs in XML configuration using ``register`` attriute similarly to MMIO BARs
8. Added UEFI firmware volume assembling functionality in hal.uefi
9. Implemented alloc_phys_mem in EFI helper

This version includes the following fixes:

1. When calling alloc_phys_mem, the argument to set maximum physical address (max_pa) for allocation is ignored on linux. A message will be printed in dmesg if the allocation is above the max_pa that is passed in, but the call will return anyway.

This version has the following known issues:

1. Decompression of images in SPI flash parsing is not available in UEFI shell.
2. UEFI Shell environment does not support ``cpuid`` or ``get_thread_count``. There are functions that simply warn that they are not supported.
3. Size of PCIEXBAR (MMCFG) is calculated incorrectly



June 2015: Version 1.2.0 released! 

This version includes the following new or updated modules:

1. Merged common.secureboot.keys module into common.secureboot.variables module
2. Updated tools.secureboot.te module to be able to test PE/TE issue on Linux or UEFI shell
3. Updated tools.smm.smm_ptr module

This version includes the following updates:

1. Added the *controls* abstraction. Modules are encouraged to use
``get_control`` and ``set_control`` when interacting with platform
registers. This permits greater flexibility in case the register that
controls a given feature or configuration changes between platform
generations. The controls are defined in the platform XML file. At this
time, only a small number of controls are defined. We plan to move
existing modules over to this new mechanism.
2. Added XML Schema for the XML configuration files
3. Support for reading, writing, and listing UEFI variables from the
UEFI Shell environment has been added.
4. Added support for decompression while SPI flash parsing via
``decode`` or ``uefi decode`` commands in Linux
5. Added basic ACPI table parsing to HAL (RSDP, RSDT/XSDT, APIC, DMAR)
6. Added UEFI tables searching and parsing to HAL (EFI system table,
runtime services table, boot services table, DXE services table, EFI
configuration table)
7. Added DIMM Serial Presence Detect (SPD) ROM dumping and parsing to
HAL
8. Added ``uefi s3bootscript`` command parsing the S3 boot script to
chipsec_util.py
9. Added virtual-to-physical address translation function to
Linux/EFI/Windows helpers
10. Added support of server platforms (Haswell server and Ivy Town) to
chipset.py

This version has the following known issues:

1. Decompression of images in SPI flash parsing is not available in UEFI
shell.
2. When calling alloc_phys_mem, the argument to set maximum physical
address (max_pa) for allocation is ignored on linux. A message will be
printed in dmesg if the allocation is above the max_pa that is passed
in, but the call will return anyway.
3. UEFI Shell environment does not support ``cpuid`` or
``get_thread_count``. There are functions that simply warn that they are
not supported.
4. Size of PCIEXBAR (MMCFG) is calculated incorrectly


March 2015: [A New Class of Vulnerabilities in SMI Handlers](https://cansecwest.com/slides/2015/A%20New%20Class%20of%20Vulnin%20SMI%20-%20Andrew%20Furtak.pdf) and release of smm_ptr tool. 

August 2014: [Summary of Attacks Against BIOS and Secure Boot](https://media.defcon.org/DEF%20CON%2022/DEF%20CON%2022%20presentations/Bulygin,%20Bazhaniul,%20Furtak,%20and%20Loucaides%20-%20Updated/DEFCON-22-Bulygin-Bazhaniul-Furtak-Loucaides-Summary-of-attacks-against-BIOS-UPDATED.pdf) and related CHIPSEC modules at DEFCON 22

March 2014: [Announcement at CanSecWest 2014](https://cansecwest.com/slides/2014/Platform%20Firmware%20Security%20Assessment%20wCHIPSEC-csw14-final.pdf) and first public release!

