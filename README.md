CHIPSEC: Platform Security Assessment Framework
===============================================

CHIPSEC is a framework for analyzing the security of PC platforms including hardware, system firmware (BIOS/UEFI), and platform components. It includes a security test suite, tools for accessing various low level interfaces, and forensic capabilities. It can be run on Windows, Linux, and UEFI shell. Instructions for installing and using CHIPSEC can be found in the [manual](chipsec-manual.pdf).

NOTE: This software is for security testing purposes. Use at your own risk.

Read [WARNING.txt](source/tool/WARNING.txt) before using.

Questions? Enter a new issue labeled as question, or e-mail chipsec@intel.com.


Announcements
-------------

Oct 2015: Version 1.2.2 released! 

This version includes the following new or updated modules:

#. Updated tools.smm.smm_ptr to perform exhaustive fuzzing of SMI handler for insufficient input validation pointer vulnerabilities
#. Updated smm_dma to remove TSEGMB 8MB alignment check and to use XML "controls". Please recheck failures in smm_dma.py with the new version.
#. Updated common.bios_smi, common.spi_lock, and common.bios_wp to use XML "controls"
#. Updated common.uefi.s3bootscript which automatically tests protections of UEFI S3 Resume Boot Script table
#. Updated tools.uefi.s3script_modify which allows further manual testing of protections of UEFI S3 Resume Boot Script table
#. Added the following VMM security testing modules:
    * tools.vmm.cpuid_fuzz to test CPUID instruction emulation by VMMs
    * tools.vmm.iofuzz to test port I/O emulation by VMMs
    * tools.vmm.msr_fuzz to test CPU Model Specific Registers (MSR) emulation by VMMs
    * tools.vmm.pcie_fuzz to test PCIe device memory-mapped I/O (MMIO) and I/O ranges emulation by VMMs
    * tools.vmm.pcie_overlap_fuzz to test handling of overlapping PCIe device MMIO ranges by VMMs
#. Added tools.vmm.venom to test for VENOM vulnerability

This version includes the following new functionality:

#. Added hal.cpu component to access x86 CPU functionality. Removed hal.cr which merged to hal.cpu
#. Added ``chipsec_util cpu`` utility, removed ``chipsec_util cr``
#. Added S3 boot script opcodes encoding functionality in hal.uefi_platform
#. Added hal.iommu, cfg/iommu.xml and ``chipsec_util iommu`` to access IOMMU/VT-d hardware
#. Added ``chipsec_util io list`` to list predefined I/O BARs
#. Added support for Broadwell, Skylake, IvyTown, Jaketown and Haswell Server CPU families
#. Added ability to define I/O BARs in XML configuration using ``register`` attriute similarly to MMIO BARs
#. Added UEFI firmware volume assembling functionality in hal.uefi
#. Implemented alloc_phys_mem in EFI helper

This version includes the following fixes:

#. When calling alloc_phys_mem, the argument to set maximum physical address (max_pa) for allocation is ignored on linux. A message will be printed in dmesg if the allocation is above the max_pa that is passed in, but the call will return anyway.

This version has the following known issues:

#. Decompression of images in SPI flash parsing is not available in UEFI shell.
#. UEFI Shell environment does not support ``cpuid`` or ``get_thread_count``. There are functions that simply warn that they are not supported.
#. Size of PCIEXBAR (MMCFG) is calculated incorrectly



June 2015: Version 1.2.0 released! 

This version includes the following new or updated modules:

#. Merged common.secureboot.keys module into common.secureboot.variables
module
#. Updated tools.secureboot.te module to be able to test PE/TE issue on
Linux or UEFI shell
#. Updated tools.smm.smm_ptr module

This version includes the following updates:

#. Added the *controls* abstraction. Modules are encouraged to use
``get_control`` and ``set_control`` when interacting with platform
registers. This permits greater flexibility in case the register that
controls a given feature or configuration changes between platform
generations. The controls are defined in the platform XML file. At this
time, only a small number of controls are defined. We plan to move
existing modules over to this new mechanism.
#. Added XML Schema for the XML configuration files
#. Support for reading, writing, and listing UEFI variables from the
UEFI Shell environment has been added.
#. Added support for decompression while SPI flash parsing via
``decode`` or ``uefi decode`` commands in Linux
#. Added basic ACPI table parsing to HAL (RSDP, RSDT/XSDT, APIC, DMAR)
#. Added UEFI tables searching and parsing to HAL (EFI system table,
runtime services table, boot services table, DXE services table, EFI
configuration table)
#. Added DIMM Serial Presence Detect (SPD) ROM dumping and parsing to
HAL
#. Added ``uefi s3bootscript`` command parsing the S3 boot script to
chipsec_util.py
#. Added virtual-to-physical address translation function to
Linux/EFI/Windows helpers
#. Added support of server platforms (Haswell server and Ivy Town) to
chipset.py

This version has the following known issues:

#. Decompression of images in SPI flash parsing is not available in UEFI
shell.
#. When calling alloc_phys_mem, the argument to set maximum physical
address (max_pa) for allocation is ignored on linux. A message will be
printed in dmesg if the allocation is above the max_pa that is passed
in, but the call will return anyway.
#. UEFI Shell environment does not support ``cpuid`` or
``get_thread_count``. There are functions that simply warn that they are
not supported.
#. Size of PCIEXBAR (MMCFG) is calculated incorrectly


March 2015: [A New Class of Vulnerabilities in SMI Handlers](https://cansecwest.com/slides/2015/A%20New%20Class%20of%20Vulnin%20SMI%20-%20Andrew%20Furtak.pdf) and release of smm_ptr tool. 

August 2014: [Summary of Attacks Against BIOS and Secure Boot](https://media.defcon.org/DEF%20CON%2022/DEF%20CON%2022%20presentations/Bulygin,%20Bazhaniul,%20Furtak,%20and%20Loucaides%20-%20Updated/DEFCON-22-Bulygin-Bazhaniul-Furtak-Loucaides-Summary-of-attacks-against-BIOS-UPDATED.pdf) and related CHIPSEC modules at DEFCON 22

March 2014: [Announcement at CanSecWest 2014](https://cansecwest.com/slides/2014/Platform%20Firmware%20Security%20Assessment%20wCHIPSEC-csw14-final.pdf) and first public release!

