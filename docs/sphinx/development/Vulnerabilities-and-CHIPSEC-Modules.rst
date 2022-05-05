CHIPSEC Modules
===============

A CHIPSEC module is just a python class that inherits from BaseModule and implements ``is_supported`` and ``run``. Modules are stored under the chipsec installation directory in a subdirectory "modules". The "modules" directory contains one subdirectory for each chipset that chipsec supports. There is also a directory for common modules that should apply to every platform.

    ===============================================  ================================================================================================
     ``chipsec/modules/``                            modules including tests or tools (that's where most of the chipsec functionality is)
     ``chipsec/modules/common/``                     modules common to all platforms
     ``chipsec/modules/<platform>/``                 modules specific to <platform>
     ``chipsec/modules/tools/``                      security tools based on CHIPSEC framework (fuzzers, etc.)
    ===============================================  ================================================================================================

Internally the chipsec application uses the concept of a module name, which is a string of the form: ``common.bios_wp``.
This means module ``common.bios_wp`` is a python script called ``bios_wp.py`` that is stored at ``<ROOT_DIR>\chipsec\modules\common\``.

Modules can be mapped to one or more security vulnerabilities being checked. More information also found in the documentation for any individual module.

Known vulnerabilities can be mapped to CHIPSEC modules as follows:

.. list-table:: **Attack Surface/Vector: Firmware protections in ROM**
   :header-rows: 1

   * - Vulnerability Description
     - CHIPSEC Module
     - Example
   * - SMI event configuration is not locked
     - common.bios_smi
     -
   * - SPI flash descriptor is not protected
     - common.spi_desc
     -
   * - SPI controller security override is enabled
     - common.spi_fdopss
     -
   * - SPI flash controller is not locked
     - common.spi_lock
     -
   * - Device-specific SPI flash protection is not used
     - chipsec_util spi write (manual analysis)
     -
   * - SMM BIOS write protection is not correctly used
     - common.bios_wp
     -
   * - Flash protected ranges do not protect bios region
     - common.bios_wp
     -
   * - BIOS interface is not locked
     - common.bios_ts
     -

.. list-table:: **Attack Surface/Vector: Runtime protection of SMRAM**
   :header-rows: 1

   * - Vulnerability Description
     - CHIPSEC Module
     - Example
   * - Compatibility SMRAM is not locked
     - common.smm
     -
   * - SMM cache attack
     - common.smrr
     -
   * - Memory remapping vulnerability in SMM protection
     - remap
     -
   * - DMA protections of SMRAM are not in use
     - smm_dma
     -
   * - Graphics aperture redirection of SMRAM
     - chipsec_util memconfig remap
     -
   * - Memory sinkhole vulnerability
     - tools.cpu.sinkhole
     -

.. list-table:: **Attack Surface/Vector: Secure boot -** Incorrect protection of secure boot configuration
   :header-rows: 1

   * - Vulnerability Description
     - CHIPSEC Module
     - Example
   * - Root certificate
     - common.bios_wp, common.secureboot.variables
     -
   * - Key exchange keys
     - common.secureboot.variables
     -
   * - Controls in setup variable (CSM enable/disable, image verification policies, secure boot enable/disable, clear/restore keys)
     - chipsec_util uefi var-find Setup
     -
   * - TE header confusion
     - tools.secureboot.te
     -
   * - UEFI NVRAM is not write protected
     - common.bios_wp
     -
   * - Insecure handling of secure boot disable
     - chipsec_util uefi var-list
     -

.. list-table:: **Attack Surface/Vector: Persistent firmware configuration**
   :header-rows: 1

   * - Vulnerability Description
     - CHIPSEC Module
     - Example
   * - Secure boot configuration is stored in unprotected variable
     - common.secureboot.variables, chipsec_util uefi var-list
     -
   * - Variable permissions are not set according to specification
     - common.uefi.access_uefispec
     -
   * - Sensitive data (like passwords) are stored in uefi variables
     - chipsec_util uefi var-list (manual analysis)
     -
   * - Firmware doesn't sanitize pointers/addresses stored in variables
     - chipsec_util uefi var-list (manual analysis)
     -
   * - Firmware hangs on invalid variable content
     - chipsec_util uefi var-write, chipsec_util uefi var-delete (manual analysis)
     -
   * - Hardware configuration stored in unprotected variables
     - chipsec_util uefi var-list (manual analysis)
     -
   * - Re-creating variables with less restrictive permissions
     - chipsec_util uefi var-write (manual analysis)
     -
   * - Variable NVRAM overflow
     - chipsec_util uefi var-write (manual analysis)
     -
   * - Critical configuration is stored in unprotected CMOS
     - chipsec_util cmos, common.rtclock
     -

.. list-table:: **Attack Surface/Vector: Platform hardware configuration**
   :header-rows: 1

   * - Vulnerability Description
     - CHIPSEC Module
     - Example
   * - Boot block top-swap mode is not locked
     - common.bios_ts
     -
   * - Architectural features not locked
     - common.ia32cfg
     -
   * - Memory map is not locked
     - memconfig
     -
   * - IOMMU usage
     - chipsec_util iommu
     -
   * - Memory remapping is not locked
     - remap
     -

.. list-table:: **Attack Surface/Vector: Runtime firmware (eg. SMI handlers)**
   :header-rows: 1

   * - Vulnerability Description
     - CHIPSEC Module
     - Example
   * - SMI handlers use pointers/addresses from OS without validation
     - tools.smm.smm_ptr
     -
   * - Legacy SMI handlers call legacy BIOS outside SMRAM
     -
     -
   * - INT15 in legacy SMI handlers
     -
     -
   * - UEFI SMI handlers call UEFI services outside SMRAM
     -
     -
   * - Malicious CommBuffer pointer and contents
     -
     -
   * - Race condition during SMI handler
     -
     -
   * - Authenticated variables SMI handler is not implemented
     - chipsec_util uefi var-write
     -
   * - SmmRuntime vulnerability
     - tools.uefi.scan_blocked
     -

.. list-table:: **Attack Surface/Vector: Boot time firmware**
   :header-rows: 1

   * - Vulnerability Description
     - CHIPSEC Module
     - Example
   * - Software vulnerabilities when parsing, decompressing, and loading data from ROM
     -
     -
   * - Software vulnerabilities in implementation of digital signature verification
     -
     -
   * - Pointers stored in UEFI variables and used during boot
     - chipsec_util uefi var-write
     -
   * - Loading unsigned PCI option ROMs
     - chipsec_util pci xrom
     -
   * - Boot hangs due to error condition (eg. ASSERT)
     -
     -

.. list-table:: **Attack Surface/Vector: Power state transitions (eg. resume from sleep)**
   :header-rows: 1

   * - Vulnerability Description
     - CHIPSEC Module
     - Example
   * - Insufficient protection of S3 boot script table
     - common.uefi.s3bootscript, tools.uefi.s3script_modify
     -
   * - Dispatch opcodes in S3 boot script call functions in unprotected memory
     - common.uefi.s3bootscript, tools.uefi.s3script_modify
     -
   * - S3 boot script interpreter stored in unprotected memory
     -
     -
   * - Pointer to S3 boot script table in unprotected UEFI variable
     - common.uefi.s3bootscript, tools.uefi.s3script_modify
     -
   * - Critical setting not recorded in S3 boot script table
     - chipsec_util uefi s3bootscript (manual analysis)
     -
   * - OS waking vector in ACPI tables can be modified
     - chipsec_util acpi dump (manual analysis)
     -
   * - Using pointers on S3 resume stored in unprotected UEFI variables
     - chipsec_util uefi var-write
     -

.. list-table:: **Attack Surface/Vector: Firmware update**
   :header-rows: 1

   * - Vulnerability Description
     - CHIPSEC Module
     - Example
   * - Software vulnerabilities when parsing firmware updates
     -
     -
   * - Unauthenticated firmware updates
     -
     -
   * - Runtime firmware update that can be interrupted
     -
     -
   * - Signature not checked on capsule update executable
     -
     -

.. list-table:: **Attack Surface/Vector: Network interfaces**
   :header-rows: 1

   * - Vulnerability Description
     - CHIPSEC Module
     - Example
   * - Software vulnerabilities when handling messages over network interfaces
     -
     -
   * - Booting unauthenticated firmware over unprotected network interfaces
     -
     -

.. list-table:: **Attack Surface/Vector: Misc**
   :header-rows: 1

   * - Vulnerability Description
     - CHIPSEC Module
     - Example
   * - BIOS keyboard buffer is not cleared during boot
     - common.bios_kbrd_buffer
     -
   * - DMA attack from devices during firmware execution
     -
     -

Modules
-------

.. toctree::

    List of modules <../modules/chipsec.modules.rst>