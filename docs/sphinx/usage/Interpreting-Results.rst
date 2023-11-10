.. _Interpreting-Results:

Interpreting results
====================

.. note::
    DRAFT (work in progress)

In order to improve usability, we are reviewing and improving the
messages and meaning of information returned by CHIPSEC.

Results
-------

.. list-table:: Generic results meanings
   :widths: 25 25
   :header-rows: 1

   * - Result
     - Meaning
   * - PASSED
     - A **mitigation** to a known vulnerability has been detected
   * - FAILED
     - A known **vulnerability** has been detected
   * - WARNING
     - We have detected something that could be a vulnerability but **manual analysis is required** to confirm (inconclusive)
   * - NOT_APPLICABLE
     - The issue checked by this module is not applicable to this platform. This result can be ignored
   * - INFORMATION
     - This module does not check for a vulnerability. It just prints information about the system
   * - ERROR
     - Something went wrong in the execution of CHIPSEC

Automated Tests
---------------

Each test module can log additional messaging in addition to the return
value. In an effort to standardize and improve the clarity of this
messaging, the mapping of result and messages is defined below:

.. list-table:: Modules results meanings
   :widths: 25 25 25 25 25
   :header-rows: 1

   * - Test
     - PASSED message
     - FAILED message
     - WARNING message
     - Notes
   * - memconfig
     - All memory map registers seem to be locked down
     - Not all memory map registers are locked down
     - N/A
     -
   * - Remap
     - Memory Remap is configured correctly and locked
     - Memory Remap is not properly configured/locked. Remaping attack may be possible.
     - N/A
     -
   * - smm_dma
     - TSEG is properly configured. SMRAM is protected from DMA attacks.
     - TSEG is properly configured, but the configuration is not locked or TSEG is not properly configured. Portions of SMRAM may be vulnerable to DMA attacks
     - TSEG is properly configured but can't determine if it covers entire SMRAM
     -
   * - common.bios_kbrd_buffer
     - 	"Keyboard buffer is filled with common fill pattern" or "Keyboard buffer looks empty. Pre-boot passwords don't seem to be exposed
     - FAILED
     - Keyboard buffer is not empty. The test cannot determine conclusively if it contains pre-boot passwords.\n The contents might have not been cleared by pre-boot firmware or overwritten with garbage.\n Visually inspect the contents of keyboard buffer for pre-boot passwords (BIOS, HDD, full-disk encryption).
     - Also printing a message if size of buffer is revealed. "Was your password %d characters long?"
   * - common.bios_smi
     - All required SMI sources seem to be enabled and locked
     - Not all required SMI sources are enabled and locked
     - Not all required SMI sources are enabled and locked, but SPI flash writes are still restricted to SMM
     -
   * - common.bios_ts
     - BIOS Interface is locked (including Top Swap Mode)
     - BIOS Interface is not locked (including Top Swap Mode)
     - N/A
     -
   * - common.bios_wp
     - BIOS is write protected
     - BIOS should enable all available SMM based write protection mechanisms or configure SPI protected ranges to protect the entire BIOS region. BIOS is NOT protected completely
     - N/A
     -
   * - common.ia32cfg
     - IA32_FEATURE_CONTROL MSR is locked on all logical CPUs
     - IA32_FEATURE_CONTROL MSR is not locked on all logical CPUs
     - N/A
     -
   * - common.rtclock
     - Protected locations in RTC memory are locked
     - N/A
     - Protected locations in RTC memory are accessible (BIOS may not be using them)
     -
   * - common.smm
     - Compatible SMRAM is locked down
     - Compatible SMRAM is not properly locked. Expected ( D_LCK = 1, D_OPEN = 0 )
     - N/A
     - Should return SKIPPED_NOT_APPLICABLE when compatible SMRAM is not enabled.
   * - common.smrr
     - SMRR protection against cache attack is properly configured
     - SMRR protection against cache attack is not configured properly
     - N/A
     -
   * - common.spi_access
     - SPI Flash Region Access Permissions in flash descriptor look ok
     - SPI Flash Region Access Permissions are not programmed securely in flash descriptor
     - Software has write access to GBe region in SPI flash" and "Certain SPI flash regions are writeable by software
     - we have observed production systems reacting badly when GBe was overwritten
   * - common.spi_desc
     - SPI flash permissions prevent SW from writing to flash descriptor
     - SPI flash permissions allow SW to write flash descriptor
     - N/A
     - we can probably remove this now that we have spi_access
   * - common.spi_fdopss
     - SPI Flash Descriptor Security Override is disabled
     - SPI Flash Descriptor Security Override is enabled
     - N/A
     -
   * - common.spi_lock
     - SPI Flash Controller configuration is locked
     - SPI Flash Controller configuration is not locked
     - N/A
     -
   * - common.cpu.spectre_v2
     - CPU and OS support hardware mitigations (enhanced IBRS and STIBP)
     - CPU mitigation (IBRS) is missing
     - CPU supports mitigation (IBRS) but doesn't support enhanced IBRS" or "CPU supports mitigation (enhanced IBRS) but OS is not using it" or "CPU supports mitigation (enhanced IBRS) but STIBP is not supported/enabled
     -
   * - common.secureboot.variables
     - All Secure Boot UEFI variables are protected
     - Not all Secure Boot UEFI variables are protected' (failure when secure boot is enabled)
     - Not all Secure Boot UEFI variables are protected' (warning when secure boot is disabled)
     -
   * - common.uefi.access_uefispec
     - All checked EFI variables are protected according to spec
     - Some EFI variables were not protected according to spec
     - Extra/Missing attributes
     -
   * - common.uefi.s3bootscript
     - N/A
     - S3 Boot-Script and Dispatch entry-points do not appear to be protected
     - S3 Boot-Script is not in SMRAM but Dispatch entry-points appear to be protected. Recommend further testing
     - unfortunately, if the boot script is well protected (in SMRAM) we cannot find it at all and end up returning warning

Tools
-----

CHIPSEC also contains tools such as fuzzers, which require a
knowledgeable user to run. We can examine the usability of these tools
as well.
