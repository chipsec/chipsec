# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2022, Intel Corporation
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Contact information:
# chipsec@intel.com
#
# Authors:
#  Sushmith Hiremath, INTEL DCG RED team
#

"""
Check SGX related configuration

Reference:
    - SGX BWG, CDI/IBP#: 565432

Usage:
    ``chipsec_main -m common.sgx_check``

Examples:
    >>> chipsec_main.py -m common.sgx_check

Registers used:
    - IA32_FEATURE_CONTROL.SGX_GLOBAL_EN
    - IA32_FEATURE_CONTROL.LOCK
    - IA32_DEBUG_INTERFACE.ENABLE
    - IA32_DEBUG_INTERFACE.LOCK
    - MTRRCAP.PRMRR
    - PRMRR_VALID_CONFIG
    - PRMRR_PHYBASE.PRMRR_base_address_fields
    - PRMRR_PHYBASE.PRMRR_MEMTYPE
    - PRMRR_MASK.PRMRR_mask_bits
    - PRMRR_MASK.PRMRR_VLD
    - PRMRR_MASK.PRMRR_LOCK
    - PRMRR_UNCORE_PHYBASE.PRMRR_base_address_fields
    - PRMRR_UNCORE_MASK.PRMRR_mask_bits
    - PRMRR_UNCORE_MASK.PRMRR_VLD
    - PRMRR_UNCORE_MASK.PRMRR_LOCK
    - BIOS_SE_SVN.PFAT_SE_SVN
    - BIOS_SE_SVN.ANC_SE_SVN
    - BIOS_SE_SVN.SCLEAN_SE_SVN
    - BIOS_SE_SVN.SINIT_SE_SVN
    - BIOS_SE_SVN_STATUS.LOCK
    - SGX_DEBUG_MODE.SGX_DEBUG_MODE_STATUS_BIT

.. note::
    - Will not run within the EFI Shell

"""

_MODULE_NAME = 'sgx_check'
from chipsec.library.exceptions import HWAccessViolationError
from chipsec.module_common import BaseModule, MTAG_HWCONFIG
from chipsec.library.returncode import ModuleResult
from chipsec.library.defines import BIT0, BIT1, BIT2, BIT5, BIT6, BIT7, BIT8
TAGS = [MTAG_HWCONFIG]


class sgx_check(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
        self.helper = self.cs.helper
        self.res = ModuleResult.PASSED

    def is_supported(self) -> bool:
        sgx_cpu_support = False
        if self.cs.os_helper.is_efi():
            self.logger.log_important('Currently this module cannot run within the EFI Shell. Exiting.')
        elif not self.cs.register.has_field('IA32_FEATURE_CONTROL', 'SGX_GLOBAL_EN'):
            self.logger.log_important('IA32_FEATURE_CONTROL.SGX_GLOBAL_EN not defined for platform.  Skipping module.')
        else:
            for tid in range(self.cs.msr.get_cpu_thread_count()):
                status = self.helper.set_affinity(tid)
                if status == -1:
                    self.logger.log_verbose(f"[*] Failed to set affinity to CPU{tid:d}")
                (_, r_ebx, _, _) = self.cs.cpu.cpuid(0x07, 0x00)
                if r_ebx & BIT2:
                    self.logger.log_verbose(f"[*] CPU{tid:d}: does support SGX")
                    sgx_cpu_support = True
                else:
                    self.logger.log_verbose(f"[*]CPU{tid:d}: does not support SGX")
                    self.logger.log_important('SGX not supported.  Skipping module.')

        return sgx_cpu_support

    def check_sgx_config(self) -> int:
        self.logger.log("[*] Test if CPU has support for SGX")
        sgx_ok = False

        self.logger.log("\n[*] SGX BIOS enablement check")
        self.logger.log("[*] Verifying IA32_FEATURE_CONTROL MSR is configured")
        bios_feature_control_enable = True
        for tid in range(self.cs.msr.get_cpu_thread_count()):
            if not (self.cs.register.read_field('IA32_FEATURE_CONTROL', 'SGX_GLOBAL_EN', False, tid) == 1):
                bios_feature_control_enable = False
        if bios_feature_control_enable:
            self.logger.log_good("Intel SGX is Enabled in BIOS")
        else:
            self.logger.log_important("Intel SGX is not enabled in BIOS")
            self.res = ModuleResult.WARNING
            self.result.setStatusBit(self.result.status.FEATURE_DISABLED)

        self.logger.log("\n[*] Verifying IA32_FEATURE_CONTROL MSR is locked")
        locked = True
        for tid in range(self.cs.msr.get_cpu_thread_count()):
            feature_cntl_lock = self.cs.control.get('Ia32FeatureControlLock', tid)
            self.logger.log_verbose(f"[*] cpu{tid:d}: IA32_Feature_Control Lock = {feature_cntl_lock:d}")
            if 0 == feature_cntl_lock:
                locked = False
        if locked:
            self.logger.log_good("IA32_Feature_Control locked")
        else:
            self.logger.log_bad("IA32_Feature_Control is unlocked")
            self.res = ModuleResult.FAILED
            self.result.setStatusBit(self.result.status.LOCKS)

        # Verify that Protected Memory Range (PRM) is supported, MSR IA32_MTRRCAP (FEh) [12]=1
        # Check on every CPU and make sure that they are all the same values
        self.logger.log("\n[*] Verifying if Protected Memory Range (PRMRR) is configured")
        prmrr_enable = False
        for tid in range(self.cs.msr.get_cpu_thread_count()):
            mtrrcap = self.cs.register.read_field('MTRRCAP', 'PRMRR', False, tid)
            if mtrrcap == 0:
                self.logger.log_verbose(f"[*] CPU{tid:d} Protected Memory Range configuration is not supported")
            else:
                prmrr_enable = True
                self.logger.log_verbose(f"[*] CPU{tid:d} Protected Memory Range configuration is supported")
        if prmrr_enable:
            self.logger.log_good("Protected Memory Range configuration is supported")
        else:
            self.logger.log_bad("Protected Memory Range configuration is not supported")
            self.res - ModuleResult.FAILED
            self.result.setStatusBit(self.result.status.UNSUPPORTED_FEATURE)

        # Check PRMRR configurations on each core.
        self.logger.log("\n[*] Verifying PRMRR Configuration on each core.")
        
        self.prmrr = self.PRMRR(self.logger, self.cs)
        try:
            self.prmrr._check_prmrr()
        except HWAccessViolationError:
            self.prmrr.reset_variables()
            self.logger.log_important("Some PRMRR registers could not be read. Following results may not be accurate.")
            if self.cs.os_helper.is_windows():
                self.logger.log_important("Please try running in a Linux environment. The results there may be more complete.")
        else:
            self.check_prmrr_values()
        
        

        if bios_feature_control_enable and locked:
            sgx1_instr_support = False
            sgx2_instr_support = False
            self.logger.log("\n[*] Verifying if SGX instructions are supported")
            for tid in range(self.cs.msr.get_cpu_thread_count()):
                status = self.helper.set_affinity(tid)
                if status == -1:
                    self.logger.log_verbose(f"[*] Failed to set affinity to CPU{tid:d}")
                (r_eax, _, _, _) = self.cs.cpu.cpuid(0x012, 0x00)
                if r_eax & BIT0:
                    self.logger.log_verbose(f"[*] CPU{tid:d} SGX-1 instructions are supported")
                    sgx1_instr_support = True
                else:
                    self.logger.log_verbose(f"[*] CPU{tid:d} SGX-1 instructions are not supported")
                if r_eax & BIT1:
                    self.logger.log_verbose(f"[*] CPU{tid:d} SGX-2 instructions are supported")
                    sgx2_instr_support = True
                else:
                    self.logger.log_verbose(f"[*] CPU{tid:d} SGX-2 instructions are not supported")
            if sgx1_instr_support:
                self.logger.log_good("Intel SGX instructions are supported and available to use")
                sgx_ok = True
            else:
                self.logger.log_bad("Intel SGX instructions are not supported on system")
                sgx_ok = False
            if sgx2_instr_support:
                self.logger.log("[*] SGX-2 instructions are supported")
            else:
                self.logger.log("[*] SGX-2 instructions are not supported")
        else:
            sgx_ok = False

        self.logger.log("\n[*] Verifying if SGX is available to use")
        if sgx_ok and prmrr_enable and self.prmrr.uniform:
            self.logger.log_good("Intel SGX is available to use")
        elif (not sgx_ok) and (not bios_feature_control_enable) and prmrr_enable and self.prmrr.uniform:
            self.logger.log_important("Intel SGX instructions disabled by firmware")
            self.result.setStatusBit(self.result.status.FEATURE_DISABLED)
            if self.res == ModuleResult.PASSED:
                self.res = ModuleResult.WARNING
        else:
            self.logger.log_bad("Intel SGX is not available to use")
            self.res = ModuleResult.FAILED
            self.result.setStatusBit(self.result.status.FEATURE_DISABLED)

        if self.cs.register.is_defined('BIOS_SE_SVN') and self.cs.register.is_defined('BIOS_SE_SVN_STATUS'):
            self.cs.register.print('BIOS_SE_SVN', self.cs.register.read('BIOS_SE_SVN'))
            self.cs.register.print('BIOS_SE_SVN_STATUS', self.cs.register.read('BIOS_SE_SVN_STATUS'))

        self.logger.log("\n[*] Check SGX debug feature settings")
        sgx_debug_status = self.cs.register.read_field('SGX_DEBUG_MODE', 'SGX_DEBUG_MODE_STATUS_BIT')
        self.logger.log(f"[*] SGX Debug Enable             : {sgx_debug_status:d}")
        self.logger.log("[*] Check Silicon debug feature settings")
        debug_interface = self.cs.register.read('IA32_DEBUG_INTERFACE')
        self.logger.log(f"[*]   IA32_DEBUG_INTERFACE : 0x{debug_interface:08X}")
        debug_enable = self.cs.register.get_field('IA32_DEBUG_INTERFACE', debug_interface, 'ENABLE')
        debug_lock = self.cs.register.get_field('IA32_DEBUG_INTERFACE', debug_interface, 'LOCK')
        self.logger.log(f"[*]     Debug enabled      : {debug_enable:d}")
        self.logger.log(f"[*]     Lock               : {debug_lock:d}")

        if sgx_debug_status == 1:
            self.logger.log_bad("SGX debug mode is enabled")
            self.res = ModuleResult.FAILED
            self.result.setStatusBit(self.result.status.DEBUG_FEATURE)
        else:
            self.logger.log_good("SGX debug mode is disabled")
        if debug_enable == 0:
            self.logger.log_good("Silicon debug features are disabled")
        else:
            self.logger.log_bad("Silicon debug features are not disabled")
            self.res = ModuleResult.FAILED
            self.result.setStatusBit(self.result.status.DEBUG_FEATURE)
        if (0 == debug_enable) and (1 == sgx_debug_status):
            self.logger.log_bad("Enabling sgx_debug without enabling debug mode in msr IA32_DEBUG_INTERFACE is not a valid configuration")
            self.res = ModuleResult.FAILED
            self.result.setStatusBit(self.result.status.CONFIGURATION)
        if debug_lock == 1:
            self.logger.log_good("Silicon debug Feature Control register is locked")
        else:
            self.logger.log_bad("Silicon debug Feature Control register is not locked")
            self.res = ModuleResult.FAILED
            self.result.setStatusBit(self.result.status.LOCKS)

        return self.res
    
    
    def check_prmrr_values(self) -> None:
        if not self.prmrr:
            return
        if not self.prmrr.uniform:
            self.logger.log_bad("PRMRR config is not uniform across all CPUs")
            self.res = ModuleResult.FAILED
            self.result.setStatusBit(self.result.status.CONFIGURATION)
        else:
            self.logger.log_good("PRMRR config is uniform across all CPUs")
            prmrr_configs = []
            config_support = False
            if BIT0 & self.prmrr.valid_config:
                prmrr_configs.append("1M")
                config_support = True
            if BIT1 & self.prmrr.valid_config:
                prmrr_configs.append("2M")
                config_support = True
            if BIT5 & self.prmrr.valid_config:
                prmrr_configs.append("32M")
                config_support = True
            if BIT6 & self.prmrr.valid_config:
                prmrr_configs.append("64M")
                config_support = True
            if BIT7 & self.prmrr.valid_config:
                prmrr_configs.append("128M")
                config_support = True
            if BIT8 & self.prmrr.valid_config:
                prmrr_configs.append("256M")
                config_support = True
            if config_support:
                self.logger.log(f"[*]  PRMRR config supports: {', '.join(prmrr_configs)}")
            else:
                self.logger.log("[*] PRMMR config has improper value")

            # In some cases the PRMRR base and mask may be zero
            if (self.prmrr.base == 0) and (self.prmrr.mask == 0):
                self.logger.log("[*] PRMRR Base and Mask are set to zero.  PRMRR appears to be disabled.")
                self.logger.log("[*]   Skipping Base/Mask settings.")
            else:
                self.logger.log(f"[*]  PRMRR base address: 0x{self.prmrr.base:012X}")
                self.logger.log("[*]  Verifying PRMR memory type is valid")
                self.logger.log(f"[*]  PRMRR memory type : 0x{self.prmrr.base_memtype:X}")
                if self.prmrr.base_memtype == 0x6:
                    self.logger.log_good("PRMRR memory type is WB as expected")
                else:
                    self.logger.log_bad("Unexpected PRMRR memory type (not WB)")
                    self.res = ModuleResult.FAILED
                    self.result.setStatusBit(self.result.status.CONFIGURATION)
                self.logger.log(f"[*]  PRMRR mask address: 0x{self.prmrr.mask:012X}")
                self.logger.log("[*]  Verifying PRMR address are valid")
                self.logger.log(f"[*]      PRMRR uncore mask valid: 0x{self.prmrr.uncore_mask_vld:d}")
                if self.prmrr.mask_vld == 0x1:
                    self.logger.log_good("Mcheck marked PRMRR address as valid")
                else:
                    self.logger.log_bad("Mcheck marked PRMRR address as invalid")
                    self.res = ModuleResult.FAILED
                    self.result.setStatusBit(self.result.status.CONFIGURATION)
                self.logger.log("[*]  Verifying if PRMR mask register is locked")
                self.logger.log(f"[*]      PRMRR mask lock: 0x{self.prmrr.mask_lock:X}")
                if self.prmrr.locked:
                    self.logger.log_good("PRMRR MASK register is locked")
                else:
                    self.logger.log_bad("PRMRR MASK register is not locked")
                    self.res = ModuleResult.FAILED
                    self.result.setStatusBit(self.result.status.LOCKS)
                if self.prmrr.check_uncore_vals:
                    self.logger.log(f"[*]  PRMRR uncore base address: 0x{self.prmrr.uncore_base:012X}")
                    self.logger.log(f"[*]  PRMRR uncore mask address: 0x{self.prmrr.uncore_mask:012X}")
                    self.logger.log("[*]  Verifying PRMR uncore address are valid")
                    self.logger.log(f"[*]      PRMRR uncore mask valid: 0x{self.prmrr.uncore_mask_vld:X}")
                    if self.prmrr.uncore_mask_vld == 0x1:
                        self.logger.log_good("Mcheck marked uncore PRMRR address as valid")
                    else:
                        self.logger.log_bad("Mcheck marked uncore PRMRR address as invalid")
                        self.res = ModuleResult.FAILED
                        self.result.setStatusBit(self.result.status.CONFIGURATION)
                    self.logger.log("[*]  Verifying if PRMR uncore mask register is locked")
                    self.logger.log(f"[*]      PRMRR uncore mask lock: 0x{self.prmrr.uncore_mask_lock:X}")
                    if self.prmrr.uncore_mask_lock == 0x1:
                        self.logger.log_good("PMRR uncore MASK register is locked")
                    else:
                        self.logger.log_bad("PMRR uncore MASK register is not locked")
                        self.res = ModuleResult.FAILED
                        self.result.setStatusBit(self.result.status.LOCKS)
    
    
    class PRMRR():
        def __init__(self, logger, cs) -> None:
            self.logger = logger
            self.cs = cs
            self.reset_variables()

        def reset_variables(self) -> None:
            self.valid_config = 0
            self.base = 0
            self.base_memtype = 0
            self.uncore_base = 0
            self.uncore_base_new = 0
            self.mask = 0
            self.uncore_mask = 0
            self.uncore_mask_new = 0
            self.mask_vld = 0
            self.uncore_mask_vld = 0
            self.uncore_mask_vld_new = 0
            self.mask_lock = 0
            self.uncore_mask_lock = 0
            self.uncore_mask_lock_new = 0
            self.uniform = False
            self.locked = False
            self.check_uncore_vals = False
        
        def _check_prmrr(self) -> None:
            self.reset_variables()
            first_iter = True
            self.uniform = True
            self.locked = True
            self.check_uncore_vals = self.cs.register.is_defined('PRMRR_UNCORE_PHYBASE') and self.cs.register.is_defined('PRMRR_UNCORE_MASK')
            for tid in range(self.cs.msr.get_cpu_thread_count()):
                self.valid_config_new = self.cs.register.read('PRMRR_VALID_CONFIG', tid)
                self.base_new = self.cs.register.read_field('PRMRR_PHYBASE', 'PRMRR_base_address_fields', False, tid)
                self.base_memtype_new = self.cs.register.read_field('PRMRR_PHYBASE', 'PRMRR_MEMTYPE', False, tid)
                self.mask_new = self.cs.register.read_field('PRMRR_MASK', 'PRMRR_mask_bits', False, tid)
                self.mask_vld_new = self.cs.register.read_field('PRMRR_MASK', 'PRMRR_VLD', False, tid)
                self.mask_lock_new = self.cs.register.read_field('PRMRR_MASK', 'PRMRR_LOCK', False, tid)
                if self.check_uncore_vals:
                    self.uncore_base_new = self.cs.register.read_field('PRMRR_UNCORE_PHYBASE', 'PRMRR_base_address_fields', False, tid)
                    self.uncore_mask_new = self.cs.register.read_field('PRMRR_UNCORE_MASK', 'PRMRR_mask_bits', False, tid)
                    self.uncore_mask_vld_new = self.cs.register.read_field('PRMRR_UNCORE_MASK', 'PRMRR_VLD', False, tid)
                    self.uncore_mask_lock_new = self.cs.register.read_field('PRMRR_UNCORE_MASK', 'PRMRR_LOCK', False, tid)
                if self.logger.VERBOSE:
                    self.logger.log(f"[*]      CPU{tid:d} PRMRR_VALID_CONFIG: 0x{self.valid_config_new:010X}")
                    self.logger.log(f"[*]      CPU{tid:d} PRMRR base address: 0x{self.base_new:012X}")
                    self.logger.log(f"[*]      CPU{tid:d} PRMRR memory type: 0x{self.base_memtype_new:d}")
                    self.logger.log(f"[*]      CPU{tid:d} PRMRR mask address: 0x{self.mask_new:012X}")
                    self.logger.log(f"[*]      CPU{tid:d} PRMRR mask valid: 0x{self.mask_vld_new:d}")
                    self.logger.log(f"[*]      CPU{tid:d} PRMRR mask lock: 0x{self.mask_lock_new:d}")
                    if self.check_uncore_vals:
                        self.logger.log(f"[*]      CPU{tid:d} PRMRR uncore base address: 0x{self.uncore_base_new:012X}")
                        self.logger.log(f"[*]      CPU{tid:d} PRMRR uncore mask address: 0x{self.uncore_mask_new:012X}")
                        self.logger.log(f"[*]      CPU{tid:d} PRMRR uncore mask valid: 0x{self.uncore_mask_vld_new:d}")
                        self.logger.log(f"[*]      CPU{tid:d} PRMRR uncore mask lock: 0x{self.uncore_mask_lock_new:d}")
                if first_iter:
                    self.valid_config = self.valid_config_new
                    self.base = self.base_new
                    self.base_memtype = self.base_memtype_new
                    self.mask = self.mask_new
                    self.mask_vld = self.mask_vld_new
                    self.mask_lock = self.mask_lock_new
                    self.uncore_base = self.uncore_base_new
                    self.uncore_mask = self.uncore_mask_new
                    self.uncore_mask_vld = self.uncore_mask_vld_new
                    self.uncore_mask_lock = self.uncore_mask_lock_new
                    first_iter = False
                if self.mask_lock_new == 0:
                    self.locked = False
                if ((self.valid_config != self.valid_config_new) or
                    (self.base != self.base_new) or (self.mask != self.mask_new) or
                    (self.uncore_base != self.uncore_base_new) or
                    (self.uncore_mask != self.uncore_mask_new) or
                    (self.mask_vld != self.mask_vld_new) or
                    (self.mask_lock != self.mask_lock_new) or
                    (self.uncore_mask_vld != self.uncore_mask_vld_new) or
                    (self.uncore_mask_lock != self.uncore_mask_lock_new) or
                        (self.base_memtype != self.base_memtype_new)):
                    self.uniform = False

        

    def run(self, _) -> int:
        self.logger.start_test("Check SGX feature support")

        self.res = self.check_sgx_config()
        if self.res == ModuleResult.PASSED:
            self.logger.log_passed('All SGX checks passed')
        elif self.res == ModuleResult.WARNING:
            self.logger.log_warning('One or more SGX checks detected a warning')
        else:
            self.logger.log_failed('One or more SGX checks failed')
        
        return self.result.getReturnCode(self.res)

