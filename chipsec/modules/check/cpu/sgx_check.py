#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2019, Intel Corporation
#
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#
# Authors:
#  Sushmith Hiremath, INTEL DCG RED team
#

"""
Check SGX related configuration
Reference: SGX BWG, CDI/IBP#: 565432
"""

_MODULE_NAME = 'sgx_check'
from chipsec.module_common import *
from chipsec.chipset import *
import chipsec.logger
from chipsec.hal.msr import *
from chipsec.hal.mmio import *
TAGS = [MTAG_HWCONFIG]


class sgx_check(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
        self.helper = self.cs.helper
        self.res = ModuleResult.PASSED

    def check_sgx_config(self):
        self.logger.start_test("Check SGX feature support")
        self.logger.log("[*] Test if CPU has support for SGX")
        sgx_cpu_support = False
        sgx_ok = False
        for tid in range(self.cs.msr.get_cpu_thread_count()):
            status = self.helper.set_affinity(tid)
            if status == -1:
                if logger().VERBOSE:
                    self.logger.log("[*] Failed to set affinity to CPU{:d}".format(tid))
            (r_eax, r_ebx, r_ecx, r_edx) = self.cs.cpu.cpuid(0x07, 0x00)
            if (r_ebx & BIT2):
                if logger().VERBOSE: self.logger.log("[*] CPU{:d}: does support SGX".format(tid))
                sgx_cpu_support = True
            else:
                if logger().VERBOSE: self.logger.log("[*]CPU{:d}: does not support SGX".format(tid))
        if sgx_cpu_support:
            self.logger.log_good("SGX is supported on CPU")
        else:
            self.logger.log_information("SGX is not supported on CPU")
            return ModuleResult.NOTAPPLICABLE

        self.logger.log("\n[*] SGX BIOS enablement check")
        self.logger.log("[*] Verifying IA32_FEATURE_CONTROL MSR is configured")
        bios_feature_control_enable = True
        for tid in range(self.cs.msr.get_cpu_thread_count()):
            if not (self.cs.read_register('IA32_FEATURE_CONTROL', tid) & BIT18):
                bios_feature_control_enable = False
        if bios_feature_control_enable:
            self.logger.log_good("Intel SGX is Enabled in BIOS")
        else:
            self.logger.log_warning( "Intel SGX is not enabled in BIOS" )
            self.res = ModuleResult.WARNING

        self.logger.log("\n[*] Verifying IA32_FEATURE_CONTROL MSR is locked")
        locked = True
        for tid in range(self.cs.msr.get_cpu_thread_count()):
            feature_cntl_lock = self.cs.get_control('Ia32FeatureControlLock', tid)
            if logger().VERBOSE: self.logger.log("[*] cpu{:d}: IA32_Feature_Control Lock = {:d}".format(tid, feature_cntl_lock))
            if 0 == feature_cntl_lock:
                locked = False
        if locked:
            self.logger.log_good("IA32_Feature_Control locked")
        else:
            self.logger.log_failed("IA32_Feature_Control is unlocked")
            self.res = ModuleResult.FAILED

        # Verify that Protected Memory Range (PRM) is supported, MSR IA32_MTRRCAP (FEh) [12]=1
        # Check on every CPU and make sure that they are all the same values
        self.logger.log( "\n[*] Verifying if Protected Memory Range (PRMRR) is configured" )
        prmrr_enable = False
        for tid in range(self.cs.msr.get_cpu_thread_count()):
            mtrrcap = self.cs.read_register('MTRRCAP', tid)
            if (0 == mtrrcap & BIT12):
                if logger().VERBOSE: self.logger.log("[*] CPU{:d} Protected Memory Range configuration is not supported".format(tid))
            else:
                prmrr_enable = True
                if logger().VERBOSE: self.logger.log("[*] CPU{:d} Protected Memory Range configuration is supported".format(tid))
        if prmrr_enable:
            self.logger.log_good( "Protected Memory Range configuration is supported" )
        else:
            self.logger.log_failed( "Protected Memory Range configuration is not supported" )
            self.res - ModuleResult.FAILED

        # Check PRMRR configurations on each core.
        self.logger.log("\n[*] Verifying PRMRR Configuration on each core.")
        first_iter = True
        prmrr_valid_config = 0
        prmrr_base = 0
        prmrr_base_memtype = 0
        prmrr_uncore_base = 0
        prmrr_uncore_base_new = 0
        prmrr_mask = 0
        prmrr_uncore_mask = 0
        prmrr_uncore_mask_new = 0
        prmrr_mask_vld = 0
        prmrr_uncore_mask_vld = 0
        prmrr_uncore_mask_vld_new = 0
        prmrr_mask_lock = 0
        prmrr_uncore_mask_lock = 0
        prmrr_uncore_mask_lock_new = 0
        prmrr_uniform = True
        check_uncore_vals = self.cs.is_register_defined('PRMRR_UNCORE_PHYBASE') and self.cs.is_register_defined('PRMRR_UNCORE_MASK')
        for tid in range(self.cs.msr.get_cpu_thread_count()):
            prmrr_valid_config_new = self.cs.read_register('PRMRR_VALID_CONFIG', tid)
            prmrr_base_new = self.cs.read_register_field('PRMRR_PHYBASE', 'PRMRR_base_address_fields', False, tid)
            prmrr_base_memtype_new = self.cs.read_register_field('PRMRR_PHYBASE', 'PRMRR_MEMTYPE', False, tid)
            prmrr_mask_new = self.cs.read_register_field('PRMRR_MASK', 'PRMRR_mask_bits', False, tid)
            prmrr_mask_vld_new = self.cs.read_register_field('PRMRR_MASK', 'PRMRR_VLD', False, tid)
            prmrr_mask_lock_new = self.cs.read_register_field('PRMRR_MASK', 'PRMRR_LOCK', False, tid)
            if check_uncore_vals:
                prmrr_uncore_base_new = self.cs.read_register_field('PRMRR_UNCORE_PHYBASE', 'PRMRR_base_address_fields', False, tid)
                prmrr_uncore_mask_new = self.cs.read_register_field('PRMRR_UNCORE_MASK', 'PRMRR_mask_bits', False, tid)
                prmrr_uncore_mask_vld_new = self.cs.read_register_field('PRMRR_UNCORE_MASK', 'PRMRR_VLD', False, tid)
                prmrr_uncore_mask_lock_new = self.cs.read_register_field('PRMRR_UNCORE_MASK', 'PRMRR_LOCK', False, tid)
            if logger().VERBOSE:
                self.logger.log("[*]      CPU{:d} PRMRR_VALID_CONFIG: 0x{:010X}".format(tid, prmrr_valid_config_new))
                self.logger.log("[*]      CPU{:d} PRMRR base address: 0x{:012X}".format(tid, prmrr_base_new))
                self.logger.log("[*]      CPU{:d} PRMRR memory type: 0x{:d}".format(tid, prmrr_base_memtype_new))
                self.logger.log("[*]      CPU{:d} PRMRR mask address: 0x{:012X}".format(tid, prmrr_mask_new))
                self.logger.log("[*]      CPU{:d} PRMRR mask valid: 0x{:d}".format(tid, prmrr_mask_vld_new))
                self.logger.log("[*]      CPU{:d} PRMRR mask lock: 0x{:d}".format(tid, prmrr_mask_lock_new))
                if check_uncore_vals:
                    self.logger.log("[*]      CPU{:d} PRMRR uncore base address: 0x{:012X}".format(tid, prmrr_uncore_base_new))
                    self.logger.log("[*]      CPU{:d} PRMRR uncore mask address: 0x{:012X}".format(tid, prmrr_uncore_mask_new))
                    self.logger.log("[*]      CPU{:d} PRMRR uncore mask valid: 0x{:d}".format(tid, prmrr_uncore_mask_vld_new))
                    self.logger.log("[*]      CPU{:d} PRMRR uncore mask lock: 0x{:d}".format(tid, prmrr_uncore_mask_lock_new))
            if first_iter:
                prmrr_valid_config = prmrr_valid_config_new
                prmrr_base = prmrr_base_new
                prmrr_base_memtype = prmrr_base_memtype_new
                prmrr_mask = prmrr_mask_new
                prmrr_mask_vld = prmrr_mask_vld_new
                prmrr_mask_lock = prmrr_mask_lock_new
                prmrr_uncore_base = prmrr_uncore_base_new
                prmrr_uncore_mask = prmrr_uncore_mask_new
                prmrr_uncore_mask_vld = prmrr_uncore_mask_vld_new
                prmrr_uncore_mask_lock = prmrr_uncore_mask_lock_new
                first_iter = False
            if ((prmrr_valid_config != prmrr_valid_config_new) or
                (prmrr_base != prmrr_base_new) or (prmrr_mask != prmrr_mask_new) or
                (prmrr_uncore_base != prmrr_uncore_base_new) or
                (prmrr_uncore_mask != prmrr_uncore_mask_new) or
                (prmrr_mask_vld != prmrr_mask_vld_new) or
                (prmrr_mask_lock != prmrr_mask_lock_new) or
                (prmrr_uncore_mask_vld != prmrr_uncore_mask_vld_new) or
                (prmrr_uncore_mask_lock != prmrr_uncore_mask_lock_new) or
                (prmrr_base_memtype != prmrr_base_memtype_new)):
                prmrr_uniform = False
        if not prmrr_uniform:
            self.logger.log_failed( "PRMRR config is not uniform across all CPUs" )
            self.res = ModuleResult.FAILED
        else:
            self.logger.log_good( "PRMRR config is uniform across all CPUs" )
            prmrr_configs = []
            # NB: BWG Provides only a list of 4 possible values, see item 5, section 2.1. So values e.g. 0x050 are prhibited, report error.
            config_support = False
            if (BIT0 & prmrr_valid_config):
                prmrr_configs.append("1M")
                config_support = True
            if (BIT1 & prmrr_valid_config):
                prmrr_configs.append("2M")
                config_support = True
            if (BIT5 & prmrr_valid_config):
                prmrr_configs.append("32M")
                config_support = True
            if (BIT6 & prmrr_valid_config):
                prmrr_configs.append("64M")
                config_support = True
            if (BIT7 & prmrr_valid_config):
                prmrr_configs.append("128M")
                config_support = True
            if (BIT8 & prmrr_valid_config):
                prmrr_configs.append("256M")
                config_support = True
            if config_support:
                self.logger.log("[*]  PRMRR config supports: {}".format(', '.join(prmrr_configs)))
            else:
                self.logger.log("[*] PRMMR config has improper value")
                sgx_ok = False

            # In some cases the PRMRR base and mask may be zero
            if prmrr_base == 0 and prmrr_mask == 0:
                self.logger.log("[*] PRMRR Base and Mask are set to zero.  PRMRR appears to be disabled.")
                self.logger.log("[*]   Skipping Base/Mask settings.")
            else:
                self.logger.log("[*]  PRMRR base address: 0x{:012X}".format(prmrr_base))
                self.logger.log("[*]  Verifying PRMR memory type is valid")
                self.logger.log("[*]  PRMRR memory type : 0x{:X}".format(prmrr_base_memtype))
                if prmrr_base_memtype == 0x6:
                    self.logger.log_good( "PRMRR memory type is WB as expected" )
                else:
                    self.logger.log_failed( "Unexpected PRMRR memory type (not WB)" )
                    self.res = ModuleResult.FAILED
                self.logger.log("[*]  PRMRR mask address: 0x{:012X}".format(prmrr_mask))
                self.logger.log("[*]  Verifying PRMR address are valid")
                self.logger.log("[*]      PRMRR uncore mask valid: 0x{:d}".format(prmrr_uncore_mask_vld))
                if prmrr_mask_vld == 0x1:
                    self.logger.log_good( "Mcheck marked PRMRR address as valid" )
                else:
                    self.logger.log_failed( "Mcheck marked PRMRR address as invalid" )
                    self.res = ModuleResult.FAILED
                self.logger.log("[*]  Verifying if PRMR mask register is locked")
                self.logger.log("[*]      PRMRR mask lock: 0x%u" % prmrr_mask_lock)
                if prmrr_mask_lock == 0x1:
                    self.logger.log_good( "PRMRR MASK register is locked" )
                else:
                    self.logger.log_failed( "PRMRR MASK register is not locked" )
                    self.res = ModuleResult.FAILED
                if check_uncore_vals:
                    self.logger.log("[*]  PRMRR uncore base address: 0x%012X" % prmrr_uncore_base)
                    self.logger.log("[*]  PRMRR uncore mask address: 0x%012X" % prmrr_uncore_mask)
                    self.logger.log("[*]  Verifying PRMR uncore address are valid")
                    self.logger.log("[*]      PRMRR uncore mask valid: 0x%u" % prmrr_uncore_mask_vld)
                    if prmrr_uncore_mask_vld == 0x1:
                        self.logger.log_good( "Mcheck marked uncore PRMRR address as valid" )
                    else:
                        self.logger.log_failed( "Mcheck marked uncore PRMRR address as invalid" )
                        self.res = ModuleResult.FAILED
                    self.logger.log("[*]  Verifying if PRMR uncore mask register is locked")
                    self.logger.log("[*]      PRMRR uncore mask lock: 0x%u" % prmrr_uncore_mask_lock)
                    if prmrr_uncore_mask_lock == 0x1:
                        self.logger.log_good( "PMRR uncore MASK register is locked" )
                    else:
                        self.logger.log_failed( "PMRR uncore MASK register is not locked" )
                        self.res = ModuleResult.FAILED

        if sgx_cpu_support and bios_feature_control_enable and locked:
            sgx1_instr_support = False
            sgx2_instr_support = False
            self.logger.log("\n[*] Verifying if SGX instructions are supported")
            for tid in range(self.cs.msr.get_cpu_thread_count()):
                status = self.helper.set_affinity(tid)
                if status == -1:
                    if logger().VERBOSE: self.logger.log("[*] Failed to set affinity to CPU{:d}".format(tid))
                (r_eax, r_ebx, r_ecx, r_edx) = self.cs.cpu.cpuid(0x012, 0x00)
                if (r_eax & BIT0):
                    if logger().VERBOSE: self.logger.log("[*] CPU{:d} SGX-1 instructions are supported".format(tid))
                    sgx1_instr_support = True
                else:
                    if logger().VERBOSE: self.logger.log("[*] CPU{:d} SGX-1 instructions are not supported".format(tid))
                if (r_eax & BIT1):
                    if logger().VERBOSE: self.logger.log("[*] CPU{:d} SGX-2 instructions are supported".format(tid))
                    sgx2_instr_support = True
                else:
                    if logger().VERBOSE: self.logger.log("[*] CPU{:d} SGX-2 instructions are not supported".format(tid))
            if sgx1_instr_support:
                self.logger.log_good("Intel SGX instructions are supported and available to use")
                sgx_ok = True
            else:
                self.logger.log_failed("Intel SGX instructions are not supported on system")
                sgx_ok = False
            if sgx2_instr_support:
                    self.logger.log("[*] SGX-2 instructions are supported")
            else:
                    self.logger.log("[*] SGX-2 instructions are not supported")
        else:
            sgx_ok = False

        self.logger.log("\n[*] Verifying if SGX is available to use")
        if sgx_ok and prmrr_enable and prmrr_uniform:
            self.logger.log_good("Intel SGX is available to use")
        elif (not sgx_ok) and (not bios_feature_control_enable) and prmrr_enable and prmrr_uniform:
            self.logger.log_warning("Intel SGX instructions disabled by firmware")
            if self.res == ModuleResult.PASSED:
                self.res = ModuleResult.WARNING
        else:
            self.logger.log_failed("Intel SGX is not available to use")
            self.res = ModuleResult.FAILED

        if self.cs.is_register_defined('BIOS_SE_SVN') and self.cs.is_register_defined('BIOS_SE_SVN_STATUS'):
            self.logger.log("\n[*] BIOS_SE_SVN : 0x{:016X}".format(self.cs.read_register('BIOS_SE_SVN')))
            self.logger.log("[*]     PFAT_SE_SVN : 0x{:02X}".format(self.cs.read_register_field('BIOS_SE_SVN', 'PFAT_SE_SVN')))
            self.logger.log("[*]     ANC_SE_SVN : 0x{:02X}".format(self.cs.read_register_field('BIOS_SE_SVN', 'ANC_SE_SVN')))
            self.logger.log("[*]     SCLEAN_SE_SVN : 0x{:02X}".format(self.cs.read_register_field('BIOS_SE_SVN', 'SCLEAN_SE_SVN')))
            self.logger.log("[*]     SINIT_SE_SVN : 0x{:02X}".format(self.cs.read_register_field('BIOS_SE_SVN', 'SINIT_SE_SVN')))
            self.logger.log("[*] BIOS_SE_SVN_STATUS : 0x{:016X}".format(self.cs.read_register('BIOS_SE_SVN_STATUS')))
            self.logger.log("[*]     BIOS_SE_SVN ACM threshold lock : 0x{:d}".format(self.cs.read_register_field('BIOS_SE_SVN_STATUS', 'LOCK')))

        self.logger.log("\n[*] Check SGX debug feature settings")
        sgx_debug_status = self.cs.read_register_field('SGX_DEBUG_MODE', 'SGX_DEBUG_MODE_STATUS_BIT')
        self.logger.log("[*] SGX Debug Enable             : {:d}".format(sgx_debug_status))
        self.logger.log("[*] Check Silicon debug feature settings")
        debug_interface = self.cs.read_register('IA32_DEBUG_INTERFACE')
        self.logger.log("[*]   IA32_DEBUG_INTERFACE : 0x{:08X}".format(debug_interface))
        debug_enable = self.cs.get_register_field('IA32_DEBUG_INTERFACE', debug_interface, 'ENABLE')
        debug_lock = self.cs.get_register_field('IA32_DEBUG_INTERFACE', debug_interface, 'LOCK')
        self.logger.log("[*]     Debug enabled      : {:d}".format(debug_enable))
        self.logger.log("[*]     Lock               : {:d}".format(debug_lock))

        if (1 == sgx_debug_status):
            self.logger.log_failed("SGX debug mode is enabled")
            self.res = ModuleResult.FAILED
        else:
            self.logger.log_good("SGX debug mode is disabled")
        if (0 == debug_enable):
            self.logger.log_good("Silicon debug features are disabled")
        else:
            self.logger.log_failed("Silicon debug features are not disabled")
            self.res = ModuleResult.FAILED
        if (0 == debug_enable) and (1==sgx_debug_status):
            self.logger.log_failed("Enabling sgx_debug without enabling debug mode in msr IA32_DEBUG_INTERFACE is not a valid configuration")
            self.res = ModuleResult.FAILED
        if (1 == debug_lock):
            self.logger.log_good("Silicon debug Feature Control register is locked")
        else:
            self.logger.log_failed("Silicon debug Feature Control register is not locked")
            self.res = ModuleResult.FAILED

        return self.res

    def run(self, module_argv):
        if self.cs.helper.is_efi():
            self.logger.error( 'Currently this module cannot run within the EFI Shell. Exiting.' )
            return ModuleResult.SKIPPED
        else:
            self.res = self.check_sgx_config()
            if self.res == ModuleResult.PASSED:
                self.logger.log_passed_check('All SGX checks passed')
            elif self.res == ModuleResult.WARNING:
                self.logger.log_warn_check('One or more SGX checks detected a warning')
            elif self.res == ModuleResult.SKIPPED:
                self.logger.log_skipped_check('SGX test is being skipped')
            elif self.res == ModuleResult.NOTAPPLICABLE:
                self.logger.log_not_applicable_check('SGX test is being skipped')
            else:
                self.logger.log_failed_check('One or more SGX checks failed')
            return self.res

