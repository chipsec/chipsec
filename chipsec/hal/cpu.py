# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
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


"""
CPU related functionality

"""
from typing import Dict, List, Tuple, Optional
from chipsec.hal import acpi, hal_base, paging
from chipsec.library.logger import logger

VMM_NONE = 0
VMM_XEN = 0x1
VMM_HYPER_V = 0x2
VMM_VMWARE = 0x3
VMM_KVM = 0x4


########################################################################################################
#
# CORES HAL Component
#
########################################################################################################

class CPU(hal_base.HALBase):
    def __init__(self, cs):
        super(CPU, self).__init__(cs)
        self.helper = cs.helper

    def read_cr(self, cpu_thread_id: int, cr_number: int) -> int:
        value = self.helper.read_cr(cpu_thread_id, cr_number)
        logger().log_hal(f'[cpu{cpu_thread_id:d}] read CR{cr_number:d}: value = 0x{value:08X}')
        return value

    def write_cr(self, cpu_thread_id: int, cr_number: int, value: int) -> int:
        logger().log_hal(f'[cpu{cpu_thread_id:d}] write CR{cr_number:d}: value = 0x{value:08X}')
        status = self.helper.write_cr(cpu_thread_id, cr_number, value)
        return status

    def cpuid(self, eax: int, ecx: int) -> Tuple[int, int, int, int]:
        logger().log_hal(f'[cpu] CPUID in : EAX=0x{eax:08X}, ECX=0x{ecx:08X}')
        (eax, ebx, ecx, edx) = self.helper.cpuid(eax, ecx)
        logger().log_hal(f'[cpu] CPUID out: EAX=0x{eax:08X}, EBX=0x{ebx:08X}, ECX=0x{ecx:08X}, EDX=0x{edx:08X}')
        return (eax, ebx, ecx, edx)

    # Using cpuid check if running under vmm control
    def check_vmm(self) -> int:
        # check Hypervisor Present
        (_, ebx, ecx, edx) = self.cpuid(0x01, 0)
        if (ecx & 0x80000000):
            (_, ebx, ecx, edx) = self.cpuid(0x40000000, 0)
            is_xen = ((ebx == 0x566e6558) and (ecx == 0x65584d4d) and (edx == 0x4d4d566e))
            if is_xen:
                return VMM_XEN
            is_hyperv = ((ebx == 0x7263694D) and (ecx == 0x666F736F) and (edx == 0x76482074))
            if is_hyperv:
                return VMM_HYPER_V
            is_vmware = ((ebx == 0x61774d56) and (ecx == 0x4d566572) and (edx == 0x65726177))
            if is_vmware:
                return VMM_VMWARE
            is_kvm = ((ebx == 0x4b4d564b) and (ecx == 0x564b4d56) and (edx == 0x0000004d))
            if is_kvm:
                return VMM_KVM
        return VMM_NONE

    # Using CPUID we can determine if Hyper-Threading is enabled in the CPU
    def is_HT_active(self) -> bool:
        logical_processor_per_core = self.get_number_logical_processor_per_core()
        return logical_processor_per_core > 1

    # Using the CPUID we determine the number of logical processors per core
    def get_number_logical_processor_per_core(self) -> int:
        (_, ebx, _, _) = self.cpuid(0x0b, 0x0)
        return ebx

    # Using CPUID we can determine the number of logical processors per package
    def get_number_logical_processor_per_package(self) -> int:
        (_, ebx, _, _) = self.cpuid(0x0b, 0x1)
        return ebx

    # Using CPUID we can determine the number of physical processors per package
    def get_number_physical_processor_per_package(self) -> int:
        logical_processor_per_core = self.get_number_logical_processor_per_core()
        logical_processor_per_package = self.get_number_logical_processor_per_package()
        return (logical_processor_per_package // logical_processor_per_core)

    # determine number of logical processors in the core
    def get_number_threads_from_APIC_table(self) -> int:
        _acpi = acpi.ACPI(self.cs)
        dACPIID = {}
        for apic in _acpi.get_parse_ACPI_table(acpi.ACPI_TABLE_SIG_APIC):  # (table_header, APIC_object, table_header_blob, table_blob)
            _, APIC_object, _, _ = apic
            for structure in APIC_object.apic_structs:
                if 0x00 == structure.Type:
                    if not structure.ACICID in dACPIID:
                        if 1 == structure.Flags:
                            dACPIID[structure.APICID] = structure.ACPIProcID
        return len(dACPIID)

    # determine the cpu threads location within a package/core
    def get_cpu_topology(self) -> Dict[str, Dict[int, List[int]]]:
        num_threads = self.cs.helper.get_threads_count()
        packages: Dict[int, List[int]] = {}
        cores: Dict[int, List[int]] = {}
        for thread in range(num_threads):
            if num_threads > 1:
                self.logger.log_hal(f'Setting affinity to: {thread:d}')
                self.cs.helper.set_affinity(thread)
            eax = 0xb   # cpuid leaf 0B contains x2apic info
            ecx = 1     # ecx 1 will get us pkg_id in edx after shifting right by _eax
            (_eax, _, _, _edx) = self.cs.cpu.cpuid(eax, ecx)
            pkg_id = _edx >> (_eax & 0xf)
            if pkg_id not in packages:
                packages[pkg_id] = []
            packages[pkg_id].append(thread)

            ecx = 0     # ecx 0 will get us the core_id in edx after shifting right by _eax
            (_eax, _, _, _edx) = self.cs.cpu.cpuid(eax, ecx)
            core_id = _edx >> (_eax & 0xf)
            if core_id not in cores:
                cores[core_id] = []
            cores[core_id].append(thread)
            self.logger.log_hal(f'pkg id is {pkg_id:x}')
            self.logger.log_hal(f'core id is {core_id:x}')
        topology = {'packages': packages, 'cores': cores}
        return topology

    # determine number of physical sockets using the CPUID and APIC ACPI table
    def get_number_sockets_from_APIC_table(self) -> int:
        number_threads = self.get_number_threads_from_APIC_table()
        logical_processor_per_package = self.get_number_logical_processor_per_package()
        return (number_threads // logical_processor_per_package)

    #
    # Return SMRR MSR physical base and mask
    #
    def get_SMRR(self) -> Tuple[int, int]:
        smrambase = self.cs.register.read_field('IA32_SMRR_PHYSBASE', 'PhysBase', True)
        smrrmask = self.cs.register.read_field('IA32_SMRR_PHYSMASK', 'PhysMask', True)
        return (smrambase, smrrmask)

    #
    # Return SMRAM region base, limit and size as defined by SMRR
    #
    def get_SMRR_SMRAM(self) -> Tuple[int, int, int]:
        (smram_base, smrrmask) = self.get_SMRR()
        smram_base &= smrrmask
        smram_size = ((~smrrmask) & 0xFFFFFFFF) + 1
        smram_limit = smram_base + smram_size - 1
        return (smram_base, smram_limit, smram_size)

    #
    # Returns TSEG base, limit and size
    #
    def get_TSEG(self) -> Tuple[int, int, int]:
        if self.cs.is_server():
            # tseg register has base and limit
            tseg_base = self.cs.register.read_field('TSEG_BASE', 'base', preserve_field_position=True)
            tseg_limit = self.cs.register.read_field('TSEG_LIMIT', 'limit', preserve_field_position=True)
            tseg_limit += 0xFFFFF
        else:
            # TSEG base is in TSEGMB, TSEG limit is BGSM - 1
            tseg_base = self.cs.register.read_field('PCI0.0.0_TSEGMB', 'TSEGMB', preserve_field_position=True)
            bgsm = self.cs.register.read_field('PCI0.0.0_BGSM', 'BGSM', preserve_field_position=True)
            tseg_limit = bgsm - 1

        tseg_size = tseg_limit - tseg_base + 1
        return (tseg_base, tseg_limit, tseg_size)

    #
    # Returns SMRAM base from either SMRR MSR or TSEG PCIe config register
    #
    def get_SMRAM(self) -> Tuple[int, int, int]:
        smram_base = None
        smram_limit = None
        smram_size = 0
        try:
            if self.check_SMRR_supported():
                (smram_base, smram_limit, smram_size) = self.get_SMRR_SMRAM()
        except Exception:
            self.logger.log_hal('[cpu] Error using get_SMRR_SMRAM() to get SMRAM!')

        if (smram_base is None) or (smram_limit is None):
            try:
                (smram_base, smram_limit, smram_size) = self.get_TSEG()
            except Exception:
                self.logger.log_hal('[cpu] Error using get_TSEG() to get SMRAM!')
                smram_base = 0
                smram_limit = 0
        return (smram_base, smram_limit, smram_size)

    #
    # Check that SMRR is supported by CPU in IA32_MTRRCAP_MSR[SMRR]
    #
    def check_SMRR_supported(self) -> bool:
        mtrrcap_msr_reg = self.cs.register.read('MTRRCAP')
        if logger().HAL:
            self.cs.register.print('MTRRCAP', mtrrcap_msr_reg)
        smrr = self.cs.register.get_field('MTRRCAP', mtrrcap_msr_reg, 'SMRR')
        return (1 == smrr)

    #
    # Dump CPU page tables at specified physical base of paging-directory hierarchy (CR3)
    #
    def dump_page_tables(self, cr3: int, pt_fname: Optional[str] = None) -> None:
        _orig_logname = logger().LOG_FILE_NAME
        hpt = paging.c_ia32e_page_tables(self.cs)
        logger().log_hal(f'[cpu] dumping paging hierarchy at physical base (CR3) = 0x{cr3:08X}...')
        if pt_fname is None:
            pt_fname = f'pt_{cr3:08X}'
        logger().set_log_file(pt_fname)
        hpt.read_pt_and_show_status(pt_fname, 'PT', cr3)
        logger().set_log_file(_orig_logname)
        if hpt.failure:
            logger().log_error('could not dump page tables')

    def dump_page_tables_all(self) -> None:
        for tid in range(self.cs.msr.get_cpu_thread_count()):
            cr3 = self.read_cr(tid, 3)
            logger().log_hal(f'[cpu{tid:d}] found paging hierarchy base (CR3): 0x{cr3:08X}')
            self.dump_page_tables(cr3)
