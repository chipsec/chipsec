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
Access to CPU resources (for each CPU thread): Model Specific Registers (MSR), IDT/GDT

usage:
    >>> read( 0x8B )
    >>> write( 0x79, 0x12345678 )
    >>> get_cpu_thread_count()
    >>> get_IDTR( 0 )
    >>> get_GDTR( 0 )
    >>> dump_Descriptor_Table( 0, DESCRIPTOR_TABLE_CODE_IDTR )
    >>> IDT( 0 )
    >>> GDT( 0 )
    >>> IDT_all()
    >>> GDT_all()
"""

from typing import Dict, Tuple, Optional
from chipsec.library.logger import logger, print_buffer_bytes
from chipsec.hal.hal_base import HALBase


DESCRIPTOR_TABLE_CODE_IDTR = 0
DESCRIPTOR_TABLE_CODE_GDTR = 1
DESCRIPTOR_TABLE_CODE_LDTR = 2

MTRR_MEMTYPE_UC = 0x0
MTRR_MEMTYPE_WC = 0x1
MTRR_MEMTYPE_WT = 0x4
MTRR_MEMTYPE_WP = 0x5
MTRR_MEMTYPE_WB = 0x6
MemType: Dict[int, str] = {
    MTRR_MEMTYPE_UC: 'Uncacheable (UC)',
    MTRR_MEMTYPE_WC: 'Write Combining (WC)',
    MTRR_MEMTYPE_WT: 'Write-through (WT)',
    MTRR_MEMTYPE_WP: 'Write-protected (WP)',
    MTRR_MEMTYPE_WB: 'Writeback (WB)'
}


class Msr(HALBase):

    def __init__(self, cs):
        super(Msr, self).__init__(cs)
        self.topo = None
        
    # TODO: Move this somewhere else.
    def get_cpu_thread_count(self) -> int:
        if not self.topo:
            self.topo = self.cs.hals.CPU.get_cpu_topology()
        self.logger.log_hal(f'[Msr] # of logical CPUs: {self.topo["threads"]:d}')
        return self.topo['threads']


    def get_cpu_core_count(self) -> int:
        if not self.topo:
            self.topo = self.cs.hals.CPU.get_cpu_topology()
        core_count = len(self.topo['cores'])
        self.logger.log_hal(f'[Msr] # of cores in Package: {core_count:d}')
        return core_count
        


##########################################################################################################
#
# Read/Write CPU MSRs
#
##########################################################################################################


    def read(self, cpu_thread_id: int, msr_addr: int) -> Tuple[int, int]:
        (eax, edx) = self.cs.helper.read_msr(cpu_thread_id, msr_addr)
        self.logger.log_hal(f'[cpu{cpu_thread_id:d}] RDMSR( 0x{msr_addr:x} ): EAX = 0x{eax:08X}, EDX = 0x{edx:08X}')
        return (eax, edx)
    
    def read_msr(self, cpu_thread_id: int, msr_addr: int) -> Tuple[int, int]:
        return self.read(cpu_thread_id, msr_addr)

    def write(self, cpu_thread_id: int, msr_addr: int, eax: int, edx: int) -> None:
        self.cs.helper.write_msr(cpu_thread_id, msr_addr, eax, edx)
        self.logger.log_hal(f'[cpu{cpu_thread_id:d}] WRMSR( 0x{msr_addr:x} ): EAX = 0x{eax:08X}, EDX = 0x{edx:08X}')
        return None
    
    def write_msr(self, cpu_thread_id: int, msr_addr: int, eax: int, edx: int) -> None:
        return self.write(cpu_thread_id, msr_addr, eax, edx)

##########################################################################################################
#
# Get CPU Descriptor Table Registers (IDTR, GDTR, LDTR..)
#
##########################################################################################################

    def get_Desc_Table_Register(self, cpu_thread_id: int, code: int) -> Tuple[int, int, int]:
        desc_table = self.cs.helper.get_descriptor_table(cpu_thread_id, code)
        if desc_table is None:
            self.logger.log_hal(f'[msr] Unable to locate CPU Descriptor Table: Descriptor table code = {code:d}')
            return (0, 0, 0)
        return desc_table

    def get_IDTR(self, cpu_thread_id: int) -> Tuple[int, int, int]:
        (limit, base, pa) = self.get_Desc_Table_Register(cpu_thread_id, DESCRIPTOR_TABLE_CODE_IDTR)
        self.logger.log_hal(f'[cpu{cpu_thread_id:d}] IDTR Limit = 0x{limit:04X}, Base = 0x{base:016X}, Physical Address = 0x{pa:016X}')
        return (limit, base, pa)

    def get_GDTR(self, cpu_thread_id: int) -> Tuple[int, int, int]:
        (limit, base, pa) = self.get_Desc_Table_Register(cpu_thread_id, DESCRIPTOR_TABLE_CODE_GDTR)
        self.logger.log_hal(f'[cpu{cpu_thread_id:d}] GDTR Limit = 0x{limit:04X}, Base = 0x{base:016X}, Physical Address = 0x{pa:016X}')
        return (limit, base, pa)

    def get_LDTR(self, cpu_thread_id: int) -> Tuple[int, int, int]:
        (limit, base, pa) = self.get_Desc_Table_Register(cpu_thread_id, DESCRIPTOR_TABLE_CODE_LDTR)
        self.logger.log_hal(f'[cpu{cpu_thread_id:d}] LDTR Limit = 0x{limit:04X}, Base = 0x{base:016X}, Physical Address = 0x{pa:016X}')
        return (limit, base, pa)


##########################################################################################################
#
# Dump CPU Descriptor Tables (IDT, GDT, LDT..)
#
##########################################################################################################


    def dump_Descriptor_Table(self, cpu_thread_id: int, code: int, num_entries: Optional[int] = None) -> Tuple[int, int]:
        (limit, _, pa) = self.cs.helper.get_descriptor_table(cpu_thread_id, code)
        dt = self.cs.helper.read_phys_mem(pa, limit + 1)
        total_num = len(dt) // 16
        if (num_entries is None) or (total_num < num_entries):
            num_entries = total_num
        self.logger.log(f'[cpu{cpu_thread_id:d}] Physical Address: 0x{pa:016X}')
        self.logger.log(f'[cpu{cpu_thread_id:d}] # of entries    : {total_num:d}')
        self.logger.log(f'[cpu{cpu_thread_id:d}] Contents ({num_entries:d} entries):')
        print_buffer_bytes(dt)
        self.logger.log('--------------------------------------')
        self.logger.log('#    segment:offset         attributes')
        self.logger.log('--------------------------------------')
        for i in range(0, num_entries):
            offset = (dt[i * 16 + 11] << 56) | (dt[i * 16 + 10] << 48) | (dt[i * 16 + 9] << 40) | (dt[i * 16 + 8] << 32) | (dt[i * 16 + 7] << 24) | (dt[i * 16 + 6] << 16) | (dt[i * 16 + 1] << 8) | dt[i * 16 + 0]
            segsel = (dt[i * 16 + 3] << 8) | dt[i * 16 + 2]
            attr = (dt[i * 16 + 5] << 8) | dt[i * 16 + 4]
            self.logger.log(f'{i:03d}  {segsel:04X}:{offset:016X}  0x{attr:04X}')

        return (pa, dt)

    def IDT(self, cpu_thread_id: int, num_entries: Optional[int] = None) -> Tuple[int, int]:
        self.logger.log_hal(f'[cpu{cpu_thread_id:d}] IDT:')
        return self.dump_Descriptor_Table(cpu_thread_id, DESCRIPTOR_TABLE_CODE_IDTR, num_entries)

    def GDT(self, cpu_thread_id: int, num_entries: Optional[int] = None) -> Tuple[int, int]:
        self.logger.log_hal(f'[cpu{cpu_thread_id:d}] GDT:')
        return self.dump_Descriptor_Table(cpu_thread_id, DESCRIPTOR_TABLE_CODE_GDTR, num_entries)

    def IDT_all(self, num_entries: Optional[int] = None) -> None:
        for tid in range(self.get_cpu_thread_count()):
            self.IDT(tid, num_entries)

    def GDT_all(self, num_entries: Optional[int] = None) -> None:
        for tid in range(self.get_cpu_thread_count()):
            self.GDT(tid, num_entries)

haldata = {"arch":[HALBase.MfgIds.Intel], 'name': ['Msr']}