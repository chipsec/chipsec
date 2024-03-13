# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2020, Intel Corporation
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
Extended Page Table (EPT) Finder

Usage:
   ``chipsec_main -m tools.vmm.ept_finder [-a dump,<file_name>|file,<file_name>,<revision_id>]``

    - ``dump``          : Dump contents
    - ``file``          : Load contents from file
    - ``<file_name>``   : File name to read from or dump to
    - ``<revision_id>`` : Revision ID (hex)

Where:
    - ``[]``: optional line

Examples:
    >>> chipsec_main.py -i -m tools.vmm.ept_finder
    >>> chipsec_main.py -i -m tools.vmm.ept_finder -a dump,my_file.bin
    >>> chipsec_main.py -i -m tools.vmm.ept_finder -a file,my_file.bin,0x0

.. important::
    - This module is designed to run in a VM environment
    - Behavior on physical HW is undefined

"""

import os
import struct
import glob

from chipsec.library.logger import logger
from chipsec.library.file import write_file
from chipsec.module_common import BaseModule
from chipsec.library.returncode import ModuleResult
from chipsec.hal.paging import c_extended_page_tables


class c_extended_page_tables_from_file(c_extended_page_tables):
    def __init__(self, cs, read_from_file, par):
        c_extended_page_tables.__init__(self, cs)
        self.read_from_file = read_from_file
        self.par = par

    def readmem(self, name, addr, size=4096):
        if self.read_from_file:
            for (pa, end_pa, source) in self.par:
                if (pa <= addr) and (addr + size <= end_pa):
                    source.seek(addr - pa)
                    return source.read(size)
            logger().log_error(f'Invalid memory address: {addr:016x}-{addr + size:016x}')
            return '\xFF' * size
        return self.cs.mem.read_physical_mem(addr, size)


class ept_finder(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
        self.read_from_file = False
        self.par = []

    def read_physical_mem(self, addr, size=0x1000):
        if self.read_from_file:
            for (pa, end_pa, source) in self.par:
                if (pa <= addr) and (addr + size <= end_pa):
                    source.seek(addr - pa)
                    return source.read(size)
            self.logger.log_error(f'Invalid memory address: {addr:016x}-{addr + size:016x}')
            return '\xFF' * size
        return self.cs.mem.read_physical_mem(addr, size)

    def read_physical_mem_dword(self, addr):
        return struct.unpack('<L', self.read_physical_mem(addr, 4))[0]

    def get_memory_ranges(self):
        MASK = 0xFFFFFFFFFFFFF000
        tsegmb = None
        touud = None

        if self.cs.register.is_defined('PCI0.0.0_TSEGMB'):
            tsegmb = self.cs.register.read('PCI0.0.0_TSEGMB') & MASK
        else:
            self.logger.log_error('Couldn not find definition of required registers: TSEGMB')

        if self.cs.register.is_defined('PCI0.0.0_TOUUD'):
            touud = self.cs.register.read('PCI0.0.0_TOUUD') & MASK
        else:
            self.logger.log_error('Could not find definition of required registers: TOUUD')

        par = []
        if not (tsegmb is None):
            par.append((0x00000000, tsegmb, None))
        if not (touud is None):
            par.append((0x100000000, touud, None))

        return par

    def find_vmcs_by_ept(self, ept_list, revision_id):
        EPTP_OFFSET = 0x0140
        MASK = 0xFFFFFFFFFFFFF000
        vmcs_list = []
        for (pa, end_pa, _) in self.par:
            while pa < end_pa:
                revid = self.read_physical_mem_dword(pa)
                eptp = self.read_physical_mem_dword(pa + EPTP_OFFSET)
                eptp += self.read_physical_mem_dword(pa + EPTP_OFFSET + 4) << 32
                if (eptp & MASK in ept_list) and (revision_id == revid):
                    vmcs_list.append(pa)
                pa += 0x1000
        return vmcs_list

    def find_ept_pt(self, pt_addr_list, mincount, level):
        pt_list = {}
        for (pa, end_pa, _) in self.par:
            while pa < end_pa:
                page = struct.unpack('<512Q', self.read_physical_mem(pa))
                count = 0
                allzeros = True
                topalike = True
                reserved = False
                for i in range(512):
                    big_page = ((page[i] >> 7) & 0x1) == 1
                    memtype = ((page[i] >> 3) & 0x7)

                    if level == 4:
                        reserved_bits_mask = 0x000FFF0000000000
                    elif level == 3:
                        if big_page:
                            reserved_bits_mask = 0x000FFF00001FF000
                        else:
                            reserved_bits_mask = 0x000FFF0000000078
                    elif level == 2:
                        if big_page:
                            reserved_bits_mask = 0x000FFF003FFFF000
                        else:
                            reserved_bits_mask = 0x000FFF0000000078
                    elif level == 1:
                        reserved_bits_mask = 0x000FFF00000000F8

                    if (page[i] & reserved_bits_mask) != 0:
                        reserved = True
                        break

                    if (level == 4) or (level in [2, 3] and big_page):
                        if memtype not in [0, 1, 4, 5, 6]:
                            reserved = True
                            break

                    if page[i] != 0:
                        allzeros = False
                        if i >= 8:
                            topalike = False

                    if (page[i] & 0x0000FFFFFFFFF000) in pt_addr_list:
                        count += 1

                if not reserved and not allzeros:
                    if level == 1:
                        if topalike and (page[0] & 0x0000FFFFFFFFF000) in pt_addr_list:
                            pt_list[pa] = 1
                    elif count >= mincount:
                        pt_list[pa] = 1
                pa += 0x1000
        return pt_list

    def dump_dram(self, filename, pa, end_pa, buffer_size=0x100000):
        with open(filename, 'wb') as dram:
            self.logger.log(f'[*] Dumping memory to {filename} ...')
            while pa < end_pa:
                dram.write(self.cs.mem.read_physical_mem(pa, min(end_pa - pa, buffer_size)))
                pa += buffer_size
        return

    def run(self, module_argv):
        self.logger.start_test('EPT Finder')

        self.read_from_file = (len(module_argv) > 0) and (module_argv[0] == 'file')

        if self.read_from_file:
            if len(module_argv) == 3:
                revision_id = int(module_argv[2], 16)
                pattern = f'{module_argv[1]}.dram_*'
                filenames = glob.glob(pattern)
                for name in filenames:
                    addr = name[len(pattern) - 1:]
                    addr = 0 if addr == 'lo' else 0x100000000 if addr == 'hi' else int(addr, 16)
                    size = os.stat(name).st_size
                    self.logger.log(f'  Mapping file to address: 0x{addr:012x}  size: 0x{size:012x}  name: {name}')
                    self.par.append((addr, addr + size, open(name, 'rb')))
            else:
                self.logger.log_error('Invalid parameters')
                self.logger.log(self.__doc__.replace('`', ''))
                return ModuleResult.ERROR
        else:
            revision_id = self.cs.msr.read_msr(0, 0x480)[0]
            self.par = self.get_memory_ranges()

        if len(self.par) == 0:
            self.logger.log_error('Memory ranges are not defined!')
            return ModuleResult.ERROR

        if (len(module_argv) == 2) and (module_argv[0] == 'dump'):
            for (pa, end_pa, _) in self.par:
                postfix = 'lo' if pa == 0x0 else 'hi' if pa == 0x100000000 else f'0x{pa:08x}'
                filename = f'{module_argv[1]}.dram_{postfix}'
                self.dump_dram(filename, pa, end_pa)
            return ModuleResult.PASSED

        self.logger.log('[*] Searching Extended Page Tables ...')
        ept_pt_list = self.find_ept_pt({}, 0, 4)
        self.logger.log(f'[*] Found PTs  : {len(ept_pt_list):d}')
        ept_pd_list = self.find_ept_pt(ept_pt_list, 4, 3)
        self.logger.log(f'[*] Found PDs  : {len(ept_pd_list):d}')
        ept_pdpt_list = self.find_ept_pt(ept_pd_list, 1, 2)
        self.logger.log(f'[*] Found PDPTs: {len(ept_pdpt_list):d}')
        ept_pml4_list = self.find_ept_pt(ept_pdpt_list, 1, 1)
        self.logger.log(f'[*] Found PML4s: {len(ept_pml4_list):d}')
        self.logger.log('[*] -> EPTP: ' + ' '.join([f'{x:08X}' for x in sorted(ept_pml4_list.keys())]))
        ept_vmcs_list = self.find_vmcs_by_ept([x for x in ept_pml4_list.keys()], revision_id)
        self.logger.log(f'[*] Found VMCSs: {len(ept_vmcs_list):d}')
        self.logger.log('[*] -> VMCS: ' + ' '.join([f'{x:08X}' for x in sorted(ept_vmcs_list)]))

        try:
            self.path = 'VMs\\'
            os.makedirs(self.path)
        except OSError:
            pass

        for addr in sorted(ept_vmcs_list):
            write_file(self.path + f'vmcs_{addr:08x}.bin', self.read_physical_mem(addr))

        count = 1
        for eptp in sorted(ept_pml4_list.keys()):
            ept = c_extended_page_tables_from_file(self.cs, self.read_from_file, self.par)
            ept.prompt = f'[VM{count:d}]'
            ept.read_pt_and_show_status(self.path + f'ept_{eptp:08x}', 'Extended', eptp)
            if not ept.failure:
                ept.save_configuration(self.path + f'ept_{eptp:08x}.py')
            count += 1
            
        for (_, _, source_fp) in self.par:
            if source_fp:
                source_fp.close()

        return ModuleResult.INFORMATION
