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
x64/IA-64 Paging functionality including x86 page tables, Extended Page Tables (EPT) and VT-d page tables
"""

import sys
import struct
from typing import Dict, List, Optional, Any
import chipsec.library.defines as defines
from chipsec.library.logger import logger
from chipsec.library.exceptions import InvalidMemoryAddress

ADDR_MASK = defines.MASK_64b
MAXPHYADDR = 0x000FFFFFFFFFF000

SIZE_4KB = defines.BOUNDARY_4KB
SIZE_2MB = defines.BOUNDARY_2MB
SIZE_1GB = defines.BOUNDARY_1GB
ADDR_4KB = 0xFFFFFFFFFFFFF000 & MAXPHYADDR
ADDR_2MB = 0xFFFFFFFFFFE00000 & MAXPHYADDR
ADDR_1GB = 0xFFFFFFFFC0000000 & MAXPHYADDR

TranslationType = Dict[int, Dict[str, Any]]  # TODO: TypedDict (PEP589)

class c_translation:

    def __init__(self):
        self.translation: TranslationType = {}

    def is_translation_exist(self, addr: int, mask: int, size: str) -> bool:
        return ((addr & mask) in self.translation) and (self.translation[addr & mask]['size'] == size)

    def get_translation(self, addr: int) -> Optional[int]:
        if len(self.translation) == 0:
            return addr
        ADDR_4KB = 0xFFFFFFFFFFFFF000
        ADDR_2MB = 0xFFFFFFFFFFE00000
        ADDR_1GB = 0xFFFFFFFFC0000000
        if self.is_translation_exist(addr, ADDR_4KB, '4KB'):
            result = self.translation[addr & ADDR_4KB]['addr'] | (addr & ~ADDR_4KB)
        elif self.is_translation_exist(addr, ADDR_2MB, '2MB'):
            result = self.translation[addr & ADDR_2MB]['addr'] | (addr & ~ADDR_2MB)
        elif self.is_translation_exist(addr, ADDR_1GB, '1GB'):
            result = self.translation[addr & ADDR_1GB]['addr'] | (addr & ~ADDR_1GB)
        else:
            result = None
        return result

    def get_pages_by_physaddr(self, addr: int) -> List[Dict[str, int]]:
        SIZE = {'4KB': ADDR_4KB, '2MB': ADDR_2MB, '1GB': ADDR_1GB}
        result = []
        for i in self.translation.keys():
            page = self.translation[i]
            size = SIZE[page['size']]
            if (page['addr'] & size) == (addr & size):
                result.append(page)
        return result

    def get_address_space(self) -> int:
        total = 0
        mem_range = self.get_mem_range()
        for i in mem_range:
            total += i[1] - i[0]
        return total

    def get_mem_range(self, noattr: bool = False) -> List[List[int]]:
        SIZE = {'4KB': SIZE_4KB, '2MB': SIZE_2MB, '1GB': SIZE_1GB}
        perm = {self.translation[a]['addr']: self.translation[a] for a in self.translation.keys()}
        mem_range = []
        for addr in sorted(perm.keys()):
            attr = perm[addr]['attr']
            size = SIZE[perm[addr]['size']]
            if noattr:
                attr = ''
            if (mem_range == []):
                mem_range += [[addr, addr + size, attr]]
            elif (mem_range[-1][1] == addr) and (mem_range[-1][2] == attr):
                mem_range[-1][1] += size
            else:
                mem_range += [[addr, addr + size, attr]]
        return mem_range

    def add_page(self, virt: int, phys: int, size: str, attr: str) -> None:
        if size not in ['4KB', '2MB', '4MB', '1GB']:
            raise Exception('Invalid size!')
        self.translation[virt] = {'addr': phys, 'size': size, 'attr': attr}
        return

    def del_page(self, addr: int) -> None:
        if addr in self.translation:
            del self.translation[addr]
        return

    def expand_pages(self, exp_size: str) -> None:
        SIZE = {'1GB': '2MB', '2MB': '4KB'}
        for virt in self.translation.keys():
            size = self.translation[virt]['size']
            attr = self.translation[virt]['attr']
            phys = self.translation[virt]['addr']
            pgsize = (1 << 12) if size == '2MB' else (1 << 20)
            if size == exp_size:
                for i in range(512):
                    self.add_page(virt + i * pgsize, phys + i * pgsize, SIZE[exp_size], attr)
        return


class c_reverse_translation:

    def __init__(self, translation: TranslationType):
        self.reverse_translation: Dict[int, List[Dict[str, Any]]] = {}
        for virt in translation.keys():
            phys = translation[virt]['addr']
            size = translation[virt]['size']
            attr = translation[virt]['attr']
            if phys not in self.reverse_translation:
                self.reverse_translation[phys] = []
            self.reverse_translation[phys].append({'addr': virt, 'size': size, 'attr': attr})

    def get_reverse_translation(self, addr: int) ->  List[Dict[str, Any]]:
        ADDR_4KB = 0xFFFFFFFFFFFFF000
        addr &= ADDR_4KB
        return self.reverse_translation[addr] if addr in self.reverse_translation else []


class c_paging_memory_access:

    def __init__(self, cs):
        self.cs = cs

    def readmem(self, name: str, addr: int, size: int = 4096) -> bytes:
        return self.cs.mem.read_physical_mem(addr, size)


class c_paging_with_2nd_level_translation(c_paging_memory_access):

    def __init__(self, cs):
        c_paging_memory_access.__init__(self, cs)
        self.translation_level2 = c_translation()

    def readmem(self, name: str, addr: int, size: int = 4096) -> bytes:
        phys = self.translation_level2.get_translation(addr)
        if phys is None:
            logger().log_hal('[paging] get_translation(): phys is None. Returning 0.')
            return b''
        if phys != addr:
            name += f'_0x{phys:08X}'
        return super(c_paging_with_2nd_level_translation, self).readmem(name, phys, size)


class c_paging(c_paging_with_2nd_level_translation, c_translation):
    def __init__(self, cs):
        c_paging_with_2nd_level_translation.__init__(self, cs)
        c_translation.__init__(self)
        # variables
        self.did = 0
        self.out = sys.stdout
        self.name = ''
        self.pt = {}
        self.pointer = None
        self.failure = False
        self.canonical_msb = 47

    def get_canonical(self, va: int) -> int:
        canonical_mask = (ADDR_MASK << (self.canonical_msb + 1)) & ADDR_MASK
        canonical_va = (va | canonical_mask) if (va >> self.canonical_msb) & 0x1 else va
        return canonical_va

    def get_field(self, entry: int, desc: Dict[str, int]) -> int:
        return (entry >> desc['offset']) & desc['mask']

    def set_field(self, value: int, desc: Dict[str, int]) -> int:
        return (value & desc['mask']) << desc['offset']

    def read_entries(self, info: str, addr: int, size: int = 8) -> List[Any]:
        data = self.readmem(f'{self.name}_{info}_0x{addr:08X}', addr, 0x1000)
        entries = struct.unpack('<512Q', data)
        if size == 16:
            entries = [[entries[i], entries[i + 1]] for i in range(0, 512, 2)]

        same = True
        for i in range(len(entries)):
            same = same and (entries[0] == entries[i])
        if same:
            return [entries[0]]
        return entries

    def print_info(self, name: str) -> None:
        logger().log(f'\n  {name} physical address ranges:')
        mem_range = self.get_mem_range()
        for index in range(len(mem_range)):
            i = mem_range[index]
            logger().log(f'    0x{i[0]:013X} - 0x{i[1] - 1:013X} {(i[1] - i[0]) >> 12:8d}  {i[2]}')

        logger().log(f'\n  {name} pages:')
        for i in sorted(self.pt.keys()):
            logger().log(f'    0x{i:013X}  {self.pt[i]}')
        logger().log('\n')
        logger().log(f'  {name} size: {len(self.pt.keys()) * 4:d} KB, address space: {self.get_address_space() >> 20:d} MB')
        return

    def check_misconfig(self, addr_list: List[int]) -> None:
        addr_list = [x & MAXPHYADDR for x in addr_list]
        mem_range = self.get_mem_range()
        for addr in addr_list:
            for i in range(len(mem_range)):
                if (mem_range[i][0] <= addr) and (addr < mem_range[i][1]):
                    logger().log_hal(f'*** WARNING: PAGE TABLES MISCONFIGURATION  0x{addr:013X}')
        return

    def save_configuration(self, path: str) -> None:
        with open(path, 'w') as cfg:
            try:
                cfg.write(str(self.translation_level2.translation) + '\n')
                cfg.write(str(self.translation) + '\n')
                cfg.write(str(self.pt))
            except:
                logger().log_hal(f'[paging] Error saving: {path}')
        return

    def load_configuration(self, path: str) -> None:
        with open(path, 'r') as cfg:
            try:
                self.translation_level2.translation = eval(cfg.readline())
                self.translation = eval(cfg.readline())
                self.pt = eval(cfg.readline())
            except:
                logger().log_hal(f'[paging] Error loading: {path}')
        return

    def read_pt_and_show_status(self, path: str, name: str, ptr: int) -> None:
        logger().log_hal(f'[paging] Reading {name} page tables at 0x{ptr:016X}...')
        try:
            self.read_page_tables(ptr)
        except InvalidMemoryAddress:
            self.translation_level2.translation = {}
            self.translation = {}
            self.pt = {}
            self.failure = True
            if logger().HAL:
                logger().log_error(f'    Invalid {name} Page Tables!')
        else:
            self.print_info(f'[paging] {name} page tables')
            self.failure = False
            logger().log_hal(f'[paging] size: {len(self.pt.keys()) * 4:d} KB, address space: {self.get_address_space() >> 20:d} MB')
        return

    def read_page_tables(self, entry: int):
        raise Exception("Function needs to be implemented by child class")


class c_4level_page_tables(c_paging):

    def __init__(self, cs):
        c_paging.__init__(self, cs)
        # constants
        self.PHYSICAL_ADDR_NAME = ''
        self.PML4_INDX = {'mask': 0x1FF, 'offset': 39}
        self.PDPT_INDX = {'mask': 0x1FF, 'offset': 30}
        self.PD_INDX = {'mask': 0x1FF, 'offset': 21}
        self.PT_INDX = {'mask': 0x1FF, 'offset': 12}
        self.PT_NAME = ['EPTP', 'PML4E', 'PDPTE', 'PDE', 'PTE']
        self.PT_SIZE = ['', '', '1GB', '2MB', '4KB']

    def get_virt_addr(self, pml4e_index: int, pdpte_index: int = 0, pde_index: int = 0, pte_index: int = 0) -> int:
        ofs1 = self.set_field(pml4e_index, self.PML4_INDX)
        ofs2 = self.set_field(pdpte_index, self.PDPT_INDX)
        ofs3 = self.set_field(pde_index, self.PD_INDX)
        ofs4 = self.set_field(pte_index, self.PT_INDX)
        return (ofs1 | ofs2 | ofs3 | ofs4)

    def print_entry(self, lvl: int, pa: int, va: int = 0, perm: str = '') -> None:
        canonical_va = self.get_canonical(va)
        info = f'  {"  " * lvl}{self.PT_NAME[lvl]:6}: {pa:013X}'
        if perm != '':
            size = self.PT_SIZE[lvl]
            info += f' - {size} PAGE  {perm}'
            info = info.ljust(64)
            if pa == va:
                info += '1:1 mapping'
            else:
                info += f'{self.PHYSICAL_ADDR_NAME}: {canonical_va:013X}'

            self.add_page(canonical_va, pa, size, perm)

        logger().log(info)
        return

    def read_page_tables(self, ptr: int) -> None:
        addr = ptr & ADDR_4KB
        self.pointer = addr
        self.pt = {addr: 'pml4'}
        self.translation = {}
        self.print_entry(0, addr)
        self.read_pml4(addr)
        return

    def is_present(self, entry: int) -> int:
        return entry & defines.BIT0

    def is_bigpage(self, entry: int) -> int:
        return entry & defines.BIT7

    def read_pml4(self, addr: int) -> None:
        pml4 = self.read_entries('pml4', addr)
        for pml4e_index in range(len(pml4)):
            pml4e = pml4[pml4e_index]
            if self.is_present(pml4e):
                addr = pml4e & ADDR_4KB
                self.pt[addr] = 'pdpt'
                self.print_entry(1, addr)
                self.read_pdpt(addr, pml4e_index)
        return

    def get_attr(self, entry: int) -> str:
        ret = ''
        if entry & defines.BIT1:
            ret += 'W'
        else:
            ret += "R"
        if entry & defines.BIT2:
            ret += 'U'
        else:
            ret += 'S'
        return ret

    def read_pdpt(self, addr: int, pml4e_index: int) -> None:
        pdpt = self.read_entries('pdpt', addr)
        for pdpte_index in range(len(pdpt)):
            pdpte = pdpt[pdpte_index]
            if self.is_present(pdpte):
                if self.is_bigpage(pdpte):
                    virt = self.get_virt_addr(pml4e_index, pdpte_index)
                    phys = pdpte & ADDR_1GB
                    self.print_entry(2, phys, virt, self.get_attr(pdpte))
                else:
                    addr = pdpte & ADDR_4KB
                    self.pt[addr] = 'pd'
                    self.print_entry(2, addr)
                    self.read_pd(addr, pml4e_index, pdpte_index)
        return

    def read_pd(self, addr: int, pml4e_index: int, pdpte_index: int) -> None:
        pd = self.read_entries('pd', addr)
        for pde_index in range(len(pd)):
            pde = pd[pde_index]
            if self.is_present(pde):
                if self.is_bigpage(pde):
                    virt = self.get_virt_addr(pml4e_index, pdpte_index, pde_index)
                    phys = pde & ADDR_2MB
                    self.print_entry(3, phys, virt, self.get_attr(pde))
                else:
                    addr = pde & ADDR_4KB
                    self.pt[addr] = 'pt'
                    self.print_entry(3, addr)
                    self.read_pt(addr, pml4e_index, pdpte_index, pde_index)
        return

    def read_pt(self, addr: int, pml4e_index: int, pdpte_index: int, pde_index: int) -> None:
        pt = self.read_entries('pt', addr)
        for pte_index in range(len(pt)):
            pte = pt[pte_index]
            if self.is_present(pte):
                virt = self.get_virt_addr(pml4e_index, pdpte_index, pde_index, pte_index)
                phys = pte & ADDR_4KB
                self.print_entry(4, phys, virt, self.get_attr(pte))
        return

    def read_entry_by_virt_addr(self, virt: int) -> Dict[str, Any]:
        if self.pointer is None:
            raise Exception('Page Table pointer is undefined!')
        addr = self.pointer
        pml4 = self.read_entries('pml4', addr)
        pml4e = pml4[self.get_field(virt, self.PML4_INDX)]
        if self.is_present(pml4e):
            addr = pml4e & ADDR_4KB
            pdpt = self.read_entries('pdpt', addr)
            pdpte = pdpt[self.get_field(virt, self.PDPT_INDX)]
            if self.is_present(pdpte):
                if self.is_bigpage(pdpte):
                    addr = (pdpte & ADDR_1GB) | (virt & ~ADDR_1GB)
                    return {'addr': addr, 'attr': self.get_attr(pdpte), 'size': '1GB'}
                else:
                    addr = pdpte & ADDR_4KB
                    pd = self.read_entries('pd', addr)
                    pde = pd[self.get_field(virt, self.PD_INDX)]
                    if self.is_present(pde):
                        if self.is_bigpage(pde):
                            addr = (pde & ADDR_2MB) | (virt & ~ADDR_2MB)
                            return {'addr': addr, 'attr': self.get_attr(pde), 'size': '2MB'}
                        else:
                            addr = pde & ADDR_4KB
                            pt = self.read_entries('pt', addr)
                            pte = pt[self.get_field(virt, self.PT_INDX)]
                            if self.is_present(pte):
                                addr = (pte & ADDR_4KB) | (virt & ~ADDR_4KB)
                                return {'addr': addr, 'attr': self.get_attr(pte), 'size': '4KB'}
        return {'addr': 0, 'attr': '', 'size': ''}


class c_ia32e_page_tables(c_4level_page_tables):

    def __init__(self, cs):
        c_4level_page_tables.__init__(self, cs)
        # constants
        self.PHYSICAL_ADDR_NAME = 'VA'
        self.PT_NAME = ['CR3P', 'PML4E', 'PDPTE', 'PDE', 'PTE']
        self.P = {'mask': 0x1, 'offset': 0}
        self.RW = {'mask': 0x1, 'offset': 1}
        self.US = {'mask': 0x1, 'offset': 2}
        self.BIGPAGE = {'mask': 0x1, 'offset': 7}

    def is_present(self, entry: int) -> bool:
        return self.get_field(entry, self.P) != 0

    def is_bigpage(self, entry: int) -> bool:
        return self.get_field(entry, self.BIGPAGE) != 0

    def get_attr(self, entry: int) -> str:
        RW_DESC = ['R', 'W']
        US_DESC = ['S', 'U']
        return f'{RW_DESC[self.get_field(entry, self.RW)]} {US_DESC[self.get_field(entry, self.US)]}'


class c_pae_page_tables(c_ia32e_page_tables):

    def __init__(self, cs):
        c_ia32e_page_tables.__init__(self, cs)
        # constants
        self.PML4_INDX = {'mask': 0x000, 'offset': 39}
        self.PDPT_INDX = {'mask': 0x003, 'offset': 30}
        self.PT_NAME = ['', 'CR3', 'PDPTE', 'PDE', 'PTE']

    def read_page_tables(self, ptr: int) -> None:
        addr = ptr & ADDR_4KB
        self.pointer = addr
        self.pt = {addr: 'pdpt'}
        self.translation = {}
        self.print_entry(1, addr)
        self.read_pdpt(addr, None)
        return

    def read_pml4(self, addr: int):
        raise Exception('PAE Page tables have no PML4!')

    def read_pdpt(self, addr: int, pml4e_index: Optional[int] = None) -> None:
        if not pml4e_index:
            raise Exception('PAE Page tables have no PML4!')
        pdpt = self.read_entries('pdpt', addr)
        for pdpte_index in range(4):
            pdpte = pdpt[pdpte_index]
            if self.is_present(pdpte):
                if self.is_bigpage(pdpte):
                    virt = self.get_virt_addr(0, pdpte_index)
                    phys = pdpte & ADDR_1GB
                    self.print_entry(2, phys, virt, self.get_attr(pdpte))
                else:
                    addr = pdpte & ADDR_4KB
                    self.pt[addr] = 'pd'
                    self.print_entry(2, addr)
                    self.read_pd(addr, 0, pdpte_index)
        return


class c_extended_page_tables(c_4level_page_tables):

    def __init__(self, cs):
        c_4level_page_tables.__init__(self, cs)
        # constants
        self.PHYSICAL_ADDR_NAME = 'GPA'
        self.XWR = {'mask': 0x7, 'offset': 0}
        self.MEM_TYPE = {'mask': 0x7, 'offset': 3}
        self.BIGPAGE = {'mask': 0x1, 'offset': 7}
        self.canonical_msb = 63

    def is_present(self, entry: int) ->  bool:
        return self.get_field(entry, self.XWR) != 0

    def is_bigpage(self, entry: int) -> bool:
        return self.get_field(entry, self.BIGPAGE) != 0

    def get_attr(self, entry: int) -> str:
        XWR_DESC = ['---', '--R', '-W-', '-WR', 'X--', 'X-R', 'XW-', 'XWR']
        MEM_DESC = ['UC', 'WC', '02', '03', 'WT', 'WP', 'WB', 'UC-']
        return f'{XWR_DESC[self.get_field(entry, self.XWR)]} {MEM_DESC[self.get_field(entry, self.MEM_TYPE)]}'

    def read_pt_and_show_status(self, path: str, name: str, ptr: int) -> None:
        super(c_extended_page_tables, self).read_pt_and_show_status(path, name, ptr)
        self.check_misconfig(list(self.pt))
        return

    def map_bigpage_1G(self, virt: int, i: int) -> None:
        if self.pointer is None:
            raise Exception('Page Table pointer is undefined!')
        addr = self.pointer
        pml4 = self.read_entries('pml4', addr)
        pml4e = pml4[self.get_field(virt, self.PML4_INDX)]
        if self.is_present(pml4e):
            addr = pml4e & ADDR_4KB
            pdpt = self.read_entries('pdpt', addr)
            new_entry = struct.pack('<Q', ((pdpt[i] | 0x87) & ~ADDR_4KB) | (i << 30))
            self.cs.mem.write_physical_mem(addr + i * 8, 8, new_entry)
        return None


class c_vtd_page_tables(c_extended_page_tables):

    def __init__(self, cs):
        c_extended_page_tables.__init__(self, cs)
        # constants
        self.DID_BUS = {'mask': 0xFF, 'offset': 8}
        self.DID_DEV = {'mask': 0x1F, 'offset': 3}
        self.DID_FUN = {'mask': 0x07, 'offset': 0}
        self.RE_LO_P = {'mask': 0x01, 'offset': 0}
        self.CE_HI_AW = {'mask': 0x07, 'offset': 0}
        self.CE_HI_AVAIL = {'mask': 0x0F, 'offset': 3}
        self.CE_HI_DID = {'mask': 0xFF, 'offset': 8}
        self.CE_LO_P = {'mask': 0x01, 'offset': 0}
        self.CE_LO_FPD = {'mask': 0x01, 'offset': 1}
        self.CE_LO_T = {'mask': 0x03, 'offset': 2}
        # variables
        self.context = {}
        self.domains = {}
        self.cpt = {}

    def read_vtd_context(self, path: str, ptr: int) -> None:
        txt = open(path, 'w')
        try:
            self.out = txt
            addr = ptr & ADDR_4KB
            self.context = {}
            self.domains = {}
            self.cpt = {addr: 'root'}
            self.read_re(addr)

            if len(self.domains) != 0:
                logger().log('[paging] VT-d domains:')
                for domain in sorted(self.domains.keys()):
                    logger().log(f'  0x{domain:016X} ')
            logger().log(f'[paging] Total VT-d domains: {len(self.domains):d}\n')

            logger().log('[paging] VT-d context entries:')
            for source_id in sorted(self.context.keys()):
                self.print_context_entry(source_id, self.context[source_id])

            logger().log('[paging] VT-d context pages:')
            for i in sorted(self.cpt.keys()):
                logger().log(f'    0x{i:013X}  {self.cpt[i]}')
        finally:
            txt.close()
        return

    def read_re(self, addr: int) -> None:
        re = self.read_entries('re', addr, 16)
        for ree_index in range(len(re)):
            ree_lo = re[ree_index][0]
            ree_hi = re[ree_index][1]
            if self.get_field(ree_lo, self.RE_LO_P):
                addr = ree_lo & ADDR_4KB
                self.read_ce(addr, ree_index)
                self.cpt[addr] = 'context'
        return

    def read_ce(self, addr: int, ree_index: int) -> None:
        ce = self.read_entries('ce', addr, 16)
        for cee_index in range(len(ce)):
            cee_lo = ce[cee_index][0]
            cee_hi = ce[cee_index][1]
            if self.get_field(cee_lo, self.CE_LO_P):
                source_id = (ree_index << 8) | cee_index
                self.context[source_id] = [cee_lo, cee_hi]
                if self.get_field(cee_lo, self.CE_LO_T) in (0, 1):
                    slptptr = cee_lo & MAXPHYADDR
                    self.domains[slptptr] = 1
        return

    def print_context_entry(self, source_id: int, cee: Dict[int, int]) -> None:
        if self.get_field(cee[0], self.CE_LO_P):
            info = (
                self.get_field(source_id, self.DID_BUS),
                self.get_field(source_id, self.DID_DEV),
                self.get_field(source_id, self.DID_FUN),
                self.get_field(cee[1], self.CE_HI_DID),
                self.get_field(cee[1], self.CE_HI_AVAIL),
                self.get_field(cee[1], self.CE_HI_AW),
                self.get_field(cee[0], self.CE_LO_T),
                self.get_field(cee[0], self.CE_LO_FPD),
                cee[0] & MAXPHYADDR
            )
            logger().log('  {:02X}:{:02X}.{:X}  DID: {:02X}  AVAIL: {:X}  AW: {:X}  T: {:X}  FPD: {:X}  SLPTPTR: {:016X}'.format(*info))
        return

    def read_page_tables(self, ptr: int) -> None:
        logger().log(f'  Page Tables for domain 0x{ptr:013X}: ')
        super(c_vtd_page_tables, self).read_page_tables(ptr)
        return

    def read_pt_and_show_status(self, path: str, name: str, ptr: int) -> None:
        super(c_vtd_page_tables, self).read_pt_and_show_status(path, name, ptr)
        self.check_misconfig(list(self.cpt))
        return
