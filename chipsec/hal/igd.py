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

# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
#
# -------------------------------------------------------------------------------

"""
Working with Intel processor Integrated Graphics Device (IGD)

usage:
    >>> gfx_aperture_dma_read(0x80000000, 0x100)
"""

from typing import Optional, Tuple
from chipsec.hal import hal_base
from chipsec.library.logger import print_buffer_bytes


class IGD(hal_base.HALBase):

    def __init__(self, cs):
        super(IGD, self).__init__(cs)
        self.helper = cs.helper
        self.is_legacy = False
        self.enabled = None

    def __identify_device(self) -> Tuple[bool, bool]:
        if self.enabled is None:
            try:
                self.dev_id = self.cs.register.read("PCI0.2.0_DID")
                self.enabled = (self.dev_id != 0xFFFF)
                if self.enabled:
                    self.is_legacy = bool(self.dev_id < 0x1600)
            except Exception:
                self.enabled = False

        return (self.enabled, self.is_legacy)

    def is_enabled(self) -> bool:
        if self.cs.register.has_field("PCI0.0.0_DEVEN", "D2EN") and self.cs.register.has_field("PCI0.0.0_CAPID0_A", "IGD"):
            if self.cs.register.read_field("PCI0.0.0_DEVEN", "D2EN") == 1 and self.cs.register.read_field("PCI0.0.0_CAPID0_A", "IGD") == 0:
                return True
        elif self.cs.register.has_field("PCI0.0.0_DEVEN", "D2EN"):
            if self.cs.register.read_field("PCI0.0.0_DEVEN", "D2EN") == 1:
                return True
        elif self.cs.register.has_field("PCI0.0.0_CAPID0_A", "IGD"):
            if self.cs.register.read_field("PCI0.0.0_CAPID0_A", "IGD") == 0:
                return True
        return self.is_device_enabled()

    def is_device_enabled(self) -> bool:
        enabled, _ = self.__identify_device()
        return enabled

    def is_legacy_gen(self) -> bool:
        _, legacy = self.__identify_device()
        return legacy

    def get_GMADR(self) -> int:
        base, _ = self.cs.mmio.get_MMIO_BAR_base_address('GMADR')
        self.logger.log_hal(f'[igd] Aperture (GMADR): 0x{base:016X}')
        return base

    def get_GTTMMADR(self) -> int:
        base, _ = self.cs.mmio.get_MMIO_BAR_base_address('GTTMMADR')
        self.logger.log_hal(f'[igd] Graphics MMIO and GTT (GTTMMADR): 0x{base:016X}')
        return base

    def get_GGTT_base(self) -> int:
        gtt_off = 0x200000 if self.is_legacy_gen() else 0x800000
        return self.get_GTTMMADR() + gtt_off

    def get_PTE_size(self) -> int:
        return 4 if self.is_legacy_gen() else 8

    def read_GGTT_PTE(self, pte_num: int) -> int:
        gtt_base = self.get_GGTT_base()
        reg_off = (self.get_PTE_size() * pte_num)

        pte_lo = self.cs.mmio.read_MMIO_reg(gtt_base, reg_off)
        pte_hi = 0
        if self.get_PTE_size() == 8:
            pte_hi = self.cs.mmio.read_MMIO_reg(gtt_base, reg_off + 4)
        return (pte_lo | (pte_hi << 32))

    def write_GGTT_PTE(self, pte_num: int, pte: int) -> int:
        gtt_base = self.get_GGTT_base()
        self.cs.mmio.write_MMIO_reg(gtt_base, self.get_PTE_size() * pte_num, pte & 0xFFFFFFFF)
        if self.get_PTE_size() == 8:
            self.cs.mmio.write_MMIO_reg(gtt_base, self.get_PTE_size() * pte_num + 4, pte >> 32)
        return pte

    def write_GGTT_PTE_from_PA(self, pte_num: int, pa: int) -> int:
        pte = self.get_GGTT_PTE_from_PA(pa)
        gtt_base = self.get_GGTT_base()
        self.cs.mmio.write_MMIO_reg(gtt_base, self.get_PTE_size() * pte_num, pte & 0xFFFFFFFF)
        if self.get_PTE_size() == 8:
            self.cs.mmio.write_MMIO_reg(gtt_base, self.get_PTE_size() * pte_num + 4, pte >> 32)
        return pte

    def dump_GGTT_PTEs(self, num: int) -> None:
        gtt_base = self.get_GGTT_base()
        self.logger.log('[igd] Global GTT contents:')
        ptes = self.cs.mmio.read_MMIO(gtt_base, num * self.get_PTE_size())
        pte_num = 0
        for pte in ptes:
            self.logger.log(f'PTE[{pte_num:03d}]: {pte:08X}')
            pte_num = pte_num + 1

    def get_GGTT_PTE_from_PA(self, pa: int) -> int:
        if self.is_legacy_gen():
            return self.get_GGTT_PTE_from_PA_legacy(pa)
        else:
            return self.get_GGTT_PTE_from_PA_gen8(pa)

    def get_GGTT_PTE_from_PA_legacy(self, pa: int) -> int:
        #
        # GTT PTE format:
        # 0     - valid
        # 2:1   - cache type (00 - reserved, 01 - UC, 10 - LLC only, 11 - MLC/LLC)
        # 3     - GFDT
        # 11:4  - PA bits 39:32
        # 31:12 - PA bits 31:12
        #
        return ((pa & 0xFFFFF000) | ((pa >> 32 & 0xFF) << 4) | 0x3)

    def get_PA_from_PTE_legacy(self, pte: int) -> int:
        return (((pte & 0x00000FF0) << 28) | (pte & 0xFFFFF000))

    def get_GGTT_PTE_from_PA_gen8(self, pa: int) -> int:
        return ((pa & ~0xFFF) | 0x1)

    def get_PA_from_PTE_gen8(self, pte: int) -> int:
        return (pte & ~0xFFF)

    def get_PA_from_PTE(self, pte: int) -> int:
        if self.is_legacy_gen():
            return self.get_PA_from_PTE_legacy(pte)
        else:
            return self.get_PA_from_PTE_gen8(pte)

    def gfx_aperture_dma_read_write(self, address: int, size: int = 0x4, value: Optional[bytes] = None, pte_num: int = 0) -> bytes:
        r = 0
        pages = 0

        gmadr = self.get_GMADR()
        off = address % 0x1000
        h = 0x1000 - off
        igd_addr = gmadr + pte_num * 0x1000
        pte_orig = self.read_GGTT_PTE(pte_num)

        self.logger.log_hal(f'[igd] Reading 0x{size:X} bytes at PA 0x{address:016X} through IGD aperture (DMA) using PTE{pte_num:d}')
        self.logger.log_hal(f'[igd] GFx aperture (GMADR): 0x{gmadr:016X}')
        self.logger.log_hal(f'[igd] GFx GTT base        : 0x{self.get_GGTT_base():016X}')
        self.logger.log_hal(f'[igd] Original GTT PTE{pte_num:03d}: 0x{pte_orig:08X}')

        if (h > 0) and (size > h):
            r = (size - h) % 0x1000
            pages = 2 + (size - h) // 0x1000
        else:
            r = size % 0x1000
            pages = 1 + size // 0x1000

        N = pages
        self.logger.log_hal(f'[igd] Pages = 0x{pages:X}, r = 0x{r:X}, N = {N:d}')

        self.logger.log_hal(f'[igd] Original data at address 0x{address:016X}:')
        if self.logger.HAL:
            print_buffer_bytes(self.cs.mem.read_physical_mem(address, size))

        buffer = b''
        pa = address
        for p in range(N):
            pte = self.get_GGTT_PTE_from_PA(pa)
            if self.logger.HAL:
                self.logger.log(f'[igd] GFx PTE for address 0x{address:016X}: 0x{pte:08X}')
            self.write_GGTT_PTE(pte_num, pte)
            if (p == 0):
                pa_off = off
                size = h if (pa_off > 0) else 0x1000
            else:
                pa_off = 0
            if (p == N - 1):
                size = r if (r > 0) else 0x1000
            if value is None:
                self.logger.log_hal(f'[igd] Reading 0x{size:X} bytes at 0x{pa:016X} through GFx aperture 0x{igd_addr + pa_off:016X}...')
                page = self.cs.mem.read_physical_mem(igd_addr + pa_off, size)
                buffer += page
                if self.logger.HAL:
                    print_buffer_bytes(page[:size])
            else:
                self.logger.log_hal(f'[igd] Writing 0x{size:X} bytes to 0x{pa:016X} through GFx aperture 0x{igd_addr + pa_off:016X}...')
                page = value[p * 0x1000:p * 0x1000 + size]
                self.cs.mem.write_physical_mem(igd_addr + pa_off, size, page)
                if self.logger.HAL:
                    print_buffer_bytes(page)
            pa += size

        # restore original PTE
        self.logger.log_hal(f'[igd] Restoring GFx PTE{pte_num:d} 0x{pte_orig:X}...')
        self.write_GGTT_PTE(pte_num, pte_orig)

        return buffer
