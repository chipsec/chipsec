#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2017, Intel Corporation
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

import struct
import sys

from chipsec.hal import hal_base
from chipsec.logger import print_buffer

class IGDRuntimeError (RuntimeError):
    pass

class IGD(hal_base.HALBase):

    def __init__(self, cs):
        super(IGD, self).__init__(cs)
        self.helper = cs.helper
        self.is_legacy = None
        self.enabled = None

    def __identify_device(self):
        if self.enabled is None:
            self.is_legacy = False
            try:
                self.dev_id = self.cs.read_register("PCI0.2.0_DID")
                self.enabled = (self.dev_id <> 0xFFFF)
                if (self.enabled):
                    self.is_legacy = (self.dev_id < 0x1600)
            except:
                self.enabled = False

        return (self.enabled, self.is_legacy)

    def is_device_enabled(self):
        enabled, legacy = self.__identify_device()
        return enabled

    def is_legacy_gen(self):
        enabled, legacy = self.__identify_device()
        return legacy

    def get_GMADR(self):
        base,size = self.cs.mmio.get_MMIO_BAR_base_address('GMADR')
        if self.logger.HAL: self.logger.log( '[igd] Aperture (GMADR): 0x%016X' % base )
        return base

    def get_GTTMMADR(self):
        base, size = self.cs.mmio.get_MMIO_BAR_base_address('GTTMMADR')
        if self.logger.HAL: self.logger.log( '[igd] Graphics MMIO and GTT (GTTMMADR): 0x%016X' % base )
        return base

    def get_GGTT_base(self):
        gtt_off = 0x200000 if self.is_legacy_gen() else 0x800000
        return self.get_GTTMMADR() + gtt_off

    def get_PTE_size(self):
        return 4 if self.is_legacy_gen() else 8

    def read_GGTT_PTE(self, pte_num):
        gtt_base = self.get_GGTT_base()
        reg_off = (self.get_PTE_size()*pte_num)
       
        pte_lo = self.cs.mmio.read_MMIO_reg( gtt_base, reg_off )
        pte_hi = 0
        if self.get_PTE_size() == 8:
            pte_hi = self.cs.mmio.read_MMIO_reg( gtt_base, reg_off + 4)
        return (pte_lo | (pte_hi << 32))

    def write_GGTT_PTE(self, pte_num, pte):
        gtt_base = self.get_GGTT_base()
        self.cs.mmio.write_MMIO_reg( gtt_base, self.get_PTE_size()*pte_num, pte & 0xFFFFFFFF)
        if self.get_PTE_size() == 8:
            self.cs.mmio.write_MMIO_reg( gtt_base, self.get_PTE_size()*pte_num + 4, pte >> 32)
        return pte

    def write_GGTT_PTE_from_PA(self, pte_num, pa):
        pte = self.get_GGTT_PTE_from_PA( pa )
        gtt_base = self.get_GGTT_base()
        self.cs.mmio.write_MMIO_reg( gtt_base, self.get_PTE_size()*pte_num, pte & 0xFFFFFFFF )
        if self.get_PTE_size() == 8:
            self.cs.mmio.write_MMIO_reg( gtt_base, self.get_PTE_size()*pte_num + 4, pte >> 32)
        return pte

    def dump_GGTT_PTEs(self, num):
        gtt_base = self.get_GGTT_base()
        self.logger.log( '[igd] Global GTT contents:' )
        ptes = self.cs.mmio.read_MMIO( gtt_base, num*self.get_PTE_size() )
        pte_num = 0
        for pte in ptes:
            self.logger.log( 'PTE[%03d]: %08X' % (pte_num, pte) )
            pte_num = pte_num + 1

    def get_GGTT_PTE_from_PA(self, pa):
        if self.is_legacy_gen():
            return self.get_GGTT_PTE_from_PA_legacy( pa )
        else:
            return self.get_GGTT_PTE_from_PA_gen8( pa )

    def get_GGTT_PTE_from_PA_legacy(self, pa):
        #
        # GTT PTE format:
        # 0     - valid
        # 2:1   - cache type (00 - reserved, 01 - UC, 10 - LLC only, 11 - MLC/LLC)
        # 3     - GFDT
        # 11:4  - PA bits 39:32
        # 31:12 - PA bits 31:12
        #
        return ((pa & 0xFFFFF000) | ((pa>>32 & 0xFF) << 4) | 0x3)

    def get_PA_from_PTE_legacy(self, pte):
        return (((pte & 0x00000FF0) << 28) | (pte & 0xFFFFF000))

    def get_GGTT_PTE_from_PA_gen8(self, pa):
        return ((pa & ~0xFFF) | 0x1)

    def get_PA_from_PTE_gen8(self, pte):
        return (pa & ~0xFFF)

    def get_PA_from_PTE(self, pte):
        if self.is_legacy_gen():
            return self.get_PA_from_PTE_legacy()
        else:
            return self.get_PA_from_PTE_gen8( pte )


    def gfx_aperture_dma_read_write(self, address, size=0x4, value=None, pte_num=0):
        r = 0
        pages = 0

        gmadr = self.get_GMADR()
        off = address%0x1000
        h = 0x1000 - off
        igd_addr = gmadr + pte_num*0x1000
        pte_orig = self.read_GGTT_PTE( pte_num )

        if self.logger.HAL:
            self.logger.log( '[igd] reading 0x%X bytes at PA 0x%016X through IGD aperture (DMA) using PTE%d' % (size,address,pte_num) )
            self.logger.log( '[igd] GFx aperture (GMADR): 0x%016X' % gmadr )
            self.logger.log( '[igd] GFx GTT base        : 0x%016X' % self.get_GGTT_base() )
            self.logger.log( '[igd] original GTT PTE%03d: 0x%08X' % (pte_num,pte_orig) )
        

        if (h > 0) and (size > h):
            r = (size - h)%0x1000
            pages = 2 + (size - h)//0x1000
        else:
            r = size%0x1000
            pages = 1 + size//0x1000

        N = pages
        if self.logger.HAL: self.logger.log( '[igd] pages = 0x%X, r = 0x%x, N = %d' % (pages,r,N) )

        if self.logger.VERBOSE:
            self.logger.log( '[igd] original data at address 0x%016X:' % address )
            print_buffer(self.cs.mem.read_physical_mem(address, size))

        buffer = ''
        pa = address    
        for p in range(N):
            pte = self.get_GGTT_PTE_from_PA(pa)
            if self.logger.HAL: self.logger.log( '[igd] GFx PTE for address 0x%016X: 0x%08X' % (address,pte) )
            self.write_GGTT_PTE(pte_num, pte)
            if (p == 0):
                pa_off = off
                size = h if (pa_off > 0)   else 0x1000
            else:
                pa_off = 0
            if (p == N-1):
                size = r if (r > 0) else 0x1000
            if value is None:
                if self.logger.HAL: self.logger.log( '[igd] reading 0x%X bytes at 0x%016X through GFx aperture 0x%016X ..' % (size,pa,igd_addr + pa_off) )
                page = self.cs.mem.read_physical_mem(igd_addr + pa_off, size)
                buffer += page
                if self.logger.HAL: print_buffer(page[:size])
            else:
                if self.logger.HAL: self.logger.log( '[igd] writing 0x%X bytes to 0x%016X through GFx aperture 0x%016X ..' % (size,pa,igd_addr + pa_off) )
                page = value[p*0x1000:p*0x1000+size]
                self.cs.mem.write_physical_mem(igd_addr + pa_off, size, page)
                if self.logger.HAL: print_buffer(page)
            pa += size

        # restore original PTE
        if self.logger.HAL: self.logger.log( '[igd] restoring GFx PTE%d 0x%X..' % (pte_num,pte_orig) )
        self.write_GGTT_PTE(pte_num, pte_orig)

        return buffer

