#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2020, Intel Corporation
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

"""
Access to physical memory

usage:
    >>> read_physical_mem( 0xf0000, 0x100 )
    >>> write_physical_mem( 0xf0000, 0x100, buffer )
    >>> write_physical_mem_dowrd( 0xf0000, 0xdeadbeef )
    >>> read_physical_mem_dowrd( 0xfed40000 )
"""

import struct
import sys

from chipsec.hal.hal_base import HALBase
from chipsec.logger import print_buffer

class MemoryRuntimeError (RuntimeError):
    pass

class MemoryAccessError (RuntimeError):
    pass

class Memory(HALBase):
    def __init__( self, cs ):
        super(Memory, self).__init__(cs)
        self.helper = cs.helper

    ####################################################################################
    #
    # Physical memory API using 64b Physical Address
    # (Same functions as below just using 64b PA instead of High and Low 32b parts of PA)
    #
    ####################################################################################

    # Reading physical memory

    def read_physical_mem( self, phys_address, length ):
        if self.logger.HAL: self.logger.log("[mem] 0x{:016X}".format(phys_address))
        return self.helper.read_physical_mem( phys_address, length )

    def read_physical_mem_dword( self, phys_address ):
        out_buf = self.read_physical_mem( phys_address, 4 )
        value = struct.unpack( '=I', out_buf )[0]
        if self.logger.HAL: self.logger.log( '[mem] dword at PA = 0x{:016X}: 0x{:08X}'.format(phys_address, value) )
        return value

    def read_physical_mem_word( self, phys_address ):
        out_buf = self.read_physical_mem( phys_address, 2 )
        value = struct.unpack( '=H', out_buf )[0]
        if self.logger.HAL: self.logger.log( '[mem] word at PA = 0x{:016X}: 0x{:04X}'.format(phys_address, value) )
        return value

    def read_physical_mem_byte( self, phys_address ):
        out_buf = self.read_physical_mem( phys_address, 1 )
        value = struct.unpack( '=B', out_buf )[0]
        if self.logger.HAL: self.logger.log( '[mem] byte at PA = 0x{:016X}: 0x{:02X}'.format(phys_address, value) )
        return value

    # Writing physical memory

    def write_physical_mem( self, phys_address, length, buf ):
        if self.logger.HAL:
            self.logger.log( '[mem] buffer len = 0x{:X} to PA = 0x{:016X}'.format(length, phys_address) )
            print_buffer( buf )
        return self.helper.write_physical_mem( phys_address, length, buf )

    def write_physical_mem_dword( self, phys_address, dword_value ):
        if self.logger.HAL: self.logger.log( '[mem] dword to PA = 0x{:016X} <- 0x{:08X}'.format(phys_address, dword_value) )
        return self.write_physical_mem( phys_address, 4, struct.pack( 'I', dword_value ) )

    def write_physical_mem_word( self, phys_address, word_value ):
        if self.logger.HAL: self.logger.log( '[mem] word to PA = 0x{:016X} <- 0x{:04X}'.format(phys_address, word_value) )
        return self.write_physical_mem( phys_address, 2, struct.pack( 'H', word_value ) )

    def write_physical_mem_byte( self, phys_address, byte_value ):
        if self.logger.HAL: self.logger.log( '[mem] byte to PA = 0x{:016X} <- 0x{:02X}'.format(phys_address, byte_value) )
        return self.write_physical_mem( phys_address, 1, struct.pack( 'B', byte_value ) )

    # Allocate physical memory buffer

    def alloc_physical_mem( self, length, max_phys_address=0xFFFFFFFFFFFFFFFF ):
        (va, pa) = self.helper.alloc_physical_mem( length, max_phys_address )
        if self.logger.HAL: self.logger.log( '[mem] Allocated: PA = 0x{:016X}, VA = 0x{:016X}'.format(pa, va) )
        return (va, pa)

    def va2pa( self, va ):
        (pa, error_code) = self.helper.va2pa( va )
        if self.logger.HAL: self.logger.log( '[mem] VA (0x{:016X}) -> PA (0x{:016X})'.format(va, pa) )
        if error_code:
            if self.logger.HAL: self.logger.log( '[mem] Looks like VA (0x{:016X}) not mapped'.format(va) )
            return 
        return pa

    # Map physical address to virtual

    def map_io_space(self, pa, length, cache_type):
        va = self.helper.map_io_space(pa, length, cache_type)
        if self.logger.HAL: self.logger.log( '[mem] Mapped: PA = 0x{:016X}, VA = 0x{:016X}'.format(pa, va) )
        return va

    # Free physical memory buffer

    def free_physical_mem(self, pa):
        ret = self.helper.free_physical_mem(pa)
        if self.logger.HAL: self.logger.log( '[mem] Deallocated : PA = 0x{:016X}'.format(pa) )
        return True if ret == 1 else False

    def set_mem_bit(self, addr, bit):
        addr += bit >> 3
        byte = self.read_physical_mem_byte(addr)
        self.write_physical_mem_byte(addr, (byte | (0x1 << (bit & 0x7))))
        return byte
