#!/usr/bin/python
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


"""
Access to virtual memory

usage:
    >>> read_virtual_mem( 0xf0000, 0x100 )
    >>> write_virtual_mem( 0xf0000, 0x100, buffer )
    >>> write_virtual_mem_dowrd( 0xf0000, 0xdeadbeef )
    >>> read_virtual_mem_dowrd( 0xfed40000 )
"""

import struct
import sys

from chipsec.logger import logger, print_buffer
from chipsec.hal import hal_base

class MemoryRuntimeError (RuntimeError):
    pass

class MemoryAccessError (RuntimeError):
    pass

class VirtMemory(hal_base.HALBase):
    def __init__( self, cs ):
        hal_base.HALBase.__init__(VirtMemory,cs)
        self.helper = cs.helper

    ####################################################################################
    #
    # virtual memory API using 64b virtual Address
    # (Same functions as below just using 64b PA instead of High and Low 32b parts of PA)
    #
    ####################################################################################

    # Reading virtual memory

    def read_virtual_mem( self, virt_address, length ):
        if logger().HAL: logger().log("[mem] 0x{:016X}".format(virt_address))
        phys_address = self.va2pa(virt_address)
        return self.helper.read_physical_mem( phys_address, length )

    def read_virtual_mem_dword( self, virt_address ):
        phys_address = self.va2pa(virt_address)
        out_buf = self.helper.read_physical_mem( phys_address, 4 )
        value = struct.unpack( '=I', out_buf )[0]
        if logger().HAL: logger().log( '[mem] dword at VA = 0x{:016X}: 0x{:08X}'.format(virt_address, value) )
        return value

    def read_virtual_mem_word( self, virt_address ):
        phys_address = self.va2pa(virt_address)
        out_buf = self.helper.read_physical_mem( phys_address, 2 )
        value = struct.unpack( '=H', out_buf )[0]
        if logger().HAL: logger().log( '[mem] word at VA = 0x{:016X}: 0x{:04X}'.format(virt_address, value) )
        return value

    def read_virtual_mem_byte( self, virt_address ):
        phys_address = self.va2pa(virt_address)
        out_buf = self.helper.read_physical_mem( phys_address, 1 )
        value = struct.unpack( '=B', out_buf )[0]
        if logger().HAL: logger().log( '[mem] byte at VA = 0x{:016X}: 0x{:02X}'.format(virt_address, value) )
        return value

    # Writing virtual memory

    def write_virtual_mem( self, virt_address, length, buf ):
        if logger().HAL:
            logger().log( '[mem] buffer len = 0x{:X} to VA = 0x{:016X}'.format(length, virt_address) )
            print_buffer( buf )
        phys_address = self.va2pa(virt_address)
        return self.helper.write_physical_mem( phys_address, length, buf )

    def write_virtual_mem_dword( self, virt_address, dword_value ):
        if logger().HAL: logger().log( '[mem] dword to VA = 0x{:016X} <- 0x{:08X}'.format(virt_address, dword_value) )
        phys_address = self.va2pa(virt_address)
        return self.helper.write_physical_mem( phys_address, 4, struct.pack( 'I', dword_value ) )

    def write_virtual_mem_word( self, virt_address, word_value ):
        if logger().HAL: logger().log( '[mem] word to VA = 0x{:016X} <- 0x{:04X}'.format(virt_address, word_value) )
        phys_address = self.va2pa(virt_address)
        return self.helper.write_physical_mem( phys_address, 2, struct.pack( 'H', word_value ) )

    def write_virtual_mem_byte( self, virt_address, byte_value ):
        if logger().HAL: logger().log( '[mem] byte to VA = 0x{:016X} <- 0x{:02X}'.format(virt_address, byte_value) )
        phys_address = self.va2pa(virt_address)
        return self.helper.write_physical_mem( phys_address, 1, struct.pack( 'B', byte_value ) )

    # Allocate virtual memory buffer

    def alloc_virtual_mem( self, length, max_phys_address=0xFFFFFFFFFFFFFFFF ):
        (va, pa) = self.helper.alloc_physical_mem( length, max_phys_address )
        if logger().HAL: logger().log( '[mem] Allocated: PA = 0x{:016X}, VA = 0x{:016X}'.format(pa, va) )
        return (va, pa)

    def va2pa( self, va ):
        (pa, error_code) = self.helper.va2pa( va )
        if logger().HAL: logger().log( '[mem] VA (0x{:016X}) -> PA (0x{:016X})'.format(va, pa) )
        if error_code:
            if logger().HAL: logger().log( '[mem] Looks like VA (0x{:016X}) not mapped'.format(va) )
            return 
        return pa

    def free_virtual_mem(self, virt_address):
        pa = self.va2pa(virt_address)
        ret = self.helper.free_physical_mem(pa)
        if logger().HAL: logger().log( '[mem] Deallocated : VA = 0x{:016X}'.format(virt_address) )
        return True if ret == 1 else False
