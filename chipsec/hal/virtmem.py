#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2016, Intel Corporation
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
# (c) 2010-2012 Intel Corporation
#
# -------------------------------------------------------------------------------

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

from chipsec.logger import *

class MemoryRuntimeError (RuntimeError):
    pass

class MemoryAccessError (RuntimeError):
    pass

class VirtMemory(hal_base.HALBase):
    def __init__( self, cs ):
        self.helper = cs.helper
        self.cs = cs

    ####################################################################################
    #
    # virtual memory API using 64b virtual Address
    # (Same functions as below just using 64b VA instead of High and Low 32b parts of VA)
    #
    ####################################################################################

    # Reading virtual memory

    def read_virtual_mem( self, virt_address, length ):
        if logger().HAL: logger().log("[mem] 0x%016X"%virt_address)
        return self.helper.read_virtual_mem( virt_address, length )

    def read_virtual_mem_dword( self, virt_address ):
        out_buf = self.read_virtual_mem( virt_address, 4 )
        value = struct.unpack( '=I', out_buf )[0]
        if logger().HAL: logger().log( '[mem] dword at VA = 0x%016X: 0x%08X' % (virt_address, value) )
        return value

    def read_virtual_mem_word( self, virt_address ):
        out_buf = self.read_virtual_mem( virt_address, 2 )
        value = struct.unpack( '=H', out_buf )[0]
        if logger().HAL: logger().log( '[mem] word at VA = 0x%016X: 0x%04X' % (virt_address, value) )
        return value

    def read_virtual_mem_byte( self, virt_address ):
        out_buf = self.read_virtual_mem( virt_address, 1 )
        value = struct.unpack( '=B', out_buf )[0]
        if logger().HAL: logger().log( '[mem] byte at VA = 0x%016X: 0x%02X' % (virt_address, value) )
        return value

    # Writing virtual memory

    def write_virtual_mem( self, virt_address, length, buf ):
        if logger().HAL:
            logger().log( '[mem] buffer len = 0x%X to VA = 0x%016X' % (length, virt_address) )
            print_buffer( buf )
        return self.helper.write_virtual_mem( virt_address, length, buf )

    def write_virtual_mem_dword( self, virt_address, dword_value ):
        if logger().HAL: logger().log( '[mem] dword to VA = 0x%016X <- 0x%08X' % (virt_address, dword_value) )
        return self.write_virtual_mem( virt_address, 4, struct.pack( 'I', dword_value ) )

    def write_virtual_mem_word( self, virt_address, word_value ):
        if logger().HAL: logger().log( '[mem] word to VA = 0x%016X <- 0x%04X' % (virt_address, word_value) )
        return self.write_virtual_mem( virt_address, 2, struct.pack( 'H', word_value ) )

    def write_virtual_mem_byte( self, virt_address, byte_value ):
        if logger().HAL: logger().log( '[mem] byte to VA = 0x%016X <- 0x%02X' % (virt_address, byte_value) )
        return self.write_virtual_mem( virt_address, 1, struct.pack( 'B', byte_value ) )

    # Allocate virtual memory buffer

    def alloc_virtual_mem( self, length, max_virt_address=0xFFFFFFFFFFFFFFFF ):
        (va, pa) = self.helper.alloc_virtual_mem( length, max_virt_address )
        if logger().HAL: logger().log( '[mem] Allocated: VA = 0x%016X, VA = 0x%016X' % (pa, va) )
        return (va, pa)
