#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2015, Intel Corporation
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
Access to physical memory

usage:
    >>> read_physical_mem( 0xf0000, 0x100 )
    >>> write_physical_mem( 0xf0000, 0x100, buffer )
    >>> write_physical_mem_dowrd( 0xf0000, 0xdeadbeef )
    >>> read_physical_mem_dowrd( 0xfed40000 )

DEPRECATED
    >>> read_phys_mem( 0xf0000, 0x100 )
    >>> write_phys_mem_dword( 0xf0000, 0xdeadbeef )
    >>> read_phys_mem_dword( 0xfed40000 )
"""

__version__ = '1.0'

import struct
import sys

from chipsec.logger import *

class MemoryRuntimeError (RuntimeError):
    pass

class MemoryAccessError (RuntimeError):
    pass

class Memory:
    def __init__( self, cs ):
        self.helper = cs.helper
        self.cs = cs

    ####################################################################################
    #
    # Physical memory API using 64b Physical Address
    # (Same functions as below just using 64b PA instead of High and Low 32b parts of PA)
    #
    ####################################################################################

    # Reading physical memory

    def read_physical_mem( self, phys_address, length ):
        if logger().VERBOSE: logger().log("[mem] 0x%016X"%phys_address)
        return self.helper.read_physical_mem( phys_address, length )

    def read_physical_mem_dword( self, phys_address ):
        out_buf = self.read_physical_mem( phys_address, 4 )
        value = struct.unpack( '=I', out_buf )[0]
        if logger().VERBOSE:
            logger().log( '[mem] dword at PA = 0x%016X: 0x%08X' % (phys_address, value) )
        return value

    def read_physical_mem_word( self, phys_address ):
        out_buf = self.read_physical_mem( phys_address, 2 )
        value = struct.unpack( '=H', out_buf )[0]
        if logger().VERBOSE:
            logger().log( '[mem] word at PA = 0x%016X: 0x%04X' % (phys_address, value) )
        return value

    def read_physical_mem_byte( self, phys_address ):
        out_buf = self.read_physical_mem( phys_address, 1 )
        value = struct.unpack( '=B', out_buf )[0]
        if logger().VERBOSE:
            logger().log( '[mem] byte at PA = 0x%016X: 0x%02X' % (phys_address, value) )
        return value

    # Writing physical memory

    def write_physical_mem( self, phys_address, length, buf ):
        if logger().VERBOSE:
            logger().log( '[mem] buffer len = 0x%X to PA = 0x%016X' % (length, phys_address) )
            print_buffer( buf )
        return self.helper.write_physical_mem( phys_address, length, buf )

    def write_physical_mem_dword( self, phys_address, dword_value ):
        if logger().VERBOSE:
            logger().log( '[mem] dword to PA = 0x%016X <- 0x%08X' % (phys_address, dword_value) )
        return self.write_physical_mem( phys_address, 4, struct.pack( 'I', dword_value ) )

    def write_physical_mem_word( self, phys_address, word_value ):
        if logger().VERBOSE:
            logger().log( '[mem] word to PA = 0x%016X <- 0x%04X' % (phys_address, word_value) )
        return self.write_physical_mem( phys_address, 2, struct.pack( 'H', word_value ) )

    def write_physical_mem_byte( self, phys_address, byte_value ):
        if logger().VERBOSE:
            logger().log( '[mem] byte to PA = 0x%016X <- 0x%02X' % (phys_address, byte_value) )
        return self.write_physical_mem( phys_address, 1, struct.pack( 'B', byte_value ) )

    # Allocate physical memory buffer

    def alloc_physical_mem( self, length, max_phys_address=0xFFFFFFFFFFFFFFFF ):
        (va, pa) = self.helper.alloc_physical_mem( length, max_phys_address )
        if logger().VERBOSE: logger().log( '[mem] Allocated: PA = 0x%016X, VA = 0x%016X' % (pa, va) )
        return (va, pa)

    def va2pa( self, va ):
        (pa, error_code) = self.helper.va2pa( va )
        if logger().VERBOSE: logger().log( '[mem] VA (0x%016X) -> PA (0x%016X)' % (va, pa) )
        if error_code:
            logger().log( '[mem] Looks like VA (0x%016X) not mapped' % (va) )
            return 
        return pa


    ####################################################################################
    #
    # DEPRECATED
    # Physical memory API using 64b Physical Address split into 32b High and Low parts
    #
    ####################################################################################

    def read_phys_mem_64( self, phys_address_hi, phys_address_lo, length ):
        out_buf = self.helper.read_phys_mem( phys_address_hi, phys_address_lo, length )
        return out_buf

    def read_phys_mem_dword_64(self, phys_address_hi, phys_address_lo ):
        out_buf = self.read_phys_mem_64( phys_address_hi, phys_address_lo, 4 )
        try:
            value = struct.unpack( 'L', out_buf.raw )[0]
        except:
            raise MemoryAccessError, "read_phys_mem did not return hex dword"
        if logger().VERBOSE:
            logger().log( '[mem] dword at PA = 0x%08X_%08X: 0x%08X' % (phys_address_hi, phys_address_lo, value) )
        return value

    def read_phys_mem_word_64(self, phys_address_hi, phys_address_lo ):
        out_buf = self.read_phys_mem_64( phys_address_hi, phys_address_lo, 2 )
        try:
            value = struct.unpack( 'H', out_buf.raw )[0]
        except:
            raise MemoryAccessError, "read_phys_mem did not return hex word"
        if logger().VERBOSE:
            logger().log( '[mem] word at PA = 0x%08X_%08X: 0x%04X' % (phys_address_hi, phys_address_lo, value) )
        return value

    def read_phys_mem_byte_64(self, phys_address_hi, phys_address_lo ):
        out_buf = self.read_phys_mem_64( phys_address_hi, phys_address_lo, 1 )
        try:
            value = struct.unpack( 'B', out_buf.raw )[0]
        except:
            raise MemoryAccessError, "read_phys_mem did not return 1 Byte"
        if logger().VERBOSE:
            logger().log( '[mem] byte at PA = 0x%08X_%08X: 0x%02X' % (phys_address_hi, phys_address_lo, value) )
        return value

    def write_phys_mem_64( self, phys_address_hi, phys_address_lo, length, buf ):
        return self.helper.write_phys_mem( phys_address_hi, phys_address_lo, length, buf )

    def write_phys_mem_dword_64( self, phys_address_hi, phys_address_lo, dword_value ):
        if logger().VERBOSE:
            logger().log( '[mem] dword to PA = 0x%08X_%08X <- 0x%08X' % (phys_address_hi, phys_address_lo, dword_value) )
        return self.write_phys_mem_64( phys_address_hi, phys_address_lo, 4, struct.pack( 'I', dword_value ) )

    def write_phys_mem_word_64( self, phys_address_hi, phys_address_lo, word_value ):
        if logger().VERBOSE:
            logger().log( '[mem] word to PA = 0x%08X_%08X <- 0x%04X' % (phys_address_hi, phys_address_lo, word_value) )
        return self.write_phys_mem_64( phys_address_hi, phys_address_lo, 2, struct.pack( 'H', word_value ) )

    def write_phys_mem_byte_64( self, phys_address_hi, phys_address_lo, byte_value ):
        if logger().VERBOSE:
            logger().log( '[mem] byte to PA = 0x%08X_%08X <- 0x%02X' % (phys_address_hi, phys_address_lo, byte_value) )
        return self.write_phys_mem_64( phys_address_hi, phys_address_lo, 1, struct.pack( 'B', byte_value ) )


    ####################################################################################
    #
    # DEPRECATED
    # Physical memory API using 32b Physical Address
    #
    ####################################################################################

    def read_phys_mem_byte(self, phys_address ):
        return self.read_phys_mem_byte_64( 0, phys_address )

    def read_phys_mem_word(self, phys_address ):
        return self.read_phys_mem_word_64( 0, phys_address )

    def read_phys_mem_dword(self, phys_address ):
        return self.read_phys_mem_dword_64( 0, phys_address )

    def read_phys_mem(self, phys_address, length ):
        return self.read_phys_mem_64( 0, phys_address, length )

    def write_phys_mem_byte( self, phys_address, byte_value ):
        return self.write_phys_mem_byte_64( 0, phys_address, byte_value )

    def write_phys_mem_word( self, phys_address, word_value ):
        return self.write_phys_mem_word_64( 0, phys_address, word_value )

    def write_phys_mem_dword( self, phys_address, dword_value ):
        return self.write_phys_mem_dword_64( 0, phys_address, dword_value )

    def write_phys_mem(self, phys_address, length, buf ):
        return self.write_phys_mem_64( 0, phys_address, length, buf )
