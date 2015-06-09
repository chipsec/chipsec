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
I/O BAR access (dump, read/write)

usage:
    >>> get_IO_BAR_base_address( bar_name )
    >>> read_IO_BAR_reg( bar_name, offset, size )
    >>> write_IO_BAR_reg( bar_name, offset, size, value )
    >>> dump_IO_BAR( bar_name )
"""

__version__ = '1.0'

import struct
import sys
import time

import chipsec.chipset
#from chipsec.hal.hal_base import HALBase
from chipsec.logger import logger


class IOBARRuntimeError (RuntimeError):
    pass
class IOBARNotFoundError (RuntimeError):
    pass


class iobar:

    def __init__( self, cs ):
        self.cs = cs

    #
    # Check if I/O BAR with bar_name has been defined in XML config
    # Use this function to fall-back to hardcoded config in case XML config is not available
    #
    def is_IO_BAR_defined( self, bar_name ):
        try:
            return (self.cs.Cfg.IO_BARS[ bar_name ] is not None)
        except KeyError:
            logger().error( "'%s' I/O BAR definition not found in XML config" % bar_name)
            #raise IOBARNotFoundError, ('IOBARNotFound: %s' % bar_name)
            return False

    #
    # Get base address of I/O range by IO BAR name
    #
    def get_IO_BAR_base_address( self, bar_name ):
        if self.is_IO_BAR_defined( bar_name):
            bar = self.cs.Cfg.IO_BARS[ bar_name ]
        else:
            raise IOBARNotFoundError, ('IOBARNotFound: %s' % bar_name)

        base = self.cs.pci.read_word( int(bar['bus'],16), int(bar['dev'],16), int(bar['fun'],16), int(bar['reg'],16) )
        if 'enable_bit' in bar:
            en_mask = 1 << int(bar['enable_bit'])
            if ( 0 == base & en_mask ): logger().warn('%s is disabled' % bar_name)
        if 'mask'   in bar: base = base & int(bar['mask'],16)
        if 'offset' in bar: base = base + int(bar['offset'],16)
        size = int(bar['size'],16) if ('size' in bar) else 0x100

        if logger().VERBOSE: logger().log( '[iobar] %s: 0x%016X (size = 0x%X)' % (bar_name,base,size) )
        return base, size

    #
    # Read I/O register from I/O range defined by I/O BAR name
    #
    def read_IO_BAR_reg( self, bar_name, offset, size ):
        if logger().VERBOSE: logger().log('[iobar] read %s + %u (%u)' % (bar_name, offset, size))
        (bar_base,bar_size) = self.get_IO_BAR_base_address( bar_name )
        io_port = bar_base + offset
        if offset > bar_size: logger().warn( 'offset 0x%X is ouside %s size (0x%X)' % (offset,bar_name,size) )
        value = self.cs.io._read_port( io_port, size )
#        if logger().VERBOSE: logger().log( '[iobar] read IO reg 0x%X from %s (0x%X): 0x%X' % (bar_name,bar_base,offset,value) )
        return value

    #
    # Write I/O register from I/O range defined by I/O BAR name
    #
    def write_IO_BAR_reg( self, bar_name, offset, size, value ):
        (bar_base,bar_size) = self.get_IO_BAR_base_address( bar_name )
        if logger().VERBOSE: logger().log( '[iobar] write IO reg 0x%X from %s (0x%X): 0x%X' % (bar_name,bar_base,offset,value) )
        io_port = bar_base + offset
        if offset > bar_size: logger().warn( 'offset 0x%X is ouside %s size (0x%X)' % (offset,bar_name,size) )
        return self.cs.io._write_port( io_port, value, size )

    #
    # Dump I/O range by I/O BAR name
    #
    def dump_IO_BAR( self, bar_name ):
        (bar_base,bar_size) = self.get_IO_BAR_base_address( bar_name )
        # @TODO
        #dump_IO( bar_base, bar_size )
        return
