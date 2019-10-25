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
I/O BAR access (dump, read/write)

usage:
    >>> get_IO_BAR_base_address( bar_name )
    >>> read_IO_BAR_reg( bar_name, offset, size )
    >>> write_IO_BAR_reg( bar_name, offset, size, value )
    >>> dump_IO_BAR( bar_name )
"""

import struct
import sys
import time

from chipsec.hal import hal_base
from chipsec.logger import logger

DEFAULT_IO_BAR_SIZE = 0x100

class IOBARRuntimeError (RuntimeError):
    pass
class IOBARNotFoundError (RuntimeError):
    pass

class IOBAR(hal_base.HALBase):

    def __init__(self, cs):
        super(IOBAR, self).__init__(cs)

    #
    # Check if I/O BAR with bar_name has been defined in XML config
    # Use this function to fall-back to hardcoded config in case XML config is not available
    #
    def is_IO_BAR_defined( self, bar_name ):
        try:
            return (self.cs.Cfg.IO_BARS[ bar_name ] is not None)
        except KeyError:
            if logger().HAL: logger().error( "'%s' I/O BAR definition not found in XML config" % bar_name)
            #raise IOBARNotFoundError, ('IOBARNotFound: %s' % bar_name)
            return False

    #
    # Get base address of I/O range by IO BAR name
    #
    def get_IO_BAR_base_address( self, bar_name ):
        bar = self.cs.Cfg.IO_BARS[ bar_name ]
        if bar is None or bar == {}:
            raise IOBARNotFoundError ('IOBARNotFound: {}'.format(bar_name))

        if 'register' in bar:
            bar_reg   = bar['register']
            if 'base_field' in bar:
                base_field = bar['base_field']
                base = self.cs.read_register_field( bar_reg, base_field, preserve_field_position=True )
                empty_base = self.cs.get_register_field_mask( bar_reg, base_field, preserve_field_position=True )
            else:
                base = self.cs.read_register( bar_reg )
                empty_base = self.cs.get_register_field_mask( bar_reg, preserve_field_position=True )
        else:
            # this method is not preferred
            base = self.cs.pci.read_word( int(bar['bus'],16), int(bar['dev'],16), int(bar['fun'],16), int(bar['reg'],16) )
            empty_base = 0xFFFF

        if 'fixed_address' in bar and (base == empty_base or base == 0):
            base = int(bar['fixed_address'],16)
            if logger().HAL: logger().log('[iobar] Using fixed address for {}: 0x{:016X}'.format(bar_name, base))

        if 'mask'   in bar: base = base & int(bar['mask'],16)
        if 'offset' in bar: base = base + int(bar['offset'],16)
        size = int(bar['size'],16) if ('size' in bar) else DEFAULT_IO_BAR_SIZE

        if logger().HAL: logger().log( '[iobar] {}: 0x{:04X} (size = 0x{:X})'.format(bar_name,base,size) )
        return base, size


    #
    # Read I/O register from I/O range defined by I/O BAR name
    #
    def read_IO_BAR_reg( self, bar_name, offset, size ):
        if logger().HAL: logger().log('[iobar] read {} + 0x{:X} ({:d})'.format(bar_name, offset, size))
        (bar_base,bar_size) = self.get_IO_BAR_base_address( bar_name )
        io_port = bar_base + offset
        if offset > bar_size and logger().HAL: logger().warn( 'offset 0x{:X} is ouside {} size (0x{:X})'.format(offset,bar_name,size) )
        value = self.cs.io._read_port( io_port, size )
        return value

    #
    # Write I/O register from I/O range defined by I/O BAR name
    #
    def write_IO_BAR_reg( self, bar_name, offset, size, value ):
        (bar_base,bar_size) = self.get_IO_BAR_base_address( bar_name )
        if logger().HAL: logger().log( '[iobar] write {} + 0x{:X} ({:d}): 0x{:X}'.format(bar_name,offset,size,value) )
        io_port = bar_base + offset
        if offset > bar_size and logger().HAL: logger().warn( 'offset 0x{:X} is ouside {} size (0x{:X})'.format(offset,bar_name,size) )
        return self.cs.io._write_port( io_port, value, size )


    #
    # Check if I/O range is enabled by BAR name
    #
    def is_IO_BAR_enabled( self, bar_name ):
        bar = self.cs.Cfg.IO_BARS[ bar_name ]
        is_enabled = True
        if 'register' in bar:
            bar_reg = bar['register']
            if 'enable_field' in bar:
                bar_en_field = bar['enable_field']
                is_enabled = (1 == self.cs.read_register_field( bar_reg, bar_en_field ))
        return is_enabled


    def list_IO_BARs( self ):
        logger().log('')
        logger().log( '--------------------------------------------------------------------------------' )
        logger().log( ' I/O Range    | BAR Register   | Base             | Size     | En? | Description' )
        logger().log( '--------------------------------------------------------------------------------' )
        for _bar_name in self.cs.Cfg.IO_BARS:
            if not self.is_IO_BAR_defined( _bar_name ): continue
            _bar = self.cs.Cfg.IO_BARS[ _bar_name ]
            (_base,_size) = self.get_IO_BAR_base_address( _bar_name )
            _en = self.is_IO_BAR_enabled( _bar_name )

            if 'register' in _bar:
                _s = _bar['register']
                if 'offset' in _bar: _s += (' + 0x{:X}'.format(int(_bar['offset'],16)))
            else:
                _s = '{:02X}:{:02X}.{:01X} + {}'.format( int(_bar['bus'],16),int(_bar['dev'],16),int(_bar['fun'],16),_bar['reg'] )

            logger().log( ' {:12} | {:14} | {:016X} | {:08X} | {:d}   | {}'.format(_bar_name, _s, _base, _size, _en, _bar['desc']) )


    #
    # Read I/O range by I/O BAR name
    #
    def read_IO_BAR( self, bar_name, size=1 ):
        (range_base,range_size) = self.get_IO_BAR_base_address( bar_name )
        n = range_size//size
        io_ports = []
        for i in range(n):
            io_ports.append( self.cs.io._read_port( range_base + i*size, size ) )
            #io_ports.append( self.read_IO_BAR_reg( bar_name, i*size, size ) )
        return io_ports

    #
    # Dump I/O range by I/O BAR name
    #
    def dump_IO_BAR( self, bar_name, size=1 ):
        (range_base,range_size) = self.get_IO_BAR_base_address( bar_name )
        n = range_size//size
        fmt = '0{:d}X'.format(size*2)
        logger().log("[iobar] I/O BAR {}:".format(bar_name))
        for i in range(n):
            reg = self.cs.io._read_port( range_base + i*size, size )
            logger().log( '{:+04X}: {:{form}}'.format(i*size,reg,form=fmt) )

