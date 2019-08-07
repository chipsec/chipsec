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
Access to Port I/O

usage:
    >>> read_port_byte( 0x61 )
    >>> read_port_word( 0x61 )
    >>> read_port_dword( 0x61 )
    >>> write_port_byte( 0x71, 0 )
    >>> write_port_word( 0x71, 0 )
    >>> write_port_dword( 0x71, 0 )
"""

import struct
import sys
import os.path

from chipsec.logger import logger

class PortIORuntimeError (RuntimeError):
    pass

class PortIO:

    def __init__( self, cs ):
        self.helper = cs.helper
        self.cs = cs

    def _read_port(self, io_port, size ):
        value = self.helper.read_io_port( io_port, size )
        if logger().HAL: logger().log( "[io] IN 0x{:04X}: value = 0x{:08X}, size = 0x{:02X}".format(io_port, value, size) )
        return value

    def _write_port(self, io_port, value, size ):
        if logger().HAL: logger().log( "[io] OUT 0x{:04X}: value = 0x{:08X}, size = 0x{:02X}".format(io_port, value, size) )
        status = self.helper.write_io_port( io_port, value, size )
        return status

    def read_port_dword(self, io_port ):
        value = self.helper.read_io_port( io_port, 4 )
        if logger().HAL:
            logger().log( "[io] reading dword from I/O port 0x{:04X} -> 0x{:08X}".format(io_port, value) )
        return value

    def read_port_word(self, io_port ):
        value = self.helper.read_io_port( io_port, 2 )
        if logger().HAL:
            logger().log( "[io] reading word from I/O port 0x{:04X} -> 0x{:04X}".format(io_port, value) )
        return value

    def read_port_byte(self, io_port ):
        value = self.helper.read_io_port( io_port, 1 )
        if logger().HAL:
            logger().log( "[io] reading byte from I/O port 0x{:04X} -> 0x{:02X}".format(io_port, value) )
        return value


    def write_port_byte(self, io_port, value ):
        if logger().HAL:
            logger().log( "[io] writing byte to I/O port 0x{:04X} <- 0x{:02X}".format(io_port, value) )
        self.helper.write_io_port( io_port, value, 1 )
        return

    def write_port_word(self, io_port, value ):
        if logger().HAL:
            logger().log( "[io] writing word to I/O port 0x{:04X} <- 0x{:04X}".format(io_port, value) )
        self.helper.write_io_port( io_port, value, 2 )
        return

    def write_port_dword(self, io_port, value ):
        if logger().HAL:
            logger().log( "[io] writing dword to I/O port 0x{:04X} <- 0x{:08X}".format(io_port, value) )
        self.helper.write_io_port( io_port, value, 4 )
        return

    #
    # Read registers from I/O range
    #
    def read_IO( self, range_base, range_size, size=1 ):
        n = range_size//size
        io_ports = []
        for i in range(n):
            io_ports.append( self._read_port( range_base + i*size, size ) )
        return io_ports

    #
    # Dump I/O range
    #
    def dump_IO( self, range_base, range_size, size=1 ):
        n = range_size//size
        fmt = '0{:d}X'.format( (size*2) )
        logger().log("[io] I/O register range [0x{:04X}:0x{:04X}+{:04X}]:".format(range_base,range_base,range_size))
        for i in range(n):
            reg = self._read_port( range_base + i*size, size )
            logger().log( '+{:04X}: {:{form}}'.format(i*size,reg,form=fmt) )
