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
Access to Port I/O

usage:
    >>> read_port_byte( 0x61 )
    >>> read_port_word( 0x61 )
    >>> read_port_dword( 0x61 )
    >>> write_port_byte( 0x71, 0 )
    >>> write_port_word( 0x71, 0 )
    >>> write_port_dword( 0x71, 0 )
"""

__version__ = '1.0'

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
        if logger().VERBOSE: logger().log( "[io] IN 0x%04X: value = 0x%08X, size = 0x%02x" % (io_port, value, size) )
        return value

    def _write_port(self, io_port, value, size ):
        if logger().VERBOSE: logger().log( "[io] OUT 0x%04X: value = 0x%08X, size = 0x%02x" % (io_port, value, size) )
        status = self.helper.write_io_port( io_port, value, size )
        return status

    def read_port_dword(self, io_port ):
        value = self.helper.read_io_port( io_port, 4 )
        if logger().VERBOSE:
            logger().log( "[io] reading dword from I/O port 0x%04X -> 0x%08X" % (io_port, value) )
        return value

    def read_port_word(self, io_port ):
        value = self.helper.read_io_port( io_port, 2 )
        if logger().VERBOSE:
            logger().log( "[io] reading word from I/O port 0x%04X -> 0x%04X" % (io_port, value) )
        return value

    def read_port_byte(self, io_port ):
        value = self.helper.read_io_port( io_port, 1 )
        if logger().VERBOSE:
            logger().log( "[io] reading byte from I/O port 0x%04X -> 0x%02X" % (io_port, value) )
        return value


    def write_port_byte(self, io_port, value ):
        if logger().VERBOSE:
            logger().log( "[io] writing byte to I/O port 0x%04X <- 0x%02X" % (io_port, value) )
        self.helper.write_io_port( io_port, value, 1 )
        return

    def write_port_word(self, io_port, value ):
        if logger().VERBOSE:
            logger().log( "[io] writing word to I/O port 0x%04X <- 0x%04X" % (io_port, value) )
        self.helper.write_io_port( io_port, value, 2 )
        return

    def write_port_dword(self, io_port, value ):
        if logger().VERBOSE:
            logger().log( "[io] writing dword to I/O port 0x%04X <- 0x%08X" % (io_port, value) )
        self.helper.write_io_port( io_port, value, 4 )
        return
