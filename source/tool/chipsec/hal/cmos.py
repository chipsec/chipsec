#!/usr/local/bin/python
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
#
# -------------------------------------------------------------------------------

"""
CMOS memory specific functions (dump, read/write)

usage:
    >>> cmos.dump_low()
    >>> cmos.dump_high()
    >>> cmos.dump()
    >>> cmos.read_cmos_low( offset )
    >>> cmos.write_cmos_low( offset, value )
    >>> cmos.read_cmos_high( offset )
    >>> cmos.write_cmos_high( offset, value )
"""

__version__ = '1.0'

import struct
import sys
import time

from chipsec.hal.hal_base import HALBase
import chipsec.logger

class CmosRuntimeError (RuntimeError):
    pass
class CmosAccessError (RuntimeError):
    pass

CMOS_ADDR_PORT_LOW  = 0x70
CMOS_DATA_PORT_LOW  = 0x71
CMOS_ADDR_PORT_HIGH = 0x72
CMOS_DATA_PORT_HIGH = 0x73


class CMOS(HALBase):

    def read_cmos_high( self, offset ):
        self.cs.io.write_port_byte( CMOS_ADDR_PORT_HIGH, offset );
        return self.cs.io.read_port_byte( CMOS_DATA_PORT_HIGH )

    def write_cmos_high( self, offset, value ):
        self.cs.io.write_port_byte( CMOS_ADDR_PORT_HIGH, offset );
        self.cs.io.write_port_byte( CMOS_DATA_PORT_HIGH, value );

    def read_cmos_low( self, offset ):
        self.cs.io.write_port_byte( CMOS_ADDR_PORT_LOW, 0x80|offset );
        return self.cs.io.read_port_byte( CMOS_DATA_PORT_LOW )

    def write_cmos_low( self, offset, value ):
        self.cs.io.write_port_byte( CMOS_ADDR_PORT_LOW, offset );
        self.cs.io.write_port_byte( CMOS_DATA_PORT_LOW, value );

    def dump_low( self ):
        cmos_buf = [0xFF]*0x80
        orig = self.cs.io.read_port_byte( CMOS_ADDR_PORT_LOW );
        for off in xrange(0x80):
            cmos_buf[off] = self.read_cmos_low( off )
        self.cs.io.write_port_byte( CMOS_ADDR_PORT_LOW, orig );
        return cmos_buf

    def dump_high( self ):
        cmos_buf = [0xFF]*0x80
        orig = self.cs.io.read_port_byte( CMOS_ADDR_PORT_HIGH );
        for off in xrange(0x80):
            cmos_buf[off] = self.read_cmos_high( off )
        self.cs.io.write_port_byte( CMOS_ADDR_PORT_HIGH, orig );
        return cmos_buf

    def dump( self ):
        self.logger.log( "Low CMOS memory contents:" )
        chipsec.logger.pretty_print_hex_buffer( self.dump_low() )
        self.logger.log( "\nHigh CMOS memory contents:" )
        chipsec.logger.pretty_print_hex_buffer( self.dump_high() )
