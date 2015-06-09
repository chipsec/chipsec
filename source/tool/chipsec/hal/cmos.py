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
CMOS memory specific functions (dump, read/write)

usage:
    >>> dump()
    >>> read_byte( offset )
    >>> write_byte( offset, value )
"""

__version__ = '1.0'

import struct
import sys
import time

from chipsec.hal.hal_base import HALBase


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
        orig = self.cs.io.read_port_byte( CMOS_ADDR_PORT_LOW );
        self.logger.log( "Low CMOS contents:" )
        self.logger.log( "....0...1...2...3...4...5...6...7...8...9...A...B...C...D...E...F" )
        cmos_str = []
        cmos_str += ["00.."]
        for n in range(1, 129):
            val = self.read_cmos_low( n-1 )
            cmos_str += ["%02X  " % val]
            if ( (0 == n%16) and n < 125 ):
                cmos_str += ["\n%0X.." % n]

        self.cs.io.write_port_byte( CMOS_ADDR_PORT_LOW, orig );
        self.logger.log( "".join(cmos_str) )
        return

    def dump_high( self ):
        orig = self.cs.io.read_port_byte( CMOS_ADDR_PORT_HIGH );
        self.logger.log( "High CMOS contents:" )
        self.logger.log( "....0...1...2...3...4...5...6...7...8...9...A...B...C...D...E...F" )
        cmos_str = []
        cmos_str += ["00.."]
        for n in range(1, 129):
            val = self.read_cmos_high( n-1 )
            cmos_str += ["%02X  " % val]
            if ( (0 == n%16) and n < 125 ):
                cmos_str += ["\n%0X.." % n]

        self.cs.io.write_port_byte( CMOS_ADDR_PORT_HIGH, orig );
        self.logger.log( "".join(cmos_str) )
        return

    def dump( self ):
        self.dump_low()
        self.dump_high()
