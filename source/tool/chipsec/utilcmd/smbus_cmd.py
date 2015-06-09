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



__version__ = '1.0'

import os
import sys
import time

import chipsec_util


from chipsec.logger     import *
from chipsec.file       import *

from chipsec.hal.smbus   import *

def smbus(argv):
    """
    >>> chipsec_util smbus read <device_addr> <start_offset> [size]
    >>> chipsec_util smbus write <device_addr> <offset> <byte_val>

    Examples:

    >>> chipsec_util smbus read  0xA0 0x0 0x100
    """
    if 3 > len(argv):
        print smbus.__doc__
        return

    try:
        _smbus = SMBus( chipsec_util._cs )
    except BaseException, msg:
        print msg
        return

    op = argv[2]
    t = time.time()

    if not _smbus.is_SMBus_supported():
        logger().log( "[CHIPSEC] SMBus controller is not supported" )
        return

    _smbus.display_SMBus_info()

    if ( 'read' == op ):
        dev_addr  = int(argv[3],16)
        start_off = int(argv[4],16)
        if len(argv) > 5:
            size   = int(argv[5],16)
            buf = _smbus.read_range( dev_addr, start_off, size )
            logger().log( "[CHIPSEC] SMBus read: device 0x%X offset 0x%X size 0x%X" % (dev_addr, start_off, size) )
            print_buffer( buf )
        else:
            val = _smbus.read_byte( dev_addr, start_off )
            logger().log( "[CHIPSEC] SMBus read: device 0x%X offset 0x%X = 0x%X" % (dev_addr, start_off, val) )
    elif ( 'write' == op ):
        dev_addr = int(argv[3],16)
        off      = int(argv[4],16)
        val      = int(argv[5],16)
        logger().log( "[CHIPSEC] SMBus write: device 0x%X offset 0x%X = 0x%X" % (dev_addr, off, val) )
        _smbus.write_byte( dev_addr, off, val )
    else:
        logger().error( "unknown command-line option '%.32s'" % op )
        print smbus.__doc__
        return

    logger().log( "[CHIPSEC] (smbus) time elapsed %.3f" % (time.time()-t) )


chipsec_util.commands['smbus'] = {'func' : smbus, 'start_driver' : True, 'help' : smbus.__doc__ }
