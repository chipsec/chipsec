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
from chipsec.hal.spd     import *


def spd(argv):
    """
    >>> chipsec_util spd detect
    >>> chipsec_util spd dump [device_addr]
    >>> chipsec_util spd read <device_addr> <offset>
    >>> chipsec_util spd write <device_addr> <offset> <byte_val>

    Examples:

    >>> chipsec_util spd detect
    >>> chipsec_util spd dump DIMM0
    >>> chipsec_util spd read  0xA0 0x0
    >>> chipsec_util spd write 0xA0 0x0 0xAA
    """
    if 3 > len(argv):
        print spd.__doc__
        return

    try:
        _smbus = SMBus( chipsec_util._cs )
        _spd   = SPD( _smbus )
    except BaseException, msg:
        print msg
        return

    op = argv[2]
    t = time.time()

    if not _smbus.is_SMBus_supported():
        logger().log( "[CHIPSEC] SMBus controller is not supported" )
        return
    #smbus.display_SMBus_info()

    dev_addr = SPD_SMBUS_ADDRESS

    if( 'detect' == op ):

        logger().log( "[CHIPSEC] Searching for DIMMs with SPD.." )
        _spd.detect()

    elif( 'dump' == op ):

        if len(argv) > 3:
            dev = argv[3].upper()
            dev_addr = chipsec.hal.spd.SPD_DIMM_ADDRESSES[ dev ] if dev in chipsec.hal.spd.SPD_DIMM_ADDRESSES else int(argv[3],16)
            if not _spd.isSPDPresent( dev_addr ):
                logger().log( "[CHIPSEC] SPD for DIMM 0x%X is not found" % dev_addr )
                return
            _spd.decode( dev_addr )
        else:
            _dimms = _spd.detect()
            for d in _dimms: _spd.decode( d )
 
    elif( 'read' == op ) or ( 'write' == op ):

        if len(argv) > 3:
            dev = argv[3].upper()
            dev_addr = chipsec.hal.spd.SPD_DIMM_ADDRESSES[ dev ] if dev in chipsec.hal.spd.SPD_DIMM_ADDRESSES else int(argv[3],16)
        if not _spd.isSPDPresent( dev_addr ):
            logger().log( "[CHIPSEC] SPD for DIMM 0x%X is not found" % dev_addr )
            return

        off = int(argv[4],16)
        if( 'read' == op ):
            val      = _spd.read_byte( off, dev_addr )
            logger().log( "[CHIPSEC] SPD read: offset 0x%X = 0x%X" % (off, val) )
        elif( 'write' == op ):
            val      = int(argv[5],16)
            logger().log( "[CHIPSEC] SPD write: offset 0x%X = 0x%X" % (off, val) )
            _spd.write_byte( off, val, dev_addr )

    else:
        logger().error( "unknown command-line option '%.32s'" % op )
        logger().log( spd.__doc__ )
        return

    logger().log( "[CHIPSEC] (spd) time elapsed %.3f" % (time.time()-t) )


chipsec_util.commands['spd'] = {'func' : spd, 'start_driver' : True, 'help' : spd.__doc__ }
