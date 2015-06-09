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

from chipsec.hal.cmos   import CMOS, CmosRuntimeError

def cmos(argv):
    """
    >>> chipsec_util cmos dump
    >>> chipsec_util cmos readl|writel|readh|writeh <byte_offset> [byte_val]

    Examples:

    >>> chipsec_util cmos dump
    >>> chipsec_util cmos rl 0x0
    >>> chipsec_util cmos wh 0x0 0xCC
    """
    if 3 > len(argv):
        print cmos.__doc__
        return

    try:
        _cmos = CMOS(  )
    except CmosRuntimeError, msg:
        print msg
        return

    op = argv[2]
    t = time.time()

    if ( 'dump' == op ):
        logger().log( "[CHIPSEC] Dumping CMOS memory.." )
        _cmos.dump()
    elif ( 'readl' == op ):
        off = int(argv[3],16)
        val = _cmos.read_cmos_low( off )
        logger().log( "[CHIPSEC] CMOS low byte 0x%X = 0x%X" % (off, val) )
    elif ( 'writel' == op ):
        off = int(argv[3],16)
        val = int(argv[4],16)
        logger().log( "[CHIPSEC] Writing CMOS low byte 0x%X <- 0x%X " % (off, val) )
        _cmos.write_cmos_low( off, val )
    elif ( 'readh' == op ):
        off = int(argv[3],16)
        val = _cmos.read_cmos_high( off )
        logger().log( "[CHIPSEC] CMOS high byte 0x%X = 0x%X" % (off, val) )
    elif ( 'writeh' == op ):
        off = int(argv[3],16)
        val = int(argv[4],16)
        logger().log( "[CHIPSEC] Writing CMOS high byte 0x%X <- 0x%X " % (off, val) )
        _cmos.write_cmos_high( off, val )
    else:
        logger().error( "unknown command-line option '%.32s'" % op )
        print usage
        return

    logger().log( "[CHIPSEC] (cmos) time elapsed %.3f" % (time.time()-t) )


chipsec_util.commands['cmos'] = {'func' : cmos,    'start_driver' : True, 'help' : cmos.__doc__  }
