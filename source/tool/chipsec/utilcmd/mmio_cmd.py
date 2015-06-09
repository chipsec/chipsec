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

from chipsec.hal.mmio   import *


# ###################################################################
#
# Access to Memory Mapped PCIe Configuration Space (MMCFG)
#
# ###################################################################
def mmio(argv):
    """
    >>> chipsec_util mmio list
    >>> chipsec_util mmio dump <MMIO_BAR_name>
    >>> chipsec_util mmio read <MMIO_BAR_name> <offset> <width>
    >>> chipsec_util mmio write <MMIO_BAR_name> <offset> <width> <value>

    Examples:
    
    >>> chipsec_util mmio list
    >>> chipsec_util mmio dump MCHBAR
    >>> chipsec_util mmio read SPIBAR 0x74 0x4
    >>> chipsec_util mmio write SPIBAR 0x74 0x4 0xFFFF0000
    """
    t = time.time()

    if 3 > len(argv):
        print mmio.__doc__
        return

    op = argv[2]
    t = time.time()

    if ( 'list' == op ):
        list_MMIO_BARs( chipsec_util._cs )
    elif ( 'dump' == op ):
        bar = argv[3].upper()
        logger().log( "[CHIPSEC] Dumping %s MMIO space.." % bar )
        dump_MMIO_BAR( chipsec_util._cs, bar )
    elif ( 'read' == op or 'write' == op ):
        bar   = argv[3].upper()
        off   = int(argv[4],16)
        width = int(argv[5],16) if len(argv) == 6 else 4
        reg = read_MMIO_BAR_reg( chipsec_util._cs, bar, off, width )
        logger().log( "[CHIPSEC] Read %s + 0x%X: 0x%08X" % (bar,off,reg) )
    elif ( 'write' == op ):
        bar   = argv[3].upper()
        off   = int(argv[4],16)
        width = int(argv[5],16) if len(argv) == 6 else 4
        if len(argv) == 7:
            reg = int(argv[6],16)
            logger().log( "[CHIPSEC] Write %s + 0x%X: 0x%08X" % (bar,off,reg) )
            write_MMIO_BAR_reg( chipsec_util._cs, bar, off, reg, width )
        else:
            print mmio.__doc__
            return
    else:
        logger().error( "unknown command-line option '%.32s'" % op )
        print mmio.__doc__
        return

    logger().log( "[CHIPSEC] (mmio) time elapsed %.3f" % (time.time()-t) )


chipsec_util.commands['mmio'] = {'func' : mmio , 'start_driver' : True, 'help' : mmio.__doc__  }
