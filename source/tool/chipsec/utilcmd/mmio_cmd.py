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




#
# usage as a standalone utility:
#
## \addtogroup standalone
#chipsec_util mmio
#------
#~~~
#chipsec_util mmio list
#chipsec_util mmio dump <MMIO_BAR_name>
#chipsec_util mmio read|write <MMIO_BAR_name> <offset> [value]
#''
#    Examples:
#''
#        chipsec_util mmio list
#        chipsec_util mmio dump MCHBAR
#        chipsec_util mmio read SPIBAR 0x74
#        chipsec_util mmio write SPIBAR 0x74 0x0
#~~~


__version__ = '1.0'

import os
import sys
import time

import chipsec_util


from chipsec.logger     import *
from chipsec.file       import *

from chipsec.hal.mmio   import *



usage = "chipsec_util mmio list\n" + \
        "chipsec_util mmio dump <MMIO_BAR_name>\n" + \
        "chipsec_util mmio read|write <MMIO_BAR_name> <offset> [value]\n" + \
        "Examples:\n" + \
        "  chipsec_util mmio list\n" + \
        "  chipsec_util mmio dump MCHBAR\n" + \
        "  chipsec_util mmio read SPIBAR 0x74\n" + \
        "  chipsec_util mmio write SPIBAR 0x74 0x0\n\n"


# ###################################################################
#
# Access to Memory Mapped PCIe Configuration Space (MMCFG)
#
# ###################################################################
def mmio(argv):

    t = time.time()

    if 3 > len(argv):
        print usage
        return

    op = argv[2]
    t = time.time()

    if ( 'list' == op ):
        list_MMIO_BARs( chipsec_util._cs )
    elif ( 'dump' == op ):
        bar = argv[3].upper()
        logger().log( "[CHIPSEC] Dumping %s MMIO space.." % bar )
        dump_MMIO_BAR( chipsec_util._cs, bar )
    elif ( 'read' == op ):
        bar = argv[3].upper()
        off = int(argv[4],16)
        reg = read_MMIO_BAR_reg( chipsec_util._cs, bar, off )
        logger().log( "[CHIPSEC] Read %s + 0x%X: 0x%08X" % (bar,off,reg) )
    elif ( 'write' == op ):
        bar = argv[3].upper()
        off = int(argv[4],16)
        reg = int(argv[5],16)
        logger().log( "[CHIPSEC] Write %s + 0x%X: 0x%08X" % (bar,off,reg) )
        write_MMIO_BAR_reg( chipsec_util._cs, bar, off, reg )
    else:
        logger().error( "unknown command-line option '%.32s'" % ucode_op )
        print usage
        return

    logger().log( "[CHIPSEC] (mmio) time elapsed %.3f" % (time.time()-t) )


chipsec_util.commands['mmio'] = {'func' : mmio ,    'start_driver' : True, 'help' : usage  }
