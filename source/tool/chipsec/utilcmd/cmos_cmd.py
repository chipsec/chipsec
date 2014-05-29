#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2014, Intel Corporation
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
#
#
#chipsec_util cmos
#------------------------
#~~~
#chipsec_util cmos dump\n
#chipsec_util cmos readl|writel|readh|writeh \<byte_offset\> [byte_val]
# ''
#    Examples:
#        chipsec_util cmos dump
#        chipsec_util cmos readh 0x0
#        chipsec_util cmos writeh 0x0 0xCC
# ~~~
#
#
__version__ = '1.0'

import os
import sys
import time

import chipsec_util
#from chipsec_util import global_usage, chipsec_util_commands, _cs
from chipsec_util import chipsec_util_commands, _cs

from chipsec.logger     import *
from chipsec.file       import *

from chipsec.hal.cmos   import CMOS, CmosRuntimeError
#from chipsec.chipset    import cs
#_cs = cs()

usage = "chipsec_util cmos dump\n" + \
        "chipsec_util cmos readl|writel|readh|writeh <byte_offset> [byte_val]\n" + \
        "Examples:\n" + \
        "  chipsec_util cmos dump\n" + \
        "  chipsec_util cmos rl 0x0\n" + \
        "  chipsec_util cmos wh 0x0 0xCC\n\n"

chipsec_util.global_usage += usage


def cmos(argv):
    if 3 > len(argv):
      print usage
      return

    try:
       cmos = CMOS(  )
    except CmosRuntimeError, msg:
       print msg
       return

    op = argv[2]
    t = time.time()

    if ( 'dump' == op ):
       logger().log( "[CHIPSEC] Dumping CMOS memory.." )
       cmos.dump()
    elif ( 'readl' == op ):
       off = int(argv[3],16)
       val = cmos.read_cmos_low( off )
       logger().log( "[CHIPSEC] CMOS low byte 0x%X = 0x%X" % (off, val) )
    elif ( 'writel' == op ):
       off = int(argv[3],16)
       val = int(argv[4],16)
       logger().log( "[CHIPSEC] Writing CMOS low byte 0x%X <- 0x%X " % (off, val) )
       cmos.write_cmos_low( off, val )
    elif ( 'readh' == op ):
       off = int(argv[3],16)
       val = cmos.read_cmos_high( off )
       logger().log( "[CHIPSEC] CMOS high byte 0x%X = 0x%X" % (off, val) )
    elif ( 'writeh' == op ):
       off = int(argv[3],16)
       val = int(argv[4],16)
       logger().log( "[CHIPSEC] Writing CMOS high byte 0x%X <- 0x%X " % (off, val) )
       cmos.write_cmos_high( off, val )
    else:
       logger().error( "unknown command-line option '%.32s'" % op )
       print usage
       return

    logger().log( "[CHIPSEC] (cmos) time elapsed %.3f" % (time.time()-t) )


chipsec_util_commands['cmos'] = {'func' : cmos,    'start_driver' : True  }

