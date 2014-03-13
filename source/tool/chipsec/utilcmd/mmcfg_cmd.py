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
#chipsec_util mmcfg
#------
#~~~
#chipsec_util mmcfg
#chipsec_util mmcfg <bus> <device> <function> <offset> <width> [value]
#''
#    Examples:
#''
#        chipsec_util mmcfg
#        chipsec_util mmcfg 0 0 0 0x88 4
#        chipsec_util mmcfg 0 0 0 0x88 byte 0x1A
#        chipsec_util mmcfg 0 0x1F 0 0xDC 1 0x1
#        chipsec_util mmcfg 0 0 0 0x98 dword 0x004E0040
#~~~


__version__ = '1.0'

import os
import sys
import time

import chipsec_util
from chipsec_util import chipsec_util_commands, _cs

from chipsec.logger     import *
from chipsec.file       import *

from chipsec.hal.mmio   import *

#_cs = cs()

usage = "chipsec_util mmcfg <bus> <device> <function> <offset> <width> [value]\n" + \
        "Examples:\n" + \
        "  chipsec_util mmcfg 0 0 0 0x88 4\n" + \
        "  chipsec_util mmcfg 0 0 0 0x88 byte 0x1A\n" + \
        "  chipsec_util mmcfg 0 0x1F 0 0xDC 1 0x1\n" + \
        "  chipsec_util mmcfg 0 0 0 0x98 dword 0x004E0040\n\n"

chipsec_util.global_usage += usage



# ###################################################################
#
# Access to Memory Mapped PCIe Configuration Space (MMCFG)
#
# ###################################################################
def mmcfg(argv):

    t = time.time()

    if 2 == len(argv):
        pciexbar = get_PCIEXBAR_base_address( _cs )
        logger().log( "[CHIPSEC] Memory Mapped Configuration Space (PCIEXBAR) = 0x%016X" % pciexbar )
        return
    elif 6 > len(argv):
        print usage
        return

    try:
       bus         = int(argv[2],16)
       device      = int(argv[3],16)
       function    = int(argv[4],16)
       offset      = int(argv[5],16)

       if 6 == len(argv):
          width = 1
       else:
          if 'byte' == argv[6]:
             width = 1
          elif 'word' == argv[6]:
             width = 2
          elif 'dword' == argv[6]:
             width = 4
          else:
             width = int(argv[6])

    except Exception as e :
       print usage
       return

    if 8 == len(argv):
       value = int(argv[7], 16)
       write_mmcfg_reg( _cs, bus, device, function, offset, width, value )
       #_cs.pci.write_mmcfg_reg( bus, device, function, offset, width, value )
       logger().log( "[CHIPSEC] writing MMCFG register (%d/%d/%d + 0x%02X): 0x%X" % (bus, device, function, offset, value) )
    else:
       value = read_mmcfg_reg( _cs, bus, device, function, offset, width )
       #value = _cs.pci.read_mmcfg_reg( bus, device, function, offset, width )
       logger().log( "[CHIPSEC] reading MMCFG register (%d/%d/%d + 0x%02X): 0x%X" % (bus, device, function, offset, value) )

    logger().log( "[CHIPSEC] (mmcfg) time elapsed %.3f" % (time.time()-t) )


chipsec_util_commands['mmcfg'] = {'func' : mmcfg ,    'start_driver' : True  }

