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
#chipsec_util pci
#-----
#~~~
#chipsec_util pci enumerate
#chipsec_util pci <bus> <device> <function> <offset> <width> [value]
#''
#    Examples:
#''
#        chipsec_util pci enumerate
#        chipsec_util pci 0 0 0 0x88 4
#        chipsec_util pci 0 0 0 0x88 byte 0x1A
#        chipsec_util pci 0 0x1F 0 0xDC 1 0x1
#        chipsec_util pci 0 0 0 0x98 dword 0x004E0040
#~~~
__version__ = '1.0'

import os
import sys
import time

import chipsec_util
from chipsec_util import chipsec_util_commands, _cs

from chipsec.logger     import *
from chipsec.file       import *

from chipsec.hal.pci    import *

#_cs = cs()

usage = "chipsec_util pci enumerate\n" + \
        "chipsec_util pci <bus> <device> <function> <offset> <width> [value]\n" + \
        "Examples:\n" + \
        "  chipsec_util pci enumerate\n" + \
        "  chipsec_util pci 0 0 0 0x88 4\n" + \
        "  chipsec_util pci 0 0 0 0x88 byte 0x1A\n" + \
        "  chipsec_util pci 0 0x1F 0 0xDC 1 0x1\n" + \
        "  chipsec_util pci 0 0 0 0x98 dword 0x004E0040\n\n"

chipsec_util.global_usage += usage



# ###################################################################
#
# PCIe Devices and Configuration Registers
#
# ###################################################################
def pci(argv):

    if 3 > len(argv):
      print usage
      return

    op = argv[2]
    t = time.time()

    if ( 'enumerate' == op ):
       logger().log( "[CHIPSEC] Enumerating available PCIe devices.." )
       print_pci_devices( _cs.pci.enumerate_devices() )
       logger().log( "[CHIPSEC] (pci) time elapsed %.3f" % (time.time()-t) )
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
       if 1 == width:
          _cs.pci.write_byte( bus, device, function, offset, value )
       elif 2 == width:
          _cs.pci.write_word( bus, device, function, offset, value )
       elif 4 == width:
          _cs.pci.write_dword( bus, device, function, offset, value )
       else:
          print "ERROR: Unsupported width 0x%x" % width
          return
       logger().log( "[CHIPSEC] writing PCI %d/%d/%d, off 0x%02X: 0x%X" % (bus, device, function, offset, value) )
    else:
       if 1 == width:
          pci_value = _cs.pci.read_byte(bus, device, function, offset)
       elif 2 == width:
          pci_value = _cs.pci.read_word(bus, device, function, offset)
       elif 4 == width:
          pci_value = _cs.pci.read_dword(bus, device, function, offset)
       else:
          print "ERROR: Unsupported width 0x%x" % width
          return
       logger().log( "[CHIPSEC] reading PCI B/D/F %d/%d/%d, off 0x%02X: 0x%X" % (bus, device, function, offset, pci_value) )

    logger().log( "[CHIPSEC] (pci) time elapsed %.3f" % (time.time()-t) )

chipsec_util_commands['pci'] = {'func' : pci ,    'start_driver' : True  }

