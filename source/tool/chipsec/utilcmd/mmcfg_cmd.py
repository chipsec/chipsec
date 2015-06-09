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



"""
The mmcfg command allows direct access to memory mapped config space.
"""


__version__ = '1.0'

import os
import sys
import time

import chipsec_util


from chipsec.logger     import *
from chipsec.file       import *

from chipsec.hal.mmio   import *


# Access to Memory Mapped PCIe Configuration Space (MMCFG)
def mmcfg(argv):
    """
    >>> chipsec_util mmcfg <bus> <device> <function> <offset> <width> [value]

    Examples:

    >>> chipsec_util mmcfg 0 0 0 0x88 4
    >>> chipsec_util mmcfg 0 0 0 0x88 byte 0x1A
    >>> chipsec_util mmcfg 0 0x1F 0 0xDC 1 0x1
    >>> chipsec_util mmcfg 0 0 0 0x98 dword 0x004E0040
    """
    t = time.time()

    if 2 == len(argv):
        #pciexbar = get_PCIEXBAR_base_address( chipsec_util._cs )
        pciexbar = get_MMCFG_base_address( chipsec_util._cs )
        logger().log( "[CHIPSEC] Memory Mapped Config Base: 0x%016X" % pciexbar )
        return
    elif 6 > len(argv):
        print mmcfg.__doc__
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
        print mmcfg.__doc__
        return

    if 8 == len(argv):
        value = int(argv[7], 16)
        write_mmcfg_reg( chipsec_util._cs, bus, device, function, offset, width, value )
        #_cs.pci.write_mmcfg_reg( bus, device, function, offset, width, value )
        logger().log( "[CHIPSEC] writing MMCFG register (%02d:%02d.%d + 0x%02X): 0x%X" % (bus, device, function, offset, value) )
    else:
        value = read_mmcfg_reg( chipsec_util._cs, bus, device, function, offset, width )
        #value = _cs.pci.read_mmcfg_reg( bus, device, function, offset, width )
        logger().log( "[CHIPSEC] reading MMCFG register (%02d:%02d.%d + 0x%02X): 0x%X" % (bus, device, function, offset, value) )

    logger().log( "[CHIPSEC] (mmcfg) time elapsed %.3f" % (time.time()-t) )


chipsec_util.commands['mmcfg'] = {'func' : mmcfg , 'start_driver' : True, 'help' : mmcfg.__doc__  }
