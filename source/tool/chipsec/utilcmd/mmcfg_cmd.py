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

import time

from chipsec.command    import BaseCommand
from chipsec.hal.mmio   import *


# Access to Memory Mapped PCIe Configuration Space (MMCFG)
class MMCfgCommand(BaseCommand):
    """
    >>> chipsec_util mmcfg <bus> <device> <function> <offset> <width> [value]

    Examples:

    >>> chipsec_util mmcfg 0 0 0 0x88 4
    >>> chipsec_util mmcfg 0 0 0 0x88 byte 0x1A
    >>> chipsec_util mmcfg 0 0x1F 0 0xDC 1 0x1
    >>> chipsec_util mmcfg 0 0 0 0x98 dword 0x004E0040
    """

    def requires_driver(self):
        return True

    def run(self):
        t = time.time()

        if 2 == len(self.argv):
            #pciexbar = get_PCIEXBAR_base_address( self.cs )
            pciexbar = get_MMCFG_base_address( self.cs )
            self.logger.log( "[CHIPSEC] Memory Mapped Config Base: 0x%016X" % pciexbar )
            return
        elif 6 > len(self.argv):
            print MMCfgCommand.__doc__
            return

        try:
            bus         = int(self.argv[2],16)
            device      = int(self.argv[3],16)
            function    = int(self.argv[4],16)
            offset      = int(self.argv[5],16)

            if 6 == len(self.argv):
                width = 1
            else:
                if 'byte' == self.argv[6]:
                    width = 1
                elif 'word' == self.argv[6]:
                    width = 2
                elif 'dword' == self.argv[6]:
                    width = 4
                else:
                    width = int(self.argv[6])

        except Exception as e :
            print MMCfgCommand.__doc__
            return

        if 8 == len(self.argv):
            value = int(self.argv[7], 16)
            write_mmcfg_reg( self.cs, bus, device, function, offset, width, value )
            #_cs.pci.write_mmcfg_reg( bus, device, function, offset, width, value )
            self.logger.log( "[CHIPSEC] writing MMCFG register (%02d:%02d.%d + 0x%02X): 0x%X" % (bus, device, function, offset, value) )
        else:
            value = read_mmcfg_reg( self.cs, bus, device, function, offset, width )
            #value = _cs.pci.read_mmcfg_reg( bus, device, function, offset, width )
            self.logger.log( "[CHIPSEC] reading MMCFG register (%02d:%02d.%d + 0x%02X): 0x%X" % (bus, device, function, offset, value) )

        self.logger.log( "[CHIPSEC] (mmcfg) time elapsed %.3f" % (time.time()-t) )

commands = { 'mmcfg': MMCfgCommand }
