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
The pci command can enumerate PCI devices and allow direct access to them by bus/device/function.
"""

__version__ = '1.0'

import time

from chipsec.command    import BaseCommand
from chipsec.hal.pci    import *


# PCIe Devices and Configuration Registers
class PCICommand(BaseCommand):
    """
    >>> chipsec_util pci enumerate
    >>> chipsec_util pci <bus> <device> <function> <offset> <width> [value]

    Examples:

    >>> chipsec_util pci enumerate
    >>> chipsec_util pci 0 0 0 0x88 4
    >>> chipsec_util pci 0 0 0 0x88 byte 0x1A
    >>> chipsec_util pci 0 0x1F 0 0xDC 1 0x1
    >>> chipsec_util pci 0 0 0 0x98 dword 0x004E0040
    """

    def requires_driver(self):
        # No driver required when printing the util documentation
        if len(self.argv) < 3:
            return False
        return True

    def run(self):
        if len(self.argv) < 3:
            print PCICommand.__doc__
            return

        op = self.argv[2]
        t = time.time()

        if ( 'enumerate' == op ):
            self.logger.log( "[CHIPSEC] Enumerating available PCIe devices.." )
            print_pci_devices( self.cs.pci.enumerate_devices() )
            self.logger.log( "[CHIPSEC] (pci) time elapsed %.3f" % (time.time()-t) )
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
            print PCICommand.__doc__
            return

        if 8 == len(self.argv):
            value = int(self.argv[7], 16)
            if 1 == width:
                self.cs.pci.write_byte( bus, device, function, offset, value )
            elif 2 == width:
                self.cs.pci.write_word( bus, device, function, offset, value )
            elif 4 == width:
                self.cs.pci.write_dword( bus, device, function, offset, value )
            else:
                print "ERROR: Unsupported width 0x%x" % width
                return
            self.logger.log( "[CHIPSEC] writing PCI %d/%d/%d, off 0x%02X: 0x%X" % (bus, device, function, offset, value) )
        else:
            if 1 == width:
                pci_value = self.cs.pci.read_byte(bus, device, function, offset)
            elif 2 == width:
                pci_value = self.cs.pci.read_word(bus, device, function, offset)
            elif 4 == width:
                pci_value = self.cs.pci.read_dword(bus, device, function, offset)
            else:
                print "ERROR: Unsupported width 0x%x" % width
                return
            self.logger.log( "[CHIPSEC] reading PCI B/D/F %d/%d/%d, off 0x%02X: 0x%X" % (bus, device, function, offset, pci_value) )

        self.logger.log( "[CHIPSEC] (pci) time elapsed %.3f" % (time.time()-t) )

commands = { 'pci': PCICommand }
