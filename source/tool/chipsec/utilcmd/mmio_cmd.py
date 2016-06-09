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

import time

import chipsec_util


from chipsec.logger     import *
from chipsec.file       import *

from chipsec.hal.mmio   import *
from chipsec.command    import BaseCommand


# ###################################################################
#
# Access to Memory Mapped PCIe Configuration Space (MMCFG)
#
# ###################################################################
class MMIOCommand(BaseCommand):
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

    def requires_driver(self):
        # No driver required when printing the util documentation
        if len(self.argv) < 3:
            return False
        return True

    def run(self):
        t = time.time()

        if len(self.argv) < 3:
            print MMIOCommand.__doc__
            return

        op = self.argv[2]
        t = time.time()

        if ( 'list' == op ):
            list_MMIO_BARs( self.cs )
        elif ( 'dump' == op ):
            bar = self.argv[3].upper()
            self.logger.log( "[CHIPSEC] Dumping %s MMIO space.." % bar )
            dump_MMIO_BAR( self.cs, bar )
        elif ( 'read' == op ):
            bar   = self.argv[3].upper()
            off   = int(self.argv[4],16)
            width = int(self.argv[5],16) if len(self.argv) == 6 else 4
            reg = read_MMIO_BAR_reg( self.cs, bar, off, width )
            self.logger.log( "[CHIPSEC] Read %s + 0x%X: 0x%08X" % (bar,off,reg) )
        elif ( 'write' == op ):
            bar   = self.argv[3].upper()
            off   = int(self.argv[4],16)
            width = int(self.argv[5],16) if len(self.argv) == 6 else 4
            if len(self.argv) == 7:
                reg = int(self.argv[6],16)
                self.logger.log( "[CHIPSEC] Write %s + 0x%X: 0x%08X" % (bar,off,reg) )
                write_MMIO_BAR_reg( self.cs, bar, off, reg, width )
            else:
                print MMIOCommand.__doc__
                return
        else:
            self.logger.error( "unknown command-line option '%.32s'" % op )
            print MMIOCommand.__doc__
            return

        self.logger.log( "[CHIPSEC] (mmio) time elapsed %.3f" % (time.time()-t) )


commands = { 'mmio': MMIOCommand }
