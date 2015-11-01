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

from chipsec.command    import BaseCommand
from chipsec.hal.cmos   import CMOS, CmosRuntimeError

class CMOSCommand(BaseCommand):
    """
    >>> chipsec_util cmos dump
    >>> chipsec_util cmos readl|writel|readh|writeh <byte_offset> [byte_val]

    Examples:

    >>> chipsec_util cmos dump
    >>> chipsec_util cmos rl 0x0
    >>> chipsec_util cmos wh 0x0 0xCC
    """

    def requires_driver(self):
        # No driver required when printing the util documentation
        if len(self.argv) < 3:
            return False
        return True

    def run(self):
        if len(self.argv) < 3:
            print CMOSCommand.__doc__
            return

        try:
            _cmos = CMOS(  )
        except CmosRuntimeError, msg:
            print msg
            return

        op = self.argv[2]
        t = time.time()

        if ( 'dump' == op ):
            self.logger.log( "[CHIPSEC] Dumping CMOS memory.." )
            _cmos.dump()
        elif ( 'readl' == op ):
            off = int(self.argv[3],16)
            val = _cmos.read_cmos_low( off )
            self.logger.log( "[CHIPSEC] CMOS low byte 0x%X = 0x%X" % (off, val) )
        elif ( 'writel' == op ):
            off = int(self.argv[3],16)
            val = int(self.argv[4],16)
            self.logger.log( "[CHIPSEC] Writing CMOS low byte 0x%X <- 0x%X " % (off, val) )
            _cmos.write_cmos_low( off, val )
        elif ( 'readh' == op ):
            off = int(self.argv[3],16)
            val = _cmos.read_cmos_high( off )
            self.logger.log( "[CHIPSEC] CMOS high byte 0x%X = 0x%X" % (off, val) )
        elif ( 'writeh' == op ):
            off = int(self.argv[3],16)
            val = int(self.argv[4],16)
            self.logger.log( "[CHIPSEC] Writing CMOS high byte 0x%X <- 0x%X " % (off, val) )
            _cmos.write_cmos_high( off, val )
        else:
            self.logger.error( "unknown command-line option '%.32s'" % op )
            print CMOSCommand.__doc__
            return

        self.logger.log( "[CHIPSEC] (cmos) time elapsed %.3f" % (time.time()-t) )

commands = { 'cmos': CMOSCommand }
