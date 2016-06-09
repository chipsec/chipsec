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

from chipsec.command     import BaseCommand
from chipsec.logger      import print_buffer
from chipsec.hal.smbus   import *

class SMBusCommand(BaseCommand):
    """
    >>> chipsec_util smbus read <device_addr> <start_offset> [size]
    >>> chipsec_util smbus write <device_addr> <offset> <byte_val>

    Examples:

    >>> chipsec_util smbus read  0xA0 0x0 0x100
    """

    def requires_driver(self):
        # No driver required when printing the util documentation
        if len(self.argv) < 3:
            return False
        return True

    def run(self):
        if len(self.argv) < 3:
            print SMBusCommand.__doc__
            return

        try:
            _smbus = SMBus( self.cs )
        except BaseException, msg:
            print msg
            return

        op = self.argv[2]
        t = time.time()

        if not _smbus.is_SMBus_supported():
            self.logger.log( "[CHIPSEC] SMBus controller is not supported" )
            return

        _smbus.display_SMBus_info()

        if ( 'read' == op ):
            dev_addr  = int(self.argv[3],16)
            start_off = int(self.argv[4],16)
            if len(self.argv) > 5:
                size   = int(self.argv[5],16)
                buf = _smbus.read_range( dev_addr, start_off, size )
                self.logger.log( "[CHIPSEC] SMBus read: device 0x%X offset 0x%X size 0x%X" % (dev_addr, start_off, size) )
                print_buffer( buf )
            else:
                val = _smbus.read_byte( dev_addr, start_off )
                self.logger.log( "[CHIPSEC] SMBus read: device 0x%X offset 0x%X = 0x%X" % (dev_addr, start_off, val) )
        elif ( 'write' == op ):
            dev_addr = int(self.argv[3],16)
            off      = int(self.argv[4],16)
            val      = int(self.argv[5],16)
            self.logger.log( "[CHIPSEC] SMBus write: device 0x%X offset 0x%X = 0x%X" % (dev_addr, off, val) )
            _smbus.write_byte( dev_addr, off, val )
        else:
            self.logger.error( "unknown command-line option '%.32s'" % op )
            print SMBusCommand.__doc__
            return

        self.logger.log( "[CHIPSEC] (smbus) time elapsed %.3f" % (time.time()-t) )

commands = { 'smbus': SMBusCommand }
