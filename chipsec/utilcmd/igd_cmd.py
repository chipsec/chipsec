#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2017, Intel Corporation
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
The igd command allows memory read/write operations using igd dma.
"""

__version__ = '1.0'

import time

import chipsec_util
from chipsec.hal import igd
from chipsec.command import BaseCommand

from chipsec.logger import *
import chipsec.file

# Port I/O
class IgdCommand(BaseCommand):
    """
    >>> chipsec_util igd 
    >>> chipsec_util igd dmaread <address> [width] [file_name]
    >>> chipsec_util igd dmawrite <address> <width> <value|file_name>

    Examples:

    >>> chipsec_util igd dmaread 0x20000000 4
    >>> chipsec_util igd dmawrite 0x2217F1000 0x4 deadbeef
    """

    def requires_driver(self):
        # No driver required when printing the util documentation
        if len(self.argv) < 3:
            return False
        return True

    def run(self):
        size = 0x100

        if len(self.argv) < 3:
            print IgdCommand.__doc__
            return

        if not self.cs.igd.is_device_enabled():
            self.logger.log( '[CHIPSEC] Looks like internal graphics device is not enabled' )
            return

        op = self.argv[2]
        t = time.time()

        if 'dmaread'     == op:
            phys_address = int(self.argv[3],16)
            size         = int(self.argv[4],16) if len(self.argv) > 4 else 0x100
            self.logger.log( '[CHIPSEC] reading buffer from memory: PA = 0x%016X, len = 0x%X..' % (phys_address, size) )
            buffer = self.cs.igd.gfx_aperture_dma_read_write( phys_address, size )
            if len(self.argv) > 5:
                buf_file = self.argv[5]
                chipsec.file.write_file( buf_file, buffer )
                self.logger.log( "[CHIPSEC] written 0x%X bytes to '%s'" % (len(buffer), buf_file) )
            else:
                print_buffer( buffer )

        elif 'dmawrite'    == op:
            phys_address = int(self.argv[3],16)
            if len(self.argv) > 4: 
                size = int(self.argv[4],16)
            else:
                self.logger.error( "must specify <length> argument in 'igddma write'" )
                return
            if len(self.argv) > 5:
                buf_file = self.argv[5]
                if not os.path.exists( buf_file ):
                    try:
                      buffer = bytearray.fromhex(buf_file)
                    except ValueError, e:
                        self.logger.error( "incorrect <value> specified: '%s'" % buf_file )
                        self.logger.error( str(e) )
                        return
                    self.logger.log( "[CHIPSEC] read 0x%X hex bytes from command-line: %s'" % (len(buffer), buf_file) )
                else:
                    buffer = chipsec.file.read_file( buf_file )
                    self.logger.log( "[CHIPSEC] read 0x%X bytes from file '%s'" % (len(buffer), buf_file) )

                if len(buffer) < size:
                    self.logger.error( "number of bytes read (0x%X) is less than the specified <length> (0x%X)" % (len(buffer),size) )
                    return

                self.logger.log( '[CHIPSEC] writing buffer to memory: PA = 0x%016X, len = 0x%X..' % (phys_address, size) )
                self.cs.igd.gfx_aperture_dma_read_write( phys_address, size, buffer )
            else:
                self.logger.error( "must specify <buffer>|<file> argument in 'igddma write'" )
                return

        else:
                print IgdDmaCommand.__doc__
                return

        self.logger.log( "[CHIPSEC] (mem) time elapsed %.3f" % (time.time()-t) )

commands = { 'igd': IgdCommand }
