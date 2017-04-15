#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2016, Intel Corporation
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

import os
import sys
import time
import re

import chipsec_util
from chipsec.command    import BaseCommand

from chipsec.logger     import *
from chipsec.file       import *
from chipsec.hal.vmm    import *

import chipsec.hal.pci

class VMMCommand(BaseCommand):
    """
    >>> chipsec_util vmm hypercall <rax> <rbx> <rcx> <rdx> <rdi> <rsi> [r8] [r9] [r10] [r11]
    >>> chipsec_util vmm hypercall <eax> <ebx> <ecx> <edx> <edi> <esi>
    >>> chipsec_util vmm pt|ept <ept_pointer>
    >>> chipsec_util vmm virtio [<bus>:<device>.<function>]

    Examples:

    >>> chipsec_util vmm hypercall 32 0 0 0 0 0
    >>> chipsec_util vmm pt 0x524B01E
    >>> chipsec_util vmm virtio
    >>> chipsec_util vmm virtio 0:6.0

    """

    def requires_driver(self):
        # No driver required when printing the util documentation
        if len(self.argv) < 3:
            return False
        return True


    def virtio(self):
        if len(self.argv) > 3:
            bdf = self.argv[3]
            match = re.search(r"^([0-9a-f]{1,2}):([0-1]?[0-9a-f]{1})\.([0-7]{1})$", bdf)
            if match:
                _bus = int(match.group(1), 16) & 0xFF
                _dev = int(match.group(2), 16) & 0x1F
                _fun = int(match.group(3), 16) & 0x07 
                vid  = self.cs.pci.read_word(_bus, _dev, _fun, 0)
                did  = self.cs.pci.read_word(_bus, _dev, _fun, 2)
                dev  = (_bus, _dev, _fun, vid, did)
                virt_dev = [dev]
            else:
                self.logger.error("invalid B:D.F (%s)" % bdf)
                print VMMCommand.__doc__
                return
        else:
            self.logger.log("[CHIPSEC] enumerating VirtIO devices..")
            virt_dev = get_virtio_devices( self.cs.pci.enumerate_devices() )

        if len(virt_dev) > 0:
            self.logger.log("[CHIPSEC] Available VirtIO devices:")
            chipsec.hal.pci.print_pci_devices( virt_dev )
            for (b, d, f, vid, did) in virt_dev:
                VirtIO_Device(self.cs, b, d, f).dump_device()
        else:
            self.logger.log("[CHIPSEC] No VirtIO devices found")


    def run(self):

        if len(self.argv) < 3:
            print VMMCommand.__doc__
            return

        op = self.argv[2]
        t = time.time()

        try:
            vmm = VMM( self.cs )
        except VMMRuntimeError, msg:
            print msg
            return

        vmm.init();

        if op == "hypercall":

            gprs_cnt = len(self.argv) - 3
            if (gprs_cnt < 6) or (gprs_cnt > 10):
                print VMMCommand.__doc__
                return

            gpr = self.argv[3:]
            while (len(gpr) < 10):
                gpr.append('0')

            (rax, rbx, rcx, rdx, rsi, rdi, r8, r9, r10, r11) = tuple([int(x, 16) for x in gpr])

            self.logger.log( "[CHIPSEC] > hypercall" )
            self.logger.log( "[CHIPSEC]   RAX: 0x%016x" % rax )
            self.logger.log( "[CHIPSEC]   RBX: 0x%016x" % rbx )
            self.logger.log( "[CHIPSEC]   RCX: 0x%016x" % rcx )
            self.logger.log( "[CHIPSEC]   RDX: 0x%016x" % rdx )
            self.logger.log( "[CHIPSEC]   RSI: 0x%016x" % rsi )
            self.logger.log( "[CHIPSEC]   RDI: 0x%016x" % rdi )
            self.logger.log( "[CHIPSEC]   R8 : 0x%016x" % r8  )
            self.logger.log( "[CHIPSEC]   R9 : 0x%016x" % r9  )
            self.logger.log( "[CHIPSEC]   R10: 0x%016x" % r10 )
            self.logger.log( "[CHIPSEC]   R11: 0x%016x" % r11 )

            rax = vmm.hypercall( rax, rbx, rcx, rdx, rsi, rdi, r8, r9, r10, r11 )

            self.logger.log( "[CHIPSEC] < RAX: 0x%016x" % rax )

        elif op in ['pt','ept']:

            if len(self.argv) == 4:
                eptp = int(self.argv[3],16) 
                pt_fname = 'ept_%08X' % eptp
                self.logger.log( "[CHIPSEC] EPT physical base: 0x%016X" % eptp )
                self.logger.log( "[CHIPSEC] dumping EPT to '%s'..." % pt_fname )
                vmm.dump_SLAT_page_tables( eptp, pt_fname )
            else:
                self.logger.log( "[CHIPSEC] finding EPT hierarchy in memory is not implemented yet" )
                print VMMCommand.__doc__
                return

        elif op == 'virtio':

            self.virtio()

        else:
            self.logger.log( "Unknown command: %s" % op )
            print VMMCommand.__doc__
            return

        self.logger.log( "[CHIPSEC] (vmm) time elapsed %.3f" % (time.time()-t) )


commands = { 'vmm': VMMCommand }

