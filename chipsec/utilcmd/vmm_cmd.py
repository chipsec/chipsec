# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Contact information:
# chipsec@intel.com
#

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

import re

from chipsec.command import BaseCommand, toLoad
from chipsec.hal.vmm import VMM, get_virtio_devices, VirtIO_Device
from chipsec.hal.pci import print_pci_devices
from chipsec.library.exceptions import VMMRuntimeError
from argparse import ArgumentParser


class VMMCommand(BaseCommand):

    def requirements(self) -> toLoad:
        return toLoad.Driver

    def parse_arguments(self) -> None:
        parser = ArgumentParser(prog='chipsec_util vmm', usage=__doc__)
        subparsers = parser.add_subparsers()

        parser_hypercall = subparsers.add_parser('hypercall')
        parser_hypercall.add_argument('ax', type=lambda x: int(x, 16), help='rax/eax value (hex)')
        parser_hypercall.add_argument('bx', type=lambda x: int(x, 16), help='rbx/ebx value (hex)')
        parser_hypercall.add_argument('cx', type=lambda x: int(x, 16), help='rcx/ecx value (hex)')
        parser_hypercall.add_argument('dx', type=lambda x: int(x, 16), help='rdx/edx value (hex)')
        parser_hypercall.add_argument('di', type=lambda x: int(x, 16), help='rdi/edi value (hex)')
        parser_hypercall.add_argument('si', type=lambda x: int(x, 16), help='rsi/esi value (hex)')
        parser_hypercall.add_argument('r8', type=lambda x: int(x, 16), nargs='?', default=0, help='r8 value (hex)')
        parser_hypercall.add_argument('r9', type=lambda x: int(x, 16), nargs='?', default=0, help='r9 value (hex)')
        parser_hypercall.add_argument('r10', type=lambda x: int(x, 16), nargs='?', default=0, help='r10 value (hex)')
        parser_hypercall.add_argument('r11', type=lambda x: int(x, 16), nargs='?', default=0, help='r11 value (hex)')
        parser_hypercall.set_defaults(func=self.vmm_hypercall)

        parser_pt = subparsers.add_parser('pt')
        parser_pt.add_argument('eptp', type=lambda x: int(x, 16), help='Pointer (hex)')
        parser_pt.set_defaults(func=self.vmm_pt)

        parser_ept = subparsers.add_parser('ept')
        parser_ept.add_argument('eptp', type=lambda x: int(x, 16), help='Pointer (hex)')
        parser_ept.set_defaults(func=self.vmm_pt)

        parser_virtio = subparsers.add_parser('virtio')
        parser_virtio.add_argument('bdf', type=str, nargs='?', default=None, help='<bus>:<device>.<function>')
        parser_virtio.set_defaults(func=self.vmm_virtio)

        parser.parse_args(self.argv, namespace=self)

    def vmm_virtio(self):
        if self.bdf is not None:
            match = re.search(r"^([0-9a-f]{1,2}):([0-1]?[0-9a-f]{1})\.([0-7]{1})$", self.bdf)
            if match:
                _bus = int(match.group(1), 16) & 0xFF
                _dev = int(match.group(2), 16) & 0x1F
                _fun = int(match.group(3), 16) & 0x07
                vid = self.cs.pci.read_word(_bus, _dev, _fun, 0)
                did = self.cs.pci.read_word(_bus, _dev, _fun, 2)
                dev = (_bus, _dev, _fun, vid, did)
                virt_dev = [dev]
            else:
                self.logger.log_error("Invalid B:D.F ({})".format(self.bdf))
                self.logger.log(VMMCommand.__doc__)
                return
        else:
            self.logger.log("[CHIPSEC] Enumerating VirtIO devices...")
            virt_dev = get_virtio_devices(self.cs.pci.enumerate_devices())

        if len(virt_dev) > 0:
            self.logger.log("[CHIPSEC] Available VirtIO devices:")
            print_pci_devices(virt_dev)
            for (b, d, f, vid, did, rid) in virt_dev:
                VirtIO_Device(self.cs, b, d, f).dump_device()
        else:
            self.logger.log("[CHIPSEC] No VirtIO devices found")

    def vmm_hypercall(self):
        self.logger.log('')
        self.logger.log("[CHIPSEC] > hypercall")
        self.logger.log("[CHIPSEC]   RAX: 0x{:016X}".format(self.ax))
        self.logger.log("[CHIPSEC]   RBX: 0x{:016X}".format(self.bx))
        self.logger.log("[CHIPSEC]   RCX: 0x{:016X}".format(self.cx))
        self.logger.log("[CHIPSEC]   RDX: 0x{:016X}".format(self.dx))
        self.logger.log("[CHIPSEC]   RSI: 0x{:016X}".format(self.si))
        self.logger.log("[CHIPSEC]   RDI: 0x{:016X}".format(self.di))
        self.logger.log("[CHIPSEC]   R8 : 0x{:016X}".format(self.r8))
        self.logger.log("[CHIPSEC]   R9 : 0x{:016X}".format(self.r9))
        self.logger.log("[CHIPSEC]   R10: 0x{:016X}".format(self.r10))
        self.logger.log("[CHIPSEC]   R11: 0x{:016X}".format(self.r11))

        rax = self.vmm.hypercall(self.ax, self.bx, self.cx, self.dx, self.si, self.di, self.r8, self.r9, self.r10, self.r11)

        self.logger.log("[CHIPSEC] < RAX: 0x{:016X}".format(rax))

    def vmm_pt(self):
        if self.eptp is not None:
            pt_fname = 'ept_{:08X}'.format(self.eptp)
            self.logger.log("[CHIPSEC] EPT physical base: 0x{:016X}".format(self.eptp))
            self.logger.log("[CHIPSEC] Dumping EPT to '{}'...".format(pt_fname))
            self.vmm.dump_EPT_page_tables(self.eptp, pt_fname)
        else:
            self.logger.log("[CHIPSEC] Finding EPT hierarchy in memory is not implemented yet")
            self.logger.log_error(VMMCommand.__doc__)
            return

    def run(self):
        try:
            self.vmm = VMM(self.cs)
        except VMMRuntimeError as msg:
            self.logger.log_error(msg)
            return

        self.vmm.init()

        self.func()


commands = {'vmm': VMMCommand}
