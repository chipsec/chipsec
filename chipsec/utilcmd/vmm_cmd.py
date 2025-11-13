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
>>> chipsec_util vmm is_virtio [<bus> <device> <function>]
>>> chipsec_util vmm virtio

Examples:

>>> chipsec_util vmm hypercall 32 0 0 0 0 0
>>> chipsec_util vmm pt 0x524B01E
>>> chipsec_util vmm virtio
>>> chipsec_util vmm is_virtio 0 6 0
"""

from argparse import ArgumentParser
from typing import List, Tuple

from chipsec.command import BaseCommand, toLoad
from chipsec.hal.common.vmm import get_virtio_devices, VirtIO_Device
from chipsec.library.pci import PCI as pcilib


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

        parser_virtio = subparsers.add_parser('is_virtio')
        parser_virtio.add_argument('bus', type=lambda x: int(x, 16), help='bus value (hex)')
        parser_virtio.add_argument('dev', type=lambda x: int(x, 16), help='device value (hex)')
        parser_virtio.add_argument('fun', type=lambda x: int(x, 16), help='function value (hex)')
        parser_virtio.set_defaults(func=self.vmm_virtio)

        parser_enumerate = subparsers.add_parser('virtio')
        parser_enumerate.set_defaults(func=self.enumerate)

        parser.parse_args(self.argv, namespace=self)

    def _dump_virtio(self, virt_dev: List[Tuple[int, int, int, int, int]]):
        if virt_dev:
            self.logger.log("[CHIPSEC] Available VirtIO devices:")
            pcilib.print_pci_devices(virt_dev)
            for (b, d, f, vid, did, rid) in virt_dev:
                VirtIO_Device(self.cs, b, d, f).dump_device()
        else:
            self.logger.log("[CHIPSEC] No VirtIO devices found")

    def enumerate(self):
        self.logger.log('[CHIPSEC] enumerating VirtIo devices...')
        virtdev_list = get_virtio_devices(self.cs.hals.pci.enumerate_devices())
        self._dump_virtio(virtdev_list)

    def vmm_virtio(self):
        did, vid = self.cs.hals.pci.get_DIDVID(self.bus, self.dev, self.fun)
        dev = (self.bus, self.dev, self.fun, vid, did, 0)
        virt_dev = get_virtio_devices([dev])
        self._dump_virtio(virt_dev)

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

        rax = self.cs.hals.vmm.hypercall(self.ax, self.bx, self.cx, self.dx, self.si, self.di, self.r8, self.r9, self.r10, self.r11)

        self.logger.log("[CHIPSEC] < RAX: 0x{:016X}".format(rax))

    def vmm_pt(self):
        if self.eptp is not None:
            pt_fname = 'ept_{:08X}'.format(self.eptp)
            self.logger.log("[CHIPSEC] EPT physical base: 0x{:016X}".format(self.eptp))
            self.logger.log("[CHIPSEC] Dumping EPT to '{}'...".format(pt_fname))
            self.cs.hals.vmm.dump_EPT_page_tables(self.eptp, pt_fname)
        else:
            self.logger.log("[CHIPSEC] Finding EPT hierarchy in memory is not implemented yet")
            self.logger.log_error(VMMCommand.__doc__)
            return

    def run(self):

        self.func()


commands = {'vmm': VMMCommand}
