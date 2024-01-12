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
The mmcfg command allows direct access to memory mapped config space.

>>> chipsec_util mmcfg base
>>> chipsec_util mmcfg read <bus> <device> <function> <offset> <width>
>>> chipsec_util mmcfg write <bus> <device> <function> <offset> <width> <value>
>>> chipsec_util mmcfg ec


Examples:

>>> chipsec_util mmcfg base
>>> chipsec_util mmcfg read 0 0 0 0x200 4
>>> chipsec_util mmcfg write 0 0 0 0x200 1 0x1A
>>> chipsec_util mmcfg ec
"""

from chipsec.command import BaseCommand, toLoad
from argparse import ArgumentParser


# Access to Memory Mapped PCIe Configuration Space (MMCFG)
class MMCfgCommand(BaseCommand):

    def requirements(self) -> toLoad:
        return toLoad.All

    def parse_arguments(self) -> None:
        parser = ArgumentParser(prog='chipsec_util mmcfg', usage=__doc__)
        subparsers = parser.add_subparsers()

        parser_base = subparsers.add_parser('base')
        parser_base.set_defaults(func=self.base)

        parser_read = subparsers.add_parser('read')
        parser_read.set_defaults(func=self.read)
        parser_read.add_argument('bus', type=lambda x: int(x, 16), help='Bus (hex)')
        parser_read.add_argument('device', type=lambda x: int(x, 16), help='Device (hex)')
        parser_read.add_argument('function', type=lambda x: int(x, 16), help='Function (hex)')
        parser_read.add_argument('offset', type=lambda x: int(x, 16), help='Offset (hex)')
        parser_read.add_argument('width', type=int, choices=[1, 2, 4], help='Width')

        parser_write = subparsers.add_parser('write')
        parser_write.set_defaults(func=self.write)
        parser_write.add_argument('bus', type=lambda x: int(x, 16), help='Bus (hex)')
        parser_write.add_argument('device', type=lambda x: int(x, 16), help='Device (hex)')
        parser_write.add_argument('function', type=lambda x: int(x, 16), help='Function (hex)')
        parser_write.add_argument('offset', type=lambda x: int(x, 16), help='Offset (hex)')
        parser_write.add_argument('width', type=int, choices=[1, 2, 4], help='Width')
        parser_write.add_argument('value', type=lambda x: int(x, 16), help='Value to write (hex)')

        # Print the pcie extended capabilities
        parser_ec = subparsers.add_parser('ec')
        parser_ec.set_defaults(func=self.ec)

        parser.parse_args(self.argv, namespace=self)

    def base(self):
        pciexbar, pciexbar_sz = self.cs.mmio.get_MMCFG_base_address()
        self.logger.log(f'[CHIPSEC] Memory Mapped Config Base: 0x{pciexbar:016X}')
        self.logger.log(f'[CHIPSEC] Memory Mapped Config Size: 0x{pciexbar_sz:016X}')

    def read(self):
        data = self.cs.mmio.read_mmcfg_reg(self.bus, self.device, self.function, self.offset, self.width)
        self.logger.log(f'[CHIPSEC] Reading MMCFG register ({self.bus:02d}:{self.device:02d}.{self.function:d} + 0x{self.offset:02X}): 0x{data:X}')

    def write(self):
        self.cs.mmio.write_mmcfg_reg(self.bus, self.device, self.function, self.offset, self.width, self.value)
        self.logger.log(f'[CHIPSEC] Writing MMCFG register ({self.bus:02d}:{self.device:02d}.{self.function:d} + 0x{self.offset:02X}): 0x{self.value:X}')

    def ec(self):
        devs = self.cs.pci.enumerate_devices()
        for (b, d, f, _, _, _) in devs:
            capabilities = self.cs.mmio.get_extended_capabilities(b, d, f)
            if capabilities:
                self.logger.log(f'Extended Capabilities for {b:02X}:{d:02X}.{f:X}:')
                for cap in capabilities:
                    self.logger.log(f'{cap}')
                    if cap.id == 0xB:
                        vsec = self.cs.mmio.get_vsec(b, d, f, cap.off)
                        self.logger.log(f'\t{vsec}')


commands = {'mmcfg': MMCfgCommand}
