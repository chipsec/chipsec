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

>>> chipsec_util mmcfg <bus> <device> <function> <offset> <width> [value]

Examples:

>>> chipsec_util mmcfg 0 0 0 0x88 4
>>> chipsec_util mmcfg 0 0 0 0x88 byte 0x1A
>>> chipsec_util mmcfg 0 0x1F 0 0xDC 1 0x1
>>> chipsec_util mmcfg 0 0 0 0x98 dword 0x004E0040
"""

import time

from chipsec.command import BaseCommand
from chipsec.hal import mmio
from argparse import ArgumentParser


# Access to Memory Mapped PCIe Configuration Space (MMCFG)
class MMCfgCommand(BaseCommand):

    def requires_driver(self):
        parser = ArgumentParser(prog='chipsec_util mmcfg', usage=__doc__)
        parser.add_argument('bus', type=lambda x: int(x, 16), help='Bus (hex)')
        parser.add_argument('device', type=lambda x: int(x, 16), help='Device (hex)')
        parser.add_argument('function', type=lambda x: int(x, 16), help='Function (hex)')
        parser.add_argument('offset', type=lambda x: int(x, 16), help='Offset (hex)')
        parser.add_argument('width', type=str, choices=['byte', 'word', 'dword', '1', '2', '4'], help='Width [byte,word,dword] or (int)')
        parser.add_argument('value', type=lambda x: int(x, 16), nargs='?', default=None, help='Value to write (hex)')
        parser.set_defaults()

        parser.parse_args(self.argv[2:], namespace=self)
        return True

    def run(self):
        t = time.time()
        _mmio = mmio.MMIO(self.cs)

        try:
            if self.width == 'byte':
                _width = 1
            elif self.width == 'word':
                _width = 2
            elif self.width == 'dword':
                _width = 4
            else:
                _width = int(self.width)
        except ValueError:
            self.logger.log_error("ValueError: Invalid inputs.")
            return

        if self.value is not None:
            _mmio.write_mmcfg_reg(self.bus, self.device, self.function, self.offset, _width, self.value)
            self.logger.log("[CHIPSEC] Writing MMCFG register ({:02d}:{:02d}.{:d} + 0x{:02X}): 0x{:X}".format(self.bus, self.device, self.function, self.offset, self.value))
        else:
            data = _mmio.read_mmcfg_reg(self.bus, self.device, self.function, self.offset, _width)
            self.logger.log("[CHIPSEC] Reading MMCFG register ({:02d}:{:02d}.{:d} + 0x{:02X}): 0x{:X}".format(self.bus, self.device, self.function, self.offset, data))

        self.logger.log('')
        self.logger.log("[CHIPSEC] (mmcfg) time elapsed {:.3f}".format(time.time() - t))


commands = {'mmcfg': MMCfgCommand}
