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
>>> chipsec_util mmio list
>>> chipsec_util mmio dump <MMIO_BAR_name> [offset] [length] [--instance/-i B:D.F]
>>> chipsec_util mmio dump-abs <MMIO_base_address> [offset] [length]
>>> chipsec_util mmio read <MMIO_BAR_name> <offset> <width> [--instance/-i B:D.F]
>>> chipsec_util mmio read-abs <MMIO_base_address> <offset> <width>
>>> chipsec_util mmio write <MMIO_BAR_name> <offset> <width> <value> [--instance/-i B:D.F]
>>> chipsec_util mmio write-abs <MMIO_base_address> <offset> <width> <value>

For BARs with multiple PCI device instances, use --instance/-i B:D.F to select
which instance to target.  Run 'mmio list' to see available instances.
When --instance/-i is omitted, the first discovered instance is used.

Examples:

>>> chipsec_util mmio list
>>> chipsec_util mmio dump 8086.HOSTCTL.MCHBAR
>>> chipsec_util mmio dump 8086.HOSTCTL.MCHBAR --instance 00:00.0
>>> chipsec_util mmio dump-abs 0xFE010000 0x70 0x10
>>> chipsec_util mmio read SPIBAR 0x74 0x4
>>> chipsec_util mmio read 8086.HOSTCTL.MCHBAR 0x0 0x4 -i 00:00.0
>>> chipsec_util mmio read-abs 0xFE010000 0x74 0x04
>>> chipsec_util mmio write SPIBAR 0x74 0x4 0xFFFF0000
>>> chipsec_util mmio write SPIBAR 0x74 0x4 0xFFFF0000 -i 00:00.0
>>> chipsec_util mmio write-abs 0xFE010000 0x74 0x04 0xFFFF0000
"""

from chipsec.command import BaseCommand, toLoad
from chipsec.hal.common import mmio
from argparse import ArgumentParser
from chipsec.library.exceptions import MMIOBARNotFoundError


# ###################################################################
#
# Access to Memory Mapped PCIe Configuration Space (MMCFG)
#
# ###################################################################
class MMIOCommand(BaseCommand):

    def requirements(self) -> toLoad:
        return toLoad.All

    def parse_arguments(self) -> None:
        parser = ArgumentParser(prog='chipsec_util mmio', usage=__doc__)
        subparsers = parser.add_subparsers()

        parser_list = subparsers.add_parser('list')
        parser_list.set_defaults(func=self.list_bars)

        parser_dump = subparsers.add_parser('dump')
        parser_dump.add_argument('bar_name', type=str, help='MMIO BAR to dump')
        parser_dump.add_argument('offset', type=lambda x: int(x, 16), nargs='?', default=0,
                                 help='Offset in BAR to start dump')
        parser_dump.add_argument('length', type=lambda x: int(x, 16), nargs='?', default=None,
                                 help='Length of the region to dump')
        parser_dump.add_argument('-i', '--instance', type=str, default=None,
                                 help='PCI instance as hex B:D.F (e.g. 00:00.0)')
        parser_dump.set_defaults(func=self.dump_bar)

        parser_dump_abs = subparsers.add_parser('dump-abs')
        parser_dump_abs.add_argument('base', type=lambda x: int(x, 16), help='MMIO region base address')
        parser_dump_abs.add_argument('offset', type=lambda x: int(x, 16), nargs='?', default=0,
                                     help='Offset in BAR to start dump')
        parser_dump_abs.add_argument('length', type=lambda x: int(x, 16), nargs='?', default=None,
                                     help='Length of the region to dump')
        parser_dump_abs.set_defaults(func=self.dump_bar_abs)

        parser_read = subparsers.add_parser('read')
        parser_read.add_argument('bar_name', type=str, help='MMIO BAR to read')
        parser_read.add_argument('offset', type=lambda x: int(x, 16), help='Offset value (hex)')
        parser_read.add_argument('width', type=lambda x: int(x, 16), choices=[1, 2, 4, 8],
                                 help='Width value [1, 2, 4, 8] (hex)')
        parser_read.add_argument('-i', '--instance', type=str, default=None,
                                 help='PCI instance as hex B:D.F (e.g. 00:00.0)')
        parser_read.set_defaults(func=self.read_bar)

        parser_read_abs = subparsers.add_parser('read-abs')
        parser_read_abs.add_argument('base', type=lambda x: int(x, 16), help='MMIO region base address')
        parser_read_abs.add_argument('offset', type=lambda x: int(x, 16), help='MMIO register offset')
        parser_read_abs.add_argument('width', type=lambda x: int(x, 16), choices=[1, 2, 4, 8],
                                     help='Data width to read')
        parser_read_abs.set_defaults(func=self.read_abs)

        parser_write = subparsers.add_parser('write')
        parser_write.add_argument('bar_name', type=str, help='MMIO BAR to write')
        parser_write.add_argument('offset', type=lambda x: int(x, 16), help='Offset value (hex)')
        parser_write.add_argument('width', type=lambda x: int(x, 16), choices=[1, 2, 4, 8],
                                  help='Width value [1, 2, 4, 8] (hex)')
        parser_write.add_argument('value', type=lambda x: int(x, 16), help='Value to write (hex)')
        parser_write.add_argument('-i', '--instance', type=str, default=None,
                                  help='PCI instance as hex B:D.F (e.g. 00:11.0)')
        parser_write.set_defaults(func=self.write_bar)

        parser_write_abs = subparsers.add_parser('write-abs')
        parser_write_abs.add_argument('base', type=lambda x: int(x, 16), help='MMIO region base address')
        parser_write_abs.add_argument('offset', type=lambda x: int(x, 16), help='MMIO register offset')
        parser_write_abs.add_argument('width', type=lambda x: int(x, 16), choices=[1, 2, 4, 8],
                                      help='Data width to read')
        parser_write_abs.add_argument('value', type=lambda x: int(x, 16), help='Value to write (hex)')
        parser_write_abs.set_defaults(func=self.write_abs)

        parser.parse_args(self.argv, namespace=self)

    def set_up(self) -> None:
        self._mmio = mmio.MMIO(self.cs)

    def _resolve_instance(self, bar_name):
        """Resolve --instance B:D.F string to a matching PCIObj, or None."""
        if not hasattr(self, 'instance') or self.instance is None:
            return None
        bdf = self.instance
        try:
            bd, f = bdf.split('.')
            b, d = bd.split(':')
            bus, dev, fun = int(b, 16), int(d, 16), int(f, 16)
        except (ValueError, AttributeError):
            message = f"[mmio] Invalid B:D.F format: '{bdf}' (expected XX:XX.X)"
            self.logger.log_error(message)
            raise AttributeError(message)
        bar = self._mmio.cs.register.mmio.get_def(bar_name)
        if bar is None:
            message = f"[mmio] Cannot find BAR name: '{bar_name}'"
            self.logger.log_error(message)
            raise MMIOBARNotFoundError(message)
        for inst in bar.instances:
            ib_ = inst.bus if inst.bus is not None else None
            id_ = inst.dev if inst.dev is not None else None
            if_ = inst.fun if inst.fun is not None else None
            if ib_ == bus and id_ == dev and if_ == fun:
                return inst
        message = f"[mmio] No {bar_name} instance found at {bdf}"
        self.logger.log_error(message)
        raise AttributeError(message)

    def list_bars(self):
        self._mmio.list_MMIO_BARs()

    def dump_bar(self):
        bar = self.bar_name.upper()
        try:
            inst = self._resolve_instance(bar)
        except AttributeError as e:
            return
        self.logger.log(f"[CHIPSEC] Dumping {bar} MMIO space..")
        (bar_base, bar_size) = self._mmio.get_MMIO_BAR_base_address(bar, inst)
        if self.length is not None:
            bar_size = self.length
        else:
            bar_size -= self.offset
        bar_base += self.offset
        self._mmio.dump_MMIO(bar_base, bar_size)

    def dump_bar_abs(self):
        tmp_base = self.base + self.offset
        if self.length is None:
            tmp_length = 0x1000
        else:
            tmp_length = self.length
        self.logger.log(f"[CHIPSEC] Dumping MMIO space 0x{tmp_base:08X} to 0x{tmp_base + tmp_length:08X}")
        self._mmio.dump_MMIO(tmp_base, tmp_length)

    def read_bar(self):
        bar = self.bar_name.upper()
        try:
            inst = self._resolve_instance(bar)
        except AttributeError as e:
            return
        reg = self._mmio.read_MMIO_BAR_reg(bar, self.offset, self.width, inst)
        self.logger.log(f"[CHIPSEC] Read {bar} + 0x{self.offset:X}: 0x{reg:08X}")

    def read_abs(self):
        if self.width == 1:
            reg = self._mmio.read_MMIO_reg_byte(self.base, self.offset)
        elif self.width == 2:
            reg = self._mmio.read_MMIO_reg_word(self.base, self.offset)
        elif self.width == 4:
            reg = self._mmio.read_MMIO_reg_dword(self.base, self.offset)
        elif self.width == 8:
            reg = self._mmio.read_MMIO_reg_dword(self.base, self.offset)
            reg |= self._mmio.read_MMIO_reg_dword(self.base, self.offset + 4) << 32
        else:
            self.logger.log_error(f"[CHIPSEC] Invalid width: {self.width}")
            return
        self.logger.log(f"[CHIPSEC] Read 0x{self.base:X} + 0x{self.offset:X}: 0x{reg:08X}")

    def write_bar(self):
        bar = self.bar_name.upper()
        try:
            inst = self._resolve_instance(bar)
        except AttributeError as e:
            return
        self.logger.log(f"[CHIPSEC] Write {bar} + 0x{self.offset:X}: 0x{self.value:08X}")
        self._mmio.write_MMIO_BAR_reg(bar, self.offset, self.value, self.width, inst)

    def write_abs(self):
        self.logger.log(f"[CHIPSEC] Write 0x{self.base:X} + 0x{self.offset:X}: 0x{self.value:08X}")
        if self.width == 1:
            self._mmio.write_MMIO_reg_byte(self.base, self.offset, self.value & 0xFF)
        elif self.width == 2:
            self._mmio.write_MMIO_reg_word(self.base, self.offset, self.value & 0xFFFF)
        elif self.width == 4:
            self._mmio.write_MMIO_reg_dword(self.base, self.offset, self.value & 0xFFFFFFFF)
        elif self.width == 8:
            self._mmio.write_MMIO_reg_dword(self.base, self.offset, self.value & 0xFFFFFFFF)
            self._mmio.write_MMIO_reg_dword(self.base, self.offset + 4, (self.value >> 32) & 0xFFFFFFFF)



commands = {'mmio': MMIOCommand}
