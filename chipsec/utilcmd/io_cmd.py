# !/usr/bin/python
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
The io command allows direct access to read and write I/O port space.

>>> chipsec_util io list
>>> chipsec_util io read  <io_port> <width>
>>> chipsec_util io write <io_port> <width> <value>

Examples:

>>> chipsec_util io list
>>> chipsec_util io read 0x61 1
>>> chipsec_util io write 0x430 1 0x0
"""

from argparse import ArgumentParser

from chipsec.hal import iobar
from chipsec.command import BaseCommand, toLoad


class PortIOCommand(BaseCommand):

    def requirements(self) -> toLoad:
        return toLoad.All

    def parse_arguments(self) -> None:
        parser = ArgumentParser(prog='chipsec_util io', usage=__doc__)
        subparsers = parser.add_subparsers()

        # list
        parser_dump = subparsers.add_parser('list')
        parser_dump.set_defaults(func=self.io_list)

        # read
        parser_r = subparsers.add_parser('read')
        parser_r.add_argument('_port', metavar='port', type=lambda x: int(x, 0), help="io port")
        parser_r.add_argument('_width', metavar='width', type=int, choices=[0x1, 0x2, 0x4], help="width")
        parser_r.set_defaults(func=self.io_read)

        # write
        parser_w = subparsers.add_parser('write')
        parser_w.add_argument('_port', metavar='port', type=lambda x: int(x, 0), help="io port")
        parser_w.add_argument('_width', metavar='width', type=int, choices=[0x1, 0x2, 0x4], help="width")
        parser_w.add_argument('_value', metavar='value', type=lambda x: int(x, 0), help="value")
        parser_w.set_defaults(func=self.io_write)

        parser.parse_args(self.argv, namespace=self)

    def set_up(self) -> None:
        self._iobar = iobar.IOBAR(self.cs)

    def io_list(self) -> None:
        self._iobar.list_IO_BARs()

    def io_read(self) -> None:
        if 0x1 == self._width:
            value = self.cs.io.read_port_byte(self._port)
        elif 0x2 == self._width:
            value = self.cs.io.read_port_word(self._port)
        elif 0x4 == self._width:
            value = self.cs.io.read_port_dword(self._port)
        else:
            self.logger.log("Invalid read size requested. 1,2,4 supported")
            return
        self.logger.log(f'[CHIPSEC] IN 0x{self._port:04X} -> 0x{value:08X} (size = 0x{self._width:02X})')
        return

    def io_write(self) -> None:
        if 0x1 == self._width:
            self.cs.io.write_port_byte(self._port, self._value)
        elif 0x2 == self._width:
            self.cs.io.write_port_word(self._port, self._value)
        elif 0x4 == self._width:
            self.cs.io.write_port_dword(self._port, self._value)
        else:
            self.logger.log("Invalid write size requested. 1,2,4 supported")
            return
        self.logger.log(
            f'[CHIPSEC] OUT 0x{self._port:04X} <- 0x{self._value:08X} (size = 0x{self._width:02X})')
        return

commands = {'io': PortIOCommand}
