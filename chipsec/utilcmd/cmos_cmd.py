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

# Contact information:
# chipsec@intel.com

"""
>>> chipsec_util cmos dump
>>> chipsec_util cmos readl|writel|readh|writeh <byte_offset> [byte_val]

Examples:

>>> chipsec_util cmos dump
>>> chipsec_util cmos readl 0x0
>>> chipsec_util cmos writeh 0x0 0xCC
"""

from argparse import ArgumentParser

from chipsec.command import BaseCommand, toLoad
from chipsec.hal.cmos import CMOS


class CMOSCommand(BaseCommand):

    def requirements(self) -> toLoad:
        return toLoad.Driver

    def parse_arguments(self) -> None:
        parser = ArgumentParser(usage=__doc__)

        parser_offset = ArgumentParser(add_help=False)
        parser_offset.add_argument('offset', type=lambda x: int(x, 0), help="offsets read")

        parser_val = ArgumentParser(add_help=False)
        parser_val.add_argument('value', type=lambda x: int(x, 0), help="value written")

        subparsers = parser.add_subparsers()

        # dump
        parser_dump = subparsers.add_parser('dump')
        parser_dump.set_defaults(func=self.cmos_dump)
        # readl
        parser_readl = subparsers.add_parser('readl', parents=[parser_offset])
        parser_readl.set_defaults(func=self.cmos_readl)
        # writel
        parser_writel = subparsers.add_parser('writel', parents=[parser_offset, parser_val])
        parser_writel.set_defaults(func=self.cmos_writel)
        # readh
        parser_readh = subparsers.add_parser('readh', parents=[parser_offset])
        parser_readh.set_defaults(func=self.cmos_readh)
        # writeh
        parser_writeh = subparsers.add_parser('writeh', parents=[parser_offset, parser_val])
        parser_writeh.set_defaults(func=self.cmos_writeh)

        parser.parse_args(self.argv, namespace=CMOSCommand)

    def set_up(self) -> None:
        self._cmos = CMOS(self.cs)

    def cmos_dump(self) -> None:
        self.logger.log("[CHIPSEC] Dumping CMOS memory..")
        self._cmos.dump()

    def cmos_readl(self) -> None:
        val = self._cmos.read_cmos_low(self.offset)
        self.logger.log(f'[CHIPSEC] CMOS low byte 0x{self.offset:X} = 0x{val:X}')

    def cmos_writel(self) -> None:
        val = self._cmos.write_cmos_low(self.offset, self.value)
        self.logger.log(f'[CHIPSEC] CMOS low byte 0x{self.offset:X} = 0x{self.value:X}')

    def cmos_readh(self) -> None:
        val = self._cmos.read_cmos_high(self.offset)
        self.logger.log(f'[CHIPSEC] CMOS high byte 0x{self.offset:X} = 0x{val:X}')

    def cmos_writeh(self) -> None:
        self.logger.log(f'[CHIPSEC] Writing CMOS high byte 0x{self.offset:X} <- 0x{self.value:X}')
        self._cmos.write_cmos_high(self.offset, self.value)

commands = {'cmos': CMOSCommand}
