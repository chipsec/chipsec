#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2020, Intel Corporation
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


from chipsec.command import BaseCommand
from chipsec.hal     import mmio
from argparse        import ArgumentParser
from time            import time


# ###################################################################
#
# Access to Memory Mapped PCIe Configuration Space (MMCFG)
#
# ###################################################################
class MMIOCommand(BaseCommand):
    """
    >>> chipsec_util mmio list
    >>> chipsec_util mmio dump <MMIO_BAR_name>
    >>> chipsec_util mmio read <MMIO_BAR_name> <offset> <width>
    >>> chipsec_util mmio write <MMIO_BAR_name> <offset> <width> <value>

    Examples:

    >>> chipsec_util mmio list
    >>> chipsec_util mmio dump MCHBAR
    >>> chipsec_util mmio read SPIBAR 0x74 0x4
    >>> chipsec_util mmio write SPIBAR 0x74 0x4 0xFFFF0000
    """

    def requires_driver(self):
        parser = ArgumentParser( prog='chipsec_util mmio', usage=MMIOCommand.__doc__ )
        subparsers = parser.add_subparsers()

        parser_list = subparsers.add_parser('list')
        parser_list.set_defaults(func=self.list_bars)

        parser_dump = subparsers.add_parser('dump')
        parser_dump.add_argument('bar_name', type=str, help='MMIO BAR to dump')
        parser_dump.set_defaults(func=self.dump_bar)

        parser_read = subparsers.add_parser('read')
        parser_read.add_argument('bar_name', type=str, help='MMIO BAR to read')
        parser_read.add_argument('offset', type=lambda x: int(x,16), help='Offset value (hex)')
        parser_read.add_argument('width', type=lambda x: int(x,16), choices=[1,2,4,8], help='Width value [1, 2, 4, 8] (hex)')
        parser_read.set_defaults(func=self.read_bar)

        parser_write = subparsers.add_parser('write')
        parser_write.add_argument('bar_name', type=str, help='MMIO BAR to write')
        parser_write.add_argument('offset', type=lambda x: int(x,16), help='Offset value (hex)')
        parser_write.add_argument('width', type=lambda x: int(x,16), choices=[1,2,4,8], help='Width value [1, 2, 4, 8] (hex)')
        parser_write.add_argument('value', type=lambda x: int(x,16), help='Value to write (hex)')
        parser_write.set_defaults(func=self.write_bar)

        parser.parse_args(self.argv[2:], namespace=self)
        if hasattr(self, 'func'):
            return True
        return False


    def list_bars(self):
        self.mmio_.list_MMIO_BARs()


    def dump_bar(self):
        self.logger.log( "[CHIPSEC] Dumping {} MMIO space..".format(self.bar_name) )
        self.mmio_.dump_MMIO_BAR(self.bar_name.upper())


    def read_bar(self):
        bar = self.bar_name.upper()
        reg = self.mmio_.read_MMIO_BAR_reg(bar, self.offset, self.width)
        self.logger.log( "[CHIPSEC] Read {} + 0x{:X}: 0x{:08X}".format(bar, self.offset, reg) )


    def write_bar(self):
        bar = self.bar_name.upper()
        self.logger.log( "[CHIPSEC] Write {} + 0x{:X}: 0x{:08X}".format(bar, self.offset, self.value) )
        self.mmio_.write_MMIO_BAR_reg(bar, self.offset, self.value, self.width)


    def run(self):
        self.mmio_ = mmio.MMIO(self.cs)

        t = time()

        self.func()

        self.logger.log( "[CHIPSEC] (mmio) time elapsed {:.3f}".format(time() -t) )

commands = { 'mmio': MMIOCommand }
