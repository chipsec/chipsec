#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2019, Intel Corporation
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

#Contact information:
#chipsec@intel.com



from time   import time
from argparse   import ArgumentParser

from chipsec.command    import BaseCommand
from chipsec.hal.cmos   import CMOS, CmosRuntimeError

class CMOSCommand(BaseCommand):
    """
    >>> chipsec_util cmos dump
    >>> chipsec_util cmos readl|writel|readh|writeh <byte_offset> [byte_val]

    Examples:

    >>> chipsec_util cmos dump
    >>> chipsec_util cmos readl 0x0
    >>> chipsec_util cmos writeh 0x0 0xCC
    """

    def requires_driver(self):
        parser = ArgumentParser(usage=CMOSCommand.__doc__)
        subparsers = parser.add_subparsers()
        parser_dump = subparsers.add_parser('dump')
        parser_dump.set_defaults(func=self.cmos_dump)
        parser_readl = subparsers.add_parser('readl')
        parser_readl.set_defaults(func=self.cmos_readl)
        parser_writel = subparsers.add_parser('writel')
        parser_writel.set_defaults(func=self.cmos_writel)
        parser_readh = subparsers.add_parser('readh')
        parser_readh.set_defaults(func=self.cmos_readh)
        parser_readh.add_argument('offset',type=lambda x: int(x,0),help="offsets read")
        parser_readl.add_argument('offset',type=lambda x: int(x,0),help="offsets read")
        parser_writeh = subparsers.add_parser('writeh')
        parser_writeh.set_defaults(func=self.cmos_writeh)
        parser_writel.add_argument('offset',type=lambda x: int(x,0),help="offsets write")
        parser_writeh.add_argument('offset',type=lambda x: int(x,0),help="offsets write")
        parser_writel.add_argument('value',type=lambda x: int(x,0),help="value written")
        parser_writeh.add_argument('value',type=lambda x: int(x,0),help="value written")
        parser.parse_args(self.argv[2:],namespace=CMOSCommand)

        return True

    def cmos_dump(self):
        self.logger.log("[CHIPSEC] Dumping CMOS memory..")
        self._cmos.dump()

    def cmos_readl(self):
        val = self._cmos.read_cmos_low( self.offset )
        self.logger.log( "[CHIPSEC] CMOS low byte 0x%X = 0x%X" % (self.offset, val) )

    def cmos_writel(self):
        val = self._cmos.write_cmos_low( self.offset, self.value )
        self.logger.log( "[CHIPSEC] CMOS low byte 0x%X = 0x%X" % (self.offset, self.value) )

    def cmos_readh(self):
        val = self._cmos.read_cmos_high( self.offset )
        self.logger.log( "[CHIPSEC] CMOS high byte 0x%X = 0x%X" % (self.offset, val) )

    def cmos_writeh(self):
        self.logger.log( "[CHIPSEC] Writing CMOS high byte 0x%X <- 0x%X " % (self.offset, self.value) )
        self._cmos.write_cmos_high( self.offset, self.value )

    def run(self):
        t = time()
        try:
            self._cmos = CMOS(self.cs)
        except CmosRuntimeError as msg:
            print(msg)
            return

        self.func()
        self.logger.log( "[CHIPSEC] (cmos) time elapsed {:.3f}".format(time()-t) )

commands = { 'cmos': CMOSCommand }
