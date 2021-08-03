#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2019-2021, Intel Corporation
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

from argparse import ArgumentParser
from time import time

from chipsec.command import BaseCommand

class CommandClass(BaseCommand):
    """
        >>> chipsec_util command_display_name action
    """

    def requires_driver(self):
        parser = ArgumentParser(prog='chipsec_util command_display_name', usage=CommandClass.__doc__)
        subparsers = parser.add_subparsers()
        parser_entrypoint = subparsers.add_parser('action')
        parser_entrypoint.set_defaults(func=self.action)
        parser.parse_args(self.argv[2:], namespace=self)
        return True


    def action(self):
        return

    def run(self):
        t = time()
        self.func()
        self.logger.log('[CHIPSEC] (command_display_name) time elapsed {:.3f}'.format(time() -t))

commands = { 'command_display_name': CommandClass }
