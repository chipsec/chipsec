#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2019, Intel Corporation
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
from chipsec.hal.smbios import SMBIOS

class smbios_cmd(BaseCommand):
    """
    >>> chipsec_util smbios entrypoint

    Examples:

    >>> chipsec_util smbios entrypoint
    """

    def requires_driver(self):
        parser = ArgumentParser(usage=smbios_cmd.__doc__)
        subparsers = parser.add_subparsers()
        parser_list = subparsers.add_parser('entrypoint')
        parser_list.set_defaults(func=self.smbios_ep)
        parser.parse_args(self.argv[2:], namespace=self)
        return True

    def smbios_ep(self):
        self.logger.log('[CHIPSEC] Attempting to detect SMBIOS structures')
        found = self.smbios.find_smbios_table()
        if found:
            if self.smbios.smbios_2_pa is not None:
                self.logger.log(self.smbios.smbios_2_ep)
            if self.smbios.smbios_3_pa is not None:
                self.logger.log(self.smbios.smbios_3_ep)
        else:
            self.logger.log('[CHIPSEC] Unable to detect SMBIOS structure(s)')

    def run(self):
        t = time()
        try:
            self.smbios = SMBIOS(self.cs)
        except Exception as e:
            self.logger.log(e)
            return

        self.func()
        self.logger.log('[CHIPSEC] (acpi) time elapsed {:.3f}'.format(time()-t))

commands = {'smbios': smbios_cmd}
