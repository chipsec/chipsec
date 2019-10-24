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
from chipsec.logger import print_buffer
from chipsec.defines import bytestostring

class smbios_cmd(BaseCommand):
    """
    >>> chipsec_util smbios entrypoint
    >>> chipsec_util smbios get [raw|decoded] [type]

    Examples:

    >>> chipsec_util smbios entrypoint
    >>> chipsec_util smbios get raw
    """

    def requires_driver(self):
        parser = ArgumentParser(prog='chipsec_util smbios', usage=smbios_cmd.__doc__)
        subparsers = parser.add_subparsers()
        parser_entrypoint = subparsers.add_parser('entrypoint')
        parser_entrypoint.set_defaults(func=self.smbios_ep)
        parser_get = subparsers.add_parser('get')
        parser_get.add_argument('method', choices=['raw', 'decoded'], default='raw', nargs='?', \
            help='Get raw data or decoded data.  Decoded data may not exist for all structures')
        parser_get.add_argument('type', type=int, default=None, nargs='?', \
            help='SMBIOS type to search for')
        parser_get.add_argument('-f', '--force', action='store_true', dest='_force_32', \
            help='Force reading from 32bit structures')
        parser_get.set_defaults(func=self.smbios_get)
        parser.parse_args(self.argv[2:], namespace=self)
        return True

    def smbios_ep(self):
        self.logger.log('[CHIPSEC] SMBIOS Entry Point Structures')
        if self.smbios.smbios_2_pa is not None:
            self.logger.log(self.smbios.smbios_2_ep)
        if self.smbios.smbios_3_pa is not None:
            self.logger.log(self.smbios.smbios_3_ep)

    def smbios_get(self):
        if self.method == 'raw':
            self.logger.log('[CHIPSEC] Dumping all requested structures in raw format')
            structs = self.smbios.get_raw_structs(self.type, self._force_32)
        elif self.method == 'decoded':
            self.logger.log('[CHIPSEC] Dumping all requested structures in decoded format')
            structs = self.smbios.get_decoded_structs(self.type, self._force_32)
        if structs is None:
            self.logger.log('[CHIPSEC] Error getting data')
            return
        if len(structs) == 0:
            self.logger.log('[CHIPSEC] Structures not found')
            return

        for data in structs:
            if self.method == 'raw':
                header = self.smbios.get_header(data)
                if header is not None:
                    self.logger.log(header)
                self.logger.log('[CHIPSEC] Raw Data')
                print_buffer(bytestostring(data))
            elif self.method == 'decoded':
                self.logger.log(data)
            self.logger.log('==================================================================')

    def run(self):
        t = time()

        # Create and initialize SMBIOS object for commands to use
        try:
            self.logger.log('[CHIPSEC] Attempting to detect SMBIOS structures')
            self.smbios = SMBIOS(self.cs)
            found = self.smbios.find_smbios_table()
            if not found:
                self.logger.log('[CHIPSEC] Unable to detect SMBIOS structure(s)')
                return
        except Exception as e:
            self.logger.log(e)
            return

        self.func()
        self.logger.log('[CHIPSEC] (smbios) time elapsed {:.3f}'.format(time()-t))

commands = {'smbios': smbios_cmd}
