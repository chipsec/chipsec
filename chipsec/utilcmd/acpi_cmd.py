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
#
#Contact information:
#chipsec@intel.com
#



"""
Command-line utility providing access to ACPI tables 
"""

from os.path import exists as path_exists
from time import time
from argparse import ArgumentParser

from chipsec.hal.acpi   import ACPI, AcpiRuntimeError, ACPI_TABLES
from chipsec.command    import BaseCommand

# ###################################################################
#
# Advanced Configuration and Power Interface (ACPI)
#
# ###################################################################

class ACPICommand(BaseCommand):
    """
    >>> chipsec_util acpi list
    >>> chipsec_util acpi table <name>|<file_path>

    Examples:

    >>> chipsec_util acpi list
    >>> chipsec_util acpi table XSDT
    >>> chipsec_util acpi table acpi_table.bin
    """

    def requires_driver(self):
        parser = ArgumentParser(usage=ACPICommand.__doc__)
        subparsers = parser.add_subparsers()
        parser_list = subparsers.add_parser('list')
        parser_list.set_defaults(func=self.acpi_list)
        parser_table = subparsers.add_parser('table')
        parser_table.add_argument('-f','--file',dest='_file', help='Read from file', action='store_true')
        parser_table.add_argument('_name',metavar='table|filename',nargs=1,help="table to list")
        parser_table.set_defaults(func=self.acpi_table)
        parser.parse_args(self.argv[2:], namespace=self)
        if self.func == self.acpi_table and self._file:
            return False
        return True

    def acpi_list(self):
        self.logger.log( "[CHIPSEC] Enumerating ACPI tables.." )
        self._acpi.print_ACPI_table_list()

    def acpi_table(self):
        name = self._name[0]
        if not self._file and not self._acpi.is_ACPI_table_present( name ):
            self.logger.error( "Please specify table name from {}".format(ACPI_TABLES.keys()) )
            return
        elif self._file and not path_exists( name ):
            self.logger.error( "[CHIPSEC] Unable to find file '{}'".format(name) )
            return
        self.logger.log( "[CHIPSEC] reading ACPI table {} '{}'".format('from file' if self._file else '',name) )
        self._acpi.dump_ACPI_table( name, self._file )
        return


    def run(self):
        t = time()
        try:
            self._acpi = ACPI(self.cs)
        except AcpiRuntimeError as msg:
            print(msg)
            return
        self.func()
        self.logger.log( "[CHIPSEC] (acpi) time elapsed {:.3f}".format(time()-t) )

commands = { 'acpi': ACPICommand }
