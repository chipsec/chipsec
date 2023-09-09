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
Command-line utility providing access to ACPI tables

>>> chipsec_util acpi list
>>> chipsec_util acpi table <name>|<file_path>

Examples:

>>> chipsec_util acpi list
>>> chipsec_util acpi table XSDT
>>> chipsec_util acpi table acpi_table.bin
"""

from os.path import exists as path_exists
from argparse import ArgumentParser

from chipsec.hal.acpi import ACPI
from chipsec.command import BaseCommand, toLoad

# ###################################################################
#
# Advanced Configuration and Power Interface (ACPI)
#
# ###################################################################


class ACPICommand(BaseCommand):
    def requirements(self) -> toLoad:
        if self.func == self.acpi_table and self._file:
            return toLoad.Nil # TODO: Fix this case. Need to update ACPI HAL to not try to auto-populate tables.
        return toLoad.All

    def parse_arguments(self) -> None:
        parser = ArgumentParser(usage=__doc__)
        subparsers = parser.add_subparsers()
        parser_list = subparsers.add_parser('list')
        parser_list.set_defaults(func=self.acpi_list)

        parser_table = subparsers.add_parser('table')
        parser_table.add_argument('-f', '--file', dest='_file', help='Read from file', action='store_true')
        parser_table.add_argument('_name', metavar='table|filename', nargs=1, help="table to list")
        parser_table.set_defaults(func=self.acpi_table)
        parser.parse_args(self.argv, namespace=self)

    def set_up(self) -> None:
        self._acpi = ACPI(self.cs)

    def acpi_list(self) -> None:
        self.logger.log('[CHIPSEC] Enumerating ACPI tables..')
        self._acpi.print_ACPI_table_list()

    def acpi_table(self) -> None:
        name = self._name[0]
        if not self._file and not self._acpi.is_ACPI_table_present(name):
            self.logger.log_error(f'Please specify table name from {self._acpi.tableList.keys()}')
            return
        elif self._file and not path_exists(name):
            self.logger.log_error(f"[CHIPSEC] Unable to find file '{name}'")
            return
        self.logger.log(f"[CHIPSEC] reading ACPI table {'from file' if self._file else ''} '{name}'")
        self._acpi.dump_ACPI_table(name, self._file)
        return


commands = {'acpi': ACPICommand}
