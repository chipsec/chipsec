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
>>> chipsec_util acpi mmio-regions

Examples:

>>> chipsec_util acpi list
>>> chipsec_util acpi table XSDT
>>> chipsec_util acpi table acpi_table.bin
>>> chipsec_util acpi mmio-regions
>>> chipsec_util acpi mmio-regions --space systemmemory
"""

from os.path import exists as path_exists
from argparse import ArgumentParser

from chipsec.hal.common.acpi import ACPI
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
        
        parser_mmio = subparsers.add_parser('mmio-regions')
        parser_mmio.add_argument('--space', dest='_space', default='systemmemory', 
                                help='Filter by space type: systemmemory, systemio, all (default: systemmemory)')
        parser_mmio.add_argument('--json', dest='_json', action='store_true', help='Output as JSON')
        parser_mmio.set_defaults(func=self.acpi_mmio_regions)
        
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

    def acpi_mmio_regions(self) -> None:
        """List ACPI OperationRegion definitions."""
        space_filter = getattr(self, '_space', 'systemmemory').lower()
        use_json = getattr(self, '_json', False)
        
        regions = self._acpi.list_operation_regions()
        
        if not regions:
            self.logger.log('[CHIPSEC] No OperationRegions found in DSDT/SSDTs')
            return
        
        # Filter by space type
        filtered = []
        if space_filter == 'all':
            filtered = regions
        else:
            space_map = {
                'systemmemory': 'SystemMemory',
                'systemio': 'SystemIO',
                'pci': 'PCI_Config',
                'ec': 'EC'
            }
            target_space = space_map.get(space_filter, 'SystemMemory')
            filtered = [r for r in regions if r['space_type_name'] == target_space]
        
        if not filtered:
            self.logger.log(f'[CHIPSEC] No {space_filter} regions found')
            return
        
        self.logger.log(f'[CHIPSEC] Found {len(filtered)} {space_filter} OperationRegions')
        
        if use_json:
            import json
            self.logger.log(json.dumps(filtered, indent=2, default=str))
        else:
            # Pretty table output
            self.logger.log('[CHIPSEC] ACPI OperationRegions:')
            self.logger.log('=' * 90)
            self.logger.log(f"{'NAME':<16} {'SPACE':<18} {'BASE':>12} {'SIZE':>12} {'END':>12}")
            self.logger.log('-' * 90)
            
            for region in sorted(filtered, key=lambda x: x['base']):
                name = region['name'][:15]
                space = region['space_type_name'][:17]
                base = region['base']
                length = region['length']
                end = base + length - 1
                
                self.logger.log(f"{name:<16} {space:<18} 0x{base:010X} 0x{length:010X} 0x{end:010X}")
            
            self.logger.log('=' * 90)


commands = {'acpi': ACPICommand}
