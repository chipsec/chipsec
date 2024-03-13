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
Command-line utility providing access to IOMMU engines

>>> chipsec_util iommu list
>>> chipsec_util iommu config [iommu_engine]
>>> chipsec_util iommu status [iommu_engine]
>>> chipsec_util iommu enable|disable <iommu_engine>
>>> chipsec_util iommu pt

Examples:

>>> chipsec_util iommu list
>>> chipsec_util iommu config VTD
>>> chipsec_util iommu status GFXVTD
>>> chipsec_util iommu enable VTD
>>> chipsec_util iommu pt
"""

from chipsec.command import BaseCommand, toLoad
from chipsec.hal import acpi, iommu
from argparse import ArgumentParser
from chipsec.library.exceptions import IOMMUError, AcpiRuntimeError


# I/O Memory Management Unit (IOMMU), e.g. Intel VT-d
class IOMMUCommand(BaseCommand):

    def requirements(self) -> toLoad:
        return toLoad.All

    def parse_arguments(self) -> None:
        parser = ArgumentParser(prog='chipsec_util iommu', usage=__doc__)
        subparsers = parser.add_subparsers()

        parser_list = subparsers.add_parser('list')
        parser_list.set_defaults(func=self.iommu_list)

        parser_config = subparsers.add_parser('config')
        parser_config.add_argument('engine', type=str, default='', nargs='?', help='IOMMU Engine')
        parser_config.set_defaults(func=self.iommu_config)

        parser_status = subparsers.add_parser('status')
        parser_status.add_argument('engine', type=str, default='', nargs='?', help='IOMMU Engine')
        parser_status.set_defaults(func=self.iommu_status)

        parser_enable = subparsers.add_parser('enable')
        parser_enable.add_argument('engine', type=str, help='IOMMU Engine')
        parser_enable.set_defaults(func=self.iommu_enable)

        parser_disable = subparsers.add_parser('disable')
        parser_disable.add_argument('engine', type=str, help='IOMMU Engine')
        parser_disable.set_defaults(func=self.iommu_disable)

        parser_pt = subparsers.add_parser('pt')
        parser_pt.add_argument('engine', type=str, default='', nargs='?', help='IOMMU Engine')
        parser_pt.set_defaults(func=self.iommu_pt)

        parser.parse_args(self.argv, namespace=self)

    def iommu_list(self) -> None:
        self.logger.log("[CHIPSEC] Enumerating supported IOMMU engine names:")
        self.logger.log(f'{list(iommu.IOMMU_ENGINES.keys())}')
        self.logger.log_important('\nNote: These are the IOMMU engine names supported by iommu_cmd.')
        self.logger.log_important('It does not mean they are supported/enabled in the current platform.')

    def iommu_engine(self, cmd) -> None:
        try:
            _iommu = iommu.IOMMU(self.cs)
        except IOMMUError as msg:
            print(msg)
            return

        if self.engine:
            if self.engine in iommu.IOMMU_ENGINES.keys():
                _iommu_engines = [self.engine]
            else:
                self.logger.log_error(f'IOMMU name \'{self.engine}\' not recognized. Run \'iommu list\' command for supported IOMMU names')
                return
        else:
            _iommu_engines = iommu.IOMMU_ENGINES.keys()

        if 'config' == cmd:
            try:
                _acpi = acpi.ACPI(self.cs)
            except AcpiRuntimeError as msg:
                print(msg)
                return

            if _acpi.is_ACPI_table_present(acpi.ACPI_TABLE_SIG_DMAR):
                self.logger.log("[CHIPSEC] Dumping contents of DMAR ACPI table..\n")
                _acpi.dump_ACPI_table(acpi.ACPI_TABLE_SIG_DMAR)
            else:
                self.logger.log("[CHIPSEC] Couldn't find DMAR ACPI table\n")

        for e in _iommu_engines:
            if (cmd == 'config'):
                _iommu.dump_IOMMU_configuration(e)
            elif (cmd == 'pt'):
                _iommu.dump_IOMMU_page_tables(e)
            elif (cmd == 'status'):
                _iommu.dump_IOMMU_status(e)
            elif (cmd == 'enable'):
                _iommu.set_IOMMU_Translation(e, 1)
            elif (cmd == 'disable'):
                _iommu.set_IOMMU_Translation(e, 0)

    def iommu_config(self) -> None:
        self.iommu_engine('config')

    def iommu_status(self) -> None:
        self.iommu_engine('status')

    def iommu_enable(self) -> None:
        self.iommu_engine('enable')

    def iommu_disable(self) -> None:
        self.iommu_engine('disable')

    def iommu_pt(self) -> None:
        self.iommu_engine('pt')

    def run(self) -> None:
        self.func()


commands = {'iommu': IOMMUCommand}
