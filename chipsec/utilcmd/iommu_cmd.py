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
from chipsec.hal.common import acpi, iommu
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
        """List discovered IOMMU engines from DMAR table."""
        self.logger.log("[CHIPSEC] Discovering IOMMU engines from DMAR table:")
        try:
            _iommu = iommu.IOMMU(self.cs)
            _iommu.initialize()
            engine_desc = _iommu.get_engine_descriptions()
            if engine_desc:
                self.logger.log(f'\nDiscovered {len(engine_desc)} VT-d engines:')
                for eng, base, label in engine_desc:
                    suffix = f' [{label}]' if label else ''
                    self.logger.log(f'  {eng}: 0x{base:016X}{suffix}')
                if _iommu.rmrrs:
                    self.logger.log(f'RMRR entries             : {len(_iommu.rmrrs)}')
                    for line in _iommu.describe_rmrr():
                        self.logger.log_verbose(line)
                if _iommu.atsrs:
                    self.logger.log(f'ATSR entries             : {len(_iommu.atsrs)}')
                    for line in _iommu.describe_atsr():
                        self.logger.log_verbose(line)
            else:
                self.logger.log('\nNo VT-d engines discovered in DMAR table.')
        except Exception as e:
            self.logger.log_error(f'Failed to discover engines: {e}')

    def iommu_engine(self, cmd) -> None:
        try:
            _iommu = iommu.IOMMU(self.cs)
            _iommu.initialize()
        except IOMMUError as msg:
            self.logger.log(msg)
            return

        if self.engine:
            discovered = _iommu.get_discovered_engines()
            if self.engine in discovered:
                _iommu_engines = [self.engine]
            else:
                self.logger.log_error(f'IOMMU name \'{self.engine}\' not recognized.')
                self.logger.log(f'Discovered engines: {discovered}')
                return
        else:
            _iommu_engines = _iommu.get_discovered_engines()
            if not _iommu_engines:
                self.logger.log('No IOMMU engines discovered; nothing to do.')
                return

        if 'config' == cmd:
            try:
                _acpi = acpi.ACPI(self.cs)
            except AcpiRuntimeError as msg:
                self.logger.log(msg)
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
