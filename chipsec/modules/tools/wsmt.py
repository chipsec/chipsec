# -*- coding: utf-8 -*-
# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2021, SentinelOne
# Copyright (c) 2021, Intel Corporation
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

"""
The Windows SMM Security Mitigation Table (WSMT) is an ACPI table defined by Microsoft that allows
system firmware to confirm to the operating system that certain security best practices have been
implemented in System Management Mode (SMM) software.

Reference:
    - See <https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-uefi-wsmt> for more details.

Usage:
    ``chipsec_main -m common.wsmt``

Examples:
    >>> chipsec_main.py -m common.wsmt

.. note::
    - Analysis is only necessary if Windows is the primary OS

"""
from chipsec.module_common import BaseModule, MTAG_BIOS, MTAG_SMM
from chipsec.library.returncode import ModuleResult
from chipsec.hal.acpi import ACPI
from chipsec.hal.acpi_tables import WSMT

TAGS = [MTAG_BIOS, MTAG_SMM]


class wsmt(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
        self._acpi = ACPI(self.cs)

    def is_supported(self):
        return True

    def check_wsmt(self):
        table_data = self._acpi.get_ACPI_table('WSMT')
        if not table_data:
            self.logger.log_warning('WSMT table was not found.')
            self.result.setStatusBit(self.result.status.UNSUPPORTED_FEATURE)
            return self.result.getReturnCode(ModuleResult.WARNING)

        wsmt_table = WSMT()
        try:
            wsmt_table.parse(table_data[0][1])
        except TypeError:
            self.logger.log_error('Issue parsing the WSMT table data.')
            self.result.setStatusBit(self.result.status.PARSE_ISSUE)
            return self.result.getReturnCode(ModuleResult.ERROR)

        self.logger.log(wsmt_table)

        if (not wsmt_table.fixed_comm_buffers) or (not wsmt_table.comm_buffer_nested_ptr_protection) or (not wsmt_table.system_resource_protection):
            self.logger.log_warning('WSMT table is present but certain mitigations are missing.')
            self.result.setStatusBit(self.result.status.MITIGATION)
            self.res = self.result.getReturnCode(ModuleResult.WARNING)
        else:
            self.logger.log_passed('WSMT table is present and reports all supported mitigations.')
            self.result.setStatusBit(self.result.status.SUCCESS)
            self.res = self.result.getReturnCode(ModuleResult.PASSED)

    def run(self, module_argv):
        self.logger.start_test('WSMT Configuration')
        self.check_wsmt()
        if self.res == ModuleResult.WARNING:
            self.logger.log_important('Manual analysis of SMI handlers is required to determine if they can be abused by attackers to circumvent VBS.')
        return self.res
