# -*- coding: utf-8 -*-
# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2021, SentinelOne
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
See <https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-uefi-wsmt> for more details.
"""
import platform

from chipsec.module_common   import BaseModule, ModuleResult, MTAG_BIOS, MTAG_SMM
from chipsec.hal.acpi        import ACPI
from chipsec.hal.acpi_tables import WSMT

TAGS = [MTAG_BIOS, MTAG_SMM]

class wsmt(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        # Only supported by Windows at the moment.
        if "windows" == platform.system().lower():
            return True
        return False

    def check_wsmt(self):
        self.logger.start_test( "WSMT Configuration" )

        try:
            acpi = ACPI(self.cs)
            table_data = acpi.get_ACPI_table("WSMT")[0][1]
        except IndexError:
            # No WSMT table
            self.logger.warn( """WSMT table was not found.
Manual analysis of SMI handlers is required to determine if they can be abused by attackers to circumvent VBS""" )
            return ModuleResult.WARNING

        wsmt_table = WSMT()
        wsmt_table.parse(table_data)
        self.logger.log(wsmt_table)

        if (not wsmt_table.fixed_comm_buffers) or (not wsmt_table.comm_buffer_nested_ptr_protection) or (not wsmt_table.system_resource_protection):
            self.logger.warn( """WSMT table is present but certain mitigations are missing.
Manual analysis of SMI handlers is required to determine if they can be abused by attackers to circumvent VBS""" )
            return ModuleResult.WARNING

        self.logger.log_passed( "WSMT table is present and reports all supported mitigations" )
        return ModuleResult.PASSED

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        self.res = self.check_wsmt()
        return self.res
