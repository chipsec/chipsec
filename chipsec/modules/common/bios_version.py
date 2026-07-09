# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2026, Intel Corporation
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

"""
Reads the BIOS version from the SMBIOS table and displays it.

This module locates the SMBIOS entry point, parses the SMBIOS BIOS Information
structure (Type 0), reads the BIOS version (and vendor / release date when
available) and prints it to the user.

Usage:
    ``chipsec_main -m common.bios_version``

Examples:
    >>> chipsec_main.py -m common.bios_version

"""

from typing import List, Optional, Sequence

from chipsec.module_common import BaseModule
from chipsec.library.returncode import ModuleResult
from chipsec.hal.common.smbios import SMBIOS_BIOS_INFO_ENTRY_ID

TAGS = []
METADATA_TAGS = ['OPENSOURCE', 'IA', 'COMMON', 'BIOS_VERSION']


class bios_version(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self) -> bool:
        return True

    def _get_smbios_string(self, strings: Optional[Sequence[str]],
                           string_index: int) -> Optional[str]:
        if not strings or string_index == 0 or string_index > len(strings):
            return None
        value = strings[string_index - 1].strip()
        return value or None

    def get_bios_version(self) -> int:
        smbios = self.cs.hals.smbios
        if not smbios.find_smbios_table():
            self.logger.log_error('Unable to locate SMBIOS table')
            return self.result.getReturnCode(ModuleResult.ERROR)

        bios_entries = smbios.get_decoded_structs(SMBIOS_BIOS_INFO_ENTRY_ID)
        if not bios_entries:
            self.logger.log_error('SMBIOS BIOS Information structure (Type 0) not found')
            return self.result.getReturnCode(ModuleResult.ERROR)

        bios_info = bios_entries[0]
        vendor = self._get_smbios_string(bios_info.strings, bios_info.vendor_str)
        version = self._get_smbios_string(bios_info.strings, bios_info.version_str)
        release_date = self._get_smbios_string(bios_info.strings, bios_info.release_str)

        self.logger.log('[*] BIOS Information (SMBIOS)')
        self.logger.log(f'    Vendor      : {vendor or "Unknown"}')
        self.logger.log(f'    BIOS Version: {version or "Unknown"}')
        self.logger.log(f'    Release Date: {release_date or "Unknown"}')

        self.logger.log_information('BIOS version collected from SMBIOS')
        return self.result.getReturnCode(ModuleResult.INFORMATION)

    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test('BIOS Version (SMBIOS)')
        return self.get_bios_version()
