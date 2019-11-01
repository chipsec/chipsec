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

from chipsec.hal.smbios import SMBIOS, SMBIOS_BIOS_INFO_ENTRY_ID
from chipsec.module_common import BaseModule, ModuleResult

class bios_version(BaseModule):
    def __init__(self):
        super(bios_version, self).__init__()
        self.smbios = SMBIOS(self.cs)

    def is_supported(self):
        # By default we assume the system has SMBIOS structures
        return True

    def run(self, module_argv):
        self.logger.start_test('SMBIOS BIOS Information')
        # Only an informataional module so just set the return result
        self.res = ModuleResult.INFORMATION

        # Attempt to detect the SMBIOS tables
        if not self.smbios.find_smbios_table():
            self.logger.log_information_check('Unable to find SMBIOS tables.')
            return self.res

        # Check to see what tables are available
        if self.smbios.smbios_2_ep is not None:
            self.logger.log_good('Found SMBIOS 2.x (32bit) Entry Point table')
            if self.logger.VERBOSE: self.logger.log(self.smbios.smbios_2_ep)
        if self.smbios.smbios_3_ep is not None:
            self.logger.log_good('Found SMBIOS 3.x (64bit) Entry Point Table')
            if self.logger.VERBOSE: self.logger.log(self.smbios.smbios_3_ep)

        # Get the Type 0 information in decoded format
        structs = self.smbios.get_decoded_structs(SMBIOS_BIOS_INFO_ENTRY_ID)
        if not structs:
            self.logger.log_information_check('Unable to find BIOS Information structure')
            return self.res
        if len(structs) != 1:
            self.logger.log_bad('Should only have one BIOS Information structure (only display first entry)')
        
        # Display the structure
        self.logger.log(structs[0])

        # Exit the module
        self.logger.log_information_check('SMBIOS BIOS Information displayed')

        return self.res
