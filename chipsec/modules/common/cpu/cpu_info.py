# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2018 - 2021, Intel Corporation
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
Displays CPU information

Reference:
    - Intel 64 and IA-32 Architectures Software Developer Manual (SDM)
        - https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html

Usage:
    ``chipsec_main -m common.cpu.cpu_info``

Examples:
    >>> chipsec_main.py -m common.cpu.cpu_info

Registers used:
    - IA32_BIOS_SIGN_ID.Microcode

.. note:
    No PASS/FAIL returned, INFORMATION only.

"""

import struct
from chipsec.module_common import BaseModule
from chipsec.library.returncode import ModuleResult
from chipsec.library.defines import bytestostring
from typing import List

class cpu_info(BaseModule):
    def __init__(self):
        super(cpu_info, self).__init__()
        self.result.url ='https://chipsec.github.io/modules/chipsec.modules.common.cpu.cpu_info.html'

    def is_supported(self) -> bool:
        if self.cs.register.has_field('IA32_BIOS_SIGN_ID', 'Microcode'):
            return True
        self.logger.log_important('IA32_BIOS_SIGN_ID.Microcode not defined for platform.  Skipping module.')
        return False

    def run(self, module_argv: List[str]) -> int:
        # Log the start of the test
        self.logger.start_test('Current Processor Information:')

        # Determine number of threads to check
        thread_count = 1
        if not self.cs.os_helper.is_efi():
            thread_count = self.cs.msr.get_cpu_thread_count()

        for thread in range(thread_count):
            # Handle processor binding so we are always checking processor 0
            # for this example.  No need to do this in UEFI Shell.
            if not self.cs.os_helper.is_efi():
                self.cs.helper.set_affinity(thread)

            # Display thread
            self.logger.log(f'[*] Thread {thread:04d}')

            # Get processor brand string
            brand = ''
            for eax_val in [0x80000002, 0x80000003, 0x80000004]:
                regs = self.cs.cpu.cpuid(eax_val, 0)
                for i in range(4):
                    brand += bytestostring(struct.pack('<I', regs[i]))
            brand = brand.rstrip('\x00')
            self.logger.log(f'[*] Processor: {brand}')

            # Get processor version information
            (eax, _, _, _) = self.cs.cpu.cpuid(0x01, 0x00)
            stepping = eax & 0xF
            model = (eax >> 4) & 0xF
            family = (eax >> 8) & 0xF
            if (family == 0x0F) or (family == 0x06):
                model = ((eax >> 12) & 0xF0) | model
            if family == 0x0F:
                family = ((eax >> 20) & 0xFF) | family
            self.logger.log(f'[*]            Family: {family:02X} Model: {model:02X} Stepping: {stepping:01X}')

            # Get microcode revision
            microcode_rev = self.cs.register.read_field('IA32_BIOS_SIGN_ID', 'Microcode', cpu_thread=thread)
            self.logger.log(f'[*]            Microcode: {microcode_rev:08X}')
            self.logger.log('[*]')

        self.logger.log_information('Processor information displayed')
        
        self.result.setStatusBit(self.result.status.INFORMATION)
        return self.result.getReturnCode(ModuleResult.INFORMATION)


