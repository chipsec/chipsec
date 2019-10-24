#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2018 - 2019, Intel Corporation
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

import struct
from chipsec.module_common import BaseModule, ModuleResult
from chipsec.defines import bytestostring

class cpu_info(BaseModule):
    def __init__(self):
        super(cpu_info, self).__init__()

    def is_supported(self):
        return True

    def run(self, module_argv):
        # Log the start of the test
        self.logger.start_test('Current Processor Information:')
        self.res = ModuleResult.INFORMATION

        # Determine number of threads to check
        thread_count = 1
        if not self.cs.helper.is_efi():
            thread_count = self.cs.msr.get_cpu_thread_count()

        for thread in range(thread_count):
            # Handle processor binding so we are allways checking processor 0
            # for this example.  No need to do this in UEFI Shell.
            if not self.cs.helper.is_efi():
                self.cs.helper.set_affinity(thread)

            # Display thread
            self.logger.log('[*] Thread {:04d}'.format(thread))

            # Get processor brand string
            brand = ''
            for eax_val in [0x80000002, 0x80000003, 0x80000004]:
                regs = self.cs.cpu.cpuid(eax_val, 0)
                for i in range(4):
                    brand += bytestostring(struct.pack('<I', regs[i]))
            self.logger.log('[*] Processor: {}'.format(brand))

            # Get processor version information
            (eax, ebx, ecx, edx) = self.cs.cpu.cpuid(0x01, 0x00)
            stepping = eax & 0xF
            model = (eax >> 4) & 0xF
            family = (eax >> 8) & 0xF
            if family == 0x0F or family == 0x06:
                model = ((eax >> 12) & 0xF0) | model
            if family == 0x0F:
                family = ((eax >> 20) & 0xFF) | family
            self.logger.log('[*]            Family: {:02X} Model: {:02X} Stepping: {:01X}'.format(family, model, stepping))

            # Get microcode revision
            microcode_rev = self.cs.read_register_field('IA32_BIOS_SIGN_ID', 'Microcode', cpu_thread=thread)
            self.logger.log('[*]            Microcode: {:08X}'.format(microcode_rev))
            self.logger.log('[*]')

        self.logger.log_information_check('Processor information displayed')
        return self.res
