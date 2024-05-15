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
This module checks if CPU is affected by 'The SMM memory sinkhole' vulnerability

References:
    - `Memory Sinkhole presentation by Christopher Domas <https://www.blackhat.com/docs/us-15/materials/us-15-Domas-The-Memory-Sinkhole-Unleashing-An-x86-Design-Flaw-Allowing-Universal-Privilege-Escalation.pdf>`_
    - `Memory Sinkhole whitepaper <https://www.blackhat.com/docs/us-15/materials/us-15-Domas-The-Memory-Sinkhole-Unleashing-An-x86-Design-Flaw-Allowing-Universal-Privilege-Escalation-wp.pdf>`_

Usage:
    ``chipsec_main -m tools.cpu.sinkhole``

Examples:
    >>> chipsec_main.py -m tools.cpu.sinkhole

Registers used:
    - IA32_APIC_BASE.APICBase
    - IA32_SMRR_PHYSBASE.PhysBase
    - IA32_SMRR_PHYSMASK

.. note::
    - Supported OS: Windows or Linux

.. warning::
    - The system may hang when running this test.
    - In that case, the mitigation to this issue is likely working but we may not be handling the exception generated.

"""

from chipsec.module_common import BaseModule, MTAG_SMM
from chipsec.library.returncode import ModuleResult


TAGS = [MTAG_SMM]


class sinkhole(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        if not (self.cs.os_helper.is_windows() or self.cs.os_helper.is_linux()):
            self.logger.log_important('Unsupported OS found.  Skipping module.')
            self.logger.log_important('Supported OS: Windows or Linux')
            return False
        elif not self.cs.register.is_defined('IA32_APIC_BASE') or \
                not self.cs.register.is_defined('IA32_SMRR_PHYSBASE') or \
                not self.cs.register.is_defined('IA32_SMRR_PHYSMASK'):
            self.logger.log_error("Couldn't find definition of required configuration registers.")
            return False
        else:
            return True

    def check_LAPIC_SMRR_overlap(self):
        smrr_physbase_msr = self.cs.register.read('IA32_SMRR_PHYSBASE', 0)
        apic_base_msr = self.cs.register.read('IA32_APIC_BASE', 0)
        self.cs.register.print('IA32_APIC_BASE', apic_base_msr)
        self.cs.register.print('IA32_SMRR_PHYSBASE', smrr_physbase_msr)

        smrrbase = self.cs.register.get_field('IA32_SMRR_PHYSBASE', smrr_physbase_msr, 'PhysBase')
        smrr_base = self.cs.register.get_field('IA32_SMRR_PHYSBASE', smrr_physbase_msr, 'PhysBase', True)
        apic_base = self.cs.register.get_field('IA32_APIC_BASE', apic_base_msr, 'APICBase', True)

        self.logger.log(f'[*] Local APIC Base: 0x{apic_base:016X}')
        self.logger.log(f'[*] SMRR Base      : 0x{smrr_base:016X}')

        self.logger.log('[*] Attempting to overlap Local APIC page with SMRR region')
        self.logger.log(f'   Writing 0x{smrrbase:X} to IA32_APIC_BASE[APICBase]..')
        self.logger.log_important('NOTE: The system may hang or process may crash when running this test.')
        self.logger.log('      In that case, the mitigation to this issue is likely working but we may not be handling the exception generated.')

        res = self.cs.register.write_field('IA32_APIC_BASE', 'APICBase', smrrbase, preserve_field_position=False, cpu_thread=0)

        if res is None:
            self.logger.log_important('Error encountered when attempting to modify IA32_APIC_BASE')

        apic_base_msr_new = self.cs.register.read('IA32_APIC_BASE', 0)
        self.logger.log(f'[*] New IA32_APIC_BASE: 0x{apic_base_msr_new:016X}')

        if apic_base_msr_new == apic_base_msr:
            self.logger.log_good('Could not modify IA32_APIC_BASE to overlap SMRR')
            self.logger.log_passed('CPU does not seem to have SMM memory sinkhole vulnerability')
            self.result.setStatusBit(self.result.status.SUCCESS)
            res = ModuleResult.PASSED
        else:
            self.logger.log_bad('Could modify IA32_APIC_BASE to overlap SMRR')
            self.cs.register.write('IA32_APIC_BASE', apic_base_msr, 0)
            self.logger.log(f'[*] Restored original value 0x{apic_base_msr:016X}')
            self.logger.log_failed('CPU is susceptible to SMM memory sinkhole vulnerability.  Verify that SMRR is programmed correctly.')
            self.result.setStatusBit(self.result.status.PROTECTION)
            res = ModuleResult.FAILED

        return self.result.getReturnCode(res)

    def run(self, module_argv):
        self.logger.start_test('x86 SMM Memory Sinkhole')

        if self.cs.cpu.check_SMRR_supported():
            self.logger.log_good('SMRR range protection is supported')
            self.res = self.check_LAPIC_SMRR_overlap()
        else:
            self.logger.log_important('CPU does not support SMRR range protection of SMRAM.  Skipping module.')
            self.result.setStatusBit(self.result.status.NOT_APPLICABLE)
            self.res = self.result.getReturnCode(ModuleResult.NOTAPPLICABLE)
        
        return self.res