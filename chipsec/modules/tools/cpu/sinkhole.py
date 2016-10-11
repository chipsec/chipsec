#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2016, Intel Corporation
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

"""
This module checks if CPU is affected by 'The SMM memory sinkhole' vulnerability by Christopher Domas

NOTE: The system may hang when running this test. In that case, the mitigation to this issue is likely working but we may not be handling the exception generated.

References:
The Memory Sinkhole `(presentation) <https://www.blackhat.com/docs/us-15/materials/us-15-Domas-The-Memory-Sinkhole-Unleashing-An-x86-Design-Flaw-Allowing-Universal-Privilege-Escalation.pdf>`_, `(whitepaper) <https://www.blackhat.com/docs/us-15/materials/us-15-Domas-The-Memory-Sinkhole-Unleashing-An-x86-Design-Flaw-Allowing-Universal-Privilege-Escalation-wp.pdf>`_ by Christopher Domas
"""

from chipsec.module_common import *
import chipsec.hal.cpu
import chipsec.helper.oshelper

TAGS = [MTAG_SMM]

class sinkhole(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self._cpu = chipsec.hal.cpu.CPU( self.cs )


    def is_supported(self):
        # @TODO: Currently this module doesn't work properly on (U)EFI
        return (self.cs.helper.is_windows() or self.cs.helper.is_linux())

    def check_LAPIC_SMRR_overlap( self ):
        if not chipsec.chipset.is_register_defined( self.cs, 'IA32_APIC_BASE' ) or \
           not chipsec.chipset.is_register_defined( self.cs, 'IA32_SMRR_PHYSBASE' ) or \
           not chipsec.chipset.is_register_defined( self.cs, 'IA32_SMRR_PHYSMASK' ):
            self.logger.error( "Couldn't find definition of required configuration registers" )
            return ModuleResult.ERROR

        if self._cpu.check_SMRR_supported():
            self.logger.log_good( "SMRR range protection is supported" )
        else:
            self.logger.log_skipped_check("CPU does not support SMRR range protection of SMRAM")
            return ModuleResult.SKIPPED

        smrr_physbase_msr = chipsec.chipset.read_register( self.cs, 'IA32_SMRR_PHYSBASE', 0 )
        apic_base_msr     = chipsec.chipset.read_register( self.cs, 'IA32_APIC_BASE', 0 )
        chipsec.chipset.print_register( self.cs, 'IA32_APIC_BASE', apic_base_msr )
        chipsec.chipset.print_register( self.cs, 'IA32_SMRR_PHYSBASE', smrr_physbase_msr )

        smrrbase  = chipsec.chipset.get_register_field( self.cs, 'IA32_SMRR_PHYSBASE', smrr_physbase_msr, 'PhysBase' )
        smrr_base = chipsec.chipset.get_register_field( self.cs, 'IA32_SMRR_PHYSBASE', smrr_physbase_msr, 'PhysBase', True )
        apicbase  = chipsec.chipset.get_register_field( self.cs, 'IA32_APIC_BASE', apic_base_msr, 'APICBase' )
        apic_base = chipsec.chipset.get_register_field( self.cs, 'IA32_APIC_BASE', apic_base_msr, 'APICBase', True )

        self.logger.log( "[*] Local APIC Base: 0x%016X" % apic_base )
        self.logger.log( "[*] SMRR Base      : 0x%016X" % smrr_base )

        self.logger.log( "[*] Attempting to overlap Local APIC page with SMRR region" )
        self.logger.log( "    writing 0x%X to IA32_APIC_BASE[APICBase].." % smrrbase )
        self.logger.log_important( "NOTE: The system may hang or process may crash when running this test. In that case, the mitigation to this issue is likely working but we may not be handling the exception generated.")
        try:
            chipsec.chipset.write_register_field( self.cs, 'IA32_APIC_BASE', 'APICBase', smrrbase, preserve_field_position=False, cpu_thread=0 )
            ex = False
            self.logger.log_bad( "Was able to modify IA32_APIC_BASE" )
        except chipsec.helper.oshelper.HWAccessViolationError:
            ex = True
            self.logger.log_good( "Could not modify IA32_APIC_BASE" )

        apic_base_msr_new = chipsec.chipset.read_register( self.cs, 'IA32_APIC_BASE', 0 )
        self.logger.log( "[*] new IA32_APIC_BASE: 0x%016X" % apic_base_msr_new )
        #chipsec.chipset.print_register( self.cs, 'IA32_APIC_BASE', apic_base_msr_new )
        
        if apic_base_msr_new == apic_base_msr and ex:
            res = ModuleResult.PASSED
            self.logger.log_passed_check( "CPU does not seem to have SMM memory sinkhole vulnerability" )
        else:
            chipsec.chipset.write_register( self.cs, 'IA32_APIC_BASE', apic_base_msr, 0 )
            self.logger.log( "[*] Restored original value 0x%016X" % apic_base_msr )
            res = ModuleResult.FAILED
            self.logger.log_failed_check( "CPU is succeptible to SMM memory sinkhole vulnerability" )

        return res

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        self.logger.start_test( "x86 SMM Memory Sinkhole" )
        return self.check_LAPIC_SMRR_overlap()
        