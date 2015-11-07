#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2015, Intel Corporation
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



# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
# (c) 2010-2012 Intel Corporation
#
# -------------------------------------------------------------------------------

"""
CPU related functionality

"""

__version__ = '1.0'

import struct
import sys
import os.path

from collections import namedtuple
from chipsec.logger import logger
import chipsec.hal.acpi


class CPURuntimeError (RuntimeError):
    pass

########################################################################################################
#
# CORES HAL Component
#
########################################################################################################

class CPU:
    def __init__( self, cs ):
        self.helper = cs.helper
        self.cs     = cs
        
    def read_cr(self, cpu_thread_id, cr_number ):
        value = self.helper.read_cr( cpu_thread_id, cr_number )
        if logger().HAL: logger().log( "[cpu%d] read CR%d: value = 0x%08X" % (cpu_thread_id, cr_number, value) )
        return value

    def write_cr(self, cpu_thread_id, cr_number, value ):
        if logger().HAL: logger().log( "[cpu%d] write CR%d: value = 0x%08X" % (cpu_thread_id, cr_number, value) )
        status = self.helper.write_cr( cpu_thread_id, cr_number, value )
        return status

    def cpuid(self, eax, ecx ):
        if logger().HAL: logger().log( "[cpu] CPUID in : EAX=0x%08X, ECX=0x%08X" % (eax, ecx) )
        (eax, ebx, ecx, edx) = self.cs.cpuid.cpuid( eax, ecx )
        if logger().HAL: logger().log( "[cpu] CPUID out: EAX=0x%08X, EBX=0x%08X, ECX=0x%08X, EDX=0x%08X" % (eax, ebx, ecx, edx) )
        return (eax, ebx, ecx, edx)

    # Using CPUID we can determine if Hyper-Threading is enabled in the CPU
    def is_HT_active(self):
        logical_processor_per_core=self.get_number_logical_processor_per_core()
        return (True if (logical_processor_per_core>1) else False) 
    
    # Using the CPUID we determine the number of logical processors per core
    def get_number_logical_processor_per_core(self):
        (eax, ebx, ecx, edx)=self.cpuid( 0x0b, 0x0 )
        return ebx
    
    # Using CPUID we can determine the number of logical processors per package
    def get_number_logical_processor_per_package(self):
        (eax, ebx, ecx, edx)=self.cpuid( 0x0b, 0x1 )
        return ebx
    
    # Using CPUID we can determine the number of physical processors per package
    def get_number_physical_processor_per_package(self):
        logical_processor_per_core=self.get_number_logical_processor_per_core()
        logical_processor_per_package=self.get_number_logical_processor_per_package()
        return (logical_processor_per_package/logical_processor_per_core)
    
    # determine number of logical processors in the core
    def get_number_threads_from_APIC_table(self):
        _acpi = chipsec.hal.acpi.ACPI( self.cs )    
        dACPIID = {}
        (table_header,APIC_object,table_header_blob,table_blob) = _acpi.get_parse_ACPI_table( chipsec.hal.acpi.ACPI_TABLE_SIG_APIC )
        for structure in APIC_object.apic_structs:
            if 0x00 == structure.Type:
                if dACPIID.has_key( structure.APICID ) == False:
                    if 1 == structure.Flags:
                        dACPIID[ structure.APICID ] = structure.ACPIProcID
        return len( dACPIID )
    
    # determine number of physical sockets using the CPUID and APIC ACPI table
    def get_number_sockets_from_APIC_table(self):
        number_threads=self.get_number_threads_from_APIC_table()
        logical_processor_per_package=self.get_number_logical_processor_per_package()
        return (number_threads/logical_processor_per_package)

    #
    # Return SMRR MSR physical base and mask
    #
    def get_SMRR( self ):
        smrambase = chipsec.chipset.read_register_field( self.cs, 'IA32_SMRR_PHYSBASE', 'PhysBase', True )
        smrrmask  = chipsec.chipset.read_register_field( self.cs, 'IA32_SMRR_PHYSMASK', 'PhysMask', True )
        return (smrambase, smrrmask)

    #
    # Return SMRAM region base, limit and size as defined by SMRR
    #
    def get_SMRR_SMRAM( self ):
        (smram_base, smrrmask) = self.get_SMRR()
        smram_base &= smrrmask
        smram_size = ((~smrrmask)&0xFFFFFFFF) + 1
        smram_limit = smram_base + smram_size - 1
        return (smram_base, smram_limit, smram_size)

    #
    # Returns TSEG base, limit and size
    #
    def get_TSEG( self ):
        if self.cs.is_server():
            # tseg register has base and limit
            tseg_base  = chipsec.chipset.read_register_field( self.cs, 'TSEG_BASE',  'base',  preserve_field_position=True ) 
            tseg_limit = chipsec.chipset.read_register_field( self.cs, 'TSEG_LIMIT', 'limit', preserve_field_position=True )
            tseg_limit += 0xFFFFF
        else:
            # TSEG base is in TSEGMB, TSEG limit is BGSM - 1
            tseg_base  = chipsec.chipset.read_register_field( self.cs, 'PCI0.0.0_TSEGMB', 'TSEGMB', preserve_field_position=True )
            bgsm       = chipsec.chipset.read_register_field( self.cs, 'PCI0.0.0_BGSM', 'BGSM', preserve_field_position=True )
            tseg_limit =  bgsm - 1 
            
        tseg_size = tseg_limit - tseg_base + 1
        return (tseg_base, tseg_limit, tseg_size)

    #
    # Returns SMRAM base from either SMRR MSR or TSEG PCIe config register
    #
    def get_SMRAM( self ):
        smram_base = None
        try:
            (smram_base, smram_limit, smram_size) = self.get_SMRR_SMRAM()
        except:
            pass

        if smram_base is None:
            try:
                (smram_base, smram_limit, smram_size) = self.get_TSEG()
            except:
                pass
        return (smram_base, smram_limit, smram_size)

    #
    # Check that SMRR is supported by CPU in IA32_MTRRCAP_MSR[SMRR]
    #
    def check_SMRR_supported( self ):
        mtrrcap_msr_reg = chipsec.chipset.read_register( self.cs, 'MTRRCAP' )
        if logger().VERBOSE: chipsec.chipset.print_register( self.cs, 'MTRRCAP', mtrrcap_msr_reg )
        smrr = chipsec.chipset.get_register_field( self.cs, 'MTRRCAP', mtrrcap_msr_reg, 'SMRR' )
        return (1 == smrr)
    