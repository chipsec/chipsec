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
Access to CPU resources (for each CPU thread): Model Specific Registers (MSR), IDT/GDT

usage:
    >>> read_msr( 0x8B )
    >>> write_msr( 0x79, 0x12345678 )
    >>> get_IDTR( 0 )
    >>> get_GDTR( 0 )
    >>> dump_Descriptor_Table( 0, DESCRIPTOR_TABLE_CODE_IDTR )
    >>> IDT( 0 )
    >>> GDT( 0 )
    >>> IDT_all()
    >>> GDT_all()
"""

__version__ = '1.0'

import struct
import sys
import os

from chipsec.logger import logger, print_buffer
from chipsec.cfg.common import *


DESCRIPTOR_TABLE_CODE_IDTR = 0
DESCRIPTOR_TABLE_CODE_GDTR = 1
DESCRIPTOR_TABLE_CODE_LDTR = 2

class MsrRuntimeError (RuntimeError):
    pass

class Msr:

    def __init__( self, cs ):
        self.helper = cs.helper
        self.cs = cs

    def get_cpu_thread_count( self ):
        thread_count = self.helper.get_threads_count()
        if thread_count is None or thread_count < 0:
            if logger().VERBOSE: logger().log( "helper.get_threads_count didn't return anything. Reading MSR 0x35 to find out number of logical CPUs (use CPUID Leaf B instead?)" )
            (core_thread_count, dummy) = self.helper.read_msr( 0, Cfg.IA32_MSR_CORE_THREAD_COUNT )
            thread_count = (core_thread_count & Cfg.IA32_MSR_CORE_THREAD_COUNT_THREADCOUNT_MASK)

        if 0 == thread_count: thread_count = 1
        if logger().VERBOSE: logger().log( "[cpu] # of logical CPUs: %d" % thread_count )
        return thread_count

    # @TODO: fix
    def get_cpu_core_count( self ):
        (core_thread_count, dummy) = self.helper.read_msr( 0, Cfg.IA32_MSR_CORE_THREAD_COUNT )
        return ((core_thread_count & Cfg.IA32_MSR_CORE_THREAD_COUNT_CORECOUNT_MASK) >> 16)


##########################################################################################################
#
# Read/Write CPU MSRs
#
##########################################################################################################

    def read_msr( self, cpu_thread_id, msr_addr ):
        (eax, edx) = self.helper.read_msr( cpu_thread_id, msr_addr )
        if logger().VERBOSE: logger().log( "[cpu%d] RDMSR( 0x%x ): EAX = 0x%08X, EDX = 0x%08X" % (cpu_thread_id, msr_addr, eax, edx) )
        return (eax, edx)

    def write_msr( self, cpu_thread_id, msr_addr, eax, edx ):
        self.helper.write_msr( cpu_thread_id, msr_addr, eax, edx )
        if logger().VERBOSE: logger().log( "[cpu%d] WRMSR( 0x%x ): EAX = 0x%08X, EDX = 0x%08X" % (cpu_thread_id, msr_addr, eax, edx) )
        return

##########################################################################################################
#
# Get CPU Descriptor Table Registers (IDTR, GDTR, LDTR..)
#
##########################################################################################################

    def get_Desc_Table_Register( self, cpu_thread_id, code ):
        return self.helper.get_descriptor_table( cpu_thread_id, code )

    def get_IDTR( self, cpu_thread_id ):
        (limit,base,pa) = self.get_Desc_Table_Register( cpu_thread_id, DESCRIPTOR_TABLE_CODE_IDTR )
        if logger().VERBOSE:
            logger().log( "[cpu%d] IDTR Limit = 0x%04X, Base = 0x%016X, Physical Address = 0x%016X" % (cpu_thread_id,limit,base,pa) )
        return (limit,base,pa)

    def get_GDTR( self, cpu_thread_id ):
        (limit,base,pa) = self.get_Desc_Table_Register( cpu_thread_id, DESCRIPTOR_TABLE_CODE_GDTR )
        if logger().VERBOSE:
            logger().log( "[cpu%d] GDTR Limit = 0x%04X, Base = 0x%016X, Physical Address = 0x%016X" % (cpu_thread_id,limit,base,pa) )
        return (limit,base,pa)

    def get_LDTR( self, cpu_thread_id ):
        (limit,base,pa) = self.get_Desc_Table_Register( cpu_thread_id, DESCRIPTOR_TABLE_CODE_LDTR )
        if logger().VERBOSE:
            logger().log( "[cpu%d] LDTR Limit = 0x%04X, Base = 0x%016X, Physical Address = 0x%016X" % (cpu_thread_id,limit,base,pa) )
        return (limit,base,pa)


##########################################################################################################
#
# Dump CPU Descriptor Tables (IDT, GDT, LDT..)
#
##########################################################################################################

    def dump_Descriptor_Table( self, cpu_thread_id, code, num_entries=None ):
        (limit,base,pa) = self.helper.get_descriptor_table( cpu_thread_id, code )
        dt = self.helper.read_physical_mem( pa, limit + 1 )
        total_num = len(dt)/16
        if (total_num < num_entries) or (num_entries is None):
            num_entries = total_num
        logger().log( '[cpu%d] Physical Address: 0x%016X' % (cpu_thread_id,pa) )
        logger().log( '[cpu%d] # of entries    : %d' % (cpu_thread_id,total_num) )
        logger().log( '[cpu%d] Contents (%d entries):' % (cpu_thread_id,num_entries) )
        print_buffer( buffer(dt,0,16*num_entries) )
        logger().log( '--------------------------------------' )
        logger().log( '#    segment:offset         attributes' )
        logger().log( '--------------------------------------' )
        for i in range(0, num_entries):
            offset = (ord(dt[i*16 + 11]) << 56) | (ord(dt[i*16 + 10]) << 48) | (ord(dt[i*16 + 9]) << 40) | (ord(dt[i*16 + 8]) << 32) | (ord(dt[i*16 + 7]) << 24) | (ord(dt[i*16 + 6]) << 16) | (ord(dt[i*16 + 1]) << 8) | ord(dt[i*16 + 0])
            segsel = (ord(dt[i*16 + 3]) << 8) | ord(dt[i*16 + 2])
            attr   = (ord(dt[i*16 + 5]) << 8) | ord(dt[i*16 + 4])
            logger().log( '%03d  %04X:%016X  0x%04X' % (i,segsel,offset,attr) )

        return (pa,dt)

    def IDT( self, cpu_thread_id, num_entries=None ):
        logger().log( '[cpu%d] IDT:' % cpu_thread_id )
        return self.dump_Descriptor_Table( cpu_thread_id, DESCRIPTOR_TABLE_CODE_IDTR, num_entries )
    def GDT( self, cpu_thread_id, num_entries=None ):
        logger().log( '[cpu%d] GDT:' % cpu_thread_id )
        return self.dump_Descriptor_Table( cpu_thread_id, DESCRIPTOR_TABLE_CODE_GDTR, num_entries )

    def IDT_all( self, num_entries=None ):
        for tid in range(self.get_cpu_thread_count()):
            self.IDT( tid, num_entries )
    def GDT_all( self, num_entries=None ):
        for tid in range(self.get_cpu_thread_count()):
            self.GDT( tid, num_entries )
