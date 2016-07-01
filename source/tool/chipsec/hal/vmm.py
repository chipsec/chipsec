#!/usr/local/bin/python
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



# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
# (c) 2010-2016 Intel Corporation
#
# -------------------------------------------------------------------------------
## \addtogroup hal
# chipsec/hal/vmm.py
# ====================
# VMM specific functionality
# 1. Hypercall interfaces
# 2. Second-level Address Translation (SLAT)
# 3. ..
#
# ~~~

__version__ = '1.0'

import struct
import sys
import os.path

from chipsec.logger import logger

class VMMRuntimeError (RuntimeError):
    pass

class VMM:

    def __init__( self, cs ):
        self.cs     = cs
        self.helper = cs.helper
        self.output = ''
        (self.membuf0_va, self.membuf0_pa) = (0, 0)
        (self.membuf1_va, self.membuf1_pa) = (0, 0)

    def __del__(self):
        if self.membuf0_va <> 0:
            #self.helper.free_physical_mem(self.membuf0_va)
            (self.membuf0_va, self.membuf0_pa) = (0, 0)
            (self.membuf1_va, self.membuf1_pa) = (0, 0)

    def init(self):
        (self.membuf0_va, self.membuf0_pa) = self.cs.mem.alloc_physical_mem(0x2000, 0xFFFFFFFFFFFFFFFF)
        (self.membuf1_va, self.membuf1_pa) = (self.membuf0_va + 0x1000, self.membuf0_pa + 0x1000)
        if self.membuf0_va == 0:
            logger().log( "[vmm] Could not allocate memory!")
            raise

    # Generic hypercall interface

    def hypercall(self, rax, rbx, rcx, rdx, rdi, rsi, r8=0, r9=0, r10=0, r11=0, xmm_buffer=0):
        return self.helper.hypercall(rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer)

    # Hypervisor-specific hypercall interfaces

    def hypercall64_five_args(self, vector, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0):
        return self.helper.hypercall(0, arg3, arg5, 0, arg4, 0, vector, 0, arg1, arg2)

    def hypercall64_memory_based(self, hypervisor_input_value, parameters, size = 0):
        self.cs.mem.write_physical_mem(self.membuf0_pa, len(parameters[:0x1000]), parameters[:0x1000])
        regs = self.helper.hypercall(hypervisor_input_value & ~0x00010000, self.membuf0_pa, self.membuf1_pa)
        self.output = self.helper.read_physical_mem(self.membuf1_pa, size) if size > 0 else ''
        return regs

    def hypercall64_fast(self, hypervisor_input_value, param0 = 0, param1 = 0):
        return self.helper.hypercall(hypervisor_input_value | 0x00010000, param0, param1)

    def hypercall64_extended_fast(self, hypervisor_input_value, parameter_block):
        (param0, param1, xmm_regs) = struct.unpack('<QQ96s', parameter_block)
        self.cs.mem.write_physical_mem(self.membuf0_pa, 0x60, xmm_regs)
        return self.helper.hypercall(hypervisor_input_value | 0x00010000, param0, param1, 0, 0, 0, 0, 0, 0, 0, self.membuf0_va)

    #
    # Dump EPT page tables at specified physical base (EPT pointer)
    #
    def dump_EPT_page_tables( self, eptp, pt_fname=None ):
        _orig_logname = logger().LOG_FILE_NAME
        paging_ept = chipsec.hal.paging.c_extended_page_tables( self.cs )
        if logger().HAL: logger().log( '[vmm] dumping EPT paging hierarchy at EPTP 0x%08X...' % eptp )
        if pt_fname is None: pt_fname = ('ept_%08X' % eptp)
        logger().set_log_file( pt_fname )
        paging_ept.read_pt_and_show_status( pt_fname, 'EPT', eptp )
        logger().set_log_file( _orig_logname )
        if paging_ept.failure: logger().error( 'could not dump EPT page tables' )
