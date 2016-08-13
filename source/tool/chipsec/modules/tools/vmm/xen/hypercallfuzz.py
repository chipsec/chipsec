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
Xen hypercall fuzzer

 Usage:
   ``chipsec_main -m tools.vmm.xen.hypercallfuzz [ -a <function>,<arg1>,<arg2>... ] -l hypercallfuzz.log``
"""

from chipsec.module_common import *
from chipsec.hal.vmm import *
import random

_MODULE_NAME = 'hypercallfuzz'

# Xen Hypercall Vectors
# Implemented hypercalls were obtained by attempting to invoke and
# from a guest and checking which hypercalls did not return 
# "Not implemented" in RC

MEMORY_OP_VECTOR        = 0x0C
SET_TIMER_OP_VECTOR     = 0x0F
XEN_VERSION_VECTOR      = 0x11
CONSOLE_IO_VECTOR       = 0x12
GRANT_TABLE_OP_VECTOR   = 0x14
SCHED_OP_VECTOR         = 0x1D
EVENT_CHANNEL_OP_VECTOR = 0x20
HVM_OP_VECTOR           = 0x22
SYSCTL_VECTOR           = 0x23
DOMCTL_VECTOR           = 0x24
TMEM_OP_VECTOR          = 0x26
ARCH_1_VECTOR           = 0x31


class HypercallFuzz (BaseModule):
    #####
    # Initialization and general purpose code
    # 
    #####
    def __init__(self):
        BaseModule.__init__(self)
        self.vmm = VMM( self.cs )
        self.vmm.init()
        
       
        
    def get_inv_err(self, status):
        return 0x10000000000000000 - (status & 0xFFFFFFFFFFFFFFFF)

    #####
    # Hypercall SCHED_OP
    # Input Parameters
    #   iterations : Number of times the hypercall will be invoked. Must be decimal.
    # Usage
    #   chipsec_main -m tools.vmm.xen_hypercalls_fuzz -a sched_op,10
    ####
    def fuzz_sched_op(self, args):
        # Constants from XEN source. These are the recognized commands for the call
        SCHEDOP_yield               = 0
        SCHEDOP_block               = 1
        SCHEDOP_shutdown            = 2
        SCHEDOP_poll                = 3
        SCHEDOP_remote_shutdown     = 4
        SCHEDOP_shutdown_code       = 5
        SCHEDOP_watchdog            = 6
    
        # define how many times we will make the hypercall
        iterations = int(args[0])

        # For most calls we need an allocated memory area
        # The call will write its output to this buffer.
        (databuf0_va, databuf0_pa) = (0, 0)
        (databuf0_va, databuf0_pa) = self.cs.helper.alloc_physical_mem(0x1000, 0xFFFFFFFFFFFFFFFF)
        if databuf0_va == 0:
            self.logger.log( "[*] Could not allocate memory!")
            return ModuleResult.ERROR
        self.logger.log( "[*] Allocated 0x1000 bytes at address 0x%016x" % databuf0_pa)
            
        # Fuzz through the cmd values
        for it in range(iterations):
            # Randomize the command (random number between 0 and 6)
            cmd = random.randint(0, 6)
            self.logger.log( "[*] Calling with command  %d" % cmd)
            if   cmd == SCHEDOP_yield:
                # Cmd yield is used to voluntarily yield the CPU. Arg can be NULL 
                rax = self.vmm.hypercall64_five_args(SCHED_OP_VECTOR, cmd, databuf0_pa, 0, 0, 0)
            elif cmd == SCHEDOP_block:
                # Cmd block is used to block the VCPU until an event is received for processing. Arg can be NULL 
                rax = self.vmm.hypercall64_five_args(SCHED_OP_VECTOR, cmd, databuf0_pa, 0, 0, 0)
            elif cmd == SCHEDOP_shutdown:
                # Cmd shutdown is used to Halt execution of this domain (all VCPUs).
                # arg must point to unsigned int reason. Normally It is a value between 0 - 4
                rax = self.vmm.hypercall64_five_args(SCHED_OP_VECTOR, cmd, databuf0_pa, 0, 0, 0)
            elif cmd == SCHEDOP_poll:
                # Cmd poll Polls a set of event-channel ports. Return when one or more are pending
                # arg must point to sched_poll_t
                rax = self.vmm.hypercall64_five_args(SCHED_OP_VECTOR, cmd, databuf0_pa, 0, 0, 0)
            elif cmd == SCHEDOP_remote_shutdown:
                # Cmd shutdown is used to Halt execution of a remote domain (all VCPUs).
                # arg must point to sched_remote_shutdown_t (domain id + reason)
                rax = self.vmm.hypercall64_five_args(SCHED_OP_VECTOR, cmd, databuf0_pa, 0, 0, 0)
            elif cmd == SCHEDOP_shutdown_code:
                # Cmd shutdown_code is used to Latch a shutdown code, so that when the domain 
                # later shuts down it reports this code to the control tools.
                # arg must point to unsigned int reason. Normally It is a value between 0 - 4
                rax = self.vmm.hypercall64_five_args(SCHED_OP_VECTOR, cmd, databuf0_pa, 0, 0, 0)
            elif cmd == SCHEDOP_watchdog:
                # Cmd watchdog is used to setup, poke and destroy a domain watchdog timer. 
                # arg must point to to sched_watchdog_t structure.
                rax = self.vmm.hypercall64_five_args(SCHED_OP_VECTOR, cmd, databuf0_pa, 0, 0, 0)
            else:
                self.logger.log( "Undefined cmd: %d " % version_cmd)
                return ModuleResult.ERROR

                
        return ModuleResult.PASSED



    #####
    # Hypercall SET_TIMER_OP
    # Input Parameters
    #   iterations : Number of times the hypercall will be invoked. Must be decimal.
    #   max_value  : Maximum number for the timeout value (values will be randomly selected)
    #                Must be hexadecimal value
    # Usage
    #   chipsec_main -m tools.vmm.xen_hypercalls_fuzz -a set_timer_op,10,0x10000000
    ####
    def fuzz_set_timer_op(self, args):
        iterations = int(args[0])
        max_value  = int(args[1], 16)
        self.logger.log( "[*] Fuzzing set_timer_op %d times in a range 0x0...0x%X" % (iterations, max_value))
        for it in range(iterations):
            timer_val = random.randint( 0, max_value )
            self.logger.log( "[*] Setting timer to  0x%016X" % timer_val)
            rax = self.vmm.hypercall64_five_args(SET_TIMER_OP_VECTOR, timer_val, 0, 0, 0, 0)
        self.logger.log_passed_check( "Test Passed" )
        return ModuleResult.PASSED
        
        
    #####
    # Hypercall XEN_VERSION
    # Input Parameters
    #   iterations : Number of times the hypercall will be invoked. Must be decimal.
    # Usage
    #   chipsec_main -m tools.vmm.xen_hypercalls_fuzz -a xen_version,50
    ####
    def fuzz_xen_version(self, args):
        # Constants from XEN source. These are the recognized commands for the call
        XENVER_version              = 0
        XENVER_extraversion         = 1
        XENVER_compile_info         = 2
        XENVER_capabilities         = 3
        XENVER_changeset            = 4
        XENVER_platform_parameters  = 5
        XENVER_get_features         = 6
        XENVER_pagesize             = 7
        XENVER_guest_handle         = 8
        XENVER_commandline          = 9
    
        # define how many times we will make the hypercall
        iterations = int(args[0])

        # For most calls we need an allocated memory area
        # The call will write its output to this buffer.
        (databuf0_va, databuf0_pa) = (0, 0)
        (databuf0_va, databuf0_pa) = self.cs.helper.alloc_physical_mem(0x1000, 0xFFFFFFFFFFFFFFFF)
        if databuf0_va == 0:
            self.logger.log( "[*] Could not allocate memory!")
            return ModuleResult.ERROR
        self.logger.log( "[*] Allocated 0x1000 bytes at address 0x%016x" % databuf0_pa)
            
        # Fuzz through the cmd values
        for it in range(iterations):
            # Randomize the command (random number between 0 and 9)
            version_cmd = random.randint(0, 9)
            self.logger.log( "[*] Calling with command  %d" % version_cmd)
            if   version_cmd == XENVER_version:
                # Cmd version does not make use of the data buffer. Only returns result in RAX
                rax = self.vmm.hypercall64_five_args(XEN_VERSION_VECTOR, version_cmd, databuf0_pa, 0, 0, 0)
            elif version_cmd == XENVER_extraversion:
                # Cmd extraversion copies 16 chars to the data buffer. 
                rax = self.vmm.hypercall64_five_args(XEN_VERSION_VECTOR, version_cmd, databuf0_pa, 0, 0, 0)
            elif version_cmd == XENVER_compile_info:
                # Cmd compile_info copies 144 chars to the data buffer. 
                rax = self.vmm.hypercall64_five_args(XEN_VERSION_VECTOR, version_cmd, databuf0_pa, 0, 0, 0)
            elif version_cmd == XENVER_capabilities:
                # Cmd capabilities copies 1024 chars to the data buffer. 
                rax = self.vmm.hypercall64_five_args(XEN_VERSION_VECTOR, version_cmd, databuf0_pa, 0, 0, 0)
            elif version_cmd == XENVER_changeset:
                # Cmd changeset copies 64 chars to the data buffer. 
                rax = self.vmm.hypercall64_five_args(XEN_VERSION_VECTOR, version_cmd, databuf0_pa, 0, 0, 0)
            elif version_cmd == XENVER_platform_parameters:
                # Cmd platform_parameters copies an unsigned long to the data buffer. 
                rax = self.vmm.hypercall64_five_args(XEN_VERSION_VECTOR, version_cmd, databuf0_pa, 0, 0, 0)
            elif version_cmd == XENVER_get_features:
                # Cmd get_features copies 64 chars to the data buffer. 
                rax = self.vmm.hypercall64_five_args(XEN_VERSION_VECTOR, version_cmd, databuf0_pa, 0, 0, 0)
            elif version_cmd == XENVER_pagesize:
                # Cmd pagesize only returns PAGESIZE in RAX. 
                rax = self.vmm.hypercall64_five_args(XEN_VERSION_VECTOR, version_cmd, databuf0_pa, 0, 0, 0)
            elif version_cmd == XENVER_guest_handle:
                # Cmd guest_handle copies current domain handle to the data buffer. 
                rax = self.vmm.hypercall64_five_args(XEN_VERSION_VECTOR, version_cmd, databuf0_pa, 0, 0, 0)
            elif version_cmd == XENVER_commandline:
                # Cmd commandline copies saved commandline to the data buffer. 
                rax = self.vmm.hypercall64_five_args(XEN_VERSION_VECTOR, version_cmd, databuf0_pa, 0, 0, 0)
            else:
                self.logger.log( "Undefined cmd: %d " % version_cmd)
                return ModuleResult.ERROR
            
        self.logger.log_passed_check( "Test Passed" )

        # Cleanup used memory buffer and bye
        if databuf0_va <> 0:
            #self.helper.free_physical_mem(databuf0_va)
            (databuf0_va, databuf0_pa) = (0, 0)
            
        return ModuleResult.PASSED
        
    # This function is not related to the fuzzing
    # It only tests the XEN_VERSION hypercall by calling it once    
    def test_version( self ):
        # For most calls we need an allocated memory area
        # The call will write its output to this buffer.
        (databuf0_va, databuf0_pa) = (0, 0)
        (databuf0_va, databuf0_pa) = self.cs.helper.alloc_physical_mem(0x1000, 0xFFFFFFFFFFFFFFFF)
        if databuf0_va == 0:
            self.logger.log( "[*] Could not allocate memory!")
            return ModuleResult.ERROR
        self.logger.log( "[*] Allocated 0x1000 bytes at address 0x%016x" % databuf0_pa)
        # Provide vector, cmd and pointer as arguments. Pointer is databuf0_pa
        # Convert RAX to a return code
        rax = self.vmm.hypercall64_five_args(XEN_VERSION_VECTOR, VERSION_CMD, databuf0_pa, 0, 0, 0)

        # Read the result from the buffer (16 chars)
        extraver = self.cs.helper.read_physical_mem(self.databuf0_pa, 16)
        
        # Display the results
        self.logger.log( "[CHIPSEC]    self.databuf0_pa: 0x%016x self.databuf0_va: 0x%016x" % (self.databuf0_pa, self.databuf0_va))
        self.logger.log( "[CHIPSEC]    Vector: 0x%02x %s " % (XEN_VERSION_VECTOR, "XEN_VERSION"))
        self.logger.log( "[CHIPSEC]    RAX: 0x%016x" % rax)
        self.logger.log( "[CHIPSEC]    Contents of extraver: \"%s\"" % extraver)
        self.logger.log_passed_check( "Test Passed" )
        return ModuleResult.PASSED

    def is_supported(self):
        return True

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        self.logger.start_test( "Xen Hypercall Fuzzer" )
        self.logger.log( "Usage: chipsec_main -m tools.vmm.xen.hypercallfuzz [ -a <function>,<arg1>,<arg2>... ]" )
        
        # Argument 0 is the function to call. Remove it
        function_argv = module_argv[1:]
        
        if module_argv[0] == 'set_timer_op':
            return self.fuzz_set_timer_op(function_argv)
        elif module_argv[0] == 'xen_version':
            return self.fuzz_xen_version(function_argv)
        elif module_argv[0] == 'sched_op':
            return self.fuzz_sched_op(function_argv)
        else:
            self.logger.log( "Undefined function: %s " % module_argv[0])
            return ModuleResult.ERROR
