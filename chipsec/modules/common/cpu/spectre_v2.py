#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2018, Eclypsium, Inc.
#Copyright (c) 2019-2020, Intel Corporation
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

"""
The module checks if system includes hardware mitigations for Speculative Execution Side Channel.
Specifically, it verifies that the system supports CPU mitigations for
Branch Target Injection vulnerability a.k.a. Spectre Variant 2 (CVE-2017-5715)

The module checks if the following hardware mitigations are supported by the CPU
and enabled by the OS/software:

1. Indirect Branch Restricted Speculation (IBRS) and Indirect Branch Predictor Barrier (IBPB):
   CPUID.(EAX=7H,ECX=0):EDX[26] == 1

2. Single Thread Indirect Branch Predictors (STIBP):
   CPUID.(EAX=7H,ECX=0):EDX[27] == 1
   IA32_SPEC_CTRL[STIBP] == 1

3. Enhanced IBRS:
   CPUID.(EAX=7H,ECX=0):EDX[29] == 1
   IA32_ARCH_CAPABILITIES[IBRS_ALL] == 1
   IA32_SPEC_CTRL[IBRS] == 1

4. @TODO: Mitigation for Rogue Data Cache Load (RDCL):
   CPUID.(EAX=7H,ECX=0):EDX[29] == 1
   IA32_ARCH_CAPABILITIES[RDCL_NO] == 1

In addition to checking if CPU supports and OS enables all mitigations, we need to check
that relevant MSR bits are set consistently on all logical processors (CPU threads).


The module returns the following results:

FAILED:
    IBRS/IBPB is not supported

WARNING:
    IBRS/IBPB is supported

    Enhanced IBRS is not supported

WARNING:
    IBRS/IBPB is supported

    Enhanced IBRS is supported

    Enhanced IBRS is not enabled by the OS

WARNING:
    IBRS/IBPB is supported

    STIBP is not supported or not enabled by the OS

PASSED:
    IBRS/IBPB is supported

    Enhanced IBRS is supported

    Enhanced IBRS is enabled by the OS

    STIBP is supported


Notes:

- The module returns WARNING when CPU doesn't support enhanced IBRS
  Even though OS/software may use basic IBRS by setting IA32_SPEC_CTRL[IBRS] when necessary,
  we have no way to verify this

- The module returns WARNING when CPU supports enhanced IBRS but OS doesn't set IA32_SPEC_CTRL[IBRS]
  Under enhanced IBRS, OS can set IA32_SPEC_CTRL[IBRS] once to take advantage of IBRS protection

- The module returns WARNING when CPU doesn't support STIBP or OS doesn't enable it
  Per Speculative Execution Side Channel Mitigations:
  "enabling IBRS prevents software operating on one logical processor from controlling
  the predicted targets of indirect branches executed on another logical processor.
  For that reason, it is not necessary to enable STIBP when IBRS is enabled"

- OS/software may implement "retpoline" mitigation for Spectre variant 2
  instead of using CPU hardware IBRS/IBPB

@TODO: we should verify CPUID.07H:EDX on all logical CPUs as well
because it may differ if ucode update wasn't loaded on all CPU cores


Hardware registers used:

- CPUID.(EAX=7H,ECX=0):EDX[26]     - enumerates support for IBRS and IBPB
- CPUID.(EAX=7H,ECX=0):EDX[27]     - enumerates support for STIBP
- CPUID.(EAX=7H,ECX=0):EDX[29]     - enumerates support for the IA32_ARCH_CAPABILITIES MSR
- IA32_ARCH_CAPABILITIES[IBRS_ALL] - enumerates support for enhanced IBRS
- IA32_ARCH_CAPABILITIES[RCDL_NO]  - enumerates support RCDL mitigation
- IA32_SPEC_CTRL[IBRS]             - enable control for enhanced IBRS by the software/OS
- IA32_SPEC_CTRL[STIBP]            - enable control for STIBP by the software/OS


References:

- Reading privileged memory with a side-channel by Jann Horn, Google Project Zero:
  https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html

- Spectre:
  https://spectreattack.com/spectre.pdf

- Meltdown:
  https://meltdownattack.com/meltdown.pdf

- Speculative Execution Side Channel Mitigations:
  https://software.intel.com/sites/default/files/managed/c5/63/336996-Speculative-Execution-Side-Channel-Mitigations.pdf

- Retpoline: a software construct for preventing branch-target-injection:
  https://support.google.com/faqs/answer/7625886

"""

from chipsec.module_common import BaseModule, MTAG_CPU, MTAG_HWCONFIG, MTAG_SMM, ModuleResult
from chipsec.helper.oshelper import HWAccessViolationError
from chipsec.defines import BIT26, BIT27, BIT29

TAGS = [MTAG_CPU,MTAG_HWCONFIG,MTAG_SMM]

class spectre_v2(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)


    def is_supported(self):
        return True

    def check_spectre_mitigations( self ):

        try:
           cpu_thread_count = self.cs.msr.get_cpu_thread_count()
        except:
           cpu_thread_count = 1

        #
        # Read CPUID Leaf 07H
        #
        (r_eax, r_ebx, r_ecx, r_edx) = self.cs.cpu.cpuid( 0x7, 0x0 )
        ibrs_ibpb_supported = (r_edx & BIT26) > 0
        stibp_supported     = (r_edx & BIT27) > 0
        arch_cap_supported  = (r_edx & BIT29) > 0
        self.logger.log( "[*] CPUID.7H:EDX[26] = {:d} Indirect Branch Restricted Speculation (IBRS) & Predictor Barrier (IBPB)".format(ibrs_ibpb_supported) )
        self.logger.log( "[*] CPUID.7H:EDX[27] = {:d} Single Thread Indirect Branch Predictors (STIBP)".format(stibp_supported) )
        self.logger.log( "[*] CPUID.7H:EDX[29] = {:d} IA32_ARCH_CAPABILITIES".format(arch_cap_supported) )

        if ibrs_ibpb_supported: self.logger.log_good( "CPU supports IBRS and IBPB" )
        else:                   self.logger.log_bad( "CPU doesn't support IBRS and IBPB" )

        if stibp_supported: self.logger.log_good( "CPU supports STIBP" )
        else:               self.logger.log_bad( "CPU doesn't support STIBP" )

        if not self.cs.is_register_defined( 'IA32_ARCH_CAPABILITIES' ) or \
           not self.cs.is_register_defined( 'IA32_SPEC_CTRL' ):
            self.logger.error( "couldn't find definition of required MSRs" )
            return ModuleResult.ERROR


        if arch_cap_supported:
            ibrs_enh_supported = True
            #rdcl_mitigation_supported = True
            self.logger.log( "[*] checking enhanced IBRS support in IA32_ARCH_CAPABILITIES..." )
            for tid in range(cpu_thread_count):
                arch_cap_msr = 0
                try:
                    arch_cap_msr = self.cs.read_register( 'IA32_ARCH_CAPABILITIES', tid )
                except HWAccessViolationError:
                    self.logger.error( "couldn't read IA32_ARCH_CAPABILITIES" )
                    ibrs_enh_supported = False
                    break

                ibrs_all = self.cs.get_register_field( 'IA32_ARCH_CAPABILITIES', arch_cap_msr, 'IBRS_ALL' )
                self.logger.log( "[*]   cpu{:d}: IBRS_ALL = {:x}".format(tid, ibrs_all) )
                if 0 == ibrs_all:
                    ibrs_enh_supported = False
                    break

                # @TODO: this checks for RDCL aka Meltdown (Variant 3) mitigation
                #self.logger.log( "[*]   cpu{:d}: checking RDCL mitigation support...".format(tid) )
                #rdcl_no = self.cs.get_register_field( 'IA32_ARCH_CAPABILITIES', arch_cap_msr, 'RDCL_NO' )
                #self.logger.log( "[*]   cpu{:d}: RDCL_NO = {:x}".format(tid, rdcl_no) )
                #if 0 == rdcl_no:
                #    rdcl_mitigation_supported = False
                #    break

            if ibrs_enh_supported: self.logger.log_good( "CPU supports enhanced IBRS (on all logical CPU)" )
            else: self.logger.log_bad( "CPU doesn't support enhanced IBRS" ) 
            #if rdcl_mitigation_supported: self.logger.log_good( "CPU supports mitigation for Rogue Data Cache Load (RDCL)" )
            #else: self.logger.log_bad( "CPU doesn't support mitigation for Rogue Data Cache Load (RDCL)" )
        else:
            ibrs_enh_supported = False
            self.logger.log_bad( "CPU doesn't support enhanced IBRS" )

        ibrs_enabled  = True
        stibp_enabled_count = 0
        if ibrs_enh_supported:
            self.logger.log( "[*] checking if OS is using Enhanced IBRS..." )
            for tid in range(cpu_thread_count):
                spec_ctrl_msr = 0
                try:
                    spec_ctrl_msr = self.cs.read_register( 'IA32_SPEC_CTRL', tid )
                except HWAccessViolationError:
                    self.logger.error( "couldn't read IA32_SPEC_CTRL" )
                    ibrs_enabled = False
                    break

                ibrs = self.cs.get_register_field( 'IA32_SPEC_CTRL', spec_ctrl_msr, 'IBRS' )
                self.logger.log( "[*]   cpu{:d}: IA32_SPEC_CTRL[IBRS] = {:x}".format(tid, ibrs) )
                if 0 == ibrs:
                    ibrs_enabled = False

                # ok to access STIBP bit even if STIBP is not supported
                stibp = self.cs.get_register_field( 'IA32_SPEC_CTRL', spec_ctrl_msr, 'STIBP' )
                self.logger.log( "[*]   cpu{:d}: IA32_SPEC_CTRL[STIBP] = {:x}".format(tid, stibp) )
                if 1 == stibp:
                    stibp_enabled_count += 1

            if ibrs_enabled:
                self.logger.log_good( "OS enabled Enhanced IBRS (on all logical processors)" )
            else:
                self.logger.log_bad( "OS doesn't seem to use Enhanced IBRS" )
            if stibp_enabled_count == cpu_thread_count:
                self.logger.log_good( "OS enabled STIBP (on all logical processors)" )
            elif stibp_enabled_count > 0:
                self.logger.log_good( "OS selectively enabling STIBP" )
            else:
                self.logger.log_information( "Unable to determine if the OS uses STIBP" )

        #
        # Combining results of all checks into final decision
        #
        # FAILED : IBRS/IBPB is not supported
        # WARNING: IBRS/IBPB is supported
        #          enhanced IBRS is not supported
        # WARNING: IBRS/IBPB is supported
        #          enhanced IBRS is supported
        #          enhanced IBRS is not enabled by the OS
        # WARNING: IBRS/IBPB is supported
        #          STIBP is not supported
        # PASSED : IBRS/IBPB is supported
        #          enhanced IBRS is supported
        #          enhanced IBRS is enabled by the OS
        #          STIBP is supported
        #
        if not ibrs_ibpb_supported:
            res = ModuleResult.FAILED
            self.logger.log_failed_check( "CPU mitigation (IBRS) is missing" )
        elif not ibrs_enh_supported:
            res = ModuleResult.WARNING
            self.logger.log_warn_check( "CPU supports mitigation (IBRS) but doesn't support enhanced IBRS" )
        elif ibrs_enh_supported and (not ibrs_enabled):
            res = ModuleResult.WARNING
            self.logger.log_warn_check( "CPU supports mitigation (enhanced IBRS) but OS is not using it" )
        else:
            if (not stibp_supported):
                res = ModuleResult.WARNING
                self.logger.log_warn_check( "CPU supports mitigation (enhanced IBRS) but STIBP is not supported" )
            else:
                res = ModuleResult.PASSED
                self.logger.log_passed_check( "CPU and OS support hardware mitigations" )

        self.logger.log_important( "OS may be using software based mitigation (eg. retpoline)" )

        return res

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        self.logger.start_test( "Checks for Branch Target Injection / Spectre v2 (CVE-2017-5715)" )
        return self.check_spectre_mitigations()

