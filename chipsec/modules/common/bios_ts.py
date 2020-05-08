#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2020, Intel Corporation
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
Checks for BIOS Interface Lock including Top Swap Mode

`BIOS Boot Hijacking and VMware Vulnerabilities Digging <http://powerofcommunity.net/poc2007/sunbing.pdf>`_ by Bing Sun
"""

from chipsec.module_common import BaseModule, ModuleResult, MTAG_BIOS
TAGS = [MTAG_BIOS]

class bios_ts(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        return True

    def check_bios_iface_lock(self):
        self.logger.start_test( "BIOS Interface Lock (including Top Swap Mode)" )

        bild = 0
        if self.cs.is_control_defined( 'BiosInterfaceLockDown' ):
            bild = self.cs.get_control( 'BiosInterfaceLockDown' )
            self.logger.log( "[*] BiosInterfaceLockDown (BILD) control = {:d}".format(bild) )
        else:
            self.logger.error( "BiosInterfaceLockDown (BILD) control is not defined" )
            return ModuleResult.ERROR

        if self.cs.is_control_defined( 'TopSwapStatus' ):
            tss = self.cs.get_control( 'TopSwapStatus' )
            self.logger.log( "[*] BIOS Top Swap mode is {} (TSS = {:d})".format('enabled' if (1==tss) else 'disabled', tss) )

        if self.cs.is_control_defined( 'TopSwap' ):
            ts  = self.cs.get_control( 'TopSwap' )
            self.logger.log( "[*] RTC TopSwap control (TS) = {:x}".format(ts) )

        if 0 == bild:
            res = ModuleResult.FAILED
            self.logger.log_failed_check( "BIOS Interface is not locked (including Top Swap Mode)" )
        else:
            res = ModuleResult.PASSED
            self.logger.log_passed_check( "BIOS Interface is locked (including Top Swap Mode)" )
        return res

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run(self, module_argv ):
        return self.check_bios_iface_lock()
