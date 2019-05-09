# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2019, Eclypsium, Inc.
# Copyright (c) 2019, Intel Corporation
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

"""
This module checks that SPD Write Disable bit in SMBus controller has been set

References:

Intel 8 Series/C220 Series Chipset Family Platform Controller Hub datasheet
Intel 300 Series Chipset Families Platform Controller Hub datasheet

This module checks the following:

    SMBUS_HCFG.SPD_WD

The module returns the following results:

    FAILED : SMBUS_HCFG.SPD_WD is not set

    PASSED : SMBUS_HCFG.SPD_WD is set

Hardware registers used:

    SMBUS_HCFG
"""

from chipsec.module_common import *

class spd_wd(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        return self.cs.is_device_enabled( 'SMBUS' )

    def check_spd_wd(self):
        self.logger.start_test( "SPD Write Disable" )

        spd_wd_res = ModuleResult.FAILED
        spd_wd_reg = self.cs.read_register( 'SMBUS_HCFG' )
        spd_wd = self.cs.get_register_field( 'SMBUS_HCFG', spd_wd_reg, 'SPD_WD' )

        if 0 == spd_wd:
            self.logger.log_failed_check( "SPD Write Disable is not set" )
        else:
            spd_wd_res = ModuleResult.PASSED
            self.logger.log_passed_check( "SPD Write Disable is set" )

        return spd_wd_res

    def run( self, module_argv ):
        return self.check_spd_wd()
