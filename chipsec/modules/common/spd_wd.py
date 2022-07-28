# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2019, Eclypsium, Inc.
# Copyright (c) 2019-2021, Intel Corporation
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

    PASSED : SMBUS_HCFG.SPD_WD is set

    FAILED : SMBUS_HCFG.SPD_WD is not set and SPDs were detected

    INFORMATION: SMBUS_HCFG.SPD_WD is not set, but no SPDs were detected

Hardware registers used:

    SMBUS_HCFG

Usage:
    ``chipsec_main -m common.spd_wd``

Examples:
    >>> chipsec_main.py -m common.spd_wd

.. NOTE::
    This module will only run if:
        - SMBUS device is enabled
        - SMBUS_HCFG.SPD_WD is defined for the platform
"""

from chipsec.module_common import BaseModule, ModuleResult
from chipsec.hal.smbus import SMBus
from chipsec.hal.spd import SPD


class spd_wd(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        if self.cs.is_device_enabled('SMBUS'):
            if self.cs.register_has_field('SMBUS_HCFG', 'SPD_WD'):
                return True
            else:
                self.logger.log_important('SMBUS_HCFG.SPD_WD is not defined for this platform.  Skipping module.')
        else:
            self.logger.log_important('SMBUS device appears disabled.  Skipping module.')
        self.res = ModuleResult.NOTAPPLICABLE
        return False

    def check_spd_wd(self):
        try:
            _smbus = SMBus(self.cs)
            _spd = SPD(_smbus)
        except BaseException as msg:
            self.logger.log_error(msg)
            self.res = ModuleResult.ERROR
            return self.res

        spd_wd_reg = self.cs.read_register('SMBUS_HCFG')
        spd_wd = self.cs.get_register_field('SMBUS_HCFG', spd_wd_reg, 'SPD_WD')

        self.cs.print_register('SMBUS_HCFG', spd_wd_reg)

        if 1 == spd_wd:
            self.logger.log_passed("SPD Write Disable is set")
            self.res = ModuleResult.PASSED
        else:
            if _spd.detect():
                self.logger.log_failed("SPD Write Disable is not set and SPDs were detected")
                self.res = ModuleResult.FAILED
            else:
                self.logger.log_information("SPD Write Disable is not set, but no SPDs detected")
                self.res = ModuleResult.INFORMATION

        return self.res

    def run(self, module_argv):
        self.logger.start_test("SPD Write Disable")
        self.logger.log('')

        return self.check_spd_wd()
