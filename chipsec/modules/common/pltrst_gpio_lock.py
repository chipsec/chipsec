# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2024-2026, Intel Corporation
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
Platform Reset GPIO pin Lock Check

Gives a pass/fail result if the platform reset GPIO configuration pin is locked or not.

If the pad multiplexed with PLTRST# is left unlocked, software running after boot
firmware can reassign it to the GPIO function and drive it low, resetting devices on
the LPC/eSPI bus (such as a discrete TPM) without a platform reset.

Reference:
    - `TPM GPIO fail: How bad OEM firmware ruins TPM security <https://mkukri.xyz/2024/06/01/tpm-gpio-fail.html>`_

Usage:
    ``chipsec_main -m common.pltrst_gpio_lock``

Examples:
    >>> chipsec_main.py -m common.pltrst_gpio_lock

Controls used:
    - PltrstGpioPin
    - PltrstGpioPinTx

.. note:: This module will only run on platforms where the controls PltrstGpioPin and PltrstGpioPinTx are defined.
.. note:: The pad used for PLTRST# is board dependent. If the board routes PLTRST# to a different pad, the result may be a false pass or false fail.
"""


from chipsec.module_common import BaseModule, HWCONFIG
from chipsec.library.returncode import ModuleResult

TAGS = [HWCONFIG]
METADATA_TAGS = ['OPENSOURCE', 'IA', 'COMMON', 'PLTRST_GPIO_LOCK']


class pltrst_gpio_lock(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self) -> bool:
        if self.cs.control.is_defined('PltrstGpioPin') and self.cs.control.is_defined('PltrstGpioPinTx'):
            return True
        self.logger.log('Platform has not defined the PltrstGpioPin/Tx controls. Skipping test.')
        self.res = ModuleResult.NOTAPPLICABLE
        return False

    def check_pltrst_gpio_pin(self) -> int:
        pin_lock = self.cs.control.get_list_by_name('PltrstGpioPin')
        tx_pin_lock = self.cs.control.get_list_by_name('PltrstGpioPinTx')
        if len(pin_lock) == 0 or len(tx_pin_lock) == 0:
            self.logger.log_error('Unable to read PltrstGpioPin/Tx controls. No enabled instances found.')
            self.result.setStatusBit(self.result.status.ACCESS_RW)
            return ModuleResult.ERROR
        pin_lock.read_and_print()
        tx_pin_lock.read_and_print()
        for control in (*pin_lock, *tx_pin_lock):
            register = self.cs.register.get_instance_by_name(control.get_register_name(), control.get_instance())
            if not register or register.value == register.get_mask():
                self.logger.log_error(f'Unable to verify {control.name}: {register.name} returned all ones or is not defined.')
                self.result.setStatusBit(self.result.status.ACCESS_RW)
                return ModuleResult.ERROR
        if pin_lock.is_any_value(0) or tx_pin_lock.is_any_value(0):
            self.logger.log_failed('Platform Reset GPIO Pin is not locked correctly.')
            self.logger.log_warning('Please confirm Platform Reset GPIO Pin location. If it has been moved, this would be a FALSE failure.')
            self.result.setStatusBit(self.result.status.LOCKS)
            return ModuleResult.FAILED
        self.logger.log_passed('Platform Reset GPIO Pins are locked correctly.')
        self.logger.log_warning('Please confirm Platform Reset GPIO Pin location. If it has been moved, this would be a FALSE pass.')
        return ModuleResult.PASSED

    def run(self, module_argv) -> int:
        self.logger.start_test('Platform Reset GPIO Lock Test')
        self.res = self.check_pltrst_gpio_pin()
        return self.result.getReturnCode(self.res)
