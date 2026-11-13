# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2026, Intel Corporation
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

import unittest
from typing import Tuple
from unittest.mock import Mock

from chipsec.cfg.parsers.controls import CONTROLHelper
from chipsec.library.register import NullRegister, ObjList
from chipsec.library.returncode import ModuleResult
from chipsec.modules.common.pltrst_gpio_lock import pltrst_gpio_lock


class TestPltrstGpioLock(unittest.TestCase):
    def setUp(self) -> None:
        self.module = Mock()
        self.registers = {}
        self.module.cs.register.get_instance_by_name.side_effect = lambda name, inst: self.registers.get((name, inst), NullRegister(name, inst))

    def _make_register(self, name: str, value: int) -> Mock:
        register = Mock()
        register.name = name
        register.value = value
        register.get_mask.return_value = 0xFFFFFFFF
        register.get_instance.return_value = 0
        register.read_field.return_value = (value >> 13) & 1
        self.registers[(name, 0)] = register
        return register

    def _make_control_list(self, unlocked: bool, reg_name: str, reg_value: int = 0x2000) -> Mock:
        self._make_register(reg_name, reg_value)
        control = Mock()
        control.get_register_name.return_value = reg_name
        control.get_instance.return_value = 0
        control_list = Mock()
        control_list.__len__ = Mock(return_value=1)
        control_list.__iter__ = Mock(return_value=iter([control]))
        control_list.is_any_value.return_value = unlocked
        return control_list

    def _set_controls(self, pin_unlocked: bool, tx_unlocked: bool, pin_reg: int = 0x2000, tx_reg: int = 0x2000) -> Tuple[Mock, Mock]:
        pin_lock = self._make_control_list(pin_unlocked, 'PADCFGLOCK_GPP_B', pin_reg)
        tx_pin_lock = self._make_control_list(tx_unlocked, 'PADCFGLOCKTX_GPP_B', tx_reg)
        controls = {'PltrstGpioPin': pin_lock, 'PltrstGpioPinTx': tx_pin_lock}
        self.module.cs.control.get_list_by_name.side_effect = controls.get
        return pin_lock, tx_pin_lock

    def _set_parser_controls(self, pin_reg: int, tx_reg: int) -> Tuple[ObjList, ObjList]:
        pin_lock = ObjList([CONTROLHelper({'name': 'PltrstGpioPin', 'register': 'PADCFGLOCK_GPP_B', 'field': 'PLTRST'},
                                          self._make_register('PADCFGLOCK_GPP_B', pin_reg))])
        tx_pin_lock = ObjList([CONTROLHelper({'name': 'PltrstGpioPinTx', 'register': 'PADCFGLOCKTX_GPP_B', 'field': 'PLTRST'},
                                             self._make_register('PADCFGLOCKTX_GPP_B', tx_reg))])
        controls = {'PltrstGpioPin': pin_lock, 'PltrstGpioPinTx': tx_pin_lock}
        self.module.cs.control.get_list_by_name.side_effect = controls.get
        return pin_lock, tx_pin_lock

    def test_is_supported_when_both_controls_defined(self) -> None:
        self.module.cs.control.is_defined.return_value = True

        self.assertTrue(pltrst_gpio_lock.is_supported(self.module))
        self.module.logger.log.assert_not_called()

    def test_is_supported_when_tx_control_missing(self) -> None:
        self.module.cs.control.is_defined.side_effect = lambda name: name == 'PltrstGpioPin'

        self.assertFalse(pltrst_gpio_lock.is_supported(self.module))
        self.assertEqual(self.module.res, ModuleResult.NOTAPPLICABLE)
        self.module.logger.log.assert_called_once()

    def test_check_passes_when_both_locked(self) -> None:
        pin_lock, tx_pin_lock = self._set_controls(pin_unlocked=False, tx_unlocked=False)

        self.assertEqual(pltrst_gpio_lock.check_pltrst_gpio_pin(self.module), ModuleResult.PASSED)
        pin_lock.read_and_print.assert_called_once()
        tx_pin_lock.read_and_print.assert_called_once()
        self.module.logger.log_passed.assert_called_once()
        self.module.result.setStatusBit.assert_not_called()

    def test_check_fails_when_pin_unlocked(self) -> None:
        self._set_controls(pin_unlocked=True, tx_unlocked=False)

        self.assertEqual(pltrst_gpio_lock.check_pltrst_gpio_pin(self.module), ModuleResult.FAILED)
        self.module.logger.log_failed.assert_called_once()
        self.module.result.setStatusBit.assert_called_once_with(self.module.result.status.LOCKS)

    def test_check_fails_when_tx_unlocked(self) -> None:
        self._set_controls(pin_unlocked=False, tx_unlocked=True)

        self.assertEqual(pltrst_gpio_lock.check_pltrst_gpio_pin(self.module), ModuleResult.FAILED)
        self.module.logger.log_failed.assert_called_once()
        self.module.result.setStatusBit.assert_called_once_with(self.module.result.status.LOCKS)

    def test_check_errors_when_pin_list_empty(self) -> None:
        _, tx_pin_lock = self._set_controls(pin_unlocked=False, tx_unlocked=False)
        self.module.cs.control.get_list_by_name.side_effect = {'PltrstGpioPin': ObjList(), 'PltrstGpioPinTx': tx_pin_lock}.get

        self.assertEqual(pltrst_gpio_lock.check_pltrst_gpio_pin(self.module), ModuleResult.ERROR)
        self.module.logger.log_error.assert_called_once()
        self.module.result.setStatusBit.assert_called_once_with(self.module.result.status.ACCESS_RW)
        tx_pin_lock.read_and_print.assert_not_called()
        self.module.logger.log_passed.assert_not_called()

    def test_check_errors_when_tx_list_empty(self) -> None:
        pin_lock, _ = self._set_controls(pin_unlocked=False, tx_unlocked=False)
        self.module.cs.control.get_list_by_name.side_effect = {'PltrstGpioPin': pin_lock, 'PltrstGpioPinTx': ObjList()}.get

        self.assertEqual(pltrst_gpio_lock.check_pltrst_gpio_pin(self.module), ModuleResult.ERROR)
        self.module.logger.log_error.assert_called_once()
        self.module.result.setStatusBit.assert_called_once_with(self.module.result.status.ACCESS_RW)
        pin_lock.read_and_print.assert_not_called()
        self.module.logger.log_passed.assert_not_called()

    def test_check_errors_when_pin_register_reads_all_ones(self) -> None:
        pin_lock, tx_pin_lock = self._set_controls(pin_unlocked=False, tx_unlocked=False, pin_reg=0xFFFFFFFF)

        self.assertEqual(pltrst_gpio_lock.check_pltrst_gpio_pin(self.module), ModuleResult.ERROR)
        pin_lock.read_and_print.assert_called_once()
        tx_pin_lock.read_and_print.assert_called_once()
        self.module.logger.log_error.assert_called_once()
        self.module.result.setStatusBit.assert_called_once_with(self.module.result.status.ACCESS_RW)
        pin_lock.is_any_value.assert_not_called()
        self.module.logger.log_passed.assert_not_called()

    def test_check_errors_when_tx_register_reads_all_ones(self) -> None:
        pin_lock, tx_pin_lock = self._set_controls(pin_unlocked=False, tx_unlocked=False, tx_reg=0xFFFFFFFF)

        self.assertEqual(pltrst_gpio_lock.check_pltrst_gpio_pin(self.module), ModuleResult.ERROR)
        self.module.logger.log_error.assert_called_once()
        self.module.result.setStatusBit.assert_called_once_with(self.module.result.status.ACCESS_RW)
        tx_pin_lock.is_any_value.assert_not_called()
        self.module.logger.log_passed.assert_not_called()

    def test_check_passes_with_parser_controls(self) -> None:
        self._set_parser_controls(pin_reg=0x2000, tx_reg=0x2000)

        self.assertEqual(pltrst_gpio_lock.check_pltrst_gpio_pin(self.module), ModuleResult.PASSED)
        self.module.logger.log_passed.assert_called_once()
        self.module.result.setStatusBit.assert_not_called()

    def test_check_fails_with_parser_controls_when_unlocked(self) -> None:
        self._set_parser_controls(pin_reg=0x2000, tx_reg=0x0)

        self.assertEqual(pltrst_gpio_lock.check_pltrst_gpio_pin(self.module), ModuleResult.FAILED)
        self.module.result.setStatusBit.assert_called_once_with(self.module.result.status.LOCKS)

    def test_check_errors_with_parser_controls_when_all_ones(self) -> None:
        self._set_parser_controls(pin_reg=0xFFFFFFFF, tx_reg=0x2000)

        self.assertEqual(pltrst_gpio_lock.check_pltrst_gpio_pin(self.module), ModuleResult.ERROR)
        self.module.result.setStatusBit.assert_called_once_with(self.module.result.status.ACCESS_RW)

    def test_check_errors_when_backing_register_not_found(self) -> None:
        self._set_controls(pin_unlocked=False, tx_unlocked=False)
        self.registers.clear()

        self.assertEqual(pltrst_gpio_lock.check_pltrst_gpio_pin(self.module), ModuleResult.ERROR)
        self.module.logger.log_error.assert_called_once()
        self.module.result.setStatusBit.assert_called_once_with(self.module.result.status.ACCESS_RW)

    def test_run_returns_result_code(self) -> None:
        self.module.check_pltrst_gpio_pin.return_value = ModuleResult.PASSED
        self.module.result.getReturnCode.return_value = ModuleResult.PASSED

        self.assertEqual(pltrst_gpio_lock.run(self.module, []), ModuleResult.PASSED)
        self.module.logger.start_test.assert_called_once()
        self.module.result.getReturnCode.assert_called_once_with(ModuleResult.PASSED)


if __name__ == '__main__':
    unittest.main()
