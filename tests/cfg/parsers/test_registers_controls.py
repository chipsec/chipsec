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
#
# Contact information:
# chipsec@intel.com
#

import unittest

from unittest.mock import MagicMock
from chipsec.cfg.parsers.registers.controls import CONTROLHelper
from chipsec.library.exceptions import ControlHelperError


def make_cfg(**overrides):
    cfg = {'name': 'LOCK_BIT', 'desc': 'Lock control bit', 'field': 'LOCK'}
    cfg.update(overrides)
    return cfg


def make_reg(name='CONTROL_REG', instance=0):
    reg = MagicMock()
    reg.name = name
    reg.instance = instance
    return reg


class _RegWithoutFieldMethods:
    """A register object missing read_field/write_field to trigger validation errors."""
    name = 'CONTROL_REG'
    instance = 0


class TestControlHelperInit(unittest.TestCase):
    """Cover CONTROLHelper construction and validation."""

    def test_successful_init(self):
        reg = make_reg(instance=3)
        control = CONTROLHelper(make_cfg(), reg)
        self.assertEqual(control.name, 'LOCK_BIT')
        self.assertEqual(control.desc, 'Lock control bit')
        self.assertEqual(control.get_field_name(), 'LOCK')
        self.assertEqual(control.instance, 3)
        self.assertIs(control.get_register_object(), reg)
        self.assertIsNone(control.get_current_value())

    def test_missing_name_key_raises(self):
        cfg = make_cfg()
        del cfg['name']
        with self.assertRaises(ControlHelperError):
            CONTROLHelper(cfg, make_reg())

    def test_missing_field_key_raises(self):
        cfg = make_cfg()
        del cfg['field']
        with self.assertRaises(ControlHelperError):
            CONTROLHelper(cfg, make_reg())

    def test_missing_desc_key_raises(self):
        cfg = make_cfg()
        del cfg['desc']
        with self.assertRaises(ControlHelperError):
            CONTROLHelper(cfg, make_reg())

    def test_none_register_raises(self):
        with self.assertRaises(ControlHelperError):
            CONTROLHelper(make_cfg(), None)

    def test_register_without_field_methods_raises(self):
        with self.assertRaises(ControlHelperError):
            CONTROLHelper(make_cfg(), _RegWithoutFieldMethods())


class TestControlHelperReadWrite(unittest.TestCase):
    """Cover read/write delegation and error wrapping."""

    def test_read_delegates_and_caches(self):
        reg = make_reg()
        reg.read_field.return_value = 0x5
        control = CONTROLHelper(make_cfg(), reg)
        self.assertEqual(control.read(), 0x5)
        reg.read_field.assert_called_once_with('LOCK')
        self.assertEqual(control.get_current_value(), 0x5)

    def test_write_delegates_and_caches(self):
        reg = make_reg()
        control = CONTROLHelper(make_cfg(), reg)
        control.write(0x1)
        reg.write_field.assert_called_once_with('LOCK', 0x1)
        self.assertEqual(control.get_current_value(), 0x1)

    def test_read_error_wrapped(self):
        reg = make_reg()
        reg.read_field.side_effect = RuntimeError('hw failure')
        control = CONTROLHelper(make_cfg(), reg)
        with self.assertRaises(ControlHelperError):
            control.read()

    def test_write_error_wrapped(self):
        reg = make_reg()
        reg.write_field.side_effect = RuntimeError('hw failure')
        control = CONTROLHelper(make_cfg(), reg)
        with self.assertRaises(ControlHelperError):
            control.write(0x1)


class TestControlHelperAccessors(unittest.TestCase):
    """Cover register-name resolution, field availability, and string forms."""

    def test_get_register_name_from_cfg(self):
        control = CONTROLHelper(make_cfg(register='EXPLICIT_REG'), make_reg(name='REG_OBJ_NAME'))
        self.assertEqual(control.get_register_name(), 'EXPLICIT_REG')

    def test_get_register_name_falls_back_to_reg_name(self):
        control = CONTROLHelper(make_cfg(), make_reg(name='REG_OBJ_NAME'))
        self.assertEqual(control.get_register_name(), 'REG_OBJ_NAME')

    def test_is_field_available_when_field_in_reg_fields(self):
        reg = make_reg()
        reg.fields = ['LOCK', 'OTHER']
        control = CONTROLHelper(make_cfg(), reg)
        self.assertTrue(control.is_field_available())

    def test_str_before_read_shows_not_read(self):
        control = CONTROLHelper(make_cfg(), make_reg())
        text = str(control)
        self.assertIn('Control: LOCK_BIT', text)
        self.assertIn('Field: LOCK', text)
        self.assertIn('Not Read', text)

    def test_str_after_read_shows_value(self):
        reg = make_reg()
        reg.read_field.return_value = 0xAB
        control = CONTROLHelper(make_cfg(), reg)
        control.read()
        self.assertIn('0xAB', str(control))

    def test_repr(self):
        control = CONTROLHelper(make_cfg(), make_reg(name='REG_OBJ_NAME'))
        rep = repr(control)
        self.assertIn("name='LOCK_BIT'", rep)
        self.assertIn("field='LOCK'", rep)


if __name__ == '__main__':
    unittest.main()
