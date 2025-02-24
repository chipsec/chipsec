# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2025, Intel Corporation
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

from unittest.mock import MagicMock, patch
from chipsec.hal.smbus import SMBus, SMBUS_POLL_COUNT
from chipsec.library.exceptions import IOBARNotFoundError, RegisterNotFoundError

class TestSMBUS(unittest.TestCase):
    @patch("chipsec.hal.smbus.iobar")
    def test_get_SMBus_Base_Address_valid_base(self, mock_iobar):
        base_address = 123456
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        smbus_hal.iobar.is_IO_BAR_defined.return_value = True
        smbus_hal.iobar.get_IO_BAR_base_address.return_value = (base_address, None)
        self.assertEqual(smbus_hal.get_SMBus_Base_Address(), base_address)

    @patch("chipsec.hal.smbus.iobar")
    def test_get_SMBus_Base_Address_invalid_base(self, mock_iobar):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        smbus_hal.iobar.is_IO_BAR_defined.return_value = False
        self.assertRaises(IOBARNotFoundError, smbus_hal.get_SMBus_Base_Address)

    def test_get_SMBus_HCFG_valid(self):
        reg_read_val = 123456
        mock_cs = MagicMock()
        mock_cs.register.is_defined.return_value = True
        mock_cs.register.read.return_value = reg_read_val
        smbus_hal = SMBus(mock_cs)
        self.assertEqual(smbus_hal.get_SMBus_HCFG(), reg_read_val)

    def test_get_SMBus_HCFG_invalid(self):
        mock_cs = MagicMock()
        mock_cs.register.is_defined.return_value = False
        smbus_hal = SMBus(mock_cs)
        self.assertRaises(RegisterNotFoundError, smbus_hal.get_SMBus_HCFG)

    @patch("chipsec.hal.smbus.iobar")
    def test_display_SMBus_info(self, mock_iobar):
        reg_read_val = 123456
        base_address = 456789
        mock_cs = MagicMock()
        mock_cs.register.is_defined.return_value = True
        mock_cs.register.read.return_value = reg_read_val
        smbus_hal = SMBus(mock_cs)
        smbus_hal.logger = MagicMock()
        smbus_hal.logger.HAL = True
        smbus_hal.iobar.is_IO_BAR_defined.return_value = True
        smbus_hal.iobar.get_IO_BAR_base_address.return_value = (base_address, None)
        smbus_hal.display_SMBus_info()
        smbus_hal.logger.log_hal.assert_called_with(f'[smbus] SMBus Base Address: 0x{base_address:04X}')

    def test_is_SMBus_enabled(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.device.is_enabled.return_value = True
        self.assertTrue(smbus_hal.is_SMBus_enabled())

    def test_is_SMBus_supported_valid(self):
        did = 1234
        vid = 0x8086
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.device.get_VendorID.return_value = (did, vid)
        self.assertTrue(smbus_hal.is_SMBus_supported())
        
    def test_is_SMBus_supported_invalid(self):
        did = 1234
        vid = 0x5678
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.device.get_VendorID.return_value = (did, vid)
        self.assertFalse(smbus_hal.is_SMBus_supported())

    def test_is_SMBus_host_controller_enabled_valid(self):
        reg_read_val = 123456
        hst_en = 1
        mock_cs = MagicMock()
        mock_cs.register.is_defined.return_value = True
        mock_cs.register.read.return_value = reg_read_val
        mock_cs.register.get_field.return_value = hst_en
        smbus_hal = SMBus(mock_cs)
        self.assertEqual(smbus_hal.is_SMBus_host_controller_enabled(), hst_en)
    
    @patch("chipsec.hal.smbus.iobar")
    def test_enable_SMBus_host_controller(self, mock_iobar):
        base_address = 123456
        mock_cs = MagicMock()
        mock_cs.register.read.return_value = 0
        smbus_hal = SMBus(mock_cs)
        smbus_hal.iobar.is_IO_BAR_defined.return_value = True
        smbus_hal.iobar.get_IO_BAR_base_address.return_value = (base_address, None)
        smbus_hal.enable_SMBus_host_controller()
        self.assertEqual(smbus_hal.cs.register.write.call_count, 2)
        self.assertEqual(smbus_hal.cs.register.read.call_count, 2)
    
    def test_reset_SMBus_controller_valid(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.register.read.side_effect = [321, 0x8, 0]
        self.assertTrue(smbus_hal.reset_SMBus_controller())
        self.assertEqual(smbus_hal.cs.register.read.call_count, 3)
    
    def test_reset_SMBus_controller_invalid(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.register.read.return_value = 0x8
        self.assertFalse(smbus_hal.reset_SMBus_controller())
        self.assertEqual(smbus_hal.cs.register.read.call_count, SMBUS_POLL_COUNT + 1)
    
    def test__is_smbus_ready_valid(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.register.read_field.return_value = 0
        self.assertTrue(smbus_hal._is_smbus_ready())
        self.assertEqual(smbus_hal.cs.register.read_field.call_count, 1)

    def test__is_smbus_ready_invalid(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.register.read_field.return_value = 1
        self.assertFalse(smbus_hal._is_smbus_ready())
        self.assertEqual(smbus_hal.cs.register.read_field.call_count, SMBUS_POLL_COUNT)

    def test__wait_for_cycle_pass(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.register.get_field.side_effect = [0, 1, 0]
        self.assertTrue(smbus_hal._wait_for_cycle())

    def test__wait_for_cycle_fail(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        smbus_hal.logger = MagicMock()
        smbus_hal.logger.HAL = True
        mock_cs.register.get_field.side_effect = [1, 1, 1]
        self.assertFalse(smbus_hal._wait_for_cycle())

    def test__wait_for_cycle_invalid_dev_err(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        smbus_hal.logger = MagicMock()
        smbus_hal.logger.HAL = True
        mock_cs.register.has_field.return_value = True
        mock_cs.register.get_field.side_effect = [1, 1, 0, 1]
        self.assertFalse(smbus_hal._wait_for_cycle())

    def test__wait_for_cycle_invalid_bus_err(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        smbus_hal.logger = MagicMock()
        smbus_hal.logger.HAL = True
        mock_cs.register.has_field.side_effect = [False, True]
        mock_cs.register.get_field.side_effect = [1, 1, 0, 1]
        self.assertFalse(smbus_hal._wait_for_cycle())

    def test_read_byte_pass(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        read_field_val = 1234
        mock_cs.register.get_field.side_effect = [0, 1, 0]
        mock_cs.register.read_field.return_value = read_field_val
        self.assertEqual(smbus_hal.read_byte(1, 2), read_field_val)

    def test_read_byte_fail(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.register.get_field.side_effect = [1, 1, 1]
        self.assertEqual(smbus_hal.read_byte(1, 2), 0xFF)

    def test_write_byte_pass(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.register.get_field.side_effect = [0, 1, 0]
        self.assertTrue(smbus_hal.write_byte(1, 2, 3))

    def test_write_byte_fail(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.register.get_field.side_effect = [1, 1, 1]
        self.assertFalse(smbus_hal.write_byte(1, 2, 3))

    def test_read_range(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        size = 1
        mock_cs.register.get_field.side_effect = [0, 1, 0] * size
        mock_cs.register.read_field.return_value = 1
        buffer = bytes([1] * size)
        self.assertEqual(smbus_hal.read_range(1, 1, size), buffer)

    def test_write_range(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.register.get_field.side_effect = [0, 1, 0]
        mock_cs.register.read_field.return_value = 1
        buffer = bytes([1])
        self.assertTrue(smbus_hal.write_range(1, 2, buffer))
        