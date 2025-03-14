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

from unittest.mock import MagicMock, call, patch
from chipsec.hal.common.smbus import SMBus, SMBUS_POLL_COUNT, SMBusMMIO
from chipsec.library.exceptions import IOBARNotFoundError

class TestSMBUS(unittest.TestCase):
    def test_get_SMBus_Base_Address_valid_base(self):
        base_address = 123456
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.hals.IOBAR.is_IO_BAR_defined.return_value = True
        mock_cs.hals.IOBAR.get_IO_BAR_base_address.return_value = (base_address, None)
        self.assertEqual(smbus_hal.get_SMBus_Base_Address(), base_address)

    def test_get_SMBus_Base_Address_invalid_base(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.hals.IOBAR.is_IO_BAR_defined.return_value = False
        self.assertRaises(IOBARNotFoundError, smbus_hal.get_SMBus_Base_Address)

    def test_display_SMBus_info(self):
        reg_read_val = 123456
        base_address = 456789
        mock_cs = MagicMock()
        mock_cs.register.is_defined.return_value = True
        mock_cs.register.get_instance_by_name().read.return_value = reg_read_val
        mock_cs.hals.IOBAR.is_IO_BAR_defined.return_value = True
        mock_cs.hals.IOBAR.get_IO_BAR_base_address.return_value = (base_address, None)
        smbus_hal = SMBus(mock_cs)
        smbus_hal.logger = MagicMock()
        smbus_hal.logger.HAL = True
        smbus_hal.display_SMBus_info()
        self.assertTrue(call(f'[smbus] SMBus Base Address: 0x{base_address:04X}') in smbus_hal.logger.log.call_args_list)

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
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.device.get_bus.return_value = None
        self.assertFalse(smbus_hal.is_SMBus_supported())

    def test_is_SMBus_host_controller_enabled_valid(self):
        hst_en = 1
        mock_cs = MagicMock()
        mock_cs.register.get_instance_by_name().get_field.return_value = hst_en
        smbus_hal = SMBus(mock_cs)
        self.assertEqual(smbus_hal.is_SMBus_host_controller_enabled(), hst_en)
    
    def test_enable_SMBus_host_controller(self):
        mock_cs = MagicMock()
        mock_cs.register.get_instance_by_name().read.return_value = 0
        smbus_hal = SMBus(mock_cs)
        smbus_hal.enable_SMBus_host_controller()
        self.assertEqual(smbus_hal.cs.register.get_instance_by_name().write.call_count, 1)
        self.assertEqual(smbus_hal.cs.register.get_instance_by_name().read.call_count, 1)

        # enable_SMBus_io_mem_space
    def test_enable_SMBus_io_mem_space(self):
        mock_cs = MagicMock()
        mock_cs.register.get_instance_by_name().read.return_value = 0
        smbus_hal = SMBus(mock_cs)
        smbus_hal.enable_SMBus_io_mem_space()
        self.assertEqual(smbus_hal.cs.register.get_instance_by_name().write.call_count, 1)
        self.assertEqual(smbus_hal.cs.register.get_instance_by_name().read.call_count, 1)
    
    # enable_pch_i2c_comm
    def test_enable_pch_i2c_comm(self):
        mock_cs = MagicMock()
        mock_cs.register.get_instance_by_name().read.return_value = 0
        smbus_hal = SMBus(mock_cs)
        smbus_hal.enable_pch_i2c_comm()
        self.assertEqual(smbus_hal.cs.register.get_instance_by_name().write.call_count, 1)
        self.assertEqual(smbus_hal.cs.register.get_instance_by_name().read.call_count, 2)

    def test_disable_pch_i2c_comm(self):
        mock_cs = MagicMock()
        mock_cs.register.get_instance_by_name().read.return_value = 0xF
        smbus_hal = SMBus(mock_cs)
        smbus_hal.disable_pch_i2c_comm()
        self.assertEqual(smbus_hal.cs.register.get_instance_by_name().write.call_count, 1)
        self.assertEqual(smbus_hal.cs.register.get_instance_by_name().read.call_count, 2)

    def test_reset_SMBus_controller_valid(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)        
        mock_cs.register.get_instance_by_name().read.side_effect = [321, 0x8, 0]
        self.assertTrue(smbus_hal.reset_SMBus_controller())
        self.assertEqual(smbus_hal.cs.register.get_instance_by_name().read.call_count, 3)
    
    def test_reset_SMBus_controller_invalid(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.register.get_instance_by_name().read.return_value = 0x8
        self.assertFalse(smbus_hal.reset_SMBus_controller())
        self.assertEqual(smbus_hal.cs.register.get_instance_by_name().read.call_count, SMBUS_POLL_COUNT + 1)
    
    def test__is_smbus_ready_valid(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.register.get_instance_by_name().get_field.return_value = 0
        mock_cs.register.get_instance_by_name().value = 0
        self.assertTrue(smbus_hal._is_smbus_ready())
        self.assertEqual(smbus_hal.cs.register.get_instance_by_name.return_value.get_field.call_count, 1)

    def test__is_smbus_ready_invalid(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.register.get_instance_by_name().get_field.return_value = 1
        mock_cs.register.get_instance_by_name().value = 1
        self.assertFalse(smbus_hal._is_smbus_ready())
        self.assertEqual(smbus_hal.cs.register.get_instance_by_name().get_field.call_count, SMBUS_POLL_COUNT)

    def test__wait_for_cycle_pass(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.register.get_instance_by_name().get_field.side_effect = [0, 0, 0, 0]
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
        mock_cs.register.get_instance_by_name().get_field.side_effect = [1, 1, 0, 1]
        self.assertFalse(smbus_hal._wait_for_cycle())


    def test_read_byte_pass(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        read_field_val = 1234
        mock_cs.register.get_instance_by_name().read.return_value = read_field_val
        mock_cs.register.get_instance_by_name().read_field.return_value = 0
        mock_cs.register.get_instance_by_name().get_field.return_value = 0
        mock_cs.register.get_instance_by_name().value = 0
        self.assertEqual(smbus_hal.read_byte(1, 2), [read_field_val])

    def test_read_byte_fail(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.register.get_instance_by_name().read_field.return_value = 0
        mock_cs.register.get_instance_by_name().get_field.return_value = 1
        mock_cs.register.get_instance_by_name().value = 1
        self.assertEqual(smbus_hal.read_byte(1, 2), False)

    def test_write_byte_pass(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.register.get_instance_by_name().read_field.return_value = 0
        mock_cs.register.get_instance_by_name().get_field.return_value = 0
        mock_cs.register.get_instance_by_name().value = 0
        self.assertTrue(smbus_hal.write_byte(1, 2, 3))

    def test_write_byte_fail(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.register.get_instance_by_name().read_field.return_value = 0
        mock_cs.register.get_instance_by_name().get_field.return_value = 1
        mock_cs.register.get_instance_by_name().value = 1
        self.assertFalse(smbus_hal.write_byte(1, 2, 3))
        
    def test_enable_with_i2c(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        smbus_hal.i2c_mode = True
        smbus_hal.enable()
        self.assertEqual(smbus_hal.cs.register.get_instance_by_name().read.call_count, 7)
        self.assertEqual(smbus_hal.cs.register.get_instance_by_name().get_field.call_count, 2)

    def test_enable_without_i2c(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        smbus_hal.i2c_mode = False
        smbus_hal.enable()
        self.assertEqual(smbus_hal.cs.register.get_instance_by_name().read.call_count, 5)
        self.assertEqual(smbus_hal.cs.register.get_instance_by_name().get_field.call_count, 2)

    def test_process_call(self):
        mock_cs = MagicMock()
        smbus_hal = SMBus(mock_cs)
        mock_cs.register.get_instance_by_name().get_field.return_value = 0
        mock_cs.register.get_instance_by_name().read.return_value = 0x5
        mock_cs.register.get_instance_by_name().value = 0
        self.assertTrue(smbus_hal.process_call(1, 1, 0x5, 0x5))

class TestSMBUSMmio(unittest.TestCase):

    def test_enable_with_i2c(self):
        mock_cs = MagicMock()
        smbus_hal = SMBusMMIO(mock_cs)
        smbus_hal.i2c_mode = True
        smbus_hal.enable()
        self.assertEqual(smbus_hal.cs.register.get_instance_by_name().read.call_count, 9)
        self.assertEqual(smbus_hal.cs.register.get_instance_by_name().get_field.call_count, 2)
                        
    def test_enable_without_i2c(self):
        mock_cs = MagicMock()
        smbus_hal = SMBusMMIO(mock_cs)
        smbus_hal.i2c_mode = False
        smbus_hal.enable()
        self.assertEqual(smbus_hal.cs.register.get_instance_by_name().read.call_count, 7)
        self.assertEqual(smbus_hal.cs.register.get_instance_by_name().get_field.call_count, 2)
        pass