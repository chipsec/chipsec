
# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2023, Intel Corporation
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
from unittest.mock import patch, Mock, MagicMock, call
from chipsec.hal.cpu import CPU


class TestHalCpu(unittest.TestCase):

    def test_hal_cpu_init(self):
        mock_cs = MagicMock()
        dci = CPU(mock_cs)
        self.assertIsInstance(dci, CPU)

    def test_hal_cpu_read_cr(self):
        mock_self = Mock()
        test_value = 0x8086
        mock_self.helper.read_cr.return_value = test_value
        result = CPU.read_cr(mock_self, 0x0, 0x0)
        self.assertEqual(result, test_value)

    def test_hal_cpu_read_cr_cmd(self):
        mock_self = Mock()
        test_value = 0x8086
        mock_self.helper.read_cr.return_value = test_value
        CPU.read_cr(mock_self, 0x16, 0x4)
        mock_self.helper.read_cr.assert_called_with(0x16, 0x4)

    def test_hal_cpu_write_cr(self):
        mock_self = Mock()
        expected_result = 0x01
        mock_self.helper.write_cr.return_value = expected_result
        result = CPU.write_cr(mock_self, 0x0, 0x0, expected_result)
        self.assertEqual(result, expected_result)

    def test_hal_cpu_write_cr_cmd(self):
        mock_self = Mock()
        mock_self.helper.write_cr.return_value = 0x1
        CPU.write_cr(mock_self, 0x32, 0x9, 0xAFAFAFAF)
        mock_self.helper.write_cr.assert_called_with(0x32, 0x9, 0xAFAFAFAF)

    def test_hal_cpu_write_cr_mock(self):
        mock_self = Mock()
        test_value = 0x1
        mock_self.helper.write_cr.return_value = test_value
        result = CPU.write_cr(mock_self, 0x0, 0x0, 0x0)
        self.assertEqual(result, test_value)

    def test_hal_cpuid(self):
        mock_self = Mock()
        expected_result = (0x80, 0x70, 0x60, 0x50)
        mock_self.helper.cpuid.return_value = expected_result
        result = CPU.cpuid(mock_self, 0x9, 0x4)
        self.assertEqual(result, expected_result)

    def test_hal_cpuid_cmd(self):
        mock_self = Mock()
        mock_self.helper.cpuid.return_value = (0x90, 0x80, 0x70, 0x60)
        CPU.cpuid(mock_self, 0x4000, 0x9000)
        mock_self.helper.cpuid.assert_called_with(0x4000, 0x9000)

    def test_hal_cpu_check_vmm_vmm_none(self):
        mock_self = Mock()
        VMM_NONE = 0x0
        expected_value = VMM_NONE
        mock_self.cpuid.return_value = (0, 0x3100800, 0x7FFAFBFF, 0xBFEBFBFF)
        result = CPU.check_vmm(mock_self)
        self.assertEqual(result, expected_value)

    def test_hal_cpu_check_vmm_cmd(self):
        mock_self = Mock()
        mock_self.cpuid.return_value = (0, 0x3100900, 0x7FFAFCFF, 0xBFEBFCFF)
        CPU.check_vmm(mock_self)
        mock_self.cpuid.assert_called_with(0x1, 0x0)

    def test_hal_cpu_check_vmm_vmm_none_vmm(self):
        mock_self = Mock()
        VMM_NONE = 0x0
        expected_value = VMM_NONE
        mock_self.cpuid.side_effect = [(0, 0x3100800, 0x80000000, 0xBFEBFBFF),
                                       (0, 0x566E6558, 0x666F736F, 0x4D4D566E)]
        result = CPU.check_vmm(mock_self)
        self.assertEqual(result, expected_value)

    def test_hal_cpu_check_vmm_vmm_xen(self):
        mock_self = Mock()
        VMM_XEN = 0x1
        expected_value = VMM_XEN
        mock_self.cpuid.side_effect = [(0, 0x3100800, 0x80000000, 0xBFEBFBFF),
                                       (0, 0x566E6558, 0x65584D4D, 0x4D4D566E)]
        result = CPU.check_vmm(mock_self)
        self.assertEqual(result, expected_value)

    def test_hal_cpu_check_vmm_vmm_hyper_v(self):
        mock_self = Mock()
        VMM_HYPER_V = 0x2
        expected_value = VMM_HYPER_V
        mock_self.cpuid.side_effect = [(0, 0x3100800, 0x80000000, 0xBFEBFBFF),
                                       (0, 0x7263694D, 0x666F736F, 0x76482074)]
        result = CPU.check_vmm(mock_self)
        self.assertEqual(result, expected_value)

    def test_hal_cpu_check_vmm_vmm_vmware(self):
        mock_self = Mock()
        VMM_VMWARE = 0x3
        expected_value = VMM_VMWARE
        mock_self.cpuid.side_effect = [(0, 0x3100800, 0x80000000, 0xBFEBFBFF),
                                       (0, 0x61774D56, 0x4D566572, 0x65726177)]
        result = CPU.check_vmm(mock_self)
        self.assertEqual(result, expected_value)

    def test_hal_cpu_check_vmm_vmm_kvm(self):
        mock_self = Mock()
        VMM_KVM = 0x4
        expected_value = VMM_KVM
        mock_self.cpuid.side_effect = [(0, 0x3100800, 0x80000000, 0xBFEBFBFF),
                                       (0, 0x4B4D564B, 0x564B4D56, 0x0000004D)]
        result = CPU.check_vmm(mock_self)
        self.assertEqual(result, expected_value)

    def test_hal_cpu_is_HT_active_false(self):
        mock_self = Mock()
        mock_self.get_number_logical_processor_per_core.return_value = 1
        result = CPU.is_HT_active(mock_self)
        self.assertFalse(result)

    def test_hal_cpu_is_HT_active_true(self):
        mock_self = Mock()
        mock_self.get_number_logical_processor_per_core.return_value = 4
        result = CPU.is_HT_active(mock_self)
        self.assertTrue(result)

    def test_hal_cpu_get_number_logical_processor_per_core_cmd(self):
        mock_self = Mock()
        mock_self.cpuid.return_value = (0x32, 0x16, 0x8, 0x4)
        CPU.get_number_logical_processor_per_core(mock_self)
        mock_self.cpuid.assert_called_with(0xb, 0x0)

    def test_hal_cpu_get_number_logical_processor_per_core(self):
        mock_self = Mock()
        expected_value = 4
        mock_self.cpuid.return_value = (0, expected_value, 0, 0)
        result = CPU.get_number_logical_processor_per_core(mock_self)
        self.assertEqual(result, expected_value)

    def test_hal_cpu_get_number_logical_processor_per_package(self):
        mock_self = Mock()
        expected_value = 16
        mock_self.cpuid.return_value = (0, expected_value, 0, 0)
        result = CPU.get_number_logical_processor_per_package(mock_self)
        self.assertEqual(result, expected_value)

    def test_hal_cpu_get_number_logical_processor_per_package_cmd(self):
        mock_self = Mock()
        mock_self.cpuid.return_value = (0x8000000000000000, 0x7000000000000000, 0x6000000000000000, 0x5000000000000000)
        CPU.get_number_logical_processor_per_package(mock_self)
        mock_self.cpuid.assert_called_with(0xb, 0x1)

    def test_hal_cpu_get_number_physical_processor_per_package(self):
        mock_self = Mock()
        core = 4
        package = 16
        expected_value = package // core
        mock_self.get_number_logical_processor_per_core.return_value = core
        mock_self.get_number_logical_processor_per_package.return_value = package
        result = CPU.get_number_physical_processor_per_package(mock_self)
        self.assertEqual(result, expected_value)

    def test_hal_cpu_get_cpu_topology(self):
        mock_self = Mock()
        mock_self.cs.helper.get_threads_count.return_value = 4
        mock_self.cs.cpu.cpuid.side_effect = [(4, 0, 0, 0),
                                              (1, 0, 0, 0),
                                              (4, 0, 0, 2),
                                              (1, 0, 0, 2),
                                              (4, 0, 0, 1),
                                              (1, 0, 0, 1),
                                              (4, 0, 0, 3),
                                              (1, 0, 0, 3),
                                              ]
        expected_result = {'cores': {0: [0, 2], 1: [1, 3]}, 'packages': {0: [0, 1, 2, 3]}}
        result = CPU.get_cpu_topology(mock_self)
        self.assertEqual(result, expected_result)

    def test_hal_cpu_get_number_sockets_from_APIC_table(self):
        mock_self = Mock()
        mock_self.get_number_threads_from_APIC_table.return_value = 4
        mock_self.get_number_logical_processor_per_package.return_value = 2
        result = CPU.get_number_sockets_from_APIC_table(mock_self)
        self.assertEqual(result, 2)

    def test_hal_cpu_get_SMRR(self):
        mock_self = Mock()
        mock_self.cs.register.read_field.side_effect = [0x88400000, 0xFFC00000]
        result = CPU.get_SMRR(mock_self)
        self.assertEqual(result, (0x88400000, 0xFFC00000))

    def test_hal_cpu_get_SMRR_cmd(self):
        mock_self = Mock()
        mock_self.cs.register.read_field.side_effect = [0x88400000, 0xFFC00000]
        call_1 = call('IA32_SMRR_PHYSBASE', 'PhysBase', True)
        call_2 = call('IA32_SMRR_PHYSMASK', 'PhysMask', True)
        CPU.get_SMRR(mock_self)
        mock_self.cs.register.read_field.assert_has_calls([call_1, call_2])

    def test_hal_cpu_get_SMRR_SMRAM(self):
        mock_self = Mock()
        mock_self.get_SMRR.return_value = (0x88400000, 0xFFC00000)
        expected_result = (0x88400000, 0x887FFFFF, 0x400000)
        result = CPU.get_SMRR_SMRAM(mock_self)
        self.assertEqual(result, expected_result)

    def test_hal_cpu_get_TSEG_is_server_true_cmd(self):
        mock_self = Mock()
        call_1 = call('TSEG_BASE', 'base', preserve_field_position=True)
        call_2 = call('TSEG_LIMIT', 'limit', preserve_field_position=True)
        mock_self.cs.is_server.return_value = True
        mock_self.cs.register.read_field.side_effect = [0x88400000, 0x88700000]
        CPU.get_TSEG(mock_self)
        mock_self.cs.register.read_field.assert_has_calls([call_1, call_2])

    def test_hal_cpu_get_TSEG_is_server_true(self):
        mock_self = Mock()
        mock_self.cs.is_server.return_value = True
        mock_self.cs.register.read_field.side_effect = [0x88400000, 0x88700000]
        expected_result = (0x88400000, 0x887FFFFF, 0x400000)
        result = CPU.get_TSEG(mock_self)
        self.assertEqual(result, expected_result)

    def test_hal_cpu_get_TSEG_is_server_false(self):
        mock_self = Mock()
        mock_self.cs.is_server.return_value = False
        mock_self.cs.register.read_field.side_effect = [0x88400000, 0x88800000]
        expected_result = (0x88400000, 0x887FFFFF, 0x400000)
        result = CPU.get_TSEG(mock_self)
        self.assertEqual(result, expected_result)

    def test_hal_cpu_get_TSEG_is_server_false_cmd(self):
        mock_self = Mock()
        call_1 = call('PCI0.0.0_TSEGMB', 'TSEGMB', preserve_field_position=True)
        call_2 = call('PCI0.0.0_BGSM', 'BGSM', preserve_field_position=True)
        mock_self.cs.is_server.return_value = False
        mock_self.cs.register.read_field.side_effect = [0x88400000, 0x88800000]
        CPU.get_TSEG(mock_self)
        mock_self.cs.register.read_field.assert_has_calls([call_1, call_2])

    def test_hal_cpu_get_SMRAM_smrr_true(self):
        mock_self = MagicMock()
        mock_self.check_SMRR_supported.__bool__.return_value = True
        expected_result = (0x88400000, 0x88400000, 0x400000)
        mock_self.get_SMRR_SMRAM.return_value = expected_result
        result = CPU.get_SMRAM(mock_self)
        self.assertEqual(result, expected_result)

    def test_hal_cpu_get_SMRAM_smrr_false(self):
        mock_self = MagicMock()
        mock_self.check_SMRR_supported.__bool__.return_value = False
        expected_result = (0x88400000, 0x88400000, 0x400000)
        mock_self.get_TSEG.return_value = expected_result
        result = CPU.get_SMRAM(mock_self)
        self.assertEqual(result, expected_result)

    def test_hal_cpu_check_SMRR_supported_cmd2(self):
        mock_self = Mock()
        mock_self.cs.register.read.return_value = 0x88442200
        mock_self.cs.register.get_field.return_value = 0
        CPU.check_SMRR_supported(mock_self)
        mock_self.cs.register.read.assert_called_with('MTRRCAP')

    def test_hal_cpu_check_SMRR_supported_cmd(self):
        mock_self = Mock()
        mock_self.cs.register.read.return_value = 0x88442200
        mock_self.cs.register.get_field.return_value = 0
        CPU.check_SMRR_supported(mock_self)
        mock_self.cs.register.get_field.assert_called_with('MTRRCAP', 0x88442200, 'SMRR')

    def test_hal_cpu_check_SMRR_supported_false(self):
        mock_self = Mock()
        mock_self.cs.register.get_field.return_value = 0
        result = CPU.check_SMRR_supported(mock_self)
        self.assertFalse(result)

    def test_hal_cpu_check_SMRR_supported_true(self):
        mock_self = Mock()
        mock_self.cs.register.get_field.return_value = 1
        result = CPU.check_SMRR_supported(mock_self)
        self.assertTrue(result)

    @patch('chipsec.hal.cpu.logger', spec=True)
    @patch('chipsec.hal.cpu.paging', spec=True)
    def test_hal_cpu_dump_page_tables_none(self, mock_paging, mock_logger):
        mock_self = Mock()
        mock_paging.c_ia32e_page_tables.return_value = Mock(failure=False)
        mock_logger().log_error.return_value = Mock()
        CPU.dump_page_tables(mock_self, 0x16B334001, None)
        self.assertEqual(5, mock_logger.call_count)

    @patch('chipsec.hal.cpu.logger', spec=True)
    @patch('chipsec.hal.cpu.paging.c_ia32e_page_tables', spec=True)
    def test_hal_cpu_dump_page_tables(self, mock_paging, mock_logger):
        mock_self = Mock()
        mock_paging.return_value = Mock(failure=False)
        CPU.dump_page_tables(mock_self, 0x16B334001, 'cpu0_pt_16B334001')
        self.assertEqual(4, mock_logger.call_count)

    @patch('chipsec.hal.cpu.logger', spec=True)
    @patch('chipsec.hal.cpu.paging.c_ia32e_page_tables', spec=True)
    def test_hal_cpu_dump_page_tables_log_error(self, mock_paging, mock_logger):
        mock_self = Mock()
        mock_paging.return_value = Mock(failure=True)
        CPU.dump_page_tables(mock_self, 0x16B334001, 'cpu0_pt_16B334001')
        self.assertEqual(5, mock_logger.call_count)

    def test_hal_cpu_dump_page_tables_all_1_thread(self):
        mock_self = Mock()
        threads = 1
        mock_self.cs.msr.get_cpu_thread_count.return_value = threads
        mock_self.return_value.dump_page_tables.return_value = 1
        mock_self.read_cr.side_effect = [0]
        CPU.dump_page_tables_all(mock_self)
        self.assertEqual(mock_self.dump_page_tables.call_count, threads)

    def test_hal_cpu_dump_page_tables_all_4_threads(self):
        mock_self = Mock()
        threads = 4
        mock_self.cs.msr.get_cpu_thread_count.return_value = threads
        mock_self.return_value.dump_page_tables.return_value = 1
        mock_self.read_cr.side_effect = [0, 1, 2, 3]
        CPU.dump_page_tables_all(mock_self)
        self.assertEqual(mock_self.dump_page_tables.call_count, threads)


if __name__ == '__main__':
    unittest.main()
