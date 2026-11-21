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
#


# To execute: python -m unittest tests.helpers.test_replayhelper

import unittest
from errno import EFAULT
from os.path import join
import chipsec.helper.replay.replayhelper as rph
from chipsec.library.exceptions import PhysicalMemoryAccessError, UnimplementedAPIError

PMA_ERROR = "!! <class 'chipsec.library.exceptions.PhysicalMemoryAccessError'>: not accessible"


class ReplayHelperTest(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.replayhelper = rph.ReplayHelper(join("tests", "helpers", "kblreplaytest.json"))
        self.assertTrue(self.replayhelper.create())
        self.assertTrue(self.replayhelper.start())


    def tearDown(self):
        unittest.TestCase.tearDown(self)
        self.assertTrue(self.replayhelper.stop())
        self.assertTrue(self.replayhelper.delete())

    def test_cpu_read_pci_reg_one_byte(self):
        pci_read_value = self.replayhelper.read_pci_reg(0,0,0,0,0x1)
        self.assertEqual(pci_read_value, 0x86)
        
    def test_cpu_read_pci_reg_two_bytes(self):
        pci_read_value = self.replayhelper.read_pci_reg(0,0,0,0,0x2)
        self.assertEqual(pci_read_value, 0x8086)
        
    def test_cpu_read_pci_reg_four_bytes(self):
        pci_read_value = self.replayhelper.read_pci_reg(0,0,0,0,0x4)
        self.assertEqual(pci_read_value, 0x59048086)

    def test_pch_read_pci_reg_one_byte(self):
        pci_read_value = self.replayhelper.read_pci_reg(0,0x1f,0,0,0x1)
        self.assertEqual(pci_read_value, 0x86)

    def test_pch_read_pci_reg_two_bytes(self):
        pci_read_value = self.replayhelper.read_pci_reg(0,0x1f,0,0,0x2)
        self.assertEqual(pci_read_value, 0x8086)
    
    def test_pch_read_pci_reg_four_bytes(self):
        pci_read_value = self.replayhelper.read_pci_reg(0,0x1f,0,0,0x4)
        self.assertEqual(pci_read_value, 0x9D4E8086)

    def test_get_thread_count(self):
        thread_count = self.replayhelper.get_threads_count()
        self.assertEqual(thread_count, 4)

    def test_read_phyis_mem_align(self):
        mem_value = self.replayhelper.read_phys_mem(0x5000, 0x2)
        self.assertEqual(mem_value, b'\xd1\x99')
        
    def test_read_phyis_mem_unaligned(self):
        mem_value = self.replayhelper.read_phys_mem(0x5001, 0x2)
        self.assertEqual(mem_value, b'\x99\xaa')

    def test_read_phyis_mem_oob(self):
        mem_value = self.replayhelper.read_phys_mem(0x5010,0x2)
        self.assertEqual(mem_value, b'\xf3\x99')

    def test_read_phys_mem_unsafe_replays_its_own_entries(self):
        self.replayhelper._data['read_phys_mem_unsafe'] = {'(983040,1)': ['\xaa']}
        self.assertEqual(self.replayhelper.read_phys_mem_unsafe(0xF0000, 1), b'\xaa')

    def test_write_phys_mem_unsafe_replays_its_own_entries(self):
        self.replayhelper._data['write_phys_mem_unsafe'] = {"(4096,1,b'\\x01')": ['1']}
        self.assertEqual(self.replayhelper.write_phys_mem_unsafe(0x1000, 1, b'\x01'), 1)

    def test_a_recorded_read_phys_mem_error_is_raised(self):
        self.replayhelper._data['read_phys_mem'] = {'(983040,1)': [PMA_ERROR]}
        with self.assertRaises(PhysicalMemoryAccessError) as ctx:
            self.replayhelper.read_phys_mem(0xF0000, 1)
        self.assertEqual(str(ctx.exception), 'not accessible')
        self.assertEqual(ctx.exception.errorcode, EFAULT)

    def test_a_recorded_read_phys_mem_unsafe_error_is_raised(self):
        self.replayhelper._data['read_phys_mem_unsafe'] = {'(983040,1)': [PMA_ERROR]}
        with self.assertRaises(PhysicalMemoryAccessError):
            self.replayhelper.read_phys_mem_unsafe(0xF0000, 1)

    def test_a_recorded_write_phys_mem_error_is_raised(self):
        self.replayhelper._data['write_phys_mem'] = {"(4096,1,b'\\x01')": [PMA_ERROR]}
        with self.assertRaises(PhysicalMemoryAccessError):
            self.replayhelper.write_phys_mem(0x1000, 1, b'\x01')

    def test_a_recorded_error_with_a_single_argument_is_raised(self):
        self.replayhelper._data['read_cr'] = {'(0,0)': ["!! <class 'chipsec.library.exceptions.UnimplementedAPIError'>: read_cr"]}
        with self.assertRaises(UnimplementedAPIError):
            self.replayhelper._get_element_eval('read_cr', (0, 0))

    def test_a_recorded_builtin_error_is_raised(self):
        self.replayhelper._data['read_phys_mem'] = {'(4096,1)': ["!! <class 'OSError'>: [Errno 5] Input/output error"]}
        with self.assertRaisesRegex(OSError, 'Input/output error'):
            self.replayhelper.read_phys_mem(0x1000, 1)

    def test_an_escaped_value_is_returned_as_recorded(self):
        payload = "!! <class 'builtins.ValueError'>: data"
        self.replayhelper._data['read_phys_mem'] = {'(4096,38)': ['!' + payload]}
        self.assertEqual(self.replayhelper.read_phys_mem(0x1000, 38), payload.encode('latin_1'))

    def test_efi_system_table_address_is_replayed(self):
        self.replayhelper._data['get_EFI_System_Table_address'] = {'()': [str(0x7FEE0018), 'None']}
        self.assertIsNone(self.replayhelper.get_EFI_System_Table_address())
        self.assertEqual(self.replayhelper.get_EFI_System_Table_address(), 0x7FEE0018)

    def test_efi_system_table_address_is_unknown_for_older_recordings(self):
        self.assertNotIn('get_EFI_System_Table_address', self.replayhelper._data)
        self.assertIsNone(self.replayhelper.get_EFI_System_Table_address())

    def test_cpuid_one(self):
        cpuid_value = self.replayhelper.cpuid(1, 0)
        self.assertEqual(cpuid_value, (526057, 51382272, 2147154879, 3219913727))
    
    def test_cpuid_two(self):
        cpuid_value = self.replayhelper.cpuid(2, 0)
        self.assertEqual(cpuid_value, (1979933441, 15775231, 0, 12779520))

    def test_write_pci_reg_new_location(self):
        self.replayhelper.write_pci_reg(0,0x3,0,0x2D, 0x33, 0x1)
        pci_read_value = self.replayhelper.read_pci_reg(0,0x3,0,0x2d,0x1)
        self.assertEqual(pci_read_value, 0xFF)

    def test_write_pci_reg_defined_location(self):
        self.replayhelper.write_pci_reg(0,0x0,0,0x0, 0x44, 0x1)
        pci_read_value = self.replayhelper.read_pci_reg(0,0x0,0,0x0,0x2)
        self.assertEqual(pci_read_value, 32902)

    def test_read_mmio_reg(self):
        mmio_read_value = self.replayhelper.read_mmio_reg(0xfed0, 0x3)
        self.assertEqual(mmio_read_value, 0xababab)

    def test_write_mmio_reg(self):
        self.replayhelper.write_mmio_reg(0x123,0x1, 0x22)
        mmio_read_value = self.replayhelper.read_mmio_reg(0x123, 0x1)
        self.assertEqual(mmio_read_value, 0x22)
        