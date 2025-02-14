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


# To execute: python -m unittest tests.helpers.test_recordhelper
from os import remove
import unittest
from os.path import join, isfile
import chipsec.helper.replay.replayhelper as rph
import chipsec.helper.record.recordhelper as rch


class RecordHelperTest(unittest.TestCase):

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        if isfile(self.temp_file):
            remove(self.temp_file)

    def test_record(self):
        self.original_file = join("tests", "helpers", "kblreplaytest.json")
        self.temp_file = join("tests", "helpers", "kblrecordtest_temp.json")
        if isfile(self.temp_file):
            remove(self.temp_file)
        self.replayhelper = rph.ReplayHelper(self.original_file)
        self.recordhelper = rch.RecordHelper(self.temp_file)
        self.recordhelper.switch_subhelper(self.replayhelper)
        self.assertTrue(self.recordhelper.create())
        self.assertTrue(self.recordhelper.start())

        pci_read_value = self.recordhelper.read_pci_reg(0, 0, 0, 0, 0x1)
        self.assertEqual(pci_read_value, 0x86)

        pci_read_value = self.recordhelper.read_pci_reg(0, 0, 0, 0, 0x2)
        self.assertEqual(pci_read_value, 0x8086)

        pci_read_value = self.recordhelper.read_pci_reg(0, 0, 0, 0, 0x4)
        self.assertEqual(pci_read_value, 0x59048086)

        pci_read_value = self.recordhelper.read_pci_reg(0, 0x1f, 0, 0, 0x1)
        self.assertEqual(pci_read_value, 0x86)

        pci_read_value = self.recordhelper.read_pci_reg(0, 0x1f, 0, 0, 0x2)
        self.assertEqual(pci_read_value, 0x8086)

        pci_read_value = self.recordhelper.read_pci_reg(0, 0x1f, 0, 0, 0x4)
        self.assertEqual(pci_read_value, 0x9D4E8086)

        thread_count = self.recordhelper.get_threads_count()
        self.assertEqual(thread_count, 4)

        mem_value = self.recordhelper.read_phys_mem(0x5000, 0x2)
        self.assertEqual(mem_value, b'\xd1\x99')

        mem_value = self.recordhelper.read_phys_mem(0x5001, 0x2)
        self.assertEqual(mem_value, b'\x99\xaa')

        mem_value = self.recordhelper.read_phys_mem(0x5010, 0x2)
        self.assertEqual(mem_value, b'\xf3\x99')

        cpuid_value = self.recordhelper.cpuid(1, 0)
        self.assertEqual(cpuid_value, (526057, 51382272, 2147154879, 3219913727))

        cpuid_value = self.recordhelper.cpuid(2, 0)
        self.assertEqual(cpuid_value, (1979933441, 15775231, 0, 12779520))

        self.recordhelper.write_pci_reg(0, 0x3, 0, 0x2D, 0x33, 0x1)
        pci_read_value = self.recordhelper.read_pci_reg(0, 0x3, 0, 0x2d, 0x1)
        self.assertEqual(pci_read_value, 0xFF)

        self.recordhelper.write_pci_reg(0, 0x0, 0, 0x0, 0x44, 0x1)
        pci_read_value = self.recordhelper.read_pci_reg(0, 0x0, 0, 0x0, 0x2)
        self.assertEqual(pci_read_value, 32902)

        mmio_read_value = self.recordhelper.read_mmio_reg(0xfed0, 0x3)
        self.assertEqual(mmio_read_value, 0xababab)

        self.recordhelper.write_mmio_reg(0x123, 0x1, 0x22)
        mmio_read_value = self.recordhelper.read_mmio_reg(0x123, 0x1)
        self.assertEqual(mmio_read_value, 0x22)

        self.assertTrue(self.recordhelper.stop())
        self.assertTrue(self.recordhelper.delete())
        self.assertTrue(self._compare_replay_and_record())

    def _compare_replay_and_record(self):
        with open(self.original_file, 'r') as of:
            original_lines = of.readlines()
        with open(self.temp_file, 'r') as tf:
            temp_lines = tf.readlines()
        if len(original_lines) != len(temp_lines):
            return False
        for i in range(len(original_lines)):
            if original_lines[i] != temp_lines[i]:
                print(f"{self.original_file} line {i+1}:{original_lines[i]}")
                print(f"{self.temp_file} line {i+1}:{temp_lines[i]}")
                return False
        return True

