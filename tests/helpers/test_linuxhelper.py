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


# To execute: python[3] -m unittest tests.helpers.test_linuxhelper

import unittest
from unittest.mock import patch, Mock
from multiprocessing import cpu_count
import sys

from chipsec.library.exceptions import UnimplementedAPIError
from tests.helpers.helper_utils import packer

# assuming 64 bit system. Will break on 32bit system. (would need to swap Q > I in pack())


@patch('chipsec.helper.linux.linuxhelper.fcntl.ioctl')
@patch('chipsec.helper.linux.linuxhelper.fcntl')
class LinuxHelperTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Set up mock modules
        cls._mocked_modules = ['fcntl', 'resource', 'pywintypes', 'win32service',
                               'winerror', 'win32file', 'win32api', 'win32process',
                               'win32security', 'win32serviceutil']
        for mod in cls._mocked_modules:
            sys.modules[mod] = Mock()

    @classmethod
    def tearDownClass(cls):
        # remove mocked modules
        for mod in cls._mocked_modules:
            del sys.modules[mod]
    cpacker = packer()
    ioctldict = {
        (0xc0084301, b'\xb8\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'):
            cpacker.pack_ioport(0x1),
        (0xc0084302, b'\xb8\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00U\x00\x00\x00\x00\x00\x00\x00'):
            0x01,
        (0xC0084303, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'):
            cpacker.pack_pci(0x86),
        (0xC0084303, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'):
            cpacker.pack_pci(0x8086),
        (0xC0084303, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'):
            cpacker.pack_pci(0x9A128086),
        (0xC0084303, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'):
            cpacker.pack_pci(0x86),
        (0xC0084303, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'):
            cpacker.pack_pci(0x8086),
        (0xC0084303, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'):
            cpacker.pack_pci(0xA0828086),
        (0xc0084304, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'):
            cpacker.pack_pci(0x1),
        (0xC0084307, b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'):
            cpacker.pack_cpuinfo(0x406F1),
        (0xC0084307, b'\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'):
            cpacker.pack_cpuinfo(0xFFFFF),
        (0xc0084307, b'\x08\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'):
            cpacker.pack_cpuinfo(0xfffff),
        (0xc008430c, b'\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00'):
            cpacker.custom_pack(2, 0x1, 0),
        (0xC0084312, b'\x00\x00\x01\xfe\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00'):
            b'\x00\x02\xff\x07\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00',
        (0xc0084313, b'#\x01\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"\x00\x00\x00\x00\x00\x00\x00'):
            0x1,
        (0xC0084314, b'E#\x01\x00\x00\x00\x00\x00'):
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
        (0xc0084315, b'\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'):
            cpacker.custom_pack(5, 0x200, 4),
        (0xc0084316, b'\x00\x00\x00\x16\x00\x00\x00\x00'):
            cpacker.custom_pack(1, 0x1, 0),
         }

    def ioctlret(*arg):
        for i in arg:
            if type(i) is int:
                print(hex(i))
            else:
                print(i)
        if arg[1:] in LinuxHelperTest.ioctldict:
            return LinuxHelperTest.ioctldict[arg[1:]]
        return b'\xab'*40

    @patch('chipsec.helper.linux.linuxhelper.open')
    @patch('chipsec.helper.linux.linuxhelper.subprocess.call')
    @patch('chipsec.helper.linux.linuxhelper.subprocess.check_output')
    @patch('chipsec.helper.linux.linuxhelper.os.path.exists')
    @patch('chipsec.helper.linux.linuxhelper.os.chmod')
    @patch('chipsec.helper.linux.linuxhelper.fcntl')
    def setUp(self, mock_fcntl, os_chmod, os_path_exists, subprocess_check_output, subprocess_call, mock_open):
        mock_fcntl().ioctl.side_effect = LinuxHelperTest.ioctlret
        import chipsec.helper.linux.linuxhelper as lh
        unittest.TestCase.setUp(self)
        with patch.dict(lh.os.__dict__, {'chown': lambda *args: None}):
            self.lhelper = lh.LinuxHelper()
            mock_open().return_value = True
            os_chmod().return_value = True
            os_path_exists().return_value = True
            subprocess_check_output().return_value = True
            subprocess_call().return_value = True
            # breakpoint()
            self.assertTrue(self.lhelper.create())
            self.assertTrue(self.lhelper.start())
            # breakpoint()
            pass

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        self.assertTrue(self.lhelper.delete())

    def test_map_io_space(self, _, lh_ioctl):
        self.assertRaises(UnimplementedAPIError, self.lhelper.map_io_space, 0, 0, 0)

    def test_write_phys_mem(self, _, _1):
        self.lhelper.dev_fh = Mock()
        self.lhelper.dev_fh.seek.return_value = 0
        self.lhelper.dev_fh.write.return_value = 2
        write_return = self.lhelper.write_phys_mem(0x5000, 0x2, b'\xab\xab')
        self.assertEqual(write_return, 2)

    def test_read_phyis_mem(self, _, _1):
        self.lhelper.dev_fh = Mock()
        self.lhelper.dev_fh.seek.return_value = 0
        self.lhelper.dev_fh.read.return_value = b'\xac\xdc'

        mem_value = self.lhelper.read_phys_mem(0x5000, 0x2)
        self.assertEqual(mem_value, b'\xac\xdc')

    def test_va2pa(self, _, lh_ioctl):
        lh_ioctl.side_effect = LinuxHelperTest.ioctlret
        pa = self.lhelper.va2pa(0x12345)
        self.assertEqual(pa, (0, 0))

    def test_read_pci_reg_cpu_one_byte(self, _, lh_ioctl):
        lh_ioctl.side_effect = LinuxHelperTest.ioctlret
        pci_read_value = self.lhelper.read_pci_reg(0, 0, 0, 0, 0x1)
        self.assertEqual(pci_read_value, 0x86)

    def test_read_pci_reg_cpu_two_bytes(self, _, lh_ioctl):
        lh_ioctl.side_effect = LinuxHelperTest.ioctlret
        pci_read_value = self.lhelper.read_pci_reg(0, 0, 0, 0, 0x2)
        self.assertEqual(pci_read_value, 0x8086)

    def test_read_pci_reg_cpu_four_bytes(self, _, lh_ioctl):
        lh_ioctl.side_effect = LinuxHelperTest.ioctlret
        pci_read_value = self.lhelper.read_pci_reg(0, 0, 0, 0, 0x4)
        self.assertEqual(pci_read_value, 0x9A128086)

    def test_read_pci_reg_pch_one_byte(self, _, lh_ioctl):
        lh_ioctl.side_effect = LinuxHelperTest.ioctlret
        pci_read_value = self.lhelper.read_pci_reg(0, 0x1f, 0, 0, 0x1)
        self.assertEqual(pci_read_value, 0x86)

    def test_read_pci_reg_pch_two_bytes(self, _, lh_ioctl):
        lh_ioctl.side_effect = LinuxHelperTest.ioctlret
        pci_read_value = self.lhelper.read_pci_reg(0, 0x1f, 0, 0, 0x2)
        self.assertEqual(pci_read_value, 0x8086)

    def test_read_pci_reg_pch_four_bytes(self, _, lh_ioctl):
        lh_ioctl.side_effect = LinuxHelperTest.ioctlret
        pci_read_value = self.lhelper.read_pci_reg(0, 0x1f, 0, 0, 0x4)
        self.assertEqual(pci_read_value, 0xA0828086)

    def test_write_pci_reg_cpu_one_byte(self, _, lh_ioctl):
        lh_ioctl.side_effect = LinuxHelperTest.ioctlret
        pci_write_return = self.lhelper.write_pci_reg(0, 0, 0, 0, 0x1, 0xab)
        self.assertEqual(pci_write_return, 0x1)

    # TODO Test: load_ucode_update() - Has error in implementation.
    # def test_load_ucode_update(self, _, lh_ioctl):
    #     lh_ioctl.side_effect = LinuxHelperTest.ioctlret
    #     load_ucode_update_return = self.lhelper.load_ucode_update(0, b'\x55')
    #     self.assertTrue(load_ucode_update_return)

    def test_read_io_port(self, _, lh_ioctl):
        lh_ioctl.side_effect = LinuxHelperTest.ioctlret
        ioport_read_value = self.lhelper.read_io_port(0xB8, 4)
        self.assertEqual(ioport_read_value, 0x1)

    def test_write_io_port(self, _, lh_ioctl):
        lh_ioctl.side_effect = LinuxHelperTest.ioctlret
        ioport_write_return = self.lhelper.write_io_port(0xB8, 0x55, 4)
        self.assertEqual(ioport_write_return, 0x1)

    # TODO Test: read_cr

    # TODO Test: write_cr

    # TODO Test: read_msr

    # TODO Test: write_msr

    # TODO Test: get_descriptor_table

    def test_cpuid_one(self, _, lh_ioctl):
        lh_ioctl.side_effect = LinuxHelperTest.ioctlret
        cpuid_value = self.lhelper.cpuid(1, 0)
        self.assertEqual(cpuid_value, (0x406F1, 0, 0, 0))

    def test_cpuid_two(self, _, lh_ioctl):
        lh_ioctl.side_effect = LinuxHelperTest.ioctlret
        cpuid_value = self.lhelper.cpuid(2, 0)
        self.assertEqual(cpuid_value, (0xFFFFF, 0, 0, 0))

    def test_alloc_phys_mem(self, _, lh_ioctl):
        lh_ioctl.side_effect = LinuxHelperTest.ioctlret
        alloc_return = self.lhelper.alloc_phys_mem(0x8, 0x1000_0000_0000)
        self.assertEqual(alloc_return, (0x1, 0x0))

    def test_free_phys_mem(self, _, lh_ioctl):
        lh_ioctl.side_effect = LinuxHelperTest.ioctlret
        free_return = self.lhelper.free_phys_mem(0x1600_0000)
        self.assertEqual(free_return, 0x1)

    def test_read_mmio_reg(self, _, lh_ioctl):
        lh_ioctl.side_effect = LinuxHelperTest.ioctlret
        mmio_read_value = self.lhelper.read_mmio_reg(0xfe010000, 0x4)
        self.assertEqual(mmio_read_value, 0x7FF0200)

    def test_write_mmio_reg(self, _, lh_ioctl):
        lh_ioctl.side_effect = LinuxHelperTest.ioctlret
        self.lhelper.write_mmio_reg(0x123, 0x1, 0x22)

    def test_get_ACPI_table(self, _, lh_ioctl):
        self.assertRaises(UnimplementedAPIError, self.lhelper.get_ACPI_table, "SDEV")

    def test_msgbus_send_read_message(self, _, lh_ioctl):
        lh_ioctl.side_effect = LinuxHelperTest.ioctlret
        msg_s_r_m = self.lhelper.msgbus_send_read_message(0x1, 0x2)
        self.assertEqual(msg_s_r_m, 0x200)

    def test_msgbus_send_write_message(self, _, lh_ioctl):
        lh_ioctl.side_effect = LinuxHelperTest.ioctlret
        msg_s_r_m = self.lhelper.msgbus_send_write_message(0x1, 0x2, 0x3)
        self.assertIsNone(msg_s_r_m)

    # TODO Test: get_affinity

    # TODO Test: set_affinity

    # TODO Test: EFI_supported

    # TODO Test: delete_EFI_variable

    # TODO Test: list_EFI_variables

    # TODO Test: get_EFI_variable

    # TODO Test: set_EFI_variable

    # TODO Test: hypercall

    # TODO Test: send_sw_smi

    # TODO Test: get_tool_info

    def test_get_threads_count(self, _, _1):
        thread_count = self.lhelper.get_threads_count()
        self.assertEqual(thread_count, cpu_count())

    def test_retpoline_enabled(self, _, lh_ioctl):
        self.assertRaises(NotImplementedError, self.lhelper.retpoline_enabled)
