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

# To execute: python[3] -m unittest tests.helpers.test_windowshelper

import unittest
from unittest.mock import patch, Mock
import sys

from chipsec.library.exceptions import UnimplementedAPIError
from tests.helpers.helper_utils import packer

DEBUG = False  # Set to True to print the args passed to the driver
DRIVER_HANDLE = '12345'


class pcibdf_sideeffect():
    def __init__(self, b, d, f, o) -> None:
        self.BUS = b
        self.DEV = d
        self.FUNC = f
        self.OFF = o


def print_args(args):
    for i in args:
        if type(i) is int:
            print(hex(i))
        else:
            print(i)


@patch('chipsec.helper.windows.windowshelper.win32file.CreateFile')
@patch('chipsec.helper.windows.windowshelper.win32file.DeviceIoControl')
class WindowsHelperTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Set up mock modules
        cls._mocked_modules = ['pywintypes', 'win32service', 'windll',
                               'winerror', 'win32file', 'win32api', 'win32process',
                               'win32security', 'win32serviceutil', 'ctypes', 'win32.lib']
        for mod in cls._mocked_modules:
            sys.modules[mod] = Mock()

    @classmethod
    def tearDownClass(cls):
        # remove mocked modules
        for mod in cls._mocked_modules:
            del sys.modules[mod]

    ipacker = packer('I')
    qpacker = packer()
    ioctl_dict = {
        (0x22e028, b'\x00\x00\x00\x004\x12\x00\x00\x08\x00\x00\x00abc'):
            b'\x01',
        (0x22e024, b'\x00\x00\x00\x00\x00P\x00\x00\x02\x00\x00\x00'):
            b'\xac\xdc',
        (0x22e054, b'E#\x01\x00\x00\x00\x00\x00'):
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
        (0x22e01c, b'\x00\x00\x00\x00\x00\x00\x00\x00\x01'):
            b'\x86',
        (0x22e01c, b'\x00\x00\x00\x00\x00\x00\x00\x00\x02'):
            b'\x86\x80',
        (0x22e01c, b'\x00\x00\x00\x00\x00\x00\x00\x00\x04'):
            ipacker.custom_pack(1, 0x9a128086, 0),
        (0x22e038, b'\xb8\x00\x01'):
            b'\x11',
        (0x22e038, b'\xb8\x00\x02'):
            b'\x22\x11',
        (0x22e038, b'\xb8\x00\x04'):
            b'\x44\x33\x22\x11',
        (0x22e04c, b'\x01\x00\x00\x00\x00\x00\x00\x00'):
            ipacker.pack_cpuinfo(0x406F1),
        (0x22e070, b'\x00\x00\x00\x00\x00\x00\x01\xfe\x04\x00\x00\x00'):
            ipacker.custom_pack(1, 0x7FF0200, 0),
        (0x22e048, b'\x00\x00\x00\x00\x00\x10\x00\x00\x08\x00\x00\x00'):
            qpacker.custom_pack(2, 1, 0),
        (0x22e064, b'\x00\x00\x00\x00\x00\x00'):
            b'3\x00\x05\x80\x00\x00\x00\x00',
        (0x22e060, b'\x00\x003\x00\x05\x80\x00\x00\x00\x00\x00\x00\x00\x00'):
            b'',
        (0x22e034, b'\x00\x00\x00\x00:\x00\x00\x00'):
            b'\x01\x00\x00\x00\x00\x00\x00\x00',
        (0x22e030, b'\x00\x00\x00\x00:\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'):
            b'',
        (0x22e040, b'\x00\x00\x00\x00\x01'):
            b'W\x00\xb0\x1f\xeav\x04\xf8\xff\xff\xb0\xbf0\x03\x00\x00\x00\x00',
    }

    def ioctlret(*args):
        if DEBUG:
            print_args(args)
        if args[1:3] in WindowsHelperTest.ioctl_dict:
            return WindowsHelperTest.ioctl_dict[args[1:3]]
        return b'\xab'*40

    @patch('chipsec.helper.windows.windowshelper.windll.ntdll.NtQuerySystemInformation')
    @patch('chipsec.helper.windows.windowshelper.logger')
    @patch('chipsec.helper.windows.windowshelper.win32file')
    @patch('chipsec.helper.windows.windowshelper.win32serviceutil')
    @patch('chipsec.helper.windows.windowshelper.win32service')
    @patch('chipsec.helper.windows.windowshelper.os.path.isfile')
    @patch('chipsec.helper.windows.windowshelper.platform')
    def setUp(self, mock_platform, os_path_isfile, mock_win32sservice, mock_win32serviceutil, mock_win32file, mock_logger, mock_NtQuerySystemInformation):
        unittest.TestCase.setUp(self)
        mock_platform.system.return_value = "windows"
        import chipsec.helper.windows.windowshelper as wh
        wh.win32service.error = Exception
        wh.win32security.TOKEN_READ = 0x20008
        wh.win32security.TOKEN_ADJUST_PRIVILEGES = 0x20
        wh.win32serviceutil.QueryServiceStatus.return_value = (16, 4, 197, 0, 0, 0, 0)
        wh.win32service.SERVICE_STOPPED = 1
        wh.win32service.SERVICE_RUNNING = 4
        wh.win32service.SERVICE_QUERY_STATUS = 4
        wh.win32service.SERVICE_START = 16
        wh.win32service.SERVICE_STOP = 32
        wh.win32service.SERVICE_KERNEL_DRIVER = 1
        wh.win32service.SERVICE_DEMAND_START = 3
        wh.win32service.SERVICE_ERROR_NORMAL = 1
        wh.FILE_SHARE_READ = 1
        wh.FILE_SHARE_WRITE = 2
        wh.OPEN_EXISTING = 3
        wh.FILE_ATTRIBUTE_NORMAL = 0x80
        wh.FILE_FLAG_OVERLAPPED = 0x40000000
        wh.INVALID_HANDLE_VALUE = -1
        wh.c_char = type('', (object,), {"__mul__": lambda self, other: Mock()})()
        os_path_isfile().return_value = True
        mock_win32sservice.CreateService.return_value = DRIVER_HANDLE
        mock_win32sservice.CloseServiceHandle().return_value = None
        self.wh = wh
        with patch.dict(wh.os.__dict__, {'chown': lambda *args: None}):
            self.whelper = wh.WindowsHelper()
            self.assertTrue(self.whelper.create())
            self.assertTrue(self.whelper.start())

    @patch('chipsec.helper.windows.windowshelper.win32api.CloseHandle')
    def tearDown(self, _):
        unittest.TestCase.tearDown(self)
        self.assertTrue(self.whelper.delete())
        self.whelper.__del__()

    # TODO def test_map_io_space(self, _):

    def _assign_mocks(self, mocks):
        mock_ioctl = mocks[0]
        mock_createfile = mocks[1]
        mock_ioctl.side_effect = WindowsHelperTest.ioctlret
        mock_createfile.return_value = DRIVER_HANDLE

    def test_write_phys_mem(self, *mocks):
        self._assign_mocks(mocks)
        retval = self.whelper.write_phys_mem(0x1234, 0x8, "abc")
        self.assertEqual(retval, 0x1)

    def test_read_phys_mem(self, *mocks):
        self._assign_mocks(mocks)
        mem_value = self.whelper.read_phys_mem(0x5000, 0x2)
        self.assertEqual(mem_value, b'\xac\xdc')

    def test_va2pa(self, *mocks):
        self._assign_mocks(mocks)
        pa = self.whelper.va2pa(0x12345)
        self.assertEqual(pa, (0, 0))

    @patch('chipsec.helper.windows.windowshelper.PCI_BDF')
    def test_read_pci_reg_cpu_one_byte(self, pci_bdf, *mocks):
        self._assign_mocks(mocks)
        pci_bdf.side_effect = pcibdf_sideeffect
        pci_read_value = self.whelper.read_pci_reg(0, 0, 0, 0, 0x1)
        self.assertEqual(pci_read_value, 0x86)

    @patch('chipsec.helper.windows.windowshelper.PCI_BDF')
    def test_read_pci_reg_cpu_two_bytes(self, pci_bdf, *mocks):
        self._assign_mocks(mocks)
        pci_bdf.side_effect = pcibdf_sideeffect
        pci_read_value = self.whelper.read_pci_reg(0, 0, 0, 0, 0x2)
        self.assertEqual(pci_read_value, 0x8086)

    @patch('chipsec.helper.windows.windowshelper.PCI_BDF')
    def test_read_pci_reg_cpu_four_bytes(self, pci_bdf, *mocks):
        self._assign_mocks(mocks)
        pci_bdf.side_effect = pcibdf_sideeffect
        pci_read_value = self.whelper.read_pci_reg(0, 0, 0, 0, 0x4)
        self.assertEqual(pci_read_value, 0x9A128086)

    @patch('chipsec.helper.windows.windowshelper.PCI_BDF')
    def test_write_pci_reg_cpu_one_byte(self, pci_bdf, *mocks):
        self._assign_mocks(mocks)
        pci_bdf.side_effect = pcibdf_sideeffect
        pci_write_return = self.whelper.write_pci_reg(0, 0, 0, 0, 0x1, 0xab)
        self.assertTrue(pci_write_return)

    def test_load_ucode_update(self, *mocks):
        self._assign_mocks(mocks)
        load_ucode_update_return = self.whelper.load_ucode_update(0, b'\x55')
        self.assertTrue(load_ucode_update_return)

    def test_read_io_port_1byte(self, *mocks):
        self._assign_mocks(mocks)
        ioport_read_value = self.whelper.read_io_port(0xB8, 1)
        self.assertEqual(ioport_read_value, 0x11)

    def test_read_io_port_2bytes(self, *mocks):
        self._assign_mocks(mocks)
        ioport_read_value = self.whelper.read_io_port(0xB8, 2)
        self.assertEqual(ioport_read_value, 0x1122)

    def test_read_io_port_4bytes(self, *mocks):
        self._assign_mocks(mocks)
        ioport_read_value = self.whelper.read_io_port(0xB8, 4)
        self.assertEqual(ioport_read_value, 0x11223344)

    def test_write_io_port(self, *mocks):
        self._assign_mocks(mocks)
        ioport_write_return = self.whelper.write_io_port(0xB8, 0x55, 4)
        self.assertTrue(ioport_write_return)

    def test_read_cr(self, *mocks):
        self._assign_mocks(mocks)
        read_cr_return = self.whelper.read_cr(0, 0)
        self.assertEqual(read_cr_return, 0x80050033)

    def test_write_cr(self, *mocks):
        self._assign_mocks(mocks)
        write_cr_return = self.whelper.write_cr(0, 0, 0x80050033)
        self.assertTrue(write_cr_return)

    def test_read_msr(self, *mocks):
        self._assign_mocks(mocks)
        read_msr_return = self.whelper.read_msr(0, 0x3A)
        self.assertEqual(read_msr_return, (1, 0))

    def test_write_msr(self, *mocks):
        self._assign_mocks(mocks)
        write_msr_return = self.whelper.write_msr(0, 0x3a, 1, 0)
        self.assertTrue(write_msr_return)

    def test_get_descriptor_table(self, *mocks):
        self._assign_mocks(mocks)
        get_des_table_return = self.whelper.get_descriptor_table(0, 1)
        self.assertEqual(get_des_table_return,  (0x57, 0xfffff80476ea1fb0, 0x330bfb0))

    def test_cpuid_one(self, *mocks):
        self._assign_mocks(mocks)
        cpuid_value = self.whelper.cpuid(1, 0)
        self.assertEqual(cpuid_value, (0x406F1, 0, 0, 0))

    def test_alloc_phys_mem(self, *mocks):
        self._assign_mocks(mocks)
        alloc_return = self.whelper.alloc_phys_mem(0x8, 0x1000_0000_0000)
        self.assertEqual(alloc_return, (0x1, 0x0))

    def test_free_phys_mem(self, *mocks):
        self._assign_mocks(mocks)
        free_return = self.whelper.free_phys_mem(0x1600_0000)
        self.assertIsNone(free_return)

    def test_read_mmio_reg(self, *mocks):
        self._assign_mocks(mocks)
        mmio_read_value = self.whelper.read_mmio_reg(0xfe010000, 0x4)
        self.assertEqual(mmio_read_value, 0x7FF0200)

    def test_write_mmio_reg(self, *mocks):
        self._assign_mocks(mocks)
        self.whelper.write_mmio_reg(0x123, 0x1, 0x22)

    # TODO def test_get_ACPI_SDT(self, *mocks):
        # self._assign_mocks(mocks)

    # TODO def test_get_ACPI_table(self, *mocks):
        # self._assign_mocks(mocks)

    def test_msgbus_send_read_message(self, *_):
        self.assertRaises(UnimplementedAPIError, self.whelper.msgbus_send_read_message, 0x1, 0x2)

    def test_msgbus_send_write_message(self, *_):
        self.assertRaises(UnimplementedAPIError, self.whelper.msgbus_send_write_message, 0x1, 0x2, 3)

    def test_msgbus_send_message(self, *_):
        self.assertRaises(UnimplementedAPIError, self.whelper.msgbus_send_message, 0x1, 0x2, 3)

    # TODO def test_get_affinity(self, *mocks):
        # self._assign_mocks(mocks)

    # TODO def test_set_affinity(self, *mocks):
        # self._assign_mocks(mocks)

    # TODO def test_EFI_supported(self, *mocks):
        # self._assign_mocks(mocks)

    # TODO def test_delete_EFI_variable(self, *mocks):
        # self._assign_mocks(mocks)

    # TODO def test_list_EFI_variables(self, *mocks):
        # self._assign_mocks(mocks)

    # TODO def test_get_EFI_variable(self, *mocks):
        # self._assign_mocks(mocks)

    # TODO def test_set_EFI_variable(self, *mocks):
        # self._assign_mocks(mocks)

    # TODO def test_hypercall(self, *mocks):
        # self._assign_mocks(mocks)

    # TODO def test_send_sw_smi(self, *mocks):
        # self._assign_mocks(mocks)

    # TODO def test_get_tool_info(self, *mocks):
        # self._assign_mocks(mocks)

    @patch('chipsec.helper.windows.windowshelper.kernel32.GetActiveProcessorCount')
    @patch('chipsec.helper.windows.windowshelper.kernel32.GetActiveProcessorGroupCount')
    def test_get_threads_count(self, mock_kernal32_GetActiveProcessorGroupCount, mock_kernal32_GetActiveProcessorCount, *_):
        mock_kernal32_GetActiveProcessorGroupCount.return_value = 0xffff0004
        mock_kernal32_GetActiveProcessorCount.return_value = 2
        thread_count = self.whelper.get_threads_count()
        self.assertEqual(thread_count, 0x8)

    @patch('chipsec.helper.windows.windowshelper.sizeof')
    @patch('chipsec.helper.windows.windowshelper.addressof')
    @patch('chipsec.helper.windows.windowshelper.c_uint32')
    def test_retpoline_enabled(self, mock_c_uint32, *_):
        mock_c_uint32.return_value = type('', (object,), {"value": 0x4000})()
        self.assertEqual(self.whelper.retpoline_enabled(), True)

# test_reg_get_control
# test_spi_dump
# test_spi_info
