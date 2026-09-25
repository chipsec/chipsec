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


# To execute: python[3] -m unittest tests.helpers.test_linuxnativehelper

import mmap
import multiprocessing
import struct
import sys
import unittest
from unittest.mock import MagicMock, mock_open, patch

import chipsec.helper.linuxnative.linuxnativehelper as lnh
from chipsec.library.exceptions import OsHelperError

MOD = 'chipsec.helper.linuxnative.linuxnativehelper'

PACK = 'Q' if sys.maxsize > 2 ** 32 else 'I'


class FakeMapping(bytearray):
    """bytearray that can carry the start/end attributes of a MemoryMapping."""


def make_region(start: int, length: int) -> FakeMapping:
    region = FakeMapping(length)
    region.start = start
    region.end = start + length
    return region


def new_helper() -> 'lnh.LinuxNativeHelper':
    helper = lnh.LinuxNativeHelper()
    helper.init()
    return helper


class LinuxNativeHelperLifecycleTest(unittest.TestCase):

    def setUp(self):
        self.helper = new_helper()

    def test_create(self):
        self.assertTrue(self.helper.create())

    def test_start_initializes_pack(self):
        self.helper._pack = None
        self.assertTrue(self.helper.start())
        self.assertEqual(self.helper._pack, PACK)

    def test_delete(self):
        self.assertTrue(self.helper.delete())

    @patch(f'{MOD}.os.close')
    def test_stop_closes_dev_mem(self, os_close):
        self.helper.dev_mem = 7
        self.assertTrue(self.helper.stop())
        os_close.assert_called_once_with(7)
        self.assertIsNone(self.helper.dev_mem)

    @patch(f'{MOD}.os.close')
    def test_close_without_dev_mem(self, os_close):
        self.helper.dev_mem = None
        self.helper.close()
        os_close.assert_not_called()
        self.assertIsNone(self.helper.dev_mem)

    def test_get_helper_returns_instance(self):
        self.assertIsInstance(lnh.get_helper(), lnh.LinuxNativeHelper)

    def test_memory_mapping_tracks_boundaries(self):
        region = lnh.MemoryMapping(-1, mmap.PAGESIZE,
                                   mmap.MAP_SHARED | mmap.MAP_ANONYMOUS,
                                   mmap.PROT_READ | mmap.PROT_WRITE,
                                   offset=0)
        try:
            self.assertEqual(region.start, 0)
            self.assertEqual(region.end, mmap.PAGESIZE)
            self.assertEqual(len(region), mmap.PAGESIZE)
        finally:
            region.close()


class LinuxNativeHelperDeviceAvailabilityTest(unittest.TestCase):

    def setUp(self):
        self.helper = new_helper()

    @patch(f'{MOD}.os.open')
    def test_devmem_available_cached(self, os_open):
        self.helper.dev_mem = 3
        self.assertTrue(self.helper.devmem_available())
        os_open.assert_not_called()

    @patch(f'{MOD}.os.open', return_value=11)
    def test_devmem_available_opens_device(self, os_open):
        self.assertTrue(self.helper.devmem_available())
        self.assertEqual(self.helper.dev_mem, 11)
        os_open.assert_called_once_with('/dev/mem', lnh.os.O_RDWR)

    @patch(f'{MOD}.os.open', side_effect=OSError(13, 'Permission denied'))
    def test_devmem_available_error(self, _os_open):
        with self.assertRaises(OsHelperError) as ctx:
            self.helper.devmem_available()
        self.assertIn('/dev/mem', str(ctx.exception))

    @patch(f'{MOD}.os.open')
    def test_devport_available_cached(self, os_open):
        self.helper.dev_port = 4
        self.assertTrue(self.helper.devport_available())
        os_open.assert_not_called()

    @patch(f'{MOD}.os.open', return_value=12)
    def test_devport_available_opens_device(self, os_open):
        self.assertTrue(self.helper.devport_available())
        self.assertEqual(self.helper.dev_port, 12)
        os_open.assert_called_once_with('/dev/port', lnh.os.O_RDWR)

    @patch(f'{MOD}.os.open', side_effect=OSError(13, 'Permission denied'))
    def test_devport_available_error(self, _os_open):
        with self.assertRaises(OsHelperError) as ctx:
            self.helper.devport_available()
        self.assertIn('/dev/port', str(ctx.exception))

    @patch(f'{MOD}.os.open')
    def test_devmsr_available_cached(self, os_open):
        self.helper.dev_msr = {0: 5}
        self.assertTrue(self.helper.devmsr_available())
        os_open.assert_not_called()

    @patch(f'{MOD}.os.open', side_effect=[20, 21])
    @patch(f'{MOD}.os.listdir', return_value=['0', '1', 'microcode'])
    @patch(f'{MOD}.os.system')
    @patch(f'{MOD}.os.path.exists', return_value=True)
    def test_devmsr_available_skips_modprobe(self, _exists, os_system, _listdir, _os_open):
        self.assertTrue(self.helper.devmsr_available())
        os_system.assert_not_called()
        self.assertEqual(self.helper.dev_msr, {0: 20, 1: 21})

    @patch(f'{MOD}.os.open', side_effect=[30])
    @patch(f'{MOD}.os.listdir', return_value=['0'])
    @patch(f'{MOD}.os.system')
    @patch(f'{MOD}.os.path.exists', return_value=False)
    def test_devmsr_available_loads_module(self, _exists, os_system, _listdir, _os_open):
        self.assertTrue(self.helper.devmsr_available())
        os_system.assert_called_once_with('modprobe msr')
        self.assertEqual(self.helper.dev_msr, {0: 30})

    @patch(f'{MOD}.os.open', side_effect=OSError(13, 'Permission denied'))
    @patch(f'{MOD}.os.listdir', return_value=['0'])
    @patch(f'{MOD}.os.path.exists', return_value=True)
    def test_devmsr_available_error(self, _exists, _listdir, _os_open):
        with self.assertRaises(OsHelperError) as ctx:
            self.helper.devmsr_available()
        self.assertIn('/dev/cpu/CPUNUM/msr', str(ctx.exception))


class LinuxNativeHelperPciTest(unittest.TestCase):

    def setUp(self):
        self.helper = new_helper()

    @patch(f'{MOD}.open', new_callable=mock_open, read_data=b'\x86\x80\x12\x9a')
    @patch(f'{MOD}.os.path.exists', return_value=True)
    def test_read_pci_reg_from_sysfs(self, exists, mocked_open):
        value = self.helper.read_pci_reg(0, 0x1f, 0, 0, 4)
        self.assertEqual(value, 0x9A128086)
        exists.assert_called_once_with('/sys/bus/pci/devices/0000:00:1f.0/config')
        mocked_open.assert_called_once_with('/sys/bus/pci/devices/0000:00:1f.0/config', 'rb')

    @patch(f'{MOD}.open', new_callable=mock_open, read_data=b'\x86\x80')
    @patch(f'{MOD}.os.path.exists', return_value=True)
    def test_read_pci_reg_from_sysfs_two_bytes(self, _exists, _mocked_open):
        self.assertEqual(self.helper.read_pci_reg(1, 2, 3, 0, 2, domain=1), 0x8086)

    @patch(f'{MOD}.open', side_effect=OSError(13, 'Permission denied'))
    @patch(f'{MOD}.os.path.exists', return_value=True)
    def test_read_pci_reg_open_failure(self, _exists, _mocked_open):
        with self.assertRaises(OsHelperError) as ctx:
            self.helper.read_pci_reg(0, 0, 0, 0, 4)
        self.assertIn('Unable to open', str(ctx.exception))

    @patch(f'{MOD}.LegacyPci.read_pci_config', return_value=0x1122334455667788)
    @patch(f'{MOD}.os.path.exists', return_value=False)
    def test_read_pci_reg_legacy_masks_by_size(self, _exists, legacy_read):
        self.assertEqual(self.helper.read_pci_reg(0, 0, 0, 0, 1), 0x88)
        self.assertEqual(self.helper.read_pci_reg(0, 0, 0, 0, 2), 0x7788)
        self.assertEqual(self.helper.read_pci_reg(0, 0, 0, 0, 4), 0x55667788)
        self.assertEqual(self.helper.read_pci_reg(0, 0, 0, 0, 8), 0x1122334455667788)
        self.assertEqual(legacy_read.call_count, 4)

    @patch(f'{MOD}.LegacyPci.read_pci_config', return_value=0x1122334455667788)
    @patch(f'{MOD}.os.path.exists', return_value=False)
    def test_read_pci_reg_legacy_unknown_size_is_unmasked(self, _exists, _legacy_read):
        self.assertEqual(self.helper.read_pci_reg(0, 0, 0, 0, 3), 0x1122334455667788)

    @patch(f'{MOD}.os.path.exists', return_value=False)
    def test_read_pci_reg_extended_offset_without_sysfs(self, _exists):
        with self.assertRaises(ValueError):
            self.helper.read_pci_reg(0, 0, 0, 0x100, 4)

    @patch(f'{MOD}.open', new_callable=mock_open)
    @patch(f'{MOD}.os.path.exists', return_value=True)
    def test_write_pci_reg_to_sysfs(self, _exists, mocked_open):
        self.assertEqual(self.helper.write_pci_reg(0, 0x1f, 0, 0x10, 0x9A128086, 4), 0)
        mocked_open.assert_called_once_with('/sys/bus/pci/devices/0000:00:1f.0/config', 'wb')
        mocked_open.return_value.write.assert_called_once_with(b'\x86\x80\x12\x9a')

    @patch(f'{MOD}.LegacyPci.write_pci_config')
    @patch(f'{MOD}.os.path.exists', return_value=False)
    def test_write_pci_reg_legacy(self, _exists, legacy_write):
        self.assertEqual(self.helper.write_pci_reg(0, 2, 1, 0x40, 0x55, 1), -1)
        legacy_write.assert_called_once_with(0, 2, 1, 0x40, 0x55)

    @patch(f'{MOD}.open', side_effect=OSError(13, 'Permission denied'))
    @patch(f'{MOD}.os.path.exists', return_value=True)
    def test_write_pci_reg_open_failure(self, _exists, _mocked_open):
        with self.assertRaises(OsHelperError) as ctx:
            self.helper.write_pci_reg(0, 0, 0, 0, 0x1, 1)
        self.assertIn('Unable to open', str(ctx.exception))


class LinuxNativeHelperMmioTest(unittest.TestCase):

    def setUp(self):
        self.helper = new_helper()
        self.helper.dev_mem = 9

    def test_memory_mapping_lookup(self):
        region = make_region(0x1000, 0x1000)
        self.helper.mappings = [region]
        self.assertIs(self.helper.memory_mapping(0x1000, 4), region)
        self.assertIs(self.helper.memory_mapping(0x1FFC, 4), region)
        self.assertIsNone(self.helper.memory_mapping(0x1FFE, 4))
        self.assertIsNone(self.helper.memory_mapping(0x0FFF, 4))

    @patch(f'{MOD}.resource.getpagesize', return_value=0x1000)
    @patch(f'{MOD}.MemoryMapping')
    def test_map_io_space_creates_mapping(self, memory_mapping, _getpagesize):
        memory_mapping.return_value = make_region(0x2000, 0x1000)
        self.helper.map_io_space(0x2004, 4, 0)
        memory_mapping.assert_called_once_with(9, 0x1000, mmap.MAP_SHARED,
                                               mmap.PROT_READ | mmap.PROT_WRITE,
                                               offset=0x2000)
        self.assertEqual(len(self.helper.mappings), 1)

    @patch(f'{MOD}.resource.getpagesize', return_value=0x1000)
    @patch(f'{MOD}.MemoryMapping')
    def test_map_io_space_skips_existing_mapping(self, memory_mapping, _getpagesize):
        self.helper.mappings = [make_region(0x2000, 0x1000)]
        self.helper.map_io_space(0x2004, 4, 0)
        memory_mapping.assert_not_called()

    def test_read_mmio_reg_byte(self):
        region = make_region(0x1000, 16)
        region[3] = 0xAB
        self.helper.mappings = [region]
        self.assertEqual(self.helper.read_mmio_reg(0x1003, 1), 0xAB)

    def test_read_mmio_reg_aligned(self):
        region = make_region(0x1000, 16)
        region[4:8] = b'\x86\x80\x12\x9a'
        self.helper.mappings = [region]
        self.assertEqual(self.helper.read_mmio_reg(0x1004, 4), 0x9A128086)

    def test_read_mmio_reg_unaligned(self):
        region = make_region(0x1000, 16)
        region[2:6] = b'\x11\x22\x33\x44'
        self.helper.mappings = [region]
        self.assertEqual(self.helper.read_mmio_reg(0x1002, 4), 0x44332211)

    def test_read_mmio_reg_maps_missing_region(self):
        region = make_region(0x1000, 16)
        region[0:4] = b'\x01\x00\x00\x00'
        self.helper.memory_mapping = MagicMock(side_effect=[None, region])
        self.helper.map_io_space = MagicMock()
        self.assertEqual(self.helper.read_mmio_reg(0x1000, 4), 1)
        self.helper.map_io_space.assert_called_once_with(0x1000, 4, 0)

    def test_read_mmio_reg_without_devmem(self):
        self.helper.devmem_available = MagicMock(return_value=False)
        self.assertEqual(self.helper.read_mmio_reg(0x1000, 4), 0)

    @patch(f'{MOD}.logger')
    def test_read_mmio_reg_unmappable_region(self, mock_logger):
        self.helper.memory_mapping = MagicMock(return_value=None)
        self.helper.map_io_space = MagicMock()
        # The helper only logs the failure, so the following memoryview(None) raises.
        with self.assertRaises(TypeError):
            self.helper.read_mmio_reg(0x1000, 4)
        mock_logger.return_value.log_error.assert_called_once_with('Unable to map region 00001000')

    def test_write_mmio_reg_byte(self):
        region = make_region(0x1000, 16)
        self.helper.mappings = [region]
        self.assertIsNone(self.helper.write_mmio_reg(0x1005, 1, 0x5A))
        self.assertEqual(region[5], 0x5A)

    def test_write_mmio_reg_aligned(self):
        region = make_region(0x1000, 16)
        self.helper.mappings = [region]
        self.helper.write_mmio_reg(0x1008, 4, 0x9A128086)
        self.assertEqual(bytes(region[8:12]), b'\x86\x80\x12\x9a')

    def test_write_mmio_reg_unaligned(self):
        region = make_region(0x1000, 16)
        self.helper.mappings = [region]
        self.helper.write_mmio_reg(0x1002, 4, 0x44332211)
        self.assertEqual(bytes(region[2:6]), b'\x11\x22\x33\x44')

    def test_write_mmio_reg_maps_missing_region(self):
        region = make_region(0x1000, 16)
        self.helper.memory_mapping = MagicMock(side_effect=[None, region])
        self.helper.map_io_space = MagicMock()
        self.helper.write_mmio_reg(0x1000, 1, 0x7F)
        self.helper.map_io_space.assert_called_once_with(0x1000, 1, 0)
        self.assertEqual(region[0], 0x7F)

    def test_write_mmio_reg_without_devmem(self):
        self.helper.devmem_available = MagicMock(return_value=False)
        self.assertIsNone(self.helper.write_mmio_reg(0x1000, 4, 0x1))

    @patch(f'{MOD}.logger')
    def test_write_mmio_reg_unmappable_region(self, mock_logger):
        self.helper.memory_mapping = MagicMock(return_value=None)
        self.helper.map_io_space = MagicMock()
        with self.assertRaises(TypeError):
            self.helper.write_mmio_reg(0x1000, 4, 0x1)
        mock_logger.return_value.log_error.assert_called_once_with('Unable to map region 00001000')


class LinuxNativeHelperPhysMemTest(unittest.TestCase):

    def setUp(self):
        self.helper = new_helper()
        self.helper.dev_mem = 9

    @patch(f'{MOD}.os.read', return_value=b'\xaa\xbb')
    @patch(f'{MOD}.os.lseek')
    def test_read_phys_mem(self, os_lseek, os_read):
        self.assertEqual(self.helper.read_phys_mem(0x5000, 2), b'\xaa\xbb')
        os_lseek.assert_called_once_with(9, 0x5000, lnh.os.SEEK_SET)
        os_read.assert_called_once_with(9, 2)

    def test_read_phys_mem_without_devmem(self):
        self.helper.devmem_available = MagicMock(return_value=False)
        self.assertEqual(self.helper.read_phys_mem(0x5000, 2), b'\x00')

    @patch(f'{MOD}.os.write', return_value=2)
    @patch(f'{MOD}.os.lseek')
    def test_write_phys_mem(self, os_lseek, os_write):
        self.assertEqual(self.helper.write_phys_mem(0x5000, 2, b'\xaa\xbb'), 2)
        os_lseek.assert_called_once_with(9, 0x5000, lnh.os.SEEK_SET)
        os_write.assert_called_once_with(9, b'\xaa\xbb')

    @patch(f'{MOD}.os.write', return_value=1)
    @patch(f'{MOD}.os.lseek')
    def test_write_phys_mem_short_write(self, _os_lseek, _os_write):
        self.assertEqual(self.helper.write_phys_mem(0x5000, 2, b'\xaa\xbb'), 1)

    def test_write_phys_mem_none_value(self):
        self.assertIsNone(self.helper.write_phys_mem(0x5000, 2, None))

    def test_write_phys_mem_without_devmem(self):
        self.helper.devmem_available = MagicMock(return_value=False)
        self.assertEqual(self.helper.write_phys_mem(0x5000, 2, b'\xaa\xbb'), -1)


class LinuxNativeHelperIoPortTest(unittest.TestCase):

    def setUp(self):
        self.helper = new_helper()
        self.helper.dev_port = 8

    @patch(f'{MOD}.os.read', return_value=b'\x5a')
    @patch(f'{MOD}.os.lseek')
    def test_read_io_port_byte(self, os_lseek, _os_read):
        self.assertEqual(self.helper.read_io_port(0xB8, 1), 0x5A)
        os_lseek.assert_called_once_with(8, 0xB8, lnh.os.SEEK_SET)

    @patch(f'{MOD}.os.read', return_value=b'\x86\x80')
    @patch(f'{MOD}.os.lseek')
    def test_read_io_port_word(self, _os_lseek, _os_read):
        self.assertEqual(self.helper.read_io_port(0xB8, 2), 0x8086)

    @patch(f'{MOD}.os.read', return_value=b'\x86\x80\x12\x9a')
    @patch(f'{MOD}.os.lseek')
    def test_read_io_port_dword(self, _os_lseek, _os_read):
        self.assertEqual(self.helper.read_io_port(0xB8, 4), 0x9A128086)

    @patch(f'{MOD}.os.read', return_value=b'\x00\x00\x00')
    @patch(f'{MOD}.os.lseek')
    def test_read_io_port_invalid_size(self, _os_lseek, _os_read):
        with self.assertRaises(ValueError):
            self.helper.read_io_port(0xB8, 3)

    def test_read_io_port_without_devport(self):
        self.helper.devport_available = MagicMock(return_value=False)
        self.assertEqual(self.helper.read_io_port(0xB8, 4), -1)

    @patch(f'{MOD}.os.write', return_value=1)
    @patch(f'{MOD}.os.lseek')
    def test_write_io_port_byte(self, _os_lseek, os_write):
        self.assertTrue(self.helper.write_io_port(0xB8, 0x55, 1))
        os_write.assert_called_once_with(8, b'\x55')

    @patch(f'{MOD}.os.write', return_value=2)
    @patch(f'{MOD}.os.lseek')
    def test_write_io_port_word(self, _os_lseek, os_write):
        self.assertTrue(self.helper.write_io_port(0xB8, 0x8086, 2))
        os_write.assert_called_once_with(8, b'\x86\x80')

    @patch(f'{MOD}.os.write', return_value=4)
    @patch(f'{MOD}.os.lseek')
    def test_write_io_port_dword(self, _os_lseek, os_write):
        self.assertTrue(self.helper.write_io_port(0xB8, 0x9A128086, 4))
        os_write.assert_called_once_with(8, b'\x86\x80\x12\x9a')

    @patch(f'{MOD}.os.write', return_value=1)
    @patch(f'{MOD}.os.lseek')
    def test_write_io_port_short_write(self, _os_lseek, _os_write):
        self.assertFalse(self.helper.write_io_port(0xB8, 0x8086, 2))

    @patch(f'{MOD}.os.lseek')
    def test_write_io_port_invalid_size(self, _os_lseek):
        with self.assertRaises(ValueError):
            self.helper.write_io_port(0xB8, 0x1, 3)

    def test_write_io_port_without_devport(self):
        self.helper.devport_available = MagicMock(return_value=False)
        self.assertFalse(self.helper.write_io_port(0xB8, 0x1, 1))


class LinuxNativeHelperMsrTest(unittest.TestCase):

    def setUp(self):
        self.helper = new_helper()
        self.helper.dev_msr = {0: 40, 1: 41}

    @patch(f'{MOD}.os.read', return_value=struct.pack('2I', 0x11111111, 0x22222222))
    @patch(f'{MOD}.os.lseek')
    def test_read_msr(self, os_lseek, os_read):
        self.assertEqual(self.helper.read_msr(1, 0x3A), (0x11111111, 0x22222222))
        os_lseek.assert_called_once_with(41, 0x3A, lnh.os.SEEK_SET)
        os_read.assert_called_once_with(41, 8)

    def test_read_msr_without_devmsr(self):
        self.helper.devmsr_available = MagicMock(return_value=False)
        self.assertEqual(self.helper.read_msr(0, 0x3A), (-1, -1))

    @patch(f'{MOD}.os.write', return_value=8)
    @patch(f'{MOD}.os.lseek')
    def test_write_msr(self, os_lseek, os_write):
        self.assertEqual(self.helper.write_msr(0, 0x3A, 0xAABBCCDD, 0x11223344), 8)
        os_lseek.assert_called_once_with(40, 0x3A, lnh.os.SEEK_SET)
        os_write.assert_called_once_with(40, struct.pack('2I', 0xAABBCCDD, 0x11223344))

    @patch(f'{MOD}.os.write', return_value=4)
    @patch(f'{MOD}.os.lseek')
    def test_write_msr_short_write(self, _os_lseek, _os_write):
        self.assertEqual(self.helper.write_msr(0, 0x3A, 0x1, 0x2), 4)

    def test_write_msr_without_devmsr(self):
        self.helper.devmsr_available = MagicMock(return_value=False)
        self.assertFalse(self.helper.write_msr(0, 0x3A, 0x1, 0x2))


class LinuxNativeHelperMiscTest(unittest.TestCase):

    def setUp(self):
        self.helper = new_helper()

    @patch(f'{MOD}.CPUID')
    def test_cpuid(self, cpuid_cls):
        cpuid_cls.return_value.return_value = (0x406F1, 0, 0, 0)
        self.assertEqual(self.helper.cpuid(1, 0), (0x406F1, 0, 0, 0))
        cpuid_cls.return_value.assert_called_once_with(1, 0)

    @patch(f'{MOD}.os.sched_getaffinity', return_value={7})
    def test_get_affinity(self, _sched_getaffinity):
        self.assertEqual(self.helper.get_affinity(), 7)

    @patch(f'{MOD}.os.sched_getaffinity', side_effect=OSError)
    def test_get_affinity_failure(self, _sched_getaffinity):
        self.assertIsNone(self.helper.get_affinity())

    @patch(f'{MOD}.os.getpid', return_value=1234)
    @patch(f'{MOD}.os.sched_setaffinity')
    def test_set_affinity(self, sched_setaffinity, _getpid):
        self.assertEqual(self.helper.set_affinity(3), 3)
        sched_setaffinity.assert_called_once_with(1234, {3})

    @patch(f'{MOD}.os.sched_setaffinity', side_effect=OSError)
    def test_set_affinity_failure(self, _sched_setaffinity):
        self.assertIsNone(self.helper.set_affinity(3))

    def test_get_threads_count(self):
        self.assertEqual(self.helper.get_threads_count(), multiprocessing.cpu_count())

    def test_unimplemented_apis(self):
        cases = [
            (self.helper.alloc_phys_mem, (0x1000, 0xFFFFFFFF)),
            (self.helper.free_phys_mem, (0x1000,)),
            (self.helper.va2pa, (0x1000,)),
            (self.helper.read_cr, (0, 0)),
            (self.helper.write_cr, (0, 0, 0)),
            (self.helper.load_ucode_update, (0, b'\x00')),
            (self.helper.get_descriptor_table, (0, 0)),
            (self.helper.EFI_supported, ()),
            (self.helper.get_EFI_variable, ('name', 'guid')),
            (self.helper.set_EFI_variable, ('name', 'guid', b'\x00')),
            (self.helper.delete_EFI_variable, ('name', 'guid')),
            (self.helper.list_EFI_variables, ()),
            (self.helper.get_ACPI_table, ('SDEV',)),
            (self.helper.enum_ACPI_tables, ()),
            (self.helper.msgbus_send_read_message, (0, 0)),
            (self.helper.msgbus_send_write_message, (0, 0, 0)),
            (self.helper.msgbus_send_message, (0, 0, 0)),
            (self.helper.send_sw_smi, (0, 0, 0, 0, 0, 0, 0, 0)),
            (self.helper.hypercall, ()),
            (self.helper.retpoline_enabled, ()),
        ]
        for func, args in cases:
            with self.subTest(func=func.__name__):
                self.assertRaises(NotImplementedError, func, *args)


class LinuxNativeHelperFirmwareInfoTest(unittest.TestCase):

    def setUp(self):
        self.helper = new_helper()

    @patch(f'{MOD}.open', new_callable=mock_open, read_data='  Intel Corp.  \n')
    def test_read_sysfs_text(self, mocked_open):
        self.assertEqual(self.helper._read_sysfs_text('/sys/dummy'), 'Intel Corp.')
        mocked_open.assert_called_once_with('/sys/dummy', 'r', encoding='utf-8')

    @patch(f'{MOD}.open', new_callable=mock_open, read_data='   \n')
    def test_read_sysfs_text_blank(self, _mocked_open):
        self.assertIsNone(self.helper._read_sysfs_text('/sys/dummy'))

    @patch(f'{MOD}.open', side_effect=OSError(2, 'No such file'))
    def test_read_sysfs_text_missing(self, _mocked_open):
        self.assertIsNone(self.helper._read_sysfs_text('/sys/dummy'))

    @patch(f'{MOD}.open', new_callable=mock_open, read_data='ACME\n')
    def test_firmware_vendor(self, mocked_open):
        self.assertEqual(self.helper.firmware_vendor(), 'ACME')
        mocked_open.assert_called_once_with('/sys/class/dmi/id/bios_vendor', 'r', encoding='utf-8')

    @patch(f'{MOD}.open', new_callable=mock_open, read_data='Board X\n')
    def test_firmware_product(self, mocked_open):
        self.assertEqual(self.helper.firmware_product(), 'Board X')
        mocked_open.assert_called_once_with('/sys/class/dmi/id/product_name', 'r', encoding='utf-8')

    @patch(f'{MOD}.open', new_callable=mock_open, read_data='1.2.3\n')
    def test_firmware_version(self, mocked_open):
        self.assertEqual(self.helper.firmware_version(), '1.2.3')
        mocked_open.assert_called_once_with('/sys/class/dmi/id/bios_version', 'r', encoding='utf-8')

    @patch(f'{MOD}.os.path.exists', return_value=True)
    def test_firmware_type_uefi(self, exists):
        self.assertEqual(self.helper.firmware_type(), 'UEFI')
        exists.assert_called_once_with('/sys/firmware/efi')

    @patch(f'{MOD}.os.path.exists', return_value=False)
    def test_firmware_type_bios(self, _exists):
        self.assertEqual(self.helper.firmware_type(), 'BIOS')

    @patch(f'{MOD}.open', new_callable=mock_open, read_data='5.6.7\n')
    def test_get_bios_version(self, mocked_open):
        self.assertEqual(self.helper.get_bios_version(), '5.6.7')
        mocked_open.assert_called_once_with('/sys/class/dmi/id/bios_version', 'r')

    @patch(f'{MOD}.open', side_effect=FileNotFoundError)
    def test_get_bios_version_missing(self, _mocked_open):
        self.assertEqual(self.helper.get_bios_version(), 'Unable to read bios version')


if __name__ == '__main__':
    unittest.main()
