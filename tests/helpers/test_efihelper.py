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
#

# To execute: python[3] -m unittest tests.helpers.test_efihelper

import struct
import sys
import unittest
import uuid
from unittest.mock import Mock, patch

from chipsec.library.exceptions import UnimplementedAPIError, OsHelperError, PhysicalMemoryAccessError
from chipsec.library.uefi.common import StatusCode, EFI_MEMORY_RO, EFI_MEMORY_RP

# ``edk2`` only exists inside the UEFI shell Python build, so it has to be
# stubbed in ``sys.modules`` before ``efihelper`` can be imported on a host OS.
MOCKED_MODULES = ['edk2']

GUID_A = '01234567-89ab-cdef-0123-456789abcdef'
GUID_B = 'fedcba98-7654-3210-fedc-ba9876543210'


class EfiHelperBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._saved_modules = {}
        for mod in MOCKED_MODULES:
            cls._saved_modules[mod] = sys.modules.get(mod)
            sys.modules[mod] = Mock()
        import chipsec.helper.efi.efihelper as eh
        cls.eh = eh

    @classmethod
    def tearDownClass(cls):
        for mod in MOCKED_MODULES:
            saved = cls._saved_modules.get(mod)
            if saved is None:
                sys.modules.pop(mod, None)
            else:
                sys.modules[mod] = saved

    def setUp(self):
        unittest.TestCase.setUp(self)
        logger_patcher = patch.object(self.eh, 'logger')
        self.addCleanup(logger_patcher.stop)
        self.mock_logger = logger_patcher.start()
        self.log = self.mock_logger.return_value
        self.log.DEBUG = True
        # The module object may already be imported by another test module, so
        # always patch attributes on it rather than relying on sys.modules.
        self.edk2 = self._patch('edk2', Mock())
        # Default to "everything is mapped" so memory tests exercise the access
        # path rather than the validation guard.
        self.edk2.GetMemoryMap.return_value = (0, [(7, 0x0, 0x1000000, 0xF)])
        self.edk2.GetMemoryAttributes.return_value = (0, 0)

    def _patch(self, name, new=None, **kwargs):
        patcher = patch.object(self.eh, name, new) if new is not None else patch.object(self.eh, name, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def _new_helper(self):
        return self.eh.EfiHelper()


class TestEfiHelperConstruction(EfiHelperBase):

    def test_init_on_host_os_uses_platform_module(self):
        import platform
        helper = self._new_helper()
        self.assertEqual(helper.name, 'EfiHelper')
        self.assertEqual(helper.os_system, platform.system())
        self.assertEqual(helper.os_release, platform.release())
        self.assertEqual(helper.os_version, platform.version())
        self.assertEqual(helper.os_machine, platform.machine())
        self.assertTrue(hasattr(helper, 'os_uname'))

    def test_init_on_uefi_reports_static_values(self):
        with patch.object(sys, 'platform', 'EFI64'):
            helper = self._new_helper()
        self.assertEqual(helper.os_system, 'EFI64')
        self.assertEqual(helper.os_release, '0.0')
        self.assertEqual(helper.os_version, '0.0')
        self.assertEqual(helper.os_machine, 'i386')

    def test_del_swallows_missing_destroy(self):
        helper = self._new_helper()
        # ``destroy()`` is not defined anywhere in the module; __del__ relies on
        # the NameError being swallowed.
        self.assertIsNone(helper.__del__())

    def test_get_helper_returns_efi_helper(self):
        helper = self.eh.get_helper()
        self.assertIsInstance(helper, self.eh.EfiHelper)

    def test_tools_table_is_empty(self):
        self.assertEqual(self.eh._tools, {})


class TestEfiHelperLifecycle(EfiHelperBase):

    def setUp(self):
        EfiHelperBase.setUp(self)
        self.helper = self._new_helper()

    def test_create(self):
        self.assertTrue(self.helper.create())

    def test_start_marks_driver_loaded(self):
        self.assertTrue(self.helper.start())
        self.assertTrue(self.helper.driver_loaded)

    def test_stop(self):
        self.assertTrue(self.helper.stop())

    def test_delete(self):
        self.assertTrue(self.helper.delete())

    def test_efi_supported(self):
        self.assertTrue(self.helper.EFI_supported())

    def test_get_threads_count(self):
        self.assertEqual(self.helper.get_threads_count(), 1)

    def test_retpoline_enabled(self):
        self.assertFalse(self.helper.retpoline_enabled())


class TestEfiHelperPhysicalMemory(EfiHelperBase):

    def setUp(self):
        EfiHelperBase.setUp(self)
        self.helper = self._new_helper()

    def test_split_address(self):
        self.assertEqual(self.helper.split_address(0x1234567890ABCDEF), (0x90ABCDEF, 0x12345678))
        self.assertEqual(self.helper.split_address(0xFF), (0xFF, 0))

    def test_a_read_outside_the_memory_map_is_refused(self):
        # The 0xA0000-0x100000 legacy hole is absent from the map; reading it
        # would page fault the CPU outright in the UEFI shell.
        self.edk2.GetMemoryMap.return_value = (0, [(7, 0x0, 0xA0, 0xF)])
        with self.assertRaises(PhysicalMemoryAccessError):
            self.helper.read_phys_mem(0xF0000, 0x10000)
        self.edk2.readmem.assert_not_called()

    def test_a_read_of_an_unmapped_page_is_refused(self):
        # Page 0 is present in the map as reserved, but firmware with
        # NULL-pointer detection leaves it unmapped.
        self.edk2.GetMemoryAttributes.return_value = (StatusCode.EFI_NO_MAPPING, 0)
        with self.assertRaises(PhysicalMemoryAccessError) as ctx:
            self.helper.read_phys_mem(0x41A, 4)
        self.assertIsInstance(ctx.exception, OsHelperError)
        self.assertEqual(ctx.exception.errorcode, StatusCode.EFI_NO_MAPPING)
        self.edk2.GetMemoryAttributes.assert_called_once_with(0x0, 0x1000)
        self.edk2.readmem.assert_not_called()

    def test_a_write_to_an_unmapped_page_is_refused(self):
        self.edk2.GetMemoryAttributes.return_value = (StatusCode.EFI_NO_MAPPING, 0)
        with self.assertRaises(PhysicalMemoryAccessError):
            self.helper.write_phys_mem(0x41A, 4, b'\x01\x02\x03\x04')
        self.edk2.writemem_dword.assert_not_called()

    def test_a_read_of_a_read_protected_page_is_refused(self):
        self.edk2.GetMemoryAttributes.return_value = (StatusCode.EFI_SUCCESS, EFI_MEMORY_RP)
        with self.assertRaises(PhysicalMemoryAccessError):
            self.helper.read_phys_mem(0x1000, 4)
        self.edk2.readmem.assert_not_called()

    def test_a_read_of_a_read_only_page_is_allowed(self):
        self.edk2.GetMemoryAttributes.return_value = (StatusCode.EFI_SUCCESS, EFI_MEMORY_RO)
        self.edk2.readmem.return_value = b'\xAA'
        self.assertEqual(self.helper.read_phys_mem(0x1000, 1), b'\xAA')

    def test_a_write_to_a_read_only_page_is_refused(self):
        self.edk2.GetMemoryAttributes.return_value = (StatusCode.EFI_SUCCESS, EFI_MEMORY_RO)
        with self.assertRaises(PhysicalMemoryAccessError):
            self.helper.write_phys_mem(0x1000, 4, b'\x01\x02\x03\x04')
        self.edk2.writemem_dword.assert_not_called()

    def test_a_uniform_multi_page_read_costs_one_query(self):
        self.edk2.readmem.return_value = b'\x00' * 0x10000
        self.helper.read_phys_mem(0x100000, 0x10000)
        self.edk2.GetMemoryAttributes.assert_called_once_with(0x100000, 0x10000)

    def test_a_multi_page_read_crossing_an_unmapped_page_is_refused(self):
        # Mixed attributes also report EFI_NO_MAPPING, so the range is split
        # until the unmapped page itself is found.
        bad_page = 0x103000

        def attributes(start, length):
            if start <= bad_page < start + length:
                return (StatusCode.EFI_NO_MAPPING, 0)
            return (StatusCode.EFI_SUCCESS, 0)

        self.edk2.GetMemoryAttributes.side_effect = attributes
        with self.assertRaises(PhysicalMemoryAccessError) as ctx:
            self.helper.read_phys_mem(0x100000, 0x8000)
        self.assertIn(f'0x{bad_page:016X}', str(ctx.exception))
        self.edk2.readmem.assert_not_called()

    def test_a_multi_page_read_over_mixed_but_readable_pages_is_allowed(self):
        def attributes(start, length):
            if length > 0x1000:
                return (StatusCode.EFI_NO_MAPPING, 0)
            return (StatusCode.EFI_SUCCESS, EFI_MEMORY_RO if start & 0x1000 else 0)

        self.edk2.GetMemoryAttributes.side_effect = attributes
        self.edk2.readmem.return_value = b'\x00' * 0x4000
        self.assertEqual(self.helper.read_phys_mem(0x100000, 0x4000), b'\x00' * 0x4000)

    def test_an_unexpected_attribute_status_allows_the_access(self):
        self.edk2.GetMemoryAttributes.return_value = (StatusCode.EFI_INVALID_PARAMETER, 0)
        self.edk2.readmem.return_value = b'\xAA'
        self.assertEqual(self.helper.read_phys_mem(0x1000, 1), b'\xAA')

    def test_a_read_spanning_adjacent_memory_map_entries_is_allowed(self):
        self.edk2.GetMemoryMap.return_value = (0, [(7, 0x100000, 0x10, 0xF), (4, 0x0, 0x100, 0xF), (3, 0x110000, 0x10, 0xF)])
        self.edk2.readmem.return_value = b'\x00' * 0x20000
        self.helper.read_phys_mem(0x100000, 0x20000)
        self.edk2.readmem.assert_called_once()

    def test_a_read_across_a_memory_map_gap_is_refused(self):
        self.edk2.GetMemoryMap.return_value = (0, [(7, 0x0, 0xA0, 0xF), (7, 0x100000, 0x100, 0xF)])
        with self.assertRaises(PhysicalMemoryAccessError):
            self.helper.read_phys_mem(0x9F000, 0x2000)
        self.edk2.readmem.assert_not_called()

    def test_a_read_from_the_legacy_hole_into_mapped_memory_is_refused(self):
        self.edk2.GetMemoryMap.return_value = (0, [(7, 0x0, 0xA0, 0xF), (7, 0x100000, 0x100, 0xF)])
        with self.assertRaises(PhysicalMemoryAccessError):
            self.helper.read_phys_mem(0xFF000, 0x2000)
        self.edk2.readmem.assert_not_called()

    def test_a_read_of_mmio_outside_the_memory_map_is_allowed(self):
        # MMIO (e.g. TXT public space) is not in the UEFI memory map; only the
        # page attributes are checked above the first 1 MiB.
        self.edk2.GetMemoryMap.return_value = (0, [(7, 0x0, 0xA0, 0xF), (7, 0x100000, 0x100, 0xF)])
        self.edk2.readmem.return_value = b'\xAA' * 4
        self.assertEqual(self.helper.read_phys_mem(0xFED30000, 4), b'\xAA' * 4)
        self.edk2.GetMemoryAttributes.assert_called_once_with(0xFED30000, 0x1000)

    def test_a_write_to_mmio_outside_the_memory_map_is_allowed(self):
        self.edk2.GetMemoryMap.return_value = (0, [(7, 0x0, 0xA0, 0xF), (7, 0x100000, 0x100, 0xF)])
        self.edk2.writemem_dword.return_value = 0
        self.assertEqual(self.helper.write_phys_mem(0xFED30000, 4, struct.pack('I', 0x1)), 0)
        self.edk2.writemem_dword.assert_called_once_with(0xFED30000, 0, 0x1)

    def test_an_unmapped_mmio_page_is_still_refused(self):
        self.edk2.GetMemoryMap.return_value = (0, [(7, 0x0, 0xA0, 0xF), (7, 0x100000, 0x100, 0xF)])
        self.edk2.GetMemoryAttributes.return_value = (StatusCode.EFI_NO_MAPPING, 0)
        with self.assertRaises(PhysicalMemoryAccessError):
            self.helper.read_phys_mem(0xFED30000, 4)
        self.edk2.readmem.assert_not_called()

    def test_an_unsafe_read_skips_the_access_checks(self):
        self.edk2.GetMemoryMap.return_value = (0, [(7, 0x0, 0xA0, 0xF)])
        self.edk2.GetMemoryAttributes.return_value = (StatusCode.EFI_NO_MAPPING, 0)
        self.edk2.readmem.return_value = b'\xAA'
        self.assertEqual(self.helper.read_phys_mem_unsafe(0xF0000, 1), b'\xAA')
        self.edk2.readmem.assert_called_once_with(0xF0000, 0, 1)
        self.edk2.GetMemoryMap.assert_not_called()
        self.edk2.GetMemoryAttributes.assert_not_called()

    def test_an_unsafe_write_skips_the_access_checks(self):
        self.edk2.GetMemoryAttributes.return_value = (StatusCode.EFI_SUCCESS, EFI_MEMORY_RO)
        self.edk2.writemem_dword.return_value = 0
        self.assertEqual(self.helper.write_phys_mem_unsafe(0x1000, 4, struct.pack('I', 0xDEADBEEF)), 0)
        self.edk2.writemem_dword.assert_called_once_with(0x1000, 0, 0xDEADBEEF)
        self.edk2.GetMemoryMap.assert_not_called()
        self.edk2.GetMemoryAttributes.assert_not_called()

    def test_a_failed_memory_map_query_does_not_block_reads(self):
        self.edk2.GetMemoryMap.return_value = (StatusCode.EFI_BUFFER_TOO_SMALL, [])
        self.edk2.readmem.return_value = b'\xAA'
        self.assertEqual(self.helper.read_phys_mem(0xF0000, 1), b'\xAA')

    def test_the_memory_map_is_only_fetched_once(self):
        self.helper.read_phys_mem(0x1000, 4)
        self.helper.read_phys_mem(0x2000, 4)
        self.assertEqual(self.edk2.GetMemoryMap.call_count, 1)

    def test_reads_are_allowed_when_the_platform_cannot_report_a_map(self):
        # An older interpreter has no GetMemoryMap/GetMemoryAttributes; fall
        # back to the previous unchecked behaviour rather than refusing reads.
        del self.edk2.GetMemoryMap
        del self.edk2.GetMemoryAttributes
        self.edk2.readmem.return_value = b'\xAA'
        self.assertEqual(self.helper.read_phys_mem(0x41A, 1), b'\xAA')

    def test_get_efi_system_table_address(self):
        self.edk2.GetSystemTable.return_value = 0x7FEE0018
        self.assertEqual(self.helper.get_EFI_System_Table_address(), 0x7FEE0018)

    def test_get_efi_system_table_address_when_unavailable(self):
        del self.edk2.GetSystemTable
        self.assertIsNone(self.helper.get_EFI_System_Table_address())

    def test_read_phys_mem(self):
        self.edk2.readmem.return_value = b'\xAA\xBB'
        self.assertEqual(self.helper.read_phys_mem(0x1_0000_0100, 2), b'\xAA\xBB')
        self.edk2.readmem.assert_called_once_with(0x100, 1, 2)

    def test_write_phys_mem_dword(self):
        self.edk2.writemem_dword.return_value = 0
        self.assertEqual(self.helper.write_phys_mem(0x1000, 4, struct.pack('I', 0xDEADBEEF)), 0)
        self.edk2.writemem_dword.assert_called_once_with(0x1000, 0, 0xDEADBEEF)
        self.edk2.writemem.assert_not_called()

    def test_write_phys_mem_converts_bytearray(self):
        self.edk2.writemem_dword.return_value = 0
        self.helper.write_phys_mem(0x1000, 4, bytearray(struct.pack('I', 0x11223344)))
        self.edk2.writemem_dword.assert_called_once_with(0x1000, 0, 0x11223344)

    def test_write_phys_mem_non_dword_uses_writemem(self):
        self.edk2.writemem.return_value = 7
        self.assertEqual(self.helper.write_phys_mem(0x2_0000_0000, 3, b'\x01\x02\x03'), 7)
        self.edk2.writemem.assert_called_once_with(0, 2, b'\x01\x02\x03')

    def test_write_phys_mem_bytearray_non_dword(self):
        self.edk2.writemem.return_value = 0
        self.helper.write_phys_mem(0x10, 2, bytearray(b'\x05\x06'))
        self.edk2.writemem.assert_called_once_with(0x10, 0, b'\x05\x06')

    def test_write_phys_mem_writes_no_more_than_the_checked_length(self):
        # Only the page holding 0x101FFE-0x101FFF is checked; the extra buffer
        # bytes would land on the next, unchecked page.
        self.edk2.writemem.return_value = 0
        self.helper.write_phys_mem(0x101FFE, 2, b'\x01\x02\x03\x04')
        self.edk2.GetMemoryAttributes.assert_called_once_with(0x101000, 0x1000)
        self.edk2.writemem.assert_called_once_with(0x101FFE, 0, b'\x01\x02')
        self.log.log_debug.assert_any_call('[helper] Buffer (0x4 bytes) is longer than the write length (0x2); '
                                           'only 0x2 bytes are written to 0x0000000000101FFE')

    def test_write_phys_mem_with_an_exact_buffer_logs_nothing_about_length(self):
        self.edk2.writemem.return_value = 0
        self.helper.write_phys_mem(0x10, 2, b'\x05\x06')
        for call in self.log.log_debug.call_args_list:
            self.assertNotIn('longer than the write length', call.args[0])

    def test_write_phys_mem_dword_ignores_extra_buffer_bytes(self):
        self.edk2.writemem_dword.return_value = 0
        self.helper.write_phys_mem(0x1000, 4, struct.pack('<II', 0x11223344, 0x55667788))
        self.edk2.writemem_dword.assert_called_once_with(0x1000, 0, 0x11223344)

    def test_alloc_phys_mem(self):
        self.edk2.allocphysmem.return_value = (0x5000, 0)
        self.assertEqual(self.helper.alloc_phys_mem(0x100, 0xFFFFFFFF), (0x5000, 0x5000))
        self.edk2.allocphysmem.assert_called_once_with(0x100, 0xFFFFFFFF)

    def test_va2pa_identity(self):
        self.assertEqual(self.helper.va2pa(0xABCD), (0xABCD, 0))

    def test_pa2va_identity(self):
        self.assertEqual(self.helper.pa2va(0xABCD), 0xABCD)

    def test_map_io_space_identity(self):
        self.assertEqual(self.helper.map_io_space(0x8000_0000, 0x1000, 0), 0x8000_0000)

    def test_free_phys_mem_unimplemented(self):
        with self.assertRaises(UnimplementedAPIError):
            self.helper.free_phys_mem(0x1000)


class TestEfiHelperMmio(EfiHelperBase):

    def setUp(self):
        EfiHelperBase.setUp(self)
        self.helper = self._new_helper()

    def test_read_mmio_reg_qword(self):
        self.edk2.readmem.return_value = struct.pack('=Q', 0x1122334455667788)
        self.assertEqual(self.helper.read_mmio_reg(0x1_0000_0000, 8), 0x1122334455667788)
        self.edk2.readmem.assert_called_once_with(0, 1, 8)

    def test_read_mmio_reg_dword(self):
        self.edk2.readmem.return_value = struct.pack('=I', 0xDEADBEEF)
        self.assertEqual(self.helper.read_mmio_reg(0x1000, 4), 0xDEADBEEF)

    def test_read_mmio_reg_word(self):
        self.edk2.readmem.return_value = struct.pack('=H', 0xBEEF)
        self.assertEqual(self.helper.read_mmio_reg(0x1000, 2), 0xBEEF)

    def test_read_mmio_reg_byte(self):
        self.edk2.readmem.return_value = struct.pack('=B', 0xAB)
        self.assertEqual(self.helper.read_mmio_reg(0x1000, 1), 0xAB)

    def test_read_mmio_reg_invalid_size_returns_zero(self):
        self.edk2.readmem.return_value = b'\x00' * 8
        self.assertEqual(self.helper.read_mmio_reg(0x1000, 3), 0)

    def test_write_mmio_reg_dword(self):
        self.edk2.writemem_dword.return_value = 0
        self.assertEqual(self.helper.write_mmio_reg(0x2_0000_1000, 4, 0xCAFEBABE), 0)
        self.edk2.writemem_dword.assert_called_once_with(0x1000, 2, 0xCAFEBABE)

    def test_write_mmio_reg_byte(self):
        self.edk2.writemem.return_value = 0
        self.assertEqual(self.helper.write_mmio_reg(0x1000, 1, 0x5A), 0)
        self.edk2.writemem.assert_called_once_with(0x1000, 0, b'\x5A')

    def test_write_mmio_reg_word(self):
        self.edk2.writemem.return_value = 0
        self.assertEqual(self.helper.write_mmio_reg(0x1000, 2, 0x1234), 0)
        self.edk2.writemem.assert_called_once_with(0x1000, 0, b'\x34\x12')

    def test_write_mmio_reg_qword(self):
        self.edk2.writemem.return_value = 0
        self.assertEqual(self.helper.write_mmio_reg(0x1000, 8, 0x1122334455667788), 0)
        self.edk2.writemem.assert_called_once_with(0x1000, 0, struct.pack('<Q', 0x1122334455667788))


class TestEfiHelperPciAndIo(EfiHelperBase):

    def setUp(self):
        EfiHelperBase.setUp(self)
        self.helper = self._new_helper()

    def test_read_pci_reg_byte_is_masked(self):
        self.edk2.readpci.return_value = 0xFFFFFFAB
        self.assertEqual(self.helper.read_pci_reg(0, 0x1F, 0, 0x10, 1), 0xAB)
        self.edk2.readpci.assert_called_once_with(0, 0x1F, 0, 0x10, 1)

    def test_read_pci_reg_word_is_masked(self):
        self.edk2.readpci.return_value = 0xFFFF1234
        self.assertEqual(self.helper.read_pci_reg(0, 0, 0, 0x02, 2), 0x1234)

    def test_read_pci_reg_dword_passthrough(self):
        self.edk2.readpci.return_value = 0x8086A0A0
        self.assertEqual(self.helper.read_pci_reg(0, 0, 0, 0x00, 4), 0x8086A0A0)

    def test_write_pci_reg(self):
        self.edk2.writepci.return_value = 0
        self.assertEqual(self.helper.write_pci_reg(0, 2, 1, 0x40, 0x1234, 2), 0)
        self.edk2.writepci.assert_called_once_with(0, 2, 1, 0x40, 0x1234, 2)

    def test_read_io_port_byte_is_masked(self):
        self.edk2.readio.return_value = 0xFF12
        self.assertEqual(self.helper.read_io_port(0xB2, 1), 0x12)
        self.edk2.readio.assert_called_once_with(0xB2, 1)

    def test_read_io_port_word_is_masked(self):
        self.edk2.readio.return_value = 0xFFFF4321
        self.assertEqual(self.helper.read_io_port(0xCF8, 2), 0x4321)

    def test_read_io_port_dword_passthrough(self):
        self.edk2.readio.return_value = 0x11223344
        self.assertEqual(self.helper.read_io_port(0xCF8, 4), 0x11223344)

    def test_write_io_port_swaps_size_and_value(self):
        self.edk2.writeio.return_value = 0
        self.assertEqual(self.helper.write_io_port(0xCF8, 0xAABBCCDD, 4), 0)
        self.edk2.writeio.assert_called_once_with(0xCF8, 4, 0xAABBCCDD)

    def test_send_sw_smi(self):
        self.edk2.swsmi.return_value = None
        self.assertIsNone(self.helper.send_sw_smi(0, 0xDEAD, 1, 2, 3, 4, 5, 6))
        self.edk2.swsmi.assert_called_once_with(0xDEAD, 1, 2, 3, 4, 5, 6)


class TestEfiHelperCpu(EfiHelperBase):

    def setUp(self):
        EfiHelperBase.setUp(self)
        self.helper = self._new_helper()

    def test_read_msr(self):
        self.edk2.rdmsr.return_value = (0x1234, 0x5678)
        self.assertEqual(self.helper.read_msr(0, 0x3A), (0x1234, 0x5678))
        self.edk2.rdmsr.assert_called_once_with(0x3A)

    def test_read_msr_truncates_to_32_bits(self):
        self.edk2.rdmsr.return_value = (0x1_0000_00FF, -1)
        self.assertEqual(self.helper.read_msr(0, 0x3A), (0xFF, 0xFFFFFFFF))

    def test_write_msr(self):
        self.edk2.wrmsr.return_value = 0
        self.assertEqual(self.helper.write_msr(0, 0x3A, 0x1, 0x2), 0)
        self.edk2.wrmsr.assert_called_once_with(0x3A, 0x1, 0x2)

    def test_cpuid(self):
        self.edk2.cpuid.return_value = (1, 2, 3, 4)
        self.assertEqual(self.helper.cpuid(0, 0), (1, 2, 3, 4))
        self.edk2.cpuid.assert_called_once_with(0, 0)

    def test_read_cr_unimplemented(self):
        with self.assertRaises(UnimplementedAPIError):
            self.helper.read_cr(0, 0)

    def test_write_cr_unimplemented(self):
        with self.assertRaises(UnimplementedAPIError):
            self.helper.write_cr(0, 0, 0)

    def test_load_ucode_update_unimplemented(self):
        with self.assertRaises(UnimplementedAPIError):
            self.helper.load_ucode_update(0, 0)

    def test_get_descriptor_table_unimplemented(self):
        with self.assertRaises(UnimplementedAPIError):
            self.helper.get_descriptor_table(0, 0)

    def test_set_affinity_unimplemented(self):
        with self.assertRaises(UnimplementedAPIError):
            self.helper.set_affinity(0)

    def test_get_affinity_unimplemented(self):
        with self.assertRaises(UnimplementedAPIError):
            self.helper.get_affinity()

    def test_hypercall_unimplemented(self):
        with self.assertRaises(UnimplementedAPIError):
            self.helper.hypercall(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)


class TestEfiHelperMsgBusAndAcpi(EfiHelperBase):

    def setUp(self):
        EfiHelperBase.setUp(self)
        self.helper = self._new_helper()

    def test_msgbus_send_read_message_unimplemented(self):
        with self.assertRaises(UnimplementedAPIError):
            self.helper.msgbus_send_read_message(0, 0)

    def test_msgbus_send_write_message_unimplemented(self):
        with self.assertRaises(UnimplementedAPIError):
            self.helper.msgbus_send_write_message(0, 0, 0)

    def test_msgbus_send_message_unimplemented(self):
        with self.assertRaises(UnimplementedAPIError):
            self.helper.msgbus_send_message(0, 0)

    def test_get_acpi_table_unimplemented(self):
        with self.assertRaises(UnimplementedAPIError):
            self.helper.get_ACPI_table('DSDT')

    def test_enum_acpi_tables_unimplemented(self):
        with self.assertRaises(UnimplementedAPIError):
            self.helper.enum_ACPI_tables()


class TestEfiHelperFileSystem(EfiHelperBase):

    def setUp(self):
        EfiHelperBase.setUp(self)
        self.helper = self._new_helper()
        self.helper.os_system = 'EFI64'
        self._patch('get_tools_path', Mock(return_value='/tools'))

    def test_get_tool_info_unknown_tool(self):
        name, path = self.helper.get_tool_info('tdes')
        self.assertEqual(name, '')
        self.assertTrue(path.endswith('efi64'))

    def test_get_tool_info_known_tool(self):
        self._patch('_tools', {'tdes': 'tdes.efi'})
        name, _ = self.helper.get_tool_info('tdes')
        self.assertEqual(name, 'tdes.efi')


class TestEfiHelperEfiVariables(EfiHelperBase):

    def setUp(self):
        EfiHelperBase.setUp(self)
        self.helper = self._new_helper()

    def test_get_efi_variable_full_success(self):
        self.edk2.GetVariable.return_value = (0, 0x7, b'\x01\x02', 2)
        self.assertEqual(self.helper.get_EFI_variable_full('Var', GUID_A), (0, b'\x01\x02', 0x7))
        self.edk2.GetVariable.assert_called_once_with('Var', GUID_A, 100)

    def test_get_efi_variable_full_retries_on_buffer_too_small(self):
        self.edk2.GetVariable.side_effect = [
            (5, 0, b'', 400),
            (0, 0x7, b'\xAA' * 400, 400),
        ]
        status, data, attrs = self.helper.get_EFI_variable_full('Var', GUID_A)
        self.assertEqual(status, 0)
        self.assertEqual(len(data), 400)
        self.assertEqual(attrs, 0x7)
        self.assertEqual(self.edk2.GetVariable.call_args_list[1][0][2], 401)

    def test_get_efi_variable_returns_data_only(self):
        self.edk2.GetVariable.return_value = (0, 0x7, b'\xFF', 1)
        self.assertEqual(self.helper.get_EFI_variable('Var', GUID_A), b'\xFF')

    def test_set_efi_variable_defaults_buffer_size(self):
        self.edk2.SetVariable.return_value = (0, 4, GUID_A)
        self.assertEqual(self.helper.set_EFI_variable('Var', GUID_A, b'\x01\x02\x03\x04'), 0)
        self.edk2.SetVariable.assert_called_once_with('Var', GUID_A, 0x7, b'\x01\x02\x03\x04', 4)

    def test_set_efi_variable_explicit_buffer_size_and_attrs(self):
        self.edk2.SetVariable.return_value = (3, 2, GUID_A)
        self.assertEqual(self.helper.set_EFI_variable('Var', GUID_A, b'\x01\x02', 2, 0x3), 3)
        self.edk2.SetVariable.assert_called_once_with('Var', GUID_A, 0x3, b'\x01\x02', 2)

    def test_set_efi_variable_none_attrs_defaults_to_7(self):
        self.edk2.SetVariable.return_value = (0, 1, GUID_A)
        self.helper.set_EFI_variable('Var', GUID_A, b'\x01', None, None)
        self.assertEqual(self.edk2.SetVariable.call_args[0][2], 0x7)
        self.log.log_important.assert_called()

    def test_set_efi_variable_bytes_attrs_are_unpacked(self):
        self.edk2.SetVariable.return_value = (0, 1, GUID_A)
        self.helper.set_EFI_variable('Var', GUID_A, b'\x01', 1, struct.pack('L', 0x7))
        self.assertEqual(self.edk2.SetVariable.call_args[0][2], 0x7)

    def test_delete_efi_variable(self):
        self.edk2.SetVariable.return_value = (0, 0, GUID_A)
        self.assertEqual(self.helper.delete_EFI_variable('Var', GUID_A), 0)
        self.edk2.SetVariable.assert_called_once_with('Var', GUID_A, 0, bytes(4), 0)


class TestEfiHelperListVariables(EfiHelperBase):
    """Variables are enumerated with edk2.GetNextVariableName() until it reports an error."""

    END = (StatusCode.EFI_NOT_FOUND, '', 200, GUID_A)

    def setUp(self):
        EfiHelperBase.setUp(self)
        self.helper = self._new_helper()
        self.edk2.GetVariable.return_value = (0, 0x7, b'\xDE\xAD', 2)

    def _enumerate(self, *results):
        """List variables with GetNextVariableName returning `results` in order."""
        self.edk2.GetNextVariableName.side_effect = list(results)
        return self.helper.list_EFI_variables()

    def test_list_efi_variables_collects_every_enumerated_variable(self):
        variables = self._enumerate((0, 'VarA', 200, GUID_A), (0, 'VarB', 200, GUID_B), self.END)
        self.assertEqual(variables, {'VarA': [(0, b'', 0, b'\xDE\xAD', GUID_A, 0x7)],
                                     'VarB': [(0, b'', 0, b'\xDE\xAD', GUID_B, 0x7)]})
        self.assertEqual(self.edk2.GetNextVariableName.call_count, 3)

    def test_list_efi_variables_reports_vendor_variables(self):
        # The S3 boot script is located through a vendor variable, which a
        # fixed list of UEFI specification names would never find.
        variables = self._enumerate((0, 'AcpiGlobalVariable', 200, GUID_B), self.END)
        self.assertIn('AcpiGlobalVariable', variables)
        self.edk2.GetVariable.assert_called_once_with('AcpiGlobalVariable', GUID_B, 100)

    def test_list_efi_variables_starts_from_an_empty_name(self):
        self._enumerate(self.END)
        (size, name, guid) = self.edk2.GetNextVariableName.call_args_list[0][0]
        self.assertEqual(size, 200)
        self.assertEqual(name, '\x00'.encode('utf-16-le'))
        self.assertEqual(len(guid), 16)

    def test_list_efi_variables_continues_from_the_previous_variable(self):
        self._enumerate((0, 'VarA', 200, GUID_A), self.END)
        self.assertEqual(self.edk2.GetNextVariableName.call_args_list[1][0],
                         (200, 'VarA\x00'.encode('utf-16-le'), uuid.UUID(GUID_A).bytes_le))

    def test_list_efi_variables_retries_with_the_required_name_size(self):
        variables = self._enumerate((StatusCode.EFI_BUFFER_TOO_SMALL, '', 600, GUID_A),
                                    (0, 'LongName', 600, GUID_A), self.END)
        (first, retry) = self.edk2.GetNextVariableName.call_args_list[:2]
        self.assertEqual(retry[0], (600,) + first[0][1:])
        self.assertIn('LongName', variables)

    def test_list_efi_variables_keeps_the_first_of_a_duplicated_name(self):
        variables = self._enumerate((0, 'Var', 200, GUID_A), (0, 'Var', 200, GUID_B), self.END)
        self.assertEqual([entry[4] for entry in variables['Var']], [GUID_A])

    def test_list_efi_variables_stops_on_an_error_status(self):
        variables = self._enumerate((0, 'VarA', 200, GUID_A), (StatusCode.EFI_DEVICE_ERROR, 'VarA', 200, GUID_A))
        self.assertEqual(list(variables), ['VarA'])
        self.assertEqual(self.edk2.GetNextVariableName.call_count, 2)

    def test_list_efi_variables_empty_when_nothing_is_enumerated(self):
        self.assertEqual(self._enumerate(self.END), {})
        self.edk2.GetVariable.assert_not_called()


if __name__ == '__main__':
    unittest.main()
