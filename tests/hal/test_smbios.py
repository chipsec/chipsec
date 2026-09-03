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

import struct
import unittest
from unittest.mock import MagicMock, patch

from chipsec.hal.common import smbios
from chipsec.hal.common.smbios import (
    SMBIOS,
    SMBIOS_2_x_ENTRY_POINT,
    SMBIOS_3_x_ENTRY_POINT,
    SMBIOS_BIOS_INFO_2_0,
    SMBIOS_STRUCT_HEADER,
    SMBIOS_SYSTEM_INFO_2_0,
)

TABLE_ADDR = 0x7A600000
TABLE_LEN = 0x400


def smbios_struct(struct_type: int, fixed: bytes, strings=(), handle: int = 0) -> bytes:
    """Build one SMBIOS structure: header, fixed area, string set, terminator."""
    length = smbios.SMBIOS_STRUCT_HEADER_SIZE + len(fixed)
    body = struct.pack(smbios.SMBIOS_STRUCT_HEADER_FMT, struct_type, length, handle) + fixed
    if strings:
        string_area = b''.join(s.encode('ascii') + b'\x00' for s in strings) + b'\x00'
    else:
        string_area = b'\x00\x00'
    return body + string_area


def bios_info(vendor=1, version=2, release=3, segment=0xE000, rom_sz=0xFF,
              characteristics=0x0123456789ABCDEF, strings=('Intel Corp.', '1.0', '01/01/2026')):
    fixed = struct.pack('=BBHBBQ', vendor, version, segment, release, rom_sz, characteristics)
    return smbios_struct(smbios.SMBIOS_BIOS_INFO_ENTRY_ID, fixed, strings)


def system_info(manufacturer=1, product=2, version=3, serial=4,
                strings=('Intel', 'Board', 'A0', 'SN12345')):
    fixed = struct.pack('=BBBB', manufacturer, product, version, serial)
    return smbios_struct(smbios.SMBIOS_SYSTEM_INFO_ENTRY_ID, fixed, strings)


def entry_point_2x(table_addr=TABLE_ADDR, table_len=TABLE_LEN, entry_len=0x1F,
                   anchor=smbios.SMBIOS_2_x_SIG, int_anchor=smbios.SMBIOS_2_x_INT_SIG):
    entry = bytearray(struct.pack(
        smbios.SMBIOS_2_x_ENTRY_POINT_FMT, anchor, 0, entry_len, 2, 8,
        0x100, 0, 0, 0, 0, 0, 0, int_anchor, 0,
        table_len, table_addr, 4, 0x28))
    int_start = smbios.SMBIOS_2_x_INT_OFFSET
    int_end = int_start + smbios.SMBIOS_2_x_INT_SIZE
    entry[0x15] = (-sum(entry[int_start:int_end])) & 0xFF
    entry[0x04] = (-sum(entry[:entry_len])) & 0xFF
    return bytes(entry)


def entry_point_3x(table_addr=TABLE_ADDR, max_size=TABLE_LEN, entry_len=0x18,
                   anchor=smbios.SMBIOS_3_x_SIG):
    entry = bytearray(struct.pack(
        smbios.SMBIOS_3_x_ENTRY_POINT_FMT, anchor, 0, entry_len,
        3, 4, 0, 1, 0, max_size, table_addr))
    if entry_len <= len(entry):
        entry[0x05] = (-sum(entry[:entry_len])) & 0xFF
    return bytes(entry)


def make_smbios():
    """SMBIOS HAL wired to a mock chipset with the UEFI dependency stubbed out."""
    cs = MagicMock()
    with patch.object(smbios.uefi, 'UEFI', MagicMock()):
        hal = SMBIOS(cs)
    return hal, cs


class TestStructureHeader(unittest.TestCase):

    def test_header_exposes_type_length_and_handle(self):
        hal, _cs = make_smbios()

        header = hal.get_header(smbios_struct(1, b'\x00' * 4, handle=0x1234))

        self.assertEqual(header.Type, 1)
        self.assertEqual(header.Length, 8)
        self.assertEqual(header.Handle, 0x1234)

    def test_missing_data_has_no_header(self):
        hal, _cs = make_smbios()

        self.assertIsNone(hal.get_header(None))

    def test_data_shorter_than_a_header_is_rejected(self):
        hal, _cs = make_smbios()

        self.assertIsNone(hal.get_header(b'\x00\x01'))

    def test_header_renders_its_fields(self):
        self.assertIn('0x1234', str(SMBIOS_STRUCT_HEADER(1, 8, 0x1234)))


class TestStringList(unittest.TestCase):

    def setUp(self):
        self.hal = make_smbios()[0]

    def test_every_string_in_the_string_area_is_returned(self):
        data = smbios_struct(1, b'\x00' * 4, strings=('Intel', 'Board', 'A0'))

        self.assertEqual(self.hal.get_string_list(data), ['Intel', 'Board', 'A0'])

    def test_a_structure_without_strings_returns_an_empty_list(self):
        data = smbios_struct(1, b'\x00' * 4)

        self.assertEqual(self.hal.get_string_list(data), [])

    def test_data_too_small_for_the_declared_length_is_rejected(self):
        data = struct.pack(smbios.SMBIOS_STRUCT_HEADER_FMT, 1, 32, 0)

        self.assertIsNone(self.hal.get_string_list(data))

    def test_data_without_a_header_is_rejected(self):
        self.assertIsNone(self.hal.get_string_list(b'\x00'))

    def test_strings_are_returned_as_text(self):
        data = smbios_struct(1, b'\x00' * 4, strings=('Intel',))

        self.assertIsInstance(self.hal.get_string_list(data)[0], str)


class TestRawStructureIteration(unittest.TestCase):

    def setUp(self):
        self.hal = make_smbios()[0]

    def test_no_table_data_yields_nothing(self):
        self.assertIsNone(self.hal.get_raw_structs(None, False))

    def test_every_structure_in_the_table_is_returned(self):
        self.hal.smbios_2_data = bios_info() + system_info()

        self.assertEqual(len(self.hal.get_raw_structs(None, False)), 2)

    def test_structures_can_be_filtered_by_type(self):
        self.hal.smbios_2_data = bios_info() + system_info()

        structs = self.hal.get_raw_structs(smbios.SMBIOS_SYSTEM_INFO_ENTRY_ID, False)

        self.assertEqual(len(structs), 1)
        self.assertEqual(self.hal.get_header(structs[0]).Type, smbios.SMBIOS_SYSTEM_INFO_ENTRY_ID)

    def test_a_filter_that_matches_nothing_returns_no_structures(self):
        self.hal.smbios_2_data = bios_info()

        self.assertEqual(self.hal.get_raw_structs(0x7F, False), [])

    def test_the_64_bit_table_is_preferred_when_both_are_present(self):
        self.hal.smbios_2_data = bios_info()
        self.hal.smbios_3_data = system_info()

        structs = self.hal.get_raw_structs(None, False)

        self.assertEqual(self.hal.get_header(structs[0]).Type, smbios.SMBIOS_SYSTEM_INFO_ENTRY_ID)

    def test_the_32_bit_table_can_be_forced(self):
        self.hal.smbios_2_data = bios_info()
        self.hal.smbios_3_data = system_info()

        structs = self.hal.get_raw_structs(None, True)

        self.assertEqual(self.hal.get_header(structs[0]).Type, smbios.SMBIOS_BIOS_INFO_ENTRY_ID)

    def test_a_returned_structure_carries_its_own_strings(self):
        self.hal.smbios_2_data = system_info(strings=('Intel', 'Board'))

        raw = self.hal.get_raw_structs(None, False)[0]

        self.assertEqual(self.hal.get_string_list(raw), ['Intel', 'Board'])

    def test_a_truncated_table_stops_iteration(self):
        self.hal.smbios_2_data = struct.pack(smbios.SMBIOS_STRUCT_HEADER_FMT, 1, 64, 0)

        self.assertEqual(self.hal.get_raw_structs(None, False), [])


class TestDecodedStructures(unittest.TestCase):

    def setUp(self):
        self.hal = make_smbios()[0]

    def test_no_table_data_yields_nothing(self):
        self.assertIsNone(self.hal.get_decoded_structs())

    def test_bios_information_is_decoded_with_its_strings(self):
        self.hal.smbios_2_data = bios_info(characteristics=0x1122334455667788)

        decoded = self.hal.get_decoded_structs()[0]

        self.assertIsInstance(decoded, SMBIOS_BIOS_INFO_2_0)
        self.assertEqual(decoded.bios_char, 0x1122334455667788)
        self.assertEqual(decoded.strings, ['Intel Corp.', '1.0', '01/01/2026'])

    def test_system_information_is_decoded_with_its_strings(self):
        self.hal.smbios_2_data = system_info()

        decoded = self.hal.get_decoded_structs()[0]

        self.assertIsInstance(decoded, SMBIOS_SYSTEM_INFO_2_0)
        self.assertEqual(decoded.strings, ['Intel', 'Board', 'A0', 'SN12345'])

    def test_structures_without_a_decoder_are_skipped(self):
        self.hal.smbios_2_data = smbios_struct(0x7F, b'\x00' * 8) + system_info()

        decoded = self.hal.get_decoded_structs()

        self.assertEqual(len(decoded), 1)
        self.assertIsInstance(decoded[0], SMBIOS_SYSTEM_INFO_2_0)

    def test_decoding_can_be_restricted_to_one_structure_type(self):
        self.hal.smbios_2_data = bios_info() + system_info()

        decoded = self.hal.get_decoded_structs(smbios.SMBIOS_BIOS_INFO_ENTRY_ID)

        self.assertEqual(len(decoded), 1)
        self.assertIsInstance(decoded[0], SMBIOS_BIOS_INFO_2_0)


class TestDecodedStructureRendering(unittest.TestCase):
    """String indexes are one-based references into the structure's string set."""

    def test_bios_information_resolves_its_string_indexes(self):
        info = SMBIOS_BIOS_INFO_2_0(0, 18, 0, 1, 2, 0xE000, 3, 0xFF, 0, ['Intel Corp.', '1.0', '01/01/2026'])

        rendered = str(info)

        self.assertIn('Intel Corp.', rendered)
        self.assertIn('01/01/2026', rendered)

    def test_bios_information_tolerates_missing_strings(self):
        info = SMBIOS_BIOS_INFO_2_0(0, 18, 0, 0, 0, 0xE000, 0, 0xFF, 0, [])

        self.assertIn('SMBIOS BIOS Information', str(info))

    def test_bios_information_tolerates_out_of_range_indexes(self):
        info = SMBIOS_BIOS_INFO_2_0(0, 18, 0, 9, 9, 0xE000, 9, 0xFF, 0, ['Intel Corp.'])

        self.assertIn('SMBIOS BIOS Information', str(info))

    def test_system_information_resolves_its_string_indexes(self):
        info = SMBIOS_SYSTEM_INFO_2_0(1, 8, 0, 1, 2, 3, 4, ['Intel', 'Board', 'A0', 'SN12345'])

        rendered = str(info)

        self.assertIn('Intel', rendered)
        self.assertIn('SN12345', rendered)

    def test_system_information_tolerates_missing_strings(self):
        info = SMBIOS_SYSTEM_INFO_2_0(1, 8, 0, 0, 0, 0, 0, [])

        self.assertIn('SMBIOS System Information', str(info))


class TestEntryPointValidation(unittest.TestCase):
    """Entry points are only accepted when their anchors and sizes check out."""

    def _validate_2x(self, buffer):
        hal, cs = make_smbios()
        cs.hals.memory.read_physical_mem.return_value = buffer
        return hal._SMBIOS__validate_ep_2_values(0xF0000)

    def _validate_3x(self, buffer):
        hal, cs = make_smbios()
        cs.hals.memory.read_physical_mem.return_value = buffer
        return hal._SMBIOS__validate_ep_3_values(0xF0000)

    def test_a_well_formed_2x_entry_point_is_accepted(self):
        ep = self._validate_2x(entry_point_2x())

        self.assertIsNotNone(ep)
        self.assertEqual(ep.TableAddr, TABLE_ADDR)
        self.assertEqual(ep.TableLen, TABLE_LEN)

    def test_the_legacy_2x_entry_point_size_is_accepted(self):
        self.assertIsNotNone(self._validate_2x(entry_point_2x(entry_len=0x1E)))

    def test_a_2x_entry_point_with_a_bad_anchor_is_rejected(self):
        self.assertIsNone(self._validate_2x(entry_point_2x(anchor=b'BAD_')))

    def test_a_2x_entry_point_with_a_bad_intermediate_anchor_is_rejected(self):
        self.assertIsNone(self._validate_2x(entry_point_2x(int_anchor=b'BAD__')))

    def test_a_2x_entry_point_with_an_unexpected_size_is_rejected(self):
        self.assertIsNone(self._validate_2x(entry_point_2x(entry_len=0x10)))

    def test_a_2x_entry_point_with_a_bad_checksum_is_rejected(self):
        entry = bytearray(entry_point_2x())
        entry[0x06] ^= 0x01

        self.assertIsNone(self._validate_2x(bytes(entry)))

    def test_a_2x_entry_point_with_a_bad_intermediate_checksum_is_rejected(self):
        entry = bytearray(entry_point_2x())
        entry[0x15] ^= 0x01
        entry[0x04] = 0
        entry[0x04] = (-sum(entry)) & 0xFF

        self.assertIsNone(self._validate_2x(bytes(entry)))

    def test_a_2x_entry_point_without_a_table_is_rejected(self):
        self.assertIsNone(self._validate_2x(entry_point_2x(table_addr=0)))
        self.assertIsNone(self._validate_2x(entry_point_2x(table_len=0)))

    def test_an_unreadable_2x_entry_point_is_rejected(self):
        self.assertIsNone(self._validate_2x(b'\x00' * 4))

    def test_a_well_formed_3x_entry_point_is_accepted(self):
        ep = self._validate_3x(entry_point_3x())

        self.assertIsNotNone(ep)
        self.assertEqual(ep.TableAddr, TABLE_ADDR)
        self.assertEqual(ep.MaxSize, TABLE_LEN)

    def test_a_3x_entry_point_with_a_bad_anchor_is_rejected(self):
        self.assertIsNone(self._validate_3x(entry_point_3x(anchor=b'BAD__')))

    def test_a_3x_entry_point_with_an_unexpected_size_is_rejected(self):
        self.assertIsNone(self._validate_3x(entry_point_3x(entry_len=0x20)))

    def test_a_3x_entry_point_with_a_bad_checksum_is_rejected(self):
        entry = bytearray(entry_point_3x())
        entry[0x07] ^= 0x01

        self.assertIsNone(self._validate_3x(bytes(entry)))

    def test_a_3x_entry_point_without_a_table_is_rejected(self):
        self.assertIsNone(self._validate_3x(entry_point_3x(table_addr=0)))
        self.assertIsNone(self._validate_3x(entry_point_3x(max_size=0)))

    def test_entry_points_render_their_table_location(self):
        ep2 = SMBIOS_2_x_ENTRY_POINT(*struct.unpack_from(smbios.SMBIOS_2_x_ENTRY_POINT_FMT, entry_point_2x()))
        ep3 = SMBIOS_3_x_ENTRY_POINT(*struct.unpack_from(smbios.SMBIOS_3_x_ENTRY_POINT_FMT, entry_point_3x()))

        self.assertIn('7A600000', str(ep2))
        self.assertIn('7A600000', str(ep3))


class TestTableDiscovery(unittest.TestCase):
    """The table is located through the UEFI config table or a memory scan."""

    @staticmethod
    def _hal_with_memory(memory_map, config_table=(False, None, None, None)):
        hal, cs = make_smbios()
        hal.uefi.find_EFI_Configuration_Table.return_value = config_table

        def read(pa, size):
            return memory_map.get(pa, b'\x00' * size)

        cs.hals.memory.read_physical_mem.side_effect = read
        return hal, cs

    def test_an_already_located_table_is_not_searched_again(self):
        hal, cs = make_smbios()
        hal.smbios_2_ep = object()

        self.assertTrue(hal.find_smbios_table())
        cs.hals.memory.read_physical_mem.assert_not_called()

    def test_a_memory_scan_that_finds_nothing_reports_failure(self):
        hal, _cs = self._hal_with_memory({})

        self.assertFalse(hal.find_smbios_table())

    def test_a_2x_entry_point_found_by_scanning_loads_the_table(self):
        table = bios_info()
        scan_page = entry_point_2x(table_len=len(table)).ljust(smbios.SCAN_SIZE, b'\x00')
        hal, _cs = self._hal_with_memory({
            smbios.SCAN_LOW_LIMIT: scan_page,
            TABLE_ADDR: table,
        })

        self.assertTrue(hal.find_smbios_table())
        self.assertEqual(hal.smbios_2_pa, smbios.SCAN_LOW_LIMIT)
        self.assertEqual(hal.smbios_2_data, table)

    def test_a_3x_entry_point_found_by_scanning_loads_the_table(self):
        table = system_info()
        scan_page = entry_point_3x(max_size=len(table)).ljust(smbios.SCAN_SIZE, b'\x00')
        hal, _cs = self._hal_with_memory({
            smbios.SCAN_LOW_LIMIT: scan_page,
            TABLE_ADDR: table,
        })

        self.assertTrue(hal.find_smbios_table())
        self.assertEqual(hal.smbios_3_data, table)

    def test_a_discovered_table_can_be_decoded_end_to_end(self):
        table = bios_info() + system_info()
        scan_page = entry_point_2x(table_len=len(table)).ljust(smbios.SCAN_SIZE, b'\x00')
        hal, _cs = self._hal_with_memory({
            smbios.SCAN_LOW_LIMIT: scan_page,
            TABLE_ADDR: table,
        })
        hal.find_smbios_table()

        decoded = hal.get_decoded_structs()

        self.assertEqual([type(d) for d in decoded], [SMBIOS_BIOS_INFO_2_0, SMBIOS_SYSTEM_INFO_2_0])

    def test_config_table_guids_are_recorded_when_present(self):
        config = MagicMock()
        config.VendorTables = {smbios.SMBIOS_2_x_GUID: TABLE_ADDR}
        table = bios_info()
        scan_page = entry_point_2x(table_len=len(table)).ljust(smbios.SCAN_SIZE, b'\x00')
        hal, cs = self._hal_with_memory(
            {smbios.SCAN_LOW_LIMIT: scan_page, TABLE_ADDR: table},
            config_table=(True, 0, config, None))
        cs.hals.cpu.get_SMRAM.return_value = (smbios.SCAN_LOW_LIMIT + smbios.SCAN_SIZE, 0, 0)

        self.assertTrue(hal.find_smbios_table())
        self.assertTrue(hal.smbios_2_guid_found)


class TestEntryPointFormats(unittest.TestCase):
    """The entry point layouts are fixed by the SMBIOS specification."""

    def test_declared_entry_point_sizes(self):
        self.assertEqual(smbios.SMBIOS_2_x_ENTRY_POINT_SIZE, smbios.SMBIOS_2_x_ENTRY_SIZE)
        self.assertEqual(smbios.SMBIOS_3_x_ENTRY_POINT_SIZE, smbios.SMBIOS_3_x_ENTRY_SIZE)

    def test_structure_header_is_four_bytes(self):
        self.assertEqual(smbios.SMBIOS_STRUCT_HEADER_SIZE, 4)

    def test_every_decodable_type_has_a_class_and_a_format(self):
        for entry in smbios.struct_decode_tree.values():
            self.assertIn('class', entry)
            self.assertIn('format', entry)


if __name__ == '__main__':
    unittest.main()
