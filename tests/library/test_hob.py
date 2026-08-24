# CHIPSEC: Platform Security Assessment Framework
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

import struct
import unittest
import xml.etree.ElementTree as ET
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import UUID

from chipsec.cfg.parsers.hob_parser import HOBParser, HOBCommands
from chipsec.hal.common.hob import HOB
from chipsec.library.register import ObjList
from chipsec.library.uefi.hob import (
    parse_phit,
    parse_hob_list,
    walk_hob_list,
    is_hob_list_complete,
    EFI_HOB_LIST_GUID,
    EFI_HOB_GENERIC_HEADER_SIZE,
    EFI_HOB_TYPE_HANDOFF,
    EFI_HOB_TYPE_RESOURCE_DESCRIPTOR,
    EFI_HOB_TYPE_GUID_EXTENSION,
    EFI_HOB_TYPE_FV,
    EFI_HOB_TYPE_FV2,
    EFI_HOB_TYPE_END_OF_HOB_LIST,
)

BASE = 0x100000


def _hdr(hob_type, hob_length):
    return struct.pack('<HHI', hob_type, hob_length, 0)


def _phit(end_of_hob_list):
    body = struct.pack('<IIQQQQQ',
                       0x9,            # Version
                       0x2,            # BootMode
                       0x4C49E000,     # EfiMemoryTop
                       0x3C4AE000,     # EfiMemoryBottom
                       0x49800000,     # EfiFreeMemoryTop
                       0x3C550C80,     # EfiFreeMemoryBottom
                       end_of_hob_list)
    return _hdr(EFI_HOB_TYPE_HANDOFF, EFI_HOB_GENERIC_HEADER_SIZE + len(body)) + body


def _fv(base, length):
    body = struct.pack('<QQ', base, length)
    return _hdr(EFI_HOB_TYPE_FV, EFI_HOB_GENERIC_HEADER_SIZE + len(body)) + body


def _resource(owner_guid, res_type, attr, start, length):
    body = struct.pack('<16sIIQQ', UUID(owner_guid).bytes_le, res_type, attr, start, length)
    return _hdr(EFI_HOB_TYPE_RESOURCE_DESCRIPTOR, EFI_HOB_GENERIC_HEADER_SIZE + len(body)) + body


def _end():
    return _hdr(EFI_HOB_TYPE_END_OF_HOB_LIST, EFI_HOB_GENERIC_HEADER_SIZE)


def _build_list():
    # Offsets are computed so the PHIT's EfiEndOfHobList points at the END HOB.
    phit_len = EFI_HOB_GENERIC_HEADER_SIZE + struct.calcsize('<IIQQQQQ')
    fv_len = EFI_HOB_GENERIC_HEADER_SIZE + struct.calcsize('<QQ')
    res_len = EFI_HOB_GENERIC_HEADER_SIZE + struct.calcsize('<16sIIQQ')
    end_offset = phit_len + fv_len + res_len
    buf = (_phit(BASE + end_offset)
           + _fv(0xDEAD0000, 0x40000)
           + _resource('00000000-0000-0000-0000-000000000000', 0, 0x3C07, 0x0, 0xA0000)
           + _end())
    return buf, end_offset


class TestParsePhit(unittest.TestCase):
    def test_valid_phit(self):
        buf, end_offset = _build_list()
        phit = parse_phit(buf)
        self.assertIsNotNone(phit)
        self.assertEqual(phit.Version, 0x9)
        self.assertEqual(phit.BootMode, 0x2)
        self.assertEqual(phit.EfiMemoryTop, 0x4C49E000)
        self.assertEqual(phit.EfiEndOfHobList, BASE + end_offset)

    def test_non_phit_returns_none(self):
        self.assertIsNone(parse_phit(_fv(0x1000, 0x2000)))

    def test_undersized_hob_length_returns_none(self):
        # Valid HANDOFF type, but HobLength smaller than the PHIT structure.
        buf, _ = _build_list()
        bad = struct.pack('<HHI', EFI_HOB_TYPE_HANDOFF, EFI_HOB_GENERIC_HEADER_SIZE, 0) + buf[EFI_HOB_GENERIC_HEADER_SIZE:]
        self.assertIsNone(parse_phit(bad))

    def test_too_short_returns_none(self):
        self.assertIsNone(parse_phit(b'\x01\x00\x38\x00'))


class TestParseHobList(unittest.TestCase):
    def test_parses_all_hobs_with_absolute_addresses(self):
        buf, _ = _build_list()
        hobs = parse_hob_list(buf, BASE)
        self.assertEqual(len(hobs), 4)
        self.assertEqual([h.HobType for h in hobs],
                         [EFI_HOB_TYPE_HANDOFF, EFI_HOB_TYPE_FV,
                          EFI_HOB_TYPE_RESOURCE_DESCRIPTOR, EFI_HOB_TYPE_END_OF_HOB_LIST])
        # First HOB sits at the base address.
        self.assertEqual(hobs[0].address, BASE)
        # Second HOB address = base + PHIT length.
        self.assertEqual(hobs[1].address, BASE + hobs[0].HobLength)

    def test_fv_fields_decoded(self):
        hobs = parse_hob_list(_build_list()[0], BASE)
        fv = hobs[1]
        self.assertEqual(fv.fields['BaseAddress'], 0xDEAD0000)
        self.assertEqual(fv.fields['Length'], 0x40000)

    def test_resource_fields_decoded(self):
        hobs = parse_hob_list(_build_list()[0], BASE)
        res = hobs[2]
        self.assertEqual(res.fields['ResourceType'], 'SYSTEM_MEMORY')
        self.assertEqual(res.fields['ResourceAttribute'], 0x3C07)
        self.assertEqual(res.fields['PhysicalStart'], 0x0)
        self.assertEqual(res.fields['ResourceLength'], 0xA0000)

    def test_guid_valued_fields_are_suffixed(self):
        # Every decoded field holding a GUID is named with a GUID suffix.
        res = parse_hob_list(_build_list()[0], BASE)[2]
        self.assertIn('Owner_GUID', res.fields)
        self.assertEqual(res.fields['Owner_GUID'], '00000000-0000-0000-0000-000000000000')

        guid = 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'
        body = struct.pack('<16s', UUID(guid).bytes_le) + b'\x01\x02'
        guid_hob = _hdr(EFI_HOB_TYPE_GUID_EXTENSION, EFI_HOB_GENERIC_HEADER_SIZE + len(body)) + body
        self.assertEqual(parse_hob_list(guid_hob)[0].fields['GUID'], guid)

        body = struct.pack('<QQ16s16s', 0x1000, 0x2000, UUID(guid).bytes_le, UUID(guid).bytes_le)
        fv2 = _hdr(EFI_HOB_TYPE_FV2, EFI_HOB_GENERIC_HEADER_SIZE + len(body)) + body
        fv2_fields = parse_hob_list(fv2)[0].fields
        self.assertEqual(fv2_fields['FvName_GUID'], guid)
        self.assertEqual(fv2_fields['FileName_GUID'], guid)

    def test_complete_list_detected(self):
        hobs = parse_hob_list(_build_list()[0], BASE)
        self.assertTrue(is_hob_list_complete(hobs))

    def test_truncated_list_not_complete(self):
        buf, _ = _build_list()
        truncated = buf[:-EFI_HOB_GENERIC_HEADER_SIZE]  # drop the END HOB
        hobs = parse_hob_list(truncated, BASE)
        self.assertFalse(is_hob_list_complete(hobs))

    def test_stops_on_end_hob(self):
        # Anything after END must be ignored.
        buf, _ = _build_list()
        hobs = parse_hob_list(buf + _fv(0x1, 0x2), BASE)
        self.assertEqual(hobs[-1].HobType, EFI_HOB_TYPE_END_OF_HOB_LIST)
        self.assertEqual(len(hobs), 4)

    def test_invalid_length_stops_parsing(self):
        bad = _phit(BASE + 0x38) + _hdr(EFI_HOB_TYPE_FV, 0)  # zero length is invalid
        hobs = parse_hob_list(bad, BASE)
        self.assertEqual(len(hobs), 1)
        self.assertEqual(hobs[0].HobType, EFI_HOB_TYPE_HANDOFF)


class TestConstants(unittest.TestCase):
    def test_hob_list_guid(self):
        self.assertEqual(EFI_HOB_LIST_GUID, '7739F24C-93D7-11D4-9A3A-0090273FC14D')


class TestWalkHobList(unittest.TestCase):
    def test_complete_walk_reports_consumed(self):
        buf, end_offset = _build_list()
        hobs, complete, consumed = walk_hob_list(buf, BASE)
        self.assertTrue(complete)
        self.assertEqual(len(hobs), 4)
        # consumed should reach past the END HOB (end_offset + 8).
        self.assertEqual(consumed, end_offset + EFI_HOB_GENERIC_HEADER_SIZE)

    def test_partial_trailing_hob_excluded(self):
        # Simulate a chunked read that ends in the middle of the RESOURCE HOB.
        buf, _ = _build_list()
        phit_len = EFI_HOB_GENERIC_HEADER_SIZE + struct.calcsize('<IIQQQQQ')
        fv_len = EFI_HOB_GENERIC_HEADER_SIZE + struct.calcsize('<QQ')
        cut = phit_len + fv_len + 4  # a few bytes into the resource HOB
        hobs, complete, consumed = walk_hob_list(buf[:cut], BASE)
        self.assertFalse(complete)
        # Only PHIT and FV are complete; the partial resource HOB is excluded.
        self.assertEqual(len(hobs), 2)
        self.assertEqual(consumed, phit_len + fv_len)

    def test_chunked_reassembly_reaches_end(self):
        # Emulate the HAL's incremental read using small chunks.
        buf, _ = _build_list()
        chunk = 16
        acc = b''
        complete = False
        consumed = 0
        while len(acc) < len(buf):
            acc += buf[len(acc):len(acc) + chunk]
            _, complete, consumed = walk_hob_list(acc, BASE)
            if complete:
                break
        self.assertTrue(complete)
        trimmed = acc[:consumed]
        self.assertTrue(is_hob_list_complete(parse_hob_list(trimmed, BASE)))


class TestHobHalContract(unittest.TestCase):
    def test_get_hob_list_returns_public_result_tuple(self):
        hal = HOB.__new__(HOB)
        hal.hobs = []
        hal.hob_pa = BASE
        hal.complete = False
        hal.found = False
        hal.definitions = None
        hal.logger = MagicMock()
        hal.read_HOB_list = MagicMock(return_value=(True, _end()))
        hal._publish_decoded_registers = MagicMock()

        found, hob_pa, hobs = hal.get_HOB_list()

        self.assertTrue(found)
        self.assertEqual(hob_pa, BASE)
        self.assertEqual(len(hobs), 1)
        self.assertEqual(hobs[0].HobType, EFI_HOB_TYPE_END_OF_HOB_LIST)

    def _hal_with_registers(self):
        """Build a HAL whose HOB list holds two decoded registers of one definition."""
        guid = '11111111-2222-3333-4444-555555555555'
        cfg = SimpleNamespace()
        parser = HOBParser(cfg)
        parser.startup()
        xml = ('<configuration><hob>'
               f'<structure name="T" guid="{guid}">'
               '<field name="A" type="uint32" /><field name="B" type="uint16" />'
               '</structure></hob></configuration>')
        for node in ET.fromstring(xml).iter('structure'):
            parser.handle_structure(node, SimpleNamespace(vid_str='8086', dev_name='HOB'))

        definitions = HOBCommands(cfg)
        buf = b''
        for b_value in (5, 7):
            body = struct.pack('<16sIH', UUID(guid).bytes_le, 0xAAAA, b_value)
            buf += _hdr(EFI_HOB_TYPE_GUID_EXTENSION, EFI_HOB_GENERIC_HEADER_SIZE + len(body)) + body
        buf += _end()

        hal = HOB.__new__(HOB)
        hal.found = True
        hal.logger = MagicMock()
        hal.definitions = definitions
        hal.hobs, _, _ = walk_hob_list(buf, BASE, definitions)
        return hal

    def test_get_list_by_name_returns_objlist(self):
        registers = self._hal_with_registers().get_list_by_name('8086.HOB.T')
        self.assertIsInstance(registers, ObjList)
        self.assertEqual(len(registers), 2)

    def test_returned_objlist_supports_register_helpers(self):
        registers = self._hal_with_registers().get_list_by_name('T')
        self.assertEqual(registers.get_field('A'), [0xAAAA, 0xAAAA])
        self.assertEqual(registers.read_field('B'), [5, 7])
        self.assertTrue(registers.is_all_field_value(0xAAAA, 'A'))
        self.assertTrue(registers.all_has_field('B'))
        self.assertEqual(registers.get_field_value_if_equivalent('A'), 0xAAAA)
        self.assertIsNone(registers.get_field_value_if_equivalent('B'))
        self.assertEqual(len(registers.filter_enabled()), 2)
        self.assertEqual(len(registers.read()), 2)

    def test_no_match_returns_empty_objlist(self):
        registers = self._hal_with_registers().get_list_by_name('8086.OTHER.T')
        self.assertIsInstance(registers, ObjList)
        self.assertEqual(len(registers), 0)


if __name__ == '__main__':
    unittest.main()
