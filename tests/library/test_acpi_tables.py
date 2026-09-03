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

from chipsec.library.acpi_tables import (
    ACPI_TABLE,
    APIC,
    BGRT,
    DMAR,
    FADT,
    GAS,
    RSDP,
    RSDT,
    UEFI_TABLE,
    WSMT,
    XSDT,
    safe_struct_unpack,
)
from tests.helpers.acpi_utils import build_rsdp


class TestACPITables(unittest.TestCase):
    """Test the ACPI Table Structures and Parsing."""

    def test_verify_dmar_table_format(self):
        test_dmar = DMAR()
        value_re = r'^=?[BHQsI\d]*'
        key_re = r'^\w+_FORMAT'
        self.assertEqual(type(test_dmar.DMAR_TABLE_FORMAT), dict)
        for key, value in test_dmar.DMAR_TABLE_FORMAT.items():
                self.assertRegex(key, key_re)
                self.assertRegex(value, value_re)

    def test_dmar_parse(self):
        test_table_content = b'&\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00\xd9\xfe\x00\x00\x00\x00\x01\x08\x00\x00\x00\x00\x02\x00\x00\x00 \x00\x01\x00\x00\x00\x00\x10\xd9\xfe\x00\x00\x00\x00\x03\x08\x00\x00\x02\xf0\x1f\x00\x04\x08\x00\x00\x00\x00\x1f\x00\x01\x00 \x00\x00\x00\x00\x00\x00\xa0\xb9z\x00\x00\x00\x00\xff?\xdez\x00\x00\x00\x00\x01\x08\x00\x00\x00\x00\x14\x00\x01\x00 \x00\x00\x00\x00\x00\x00\x00\x80{\x00\x00\x00\x00\xff\xff\xff\x7f\x00\x00\x00\x00\x01\x08\x00\x00\x00\x00\x02\x00'
        test_dmar = DMAR()
        test_dmar.parse(test_table_content)
        self.assertEqual(len(test_dmar.dmar_structures), 4)

    def test__str__(self):
        test_table_content = b'&\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00\xd9\xfe\x00\x00\x00\x00\x01\x08\x00\x00\x00\x00\x02\x00\x00\x00 \x00\x01\x00\x00\x00\x00\x10\xd9\xfe\x00\x00\x00\x00\x03\x08\x00\x00\x02\xf0\x1f\x00\x04\x08\x00\x00\x00\x00\x1f\x00\x01\x00 \x00\x00\x00\x00\x00\x00\xa0\xb9z\x00\x00\x00\x00\xff?\xdez\x00\x00\x00\x00\x01\x08\x00\x00\x00\x00\x14\x00\x01\x00 \x00\x00\x00\x00\x00\x00\x00\x80{\x00\x00\x00\x00\xff\xff\xff\x7f\x00\x00\x00\x00\x01\x08\x00\x00\x00\x00\x02\x00'
        #test_table_content = b'&\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00\xd9\xfe\x00\x00\x00\x00\x01\x08\x00\x00\x00\x00\x02\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00`\xd8\xfe\x00\x00\x00\x00\x02\x08\x00\x00\x00\x00\x07\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00p\xd8\xfe\x00\x00\x00\x00\x02\x08\x00\x00\x00\x00\x07\x03\x00\x00 \x00\x01\x00\x00\x00\x00\x10\xd9\xfe\x00\x00\x00\x00\x03\x08\x00\x00\x02\x00\x1e\x07\x04\x08\x00\x00\x00\x00\x1e\x06\x01\x00 \x00\x00\x00\x00\x00\x00\x00\x00/\x00\x00\x00\x00\xff\xff\x7fO\x00\x00\x00\x00\x01\x08\x00\x00\x00\x00\x02\x00'
        test_dmar = DMAR()
        test_dmar.parse(test_table_content)
        str_header = 'DMAR Table Contents'
        str_contents = test_dmar.__str__()
        self.assertIn(str_header, str_contents)
        self.assertTrue(1500 <= len(str_contents) <= 2000)

    def test_get_structure_dmar_type_7(self):
        test_dmar = DMAR()
        type = 0x07
        structure_DMAR_ret = test_dmar._get_structure_DMAR(type, b'\x00\x00\x00\x00')
        self.assertIn(f"\n  Unknown DMAR structure 0x{type:02X}\n", structure_DMAR_ret)

    def test_verify_apic_table_format(self):
        test_apic = APIC()
        value_re = r'^[<=]?[BHQsI\d]*'
        key_re = r'^\w+'
        self.assertEqual(type(test_apic.APIC_TABLE_FORMAT), dict)
        for key, value in test_apic.APIC_TABLE_FORMAT.items():
                self.assertRegex(key, key_re)
                self.assertRegex(value, value_re)

    def test_apic_parse(self):
        test_table_content = b'\x00\x00\xe0\xfe\x01\x00\x00\x00\x00\x08\x01\x00\x01\x00\x00\x00\x04\x06\x01\x05\x00\x01\x00\x08\x02\x02\x01\x00\x00\x00\x04\x06\x02\x05\x00\x01\x00\x08\x03\x01\x01\x00\x00\x00\x04\x06\x03\x05\x00\x01\x00\x08\x04\x03\x01\x00\x00\x00\x04\x06\x04\x05\x00\x01\x01\x0c\x02\x00\x00\x00\xc0\xfe\x00\x00\x00\x00\x02\n\x00\x00\x02\x00\x00\x00\x00\x00\x02\n\x00\t\t\x00\x00\x00\r\x00'
        test_apic = APIC()
        test_apic.parse(test_table_content)
        self.assertEqual(len(test_apic.apic_structs), 11)

    def test_xsdt_parse(self):
        test_table_content = b'h\x9daz\x00\x00\x00\x00\x80\x9eaz\x00\x00\x00\x00\x08\x9faz\x00\x00\x00\x00P\x9faz\x00\x00\x00\x00\xf0\x9faz\x00\x00\x00\x000\xa0az\x00\x00\x00\x00\x90\xa3az\x00\x00\x00\x00\xf8\xd4az\x00\x00\x00\x000\xd5az\x00\x00\x00\x00\x18\xdfaz\x00\x00\x00\x00`\xdfaz\x00\x00\x00\x00\xc0\xe9az\x00\x00\x00\x00p\x01bz\x00\x00\x00\x00\x08\x02bz\x00\x00\x00\x00P\x03bz\x00\x00\x00\x00\xf0\x05bz\x00\x00\x00\x00\xf85bz\x00\x00\x00\x00\xd86bz\x00\x00\x00\x00\xc89bz\x00\x00\x00\x00\x00:bz\x00\x00\x00\x00X:bz\x00\x00\x00\x00@Mbz\x00\x00\x00\x00\xe8Mbz\x00\x00\x00\x00\x18Nbz\x00\x00\x00\x00PNbz\x00\x00\x00\x00\x88Nbz\x00\x00\x00\x00\xe0Nbz\x00\x00\x00\x00'
        test_xsdt = XSDT()
        test_xsdt.parse(test_table_content)
        self.assertEqual(len(test_xsdt.Entries), 27)

    def test_bgrt_parse(self):
        test_table_content = b"\x01\x00\x01\x00\x18P\x9fv\x00\x00\x00\x00\xf3\x02\x00\x00'\x01\x00\x00"
        test_bgrt = BGRT()
        test_bgrt.parse(test_table_content)
        self.assertEqual(test_bgrt.Version, 1)
        self.assertEqual(test_bgrt.Status, 1)
        self.assertEqual(test_bgrt.ImageOffsetY, 295)

    def test_uefi_parse(self):
        test_table_content = b'\xe2\xd8\x8e\xc6\xc6\x9d\xbdL\x9d\x94\xdbe\xac\xc5\xc328\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\xb0\x9fz\x00\x00\x00\x00'
        test_uefi = UEFI_TABLE()
        test_uefi.parse(test_table_content)
        self.assertEqual(test_uefi.smi, 1)
        self.assertEqual(test_uefi.buf_addr, 0x7a9fb00000000000)

    def test_wsmt_parse(self):
        test_table_content = b'\x00\x00\x00\x00'
        test_wsmt = WSMT()
        test_wsmt.parse(test_table_content)
        self.assertEqual(test_wsmt.fixed_comm_buffers, 0)
        self.assertEqual(test_wsmt.comm_buffer_nested_ptr_protection, 0)
        self.assertEqual(test_wsmt.system_resource_protection, 0)
    # def test_get_structure_dmar(self):
    #     test_table_content = b'&\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00\xd9\xfe\x00\x00\x00\x00\x01\x08\x00\x00\x00\x00\x02\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00`\xd8\xfe\x00\x00\x00\x00\x02\x08\x00\x00\x00\x00\x07\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00p\xd8\xfe\x00\x00\x00\x00\x02\x08\x00\x00\x00\x00\x07\x03\x00\x00 \x00\x01\x00\x00\x00\x00\x10\xd9\xfe\x00\x00\x00\x00\x03\x08\x00\x00\x02\x00\x1e\x07\x04\x08\x00\x00\x00\x00\x1e\x06\x01\x00 \x00\x00\x00\x00\x00\x00\x00\x00/\x00\x00\x00\x00\xff\xff\x7fO\x00\x00\x00\x00\x01\x08\x00\x00\x00\x00\x02\x00'
    #     test_dmar = DMAR()
    #     i = 1
    #     for key, value in test_dmar.DMAR_TABLE_FORMAT.items():
    #         size = struct.calcsize(value)
    #         test_dmar._get_structure_DMAR(i, test_table_content[])
    #         i += 1
    #     print(test_dmar._get_DMAR_structure_SATC(b'\x00'))


class TestACPITableBase(unittest.TestCase):
    """The base class supplies inert defaults for tables without a parser."""

    def test_parse_accepts_any_content(self):
        self.assertIsNone(ACPI_TABLE().parse(b'\x00' * 16))

    def test_default_rendering_reports_an_unparsed_table(self):
        self.assertIn('Table Content', str(ACPI_TABLE()))


def legacy_rsdp(revision=0, signature=b'RSD PTR '):
    return build_rsdp(
        revision=revision,
        rsdt_address=0x7A611000,
        signature=signature)


def extended_rsdp(revision=2, length=36, signature=b'RSD PTR '):
    return build_rsdp(
        revision=revision,
        rsdt_address=0x7A611000,
        xsdt_address=0x7A612000,
        signature=signature,
        length=length)


class TestRSDP(unittest.TestCase):
    """The RSDP is the entry point that points at the RSDT and/or XSDT."""

    LEGACY = legacy_rsdp()
    EXTENDED = extended_rsdp()

    def test_legacy_rsdp_exposes_the_rsdt_pointer(self):
        rsdp = RSDP()
        rsdp.parse(self.LEGACY)

        self.assertEqual(rsdp.Signature, b'RSD PTR ')
        self.assertEqual(rsdp.RsdtAddress, 0x7A611000)

    def test_legacy_rsdp_has_no_extended_fields(self):
        rsdp = RSDP()
        rsdp.parse(self.LEGACY)

        self.assertIsNone(rsdp.XsdtAddress)
        self.assertIsNone(rsdp.Length)

    def test_extended_rsdp_exposes_the_xsdt_pointer(self):
        rsdp = RSDP()
        rsdp.parse(self.EXTENDED)

        self.assertEqual(rsdp.XsdtAddress, 0x7A612000)
        self.assertEqual(rsdp.Length, 36)

    def test_trailing_bytes_beyond_the_extended_structure_are_ignored(self):
        rsdp = RSDP()
        rsdp.parse(self.EXTENDED + b'\xff' * 8)

        self.assertEqual(rsdp.XsdtAddress, 0x7A612000)

    def test_empty_content_is_rejected(self):
        with self.assertRaises(ValueError):
            RSDP().parse(b'')

    def test_truncated_content_is_rejected(self):
        with self.assertRaises(ValueError):
            RSDP().parse(b'\x00' * 8)

    def test_content_between_the_two_known_sizes_is_rejected(self):
        with self.assertRaises(ValueError):
            RSDP().parse(self.LEGACY + b'\x00' * 4)

    def test_valid_rsdp_requires_a_checksum_and_a_known_revision(self):
        rsdp = RSDP()
        rsdp.parse(self.LEGACY)

        self.assertTrue(rsdp.is_RSDP_valid())

    def test_bad_legacy_checksum_is_not_valid(self):
        rsdp = RSDP()
        data = bytearray(self.LEGACY)
        data[19] ^= 0x01
        rsdp.parse(bytes(data))

        self.assertFalse(rsdp.is_RSDP_valid())

    def test_bad_extended_checksum_is_not_valid(self):
        rsdp = RSDP()
        data = bytearray(self.EXTENDED)
        data[24] ^= 0x01
        data[8] = 0
        data[8] = (-sum(data[:20])) & 0xFF
        rsdp.parse(bytes(data))

        self.assertFalse(rsdp.is_RSDP_valid())

    def test_unknown_revision_is_not_valid(self):
        rsdp = RSDP()
        rsdp.parse(legacy_rsdp(revision=9))

        self.assertFalse(rsdp.is_RSDP_valid())

    def test_bad_signature_is_not_valid(self):
        rsdp = RSDP()
        rsdp.parse(legacy_rsdp(signature=b'BAD PTR '))

        self.assertFalse(rsdp.is_RSDP_valid())

    def test_rendering_includes_the_extended_fields_when_present(self):
        legacy, extended = RSDP(), RSDP()
        legacy.parse(self.LEGACY)
        extended.parse(self.EXTENDED)

        self.assertNotIn('XSDT Address', str(legacy))
        self.assertIn('XSDT Address', str(extended))


class TestRSDPBuilder(unittest.TestCase):

    def test_legacy_rsdp_has_a_valid_checksum(self):
        data = build_rsdp(revision=0, rsdt_address=0x12345678)

        self.assertEqual(len(data), 20)
        self.assertEqual(sum(data) & 0xFF, 0)

    def test_extended_rsdp_has_valid_legacy_and_extended_checksums(self):
        data = build_rsdp(
            revision=2,
            rsdt_address=0x12345678,
            xsdt_address=0x123456789ABCDEF0)

        self.assertEqual(len(data), 36)
        self.assertEqual(sum(data[:20]) & 0xFF, 0)
        self.assertEqual(sum(data) & 0xFF, 0)


class TestRSDTAndXSDT(unittest.TestCase):
    """RSDT and XSDT are arrays of 32-bit and 64-bit table pointers."""

    def test_rsdt_entries_are_32_bit_pointers(self):
        rsdt = RSDT()
        rsdt.parse(struct.pack('<2I', 0x7A611000, 0x7A612000))

        self.assertEqual(list(rsdt.Entries), [0x7A611000, 0x7A612000])

    def test_xsdt_entries_are_64_bit_pointers(self):
        xsdt = XSDT()
        xsdt.parse(struct.pack('<2Q', 0x7A611000, 0x7A612000))

        self.assertEqual(list(xsdt.Entries), [0x7A611000, 0x7A612000])

    def test_trailing_partial_entries_are_dropped(self):
        rsdt = RSDT()
        rsdt.parse(struct.pack('<I', 0x7A611000) + b'\x00\x00')

        self.assertEqual(len(rsdt.Entries), 1)

    def test_content_smaller_than_one_entry_yields_no_entries(self):
        xsdt = XSDT()
        xsdt.parse(b'\x00' * 4)

        self.assertEqual(len(xsdt.Entries), 0)

    def test_empty_content_is_rejected(self):
        with self.assertRaises(ValueError):
            RSDT().parse(b'')
        with self.assertRaises(ValueError):
            XSDT().parse(b'')

    def test_entries_are_listed_when_rendered(self):
        xsdt = XSDT()
        xsdt.parse(struct.pack('<Q', 0x7A611000))

        self.assertIn('0x000000007A611000', str(xsdt))


class TestFADT(unittest.TestCase):
    """The FADT locates the DSDT through either a 32-bit or 64-bit pointer."""

    @staticmethod
    def _fadt(dsdt=0x7A611000, x_dsdt=None, smi=0xB2, enable=0xA0, disable=0xA1):
        content = bytearray(112 if x_dsdt is not None else 64)
        struct.pack_into('<I', content, 4, dsdt)
        struct.pack_into('<I', content, 12, smi)
        content[16] = enable
        content[17] = disable
        if x_dsdt is not None:
            struct.pack_into('<Q', content, 104, x_dsdt)
        return bytes(content)

    def test_legacy_fields_are_parsed(self):
        fadt = FADT()
        fadt.parse(self._fadt())

        self.assertEqual(fadt.dsdt, 0x7A611000)
        self.assertEqual(fadt.smi, 0xB2)
        self.assertEqual(fadt.acpi_enable, 0xA0)
        self.assertEqual(fadt.acpi_disable, 0xA1)

    def test_short_tables_have_no_extended_dsdt_pointer(self):
        fadt = FADT()
        fadt.parse(self._fadt())

        self.assertIsNone(fadt.x_dsdt)

    def test_extended_dsdt_pointer_is_parsed_when_present(self):
        fadt = FADT()
        fadt.parse(self._fadt(x_dsdt=0x7A620000))

        self.assertEqual(fadt.x_dsdt, 0x7A620000)

    def test_empty_content_is_rejected(self):
        with self.assertRaises(ValueError):
            FADT().parse(b'')

    def test_truncated_content_is_rejected(self):
        with self.assertRaises(ValueError):
            FADT().parse(b'\x00' * 10)

    def test_legacy_pointer_is_used_when_there_is_no_extended_pointer(self):
        fadt = FADT()
        fadt.parse(self._fadt(dsdt=0x7A611000))

        self.assertEqual(fadt.get_DSDT_address_to_use(), 0x7A611000)

    def test_extended_pointer_wins_when_the_legacy_pointer_is_empty(self):
        fadt = FADT()
        fadt.parse(self._fadt(dsdt=0, x_dsdt=0x7A620000))

        self.assertEqual(fadt.get_DSDT_address_to_use(), 0x7A620000)

    def test_legacy_pointer_is_used_when_the_extended_pointer_is_empty(self):
        fadt = FADT()
        fadt.parse(self._fadt(dsdt=0x7A611000, x_dsdt=0))

        self.assertEqual(fadt.get_DSDT_address_to_use(), 0x7A611000)

    def test_matching_pointers_resolve_to_a_single_address(self):
        fadt = FADT()
        fadt.parse(self._fadt(dsdt=0x7A611000, x_dsdt=0x7A611000))

        self.assertEqual(fadt.get_DSDT_address_to_use(), 0x7A611000)

    def test_conflicting_pointers_are_not_resolved(self):
        fadt = FADT()
        fadt.parse(self._fadt(dsdt=0x7A611000, x_dsdt=0x7A620000))

        self.assertIsNone(fadt.get_DSDT_address_to_use())

    def test_no_pointer_at_all_is_not_resolved(self):
        fadt = FADT()
        fadt.parse(self._fadt(dsdt=0))

        self.assertIsNone(fadt.get_DSDT_address_to_use())

    def test_rendering_reports_a_missing_extended_pointer(self):
        fadt = FADT()
        fadt.parse(self._fadt())

        self.assertIn('Not found', str(fadt))


class TestBGRT(unittest.TestCase):
    """BGRT describes the boot logo and its orientation."""

    @staticmethod
    def _bgrt(status=0, image_type=0):
        return struct.pack('<HbbQII', 1, status, image_type, 0x769F5018, 0x2F3, 0x127)

    def test_image_geometry_is_parsed(self):
        bgrt = BGRT()
        bgrt.parse(self._bgrt())

        self.assertEqual(bgrt.ImageAddress, 0x769F5018)
        self.assertEqual(bgrt.ImageOffsetX, 0x2F3)
        self.assertEqual(bgrt.ImageOffsetY, 0x127)

    def test_each_defined_status_maps_to_a_rotation(self):
        rotations = []
        for status in range(4):
            bgrt = BGRT()
            bgrt.parse(self._bgrt(status=status))
            rotations.append(bgrt.OrientationOffset)

        self.assertEqual(rotations, ['0 degrees', '90 degrees', '180 degrees', '270 degrees'])

    def test_undefined_status_is_reported_as_reserved(self):
        bgrt = BGRT()
        bgrt.parse(self._bgrt(status=7))

        self.assertIn('Reserved', bgrt.OrientationOffset)

    def test_image_type_zero_is_a_bitmap(self):
        bgrt = BGRT()
        bgrt.parse(self._bgrt(image_type=0))

        self.assertIn('Bitmap', bgrt.ImageTypeStr)

    def test_other_image_types_are_reserved(self):
        bgrt = BGRT()
        bgrt.parse(self._bgrt(image_type=1))

        self.assertEqual(bgrt.ImageTypeStr, 'Reserved')

    def test_rendering_includes_the_decoded_orientation(self):
        bgrt = BGRT()
        bgrt.parse(self._bgrt(status=2))

        self.assertIn('180 degrees', str(bgrt))


class TestWSMT(unittest.TestCase):
    """WSMT advertises which SMM mitigations the firmware implements."""

    def test_no_mitigations_are_reported_when_no_bits_are_set(self):
        wsmt = WSMT()
        wsmt.parse(struct.pack('<L', 0))

        self.assertFalse(wsmt.fixed_comm_buffers)
        self.assertFalse(wsmt.comm_buffer_nested_ptr_protection)
        self.assertFalse(wsmt.system_resource_protection)

    def test_each_mitigation_bit_is_decoded_independently(self):
        wsmt = WSMT()
        wsmt.parse(struct.pack('<L', WSMT.FIXED_COMM_BUFFERS | WSMT.SYSTEM_RESOURCE_PROTECTION))

        self.assertTrue(wsmt.fixed_comm_buffers)
        self.assertFalse(wsmt.comm_buffer_nested_ptr_protection)
        self.assertTrue(wsmt.system_resource_protection)

    def test_all_mitigations_can_be_set_at_once(self):
        wsmt = WSMT()
        wsmt.parse(struct.pack('<L', 0x7))

        self.assertTrue(all([wsmt.fixed_comm_buffers,
                             wsmt.comm_buffer_nested_ptr_protection,
                             wsmt.system_resource_protection]))

    def test_truncated_content_leaves_the_defaults_in_place(self):
        wsmt = WSMT()
        wsmt.parse(b'\x00')

        self.assertFalse(wsmt.fixed_comm_buffers)

    def test_rendering_lists_every_mitigation(self):
        wsmt = WSMT()
        wsmt.parse(struct.pack('<L', 0x7))
        rendered = str(wsmt)

        self.assertIn('FIXED_COMM_BUFFERS', rendered)
        self.assertIn('SYSTEM_RESOURCE_PROTECTION', rendered)


class TestUEFITable(unittest.TestCase):
    """The UEFI table carries the SMM communication buffer description."""

    SMM_COMM_GUID = b'\xe2\xd8\x8e\xc6\xc6\x9d\xbdL\x9d\x94\xdbe\xac\xc5\xc32'
    OTHER_GUID = b'\x11' * 16

    @classmethod
    def _table(cls, guid=None, data_offset=54, smi=1, buf_addr=0x7A9FB000, gas=None):
        content = (guid or cls.SMM_COMM_GUID) + struct.pack('<H', data_offset)
        content += struct.pack('<I', smi) + struct.pack('<Q', buf_addr)
        if gas is not None:
            content += gas
        return content

    def test_content_too_short_for_a_guid_is_ignored(self):
        table = UEFI_TABLE()
        table.parse(b'\x00' * 8)

        self.assertEqual(table.get_commbuf_info(), (0, 0, None))

    def test_tables_for_other_guids_are_not_decoded_further(self):
        table = UEFI_TABLE()
        table.parse(self._table(guid=self.OTHER_GUID))

        self.assertEqual(table.get_commbuf_info(), (0, 0, None))

    def test_smm_communication_buffer_is_decoded(self):
        table = UEFI_TABLE()
        table.parse(self._table())

        smi, buf_addr, _invoc = table.get_commbuf_info()
        self.assertEqual(smi, 1)
        self.assertEqual(buf_addr, 0x7A9FB000)

    def test_missing_invocation_register_is_reported(self):
        table = UEFI_TABLE()
        table.parse(self._table())

        self.assertIsNone(table.get_commbuf_info()[2])
        self.assertIn('Invocation Register        : None', str(table))

    def test_invocation_register_is_decoded_when_present(self):
        gas = struct.pack('<BBBBQ', 1, 8, 0, 1, 0xB2)
        table = UEFI_TABLE()
        table.parse(self._table(gas=gas))

        invoc = table.get_commbuf_info()[2]
        self.assertIsInstance(invoc, GAS)
        self.assertEqual(invoc.addr, 0xB2)

    def test_data_offset_outside_the_table_is_ignored(self):
        table = UEFI_TABLE()
        table.parse(self._table(data_offset=0))

        self.assertEqual(table.get_commbuf_info()[0], 0)


class TestGenericAddressStructure(unittest.TestCase):
    """GAS is the generic register descriptor reused across ACPI tables."""

    @staticmethod
    def _gas(space_id=0, access_size=3, addr=0xFED40000):
        return struct.pack('<BBBBQ', space_id, 32, 0, access_size, addr)

    def test_fields_are_decoded_in_order(self):
        gas = GAS(self._gas())

        self.assertEqual(gas.get_info(), (0, 32, 0, 3, 0xFED40000))

    def test_known_address_spaces_are_named(self):
        names = [GAS(self._gas(space_id=sid)).addrSpaceID_str for sid in (0, 1, 2, 3, 4, 0x0A, 0x7F)]

        self.assertNotIn('Reserved', names)
        self.assertEqual(names[0], 'System Memory Space')

    def test_oem_range_is_recognized(self):
        self.assertEqual(GAS(self._gas(space_id=0xC5)).addrSpaceID_str, 'OEM Defined')

    def test_unassigned_address_space_is_reserved(self):
        self.assertEqual(GAS(self._gas(space_id=0x50)).addrSpaceID_str, 'Reserved')

    def test_known_access_sizes_are_named(self):
        self.assertEqual(GAS(self._gas(access_size=2)).accessSize_str, 'Word Access')

    def test_out_of_range_access_size_falls_back_to_the_catch_all(self):
        self.assertIn('Not a defined value', GAS(self._gas(access_size=9)).accessSize_str)

    def test_rendering_includes_the_address(self):
        self.assertIn('FED40000', str(GAS(self._gas())))


class TestSafeStructUnpack(unittest.TestCase):

    def test_unpacks_when_enough_data_is_available(self):
        self.assertEqual(safe_struct_unpack('<I', struct.pack('<I', 0x1234)), (0x1234,))

    def test_honors_the_requested_offset(self):
        self.assertEqual(safe_struct_unpack('<I', b'\xff' * 4 + struct.pack('<I', 7), 4), (7,))

    def test_insufficient_data_is_rejected(self):
        with self.assertRaises(ValueError):
            safe_struct_unpack('<Q', b'\x00' * 4)

    def test_insufficient_data_after_the_offset_is_rejected(self):
        with self.assertRaises(ValueError):
            safe_struct_unpack('<I', b'\x00' * 6, 4)


class TestDMARStructureTypes(unittest.TestCase):
    """Each DMAR remapping structure type has its own decoder."""

    def setUp(self):
        self.dmar = DMAR()

    def test_hardware_unit_definition(self):
        structure = struct.pack('=HHBBHQ', 0, 24, 0, 0, 0, 0xFED90000)
        structure += struct.pack('=BBBBBB', 1, 8, 0, 0, 0, 0) + b'\x02\x00'

        rendered = self.dmar._get_structure_DMAR(0x00, structure)

        self.assertIn('DMA Remapping Hardware Unit Definition', rendered)
        self.assertIn('FED90000', rendered)

    def test_reserved_memory_region(self):
        structure = struct.pack('=HHHHQQ', 1, 24, 0, 0, 0x7AB90000, 0x7ADEFFFF)

        rendered = self.dmar._get_structure_DMAR(0x01, structure)

        self.assertIn('Reserved Memory Range', rendered)
        self.assertIn('7AB90000', rendered)

    def test_root_port_ats_capability(self):
        rendered = self.dmar._get_structure_DMAR(0x02, struct.pack('=HHBBH', 2, 8, 0, 0, 0))

        self.assertIn('Root Port ATS Capability', rendered)

    def test_hardware_static_affinity(self):
        structure = struct.pack('=HHIQI', 3, 20, 0, 0xFED91000, 0)

        rendered = self.dmar._get_structure_DMAR(0x03, structure)

        self.assertIn('FED91000', rendered)

    def test_namespace_device_declaration(self):
        structure = struct.pack('HH3sB4s', 4, 12, b'\x00\x00\x00', 1, b'NAME')

        rendered = self.dmar._get_structure_DMAR(0x04, structure)

        self.assertIn('ACPI Device Number', rendered)

    def test_soc_address_translation_cache(self):
        rendered = str(self.dmar._get_structure_DMAR(0x05, struct.pack('HHBBH', 5, 8, 0, 0, 0)))

        self.assertIn('SoC Integrated Address Translation Cache', rendered)

    def test_soc_device_property(self):
        rendered = str(self.dmar._get_structure_DMAR(0x06, struct.pack('HHHH', 6, 8, 0, 0)))

        self.assertIn('Reporting Structure', rendered)

    def test_device_scope_entries_are_attached_to_their_parent(self):
        structure = struct.pack('=HHBBHQ', 0, 24, 0, 0, 0, 0xFED90000)
        structure += struct.pack('=BBBBBB', 3, 8, 0, 0, 2, 0) + b'\x1f\x00'

        rendered = self.dmar._get_structure_DMAR(0x00, structure)

        self.assertIn('I/O APIC Device', rendered)

    def test_empty_content_is_rejected(self):
        with self.assertRaises(ValueError):
            DMAR().parse(b'')

    def test_truncated_content_is_rejected(self):
        with self.assertRaises(ValueError):
            DMAR().parse(b'\x00' * 4)

    def test_structure_longer_than_the_table_stops_parsing(self):
        header = struct.pack('=BB10s', 39, 0, b'\x00' * 10)
        table = DMAR()
        table.parse(header + struct.pack('=HH', 0, 0xFF))

        self.assertEqual(table.dmar_structures, [])

    def test_zero_length_structure_stops_parsing(self):
        header = struct.pack('=BB10s', 39, 0, b'\x00' * 10)
        table = DMAR()
        table.parse(header + struct.pack('=HH', 0, 0))

        self.assertEqual(table.dmar_structures, [])
        self.assertEqual(table.HostAddrWidth, 39)


class TestAPICStructureTypes(unittest.TestCase):
    """Each MADT interrupt controller structure type has its own decoder."""

    def setUp(self):
        self.apic = APIC()

    def _render(self, type_id, fmt_key, *fields):
        data = struct.pack(self.apic.APIC_TABLE_FORMAT[fmt_key], *fields)
        return self.apic.get_structure_APIC(type_id, data)

    def test_processor_local_apic(self):
        self.assertIn('Processor Local APIC', self._render(0x00, 'PROCESSOR_LAPIC', 0, 8, 1, 2, 1))

    def test_io_apic(self):
        self.assertIn('I/O APIC', self._render(0x01, 'IOAPIC', 1, 12, 2, 0, 0xFEC00000, 0))

    def test_interrupt_source_override(self):
        self.assertIn('Interrupt Source Override',
                      self._render(0x02, 'INTERRUPT_SOURSE_OVERRIDE', 2, 10, 0, 0, 2, 0))

    def test_nmi_source(self):
        self.assertIn('Non-maskable Interrupt', self._render(0x03, 'NMI_SOURCE', 3, 8, 0, 0))

    def test_local_apic_nmi(self):
        self.assertIn('Local APIC NMI', self._render(0x04, 'LAPIC_NMI', 4, 6, 1, 0, 1))

    def test_local_apic_address_override(self):
        self.assertIn('Local APIC Address Override',
                      self._render(0x05, 'LAPIC_ADDRESS_OVERRIDE', 5, 12, 0, 0xFEE00000))

    def test_io_sapic(self):
        self.assertIn('I/O SAPIC', self._render(0x06, 'IOSAPIC', 6, 16, 1, 0, 0, 0xFEC00000))

    def test_platform_interrupt_sources(self):
        rendered = self._render(
            0x08, 'PLATFORM_INTERRUPT_SOURCES',
            8, 16, 0x1, 0x2, 0x3, 0x4, 0x5, 0x1234, 0x6)

        self.assertIn('Platform Interrupt Sources', rendered)
        self.assertIn('0x05', rendered)
        self.assertIn('0x1234', rendered)

    def test_processor_local_x2apic(self):
        self.assertIn('Processor Local x2APIC',
                      self._render(0x09, 'PROCESSOR_Lx2APIC', 9, 16, 0, 4, 1, 4))

    def test_local_x2apic_nmi(self):
        self.assertIn('Local x2APIC NMI',
                      self._render(0x0A, 'Lx2APIC_NMI', 0x0A, 12, 0, 0, 1, b'\x00\x00\x00'))

    def test_gicc_cpu_interface(self):
        self.assertIn('GICC CPU Interface',
                      self._render(0x0B, 'GICC_CPU', 0x0B, 76, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    def test_gic_distributor(self):
        self.assertIn('GIC Distributor',
                      self._render(0x0C, 'GIC_DISTRIBUTOR', 0x0C, 24, 0, 0, 0, 0, 0))

    def test_gic_msi_frame(self):
        self.assertIn('MSI Frame', self._render(0x0D, 'GIC_MSI', 0x0D, 24, 0, 0, 0, 0, 0, 0))

    def test_gic_redistributor(self):
        self.assertIn('Redistributor', self._render(0x0E, 'GIC_REDISTRIBUTOR', 0x0E, 16, 0, 0, 0))

    def test_unknown_structure_type_is_dumped_rather_than_dropped(self):
        rendered = self.apic.get_structure_APIC(0x7F, b'\xAA' * 8)

        self.assertIn('Reserved', rendered)

    def test_empty_content_is_rejected(self):
        with self.assertRaises(ValueError):
            APIC().parse(b'')

    def test_truncated_content_is_rejected(self):
        with self.assertRaises(ValueError):
            APIC().parse(b'\x00' * 4)

    def test_zero_length_structure_stops_parsing(self):
        table = APIC()
        table.parse(struct.pack('=II', 0xFEE00000, 1) + struct.pack('=BB', 0, 0))

        self.assertEqual(table.apic_structs, [])
        self.assertEqual(table.LAPICBase, 0xFEE00000)

    def test_structure_longer_than_the_table_stops_parsing(self):
        table = APIC()
        table.parse(struct.pack('=II', 0xFEE00000, 1) + struct.pack('=BB', 0, 0xFF))

        self.assertEqual(table.apic_structs, [])


if __name__ == '__main__':
    unittest.main()
