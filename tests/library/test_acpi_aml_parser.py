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

from chipsec.library.acpi_aml_parser import (
    AMLParser,
    CRSExecutor,
    CRSResourceParser,
    OperationRegion,
    ResourceDescriptorParser,
    parse_operation_regions,
)

ACPI_HEADER_SIZE = 36


def aml_byte(value: int) -> bytes:
    """Encode an AML BytePrefix integer."""
    return b'\x0a' + struct.pack('<B', value)


def aml_word(value: int) -> bytes:
    return b'\x0b' + struct.pack('<H', value)


def aml_dword(value: int) -> bytes:
    return b'\x0c' + struct.pack('<I', value)


def aml_qword(value: int) -> bytes:
    return b'\x0e' + struct.pack('<Q', value)


def op_region(name: bytes, space_type: int, base: bytes, length: bytes) -> bytes:
    """Build an AML OperationRegion declaration."""
    return b'\x5b\x80' + name + struct.pack('<B', space_type) + base + length


def name_decl(name: bytes, value: bytes) -> bytes:
    """Build an AML Name() declaration."""
    return b'\x08' + name + value


def table(*payloads: bytes) -> bytes:
    """Prefix an AML payload with a dummy 36-byte ACPI description header."""
    return b'\x00' * ACPI_HEADER_SIZE + b''.join(payloads) + b'\x00' * 8


class TestAMLParserOperationRegions(unittest.TestCase):
    """OperationRegion discovery is the primary contract of the AML parser."""

    def test_finds_operation_region_with_literal_address(self):
        dsdt = table(op_region(b'PMCR', 0x00, aml_dword(0xFE000000), aml_dword(0x1000)))

        regions = AMLParser().parse([dsdt])

        self.assertEqual(len(regions), 1)
        self.assertEqual(regions[0].name, 'PMCR')
        self.assertEqual(regions[0].base, 0xFE000000)
        self.assertEqual(regions[0].length, 0x1000)

    def test_space_type_is_resolved_to_a_readable_name(self):
        dsdt = table(op_region(b'IOPR', 0x01, aml_dword(0x00001000), aml_byte(0x40)))

        regions = AMLParser().parse([dsdt])

        self.assertEqual(regions[0].space_type, 0x01)
        self.assertEqual(regions[0].space_type_name, 'SystemIO')

    def test_unknown_space_type_is_reported_rather_than_dropped(self):
        dsdt = table(op_region(b'ODDR', 0x42, aml_dword(0xFE000000), aml_byte(0x40)))

        regions = AMLParser().parse([dsdt])

        self.assertEqual(len(regions), 1)
        self.assertIn('Unknown', regions[0].space_type_name)

    def test_address_declared_through_a_name_symbol_is_resolved(self):
        dsdt = table(
            name_decl(b'BASV', aml_dword(0xFE000000)),
            op_region(b'RGNX', 0x00, b'BASV', aml_dword(0x2000)),
        )

        regions = AMLParser().parse([dsdt])

        self.assertEqual(len(regions), 1)
        self.assertEqual(regions[0].base, 0xFE000000)
        self.assertEqual(regions[0].length, 0x2000)

    def test_unresolvable_symbol_reference_is_skipped(self):
        dsdt = table(op_region(b'RGNX', 0x00, b'NOPE', aml_dword(0x2000)))

        self.assertEqual(AMLParser().parse([dsdt]), [])

    def test_regions_with_no_length_are_rejected(self):
        dsdt = table(op_region(b'RGNX', 0x00, aml_dword(0xFE000000), b'\x00'))

        self.assertEqual(AMLParser().parse([dsdt]), [])

    def test_regions_with_implausible_length_are_rejected(self):
        dsdt = table(op_region(b'RGNX', 0x00, aml_dword(0xFE000000), aml_dword(0x20000000)))

        self.assertEqual(AMLParser().parse([dsdt]), [])

    def test_regions_with_invalid_base_are_rejected(self):
        zero_base = table(op_region(b'RGNA', 0x00, b'\x00', aml_dword(0x1000)))
        all_ones_base = table(op_region(b'RGNB', 0x00, aml_dword(0xFFFFFFFF), aml_dword(0x1000)))

        self.assertEqual(AMLParser().parse([zero_base]), [])
        self.assertEqual(AMLParser().parse([all_ones_base]), [])

    def test_regions_above_the_supported_address_ceiling_are_dropped(self):
        dsdt = table(op_region(b'HIGH', 0x00, aml_qword(0x2000000000), aml_dword(0x1000)))

        self.assertEqual(AMLParser().parse([dsdt]), [])

    def test_regions_are_returned_sorted_by_base_address(self):
        dsdt = table(
            op_region(b'HIGH', 0x00, aml_dword(0xFF000000), aml_dword(0x1000)),
            op_region(b'LOWR', 0x00, aml_dword(0xE0000000), aml_dword(0x1000)),
        )

        bases = [r.base for r in AMLParser().parse([dsdt])]

        self.assertEqual(bases, sorted(bases))

    def test_regions_are_collected_across_multiple_tables(self):
        dsdt = table(op_region(b'RGNA', 0x00, aml_dword(0xE0000000), aml_dword(0x1000)))
        ssdt = table(op_region(b'RGNB', 0x00, aml_dword(0xF0000000), aml_dword(0x1000)))

        names = {r.name for r in AMLParser().parse([dsdt, ssdt])}

        self.assertEqual(names, {'RGNA', 'RGNB'})

    def test_tables_smaller_than_an_acpi_header_are_ignored(self):
        self.assertEqual(AMLParser().parse([b'\x00' * 10]), [])

    def test_parse_is_repeatable_and_does_not_accumulate_state(self):
        dsdt = table(op_region(b'PMCR', 0x00, aml_dword(0xFE000000), aml_dword(0x1000)))
        parser = AMLParser()

        first = parser.parse([dsdt])
        second = parser.parse([dsdt])

        self.assertEqual(len(first), len(second))

    def test_garbage_input_does_not_raise(self):
        garbage = b'\x00' * ACPI_HEADER_SIZE + bytes(range(256)) * 4

        self.assertIsInstance(AMLParser().parse([garbage]), list)


class TestAMLParserNameDecoding(unittest.TestCase):
    """Name string decoding drives both symbol resolution and region naming."""

    def setUp(self):
        self.parser = AMLParser()

    def test_simple_name_segment(self):
        self.assertEqual(self.parser._decode_name_string_simple(b'PMCR', 0), ('PMCR', 4))

    def test_trailing_underscore_padding_is_stripped(self):
        name, consumed = self.parser._decode_name_string_simple(b'PM__', 0)
        self.assertEqual(name, 'PM')
        self.assertEqual(consumed, 4)

    def test_root_prefixed_name(self):
        name, consumed = self.parser._decode_name_string_simple(b'\\PMCR', 0)
        self.assertEqual(name, '\\PMCR')
        self.assertEqual(consumed, 5)

    def test_dual_name_path(self):
        name, consumed = self.parser._decode_name_string_simple(b'\x2ePCI0PMCR', 0)
        self.assertEqual(name, 'PCI0.PMCR')
        self.assertEqual(consumed, 9)

    def test_multi_name_path(self):
        name, consumed = self.parser._decode_name_string_simple(b'\x2f\x03SB__PCI0PMCR', 0)
        self.assertEqual(name, 'SB.PCI0.PMCR')
        self.assertEqual(consumed, 14)

    def test_parent_prefix_is_not_supported(self):
        self.assertEqual(self.parser._decode_name_string_simple(b'\x5ePMCR', 0), (None, 0))

    def test_non_name_bytes_are_rejected(self):
        self.assertEqual(self.parser._decode_name_string_simple(b'\xff\xff\xff\xff', 0), (None, 0))

    def test_offset_past_end_of_buffer(self):
        self.assertEqual(self.parser._decode_name_string_simple(b'PMCR', 99), (None, 0))


class TestAMLParserIntegerDecoding(unittest.TestCase):
    """AML integers use a variable-length encoding that the parser must honor."""

    def setUp(self):
        self.parser = AMLParser()

    def test_zero_and_one_opcodes(self):
        self.assertEqual(self.parser._decode_aml_integer(b'\x00', 0), (0, 1))
        self.assertEqual(self.parser._decode_aml_integer(b'\x01', 0), (1, 1))

    def test_literal_single_byte_opcodes(self):
        self.assertEqual(self.parser._decode_aml_integer(b'\x05', 0), (5, 1))

    def test_prefixed_widths(self):
        self.assertEqual(self.parser._decode_aml_integer(aml_byte(0xAB), 0), (0xAB, 2))
        self.assertEqual(self.parser._decode_aml_integer(aml_word(0xBEEF), 0), (0xBEEF, 3))
        self.assertEqual(self.parser._decode_aml_integer(aml_dword(0xDEADBEEF), 0), (0xDEADBEEF, 5))
        self.assertEqual(
            self.parser._decode_aml_integer(aml_qword(0x1122334455667788), 0),
            (0x1122334455667788, 9),
        )

    def test_truncated_encoding_is_not_decoded(self):
        self.assertEqual(self.parser._decode_aml_integer(b'\x0c\x01\x02', 0), (None, 0))

    def test_name_reference_is_reported_as_undecodable(self):
        self.assertEqual(self.parser._decode_aml_integer(b'BASV', 0), (None, 0))

    def test_offset_past_end_of_buffer(self):
        self.assertEqual(self.parser._decode_aml_integer(b'\x0a\x01', 5), (None, 0))


class TestParseOperationRegionsFunction(unittest.TestCase):
    """The module level helper adapts the parser output for callers."""

    def test_returns_serializable_dictionaries(self):
        dsdt = table(op_region(b'PMCR', 0x00, aml_dword(0xFE000000), aml_dword(0x1000)))

        results = parse_operation_regions([dsdt])

        self.assertEqual(len(results), 1)
        self.assertEqual(
            set(results[0]),
            {'name', 'space_type', 'space_type_name', 'base', 'length', 'source'},
        )
        self.assertEqual(results[0]['base'], 0xFE000000)

    def test_no_tables_yields_no_regions(self):
        self.assertEqual(parse_operation_regions([]), [])


class TestCRSPackageLength(unittest.TestCase):
    """AML package lengths use a lead byte that selects the encoding width."""

    def test_single_byte_encoding(self):
        self.assertEqual(CRSResourceParser.parse_pkg_length(b'\x25', 0), (0x25, 1))

    def test_multi_byte_encoding_consumes_follow_on_bytes(self):
        length, pos = CRSResourceParser.parse_pkg_length(b'\x41\x02', 0)
        self.assertEqual(length, 0x21)
        self.assertEqual(pos, 2)

    def test_offset_past_end_of_buffer_is_safe(self):
        self.assertEqual(CRSResourceParser.parse_pkg_length(b'\x25', 5), (0, 5))


class TestCRSBufferExtraction(unittest.TestCase):
    """_CRS methods that simply return a Buffer are decoded statically."""

    @staticmethod
    def _crs_method(resource_bytes: bytes) -> bytes:
        buffer_op = (b'\x11' + struct.pack('<B', len(resource_bytes) + 2) +
                     b'\x0a' + struct.pack('<B', len(resource_bytes)) + resource_bytes)
        body = b'\xa4' + buffer_op
        rest = b'_CRS' + b'\x00' + body
        return b'\x14' + struct.pack('<B', len(rest)) + rest

    def test_buffer_is_extracted_from_crs_method(self):
        resource = b'\x85\x09\x00\x00' + struct.pack('<I', 0xFED00000) + struct.pack('<I', 0x1000)

        extracted = CRSResourceParser.extract_crs_buffer(self._crs_method(resource))

        self.assertEqual(extracted, resource)

    def test_missing_crs_method_returns_none(self):
        self.assertIsNone(CRSResourceParser.extract_crs_buffer(b'\x00' * 64))

    def test_truncated_input_returns_none(self):
        self.assertIsNone(CRSResourceParser.extract_crs_buffer(b''))


class TestCRSResourceDecoding(unittest.TestCase):
    """Resource descriptors inside a _CRS buffer map to address/size pairs."""

    def test_fixed_memory32_descriptor(self):
        buf = (b'\x85\x09\x00' + b'\x00' + struct.pack('<I', 0xFED00000) +
               struct.pack('<I', 0x1000) + b'\x79\x00')

        resources = CRSResourceParser.decode_crs_buffer(buf)

        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['type'], 'FixedMemory32')
        self.assertEqual(resources[0]['address'], 0xFED00000)
        self.assertEqual(resources[0]['size'], 0x1000)

    def test_memory32_descriptor_derives_size_from_range_when_length_is_zero(self):
        data = (b'\x01' + struct.pack('<I', 0x1000) + struct.pack('<I', 0x1FFF) +
                struct.pack('<I', 0) + struct.pack('<I', 0))
        buf = b'\x84' + struct.pack('<H', len(data)) + data + b'\x79\x00'

        resources = CRSResourceParser.decode_crs_buffer(buf)

        self.assertEqual(resources[0]['type'], 'Memory32')
        self.assertEqual(resources[0]['address'], 0x1000)
        self.assertEqual(resources[0]['size'], 0x1000)

    def test_dword_address_space_memory_descriptor(self):
        data = (b'\x00\x00\x00\x00' + struct.pack('<I', 0xC0000000) +
                struct.pack('<I', 0xCFFFFFFF) + struct.pack('<I', 0) +
                struct.pack('<I', 0) + struct.pack('<I', 0x10000000))
        buf = b'\x87' + struct.pack('<H', len(data)) + data + b'\x79\x00'

        resources = CRSResourceParser.decode_crs_buffer(buf)

        self.assertEqual(resources[0]['type'], 'DWordMemory')
        self.assertEqual(resources[0]['address'], 0xC0000000)
        self.assertEqual(resources[0]['size'], 0x10000000)

    def test_qword_address_space_memory_descriptor(self):
        data = (b'\x00\x00\x00\x00' + struct.pack('<Q', 0x100000000) +
                struct.pack('<Q', 0x1FFFFFFFF) + struct.pack('<Q', 0) +
                struct.pack('<Q', 0) + struct.pack('<Q', 0x100000000) + b'\x00' * 3)
        buf = b'\x8a' + struct.pack('<H', len(data)) + data + b'\x79\x00'

        resources = CRSResourceParser.decode_crs_buffer(buf)

        self.assertEqual(resources[0]['type'], 'QWordMemory')
        self.assertEqual(resources[0]['address'], 0x100000000)

    def test_small_irq_and_dma_descriptors(self):
        buf = b'\x23\x00\xf8\x00' + b'\x2a\x00\x04' + b'\x79\x00'

        types = [r['type'] for r in CRSResourceParser.decode_crs_buffer(buf)]

        self.assertEqual(types, ['IRQ', 'DMA'])

    def test_decoding_stops_at_the_end_tag(self):
        trailing = b'\x85\x09\x00' + b'\x00' + struct.pack('<I', 0xFED00000) + struct.pack('<I', 0x1000)
        buf = b'\x79\x00' + trailing

        self.assertEqual(CRSResourceParser.decode_crs_buffer(buf), [])

    def test_empty_buffer_yields_no_resources(self):
        self.assertEqual(CRSResourceParser.decode_crs_buffer(b''), [])


class TestCRSExecutor(unittest.TestCase):
    """Dynamic _CRS methods assign their base/length through Store operations."""

    def test_store_assignments_to_known_fields_are_captured(self):
        aml = (b'\x70' + aml_dword(0xFE000000) + b'BAS1' +
               b'\x70' + aml_dword(0x00001000) + b'LEN1')

        fields = CRSExecutor().extract_crs_fields(aml)

        self.assertEqual(fields['BAS1'], 0xFE000000)
        self.assertEqual(fields['LEN1'], 0x1000)

    def test_stores_to_unrelated_fields_are_ignored(self):
        aml = b'\x70' + aml_dword(0x1234) + b'FOO1' + b'\x00' * 8

        self.assertEqual(CRSExecutor().extract_crs_fields(aml), {})

    def test_synthetic_regions_are_created_from_crs_field_pairs(self):
        aml = (b'\x70' + aml_dword(0xFE000000) + b'BAS1' +
               b'\x70' + aml_dword(0x00001000) + b'LEN1')

        regions = AMLParser().parse([b'\x00' * ACPI_HEADER_SIZE + aml + b'\x00' * 8])

        crs_regions = [r for r in regions if r.source == 'CRS_Fields']
        self.assertEqual(len(crs_regions), 1)
        self.assertEqual(crs_regions[0].base, 0xFE000000)
        self.assertEqual(crs_regions[0].length, 0x1000)
        self.assertTrue(crs_regions[0].name.endswith('BAS1'))

    def test_base_without_a_matching_length_produces_no_region(self):
        aml = b'\x70' + aml_dword(0xFE000000) + b'BAS1'

        regions = AMLParser().parse([b'\x00' * ACPI_HEADER_SIZE + aml + b'\x00' * 8])

        self.assertEqual([r for r in regions if r.source == 'CRS_Fields'], [])


class TestResourceDescriptorParser(unittest.TestCase):
    """The descriptor scanner walks a raw _CRS body without a package wrapper."""

    def test_returns_nothing_for_buffers_without_descriptors(self):
        self.assertEqual(ResourceDescriptorParser().extract_from_crs_binary(b'\x00' * 32, {}), [])

    def test_malformed_large_descriptor_does_not_raise(self):
        self.assertEqual(ResourceDescriptorParser().extract_from_crs_binary(b'\x87\xff\xff\x01', {}), [])


class TestOperationRegionDataclass(unittest.TestCase):

    def test_source_defaults_to_static_operation_region(self):
        region = OperationRegion('PMCR', 0, 'SystemMemory', 0xFE000000, 0x1000)

        self.assertEqual(region.source, 'OperationRegion')


if __name__ == '__main__':
    unittest.main()
