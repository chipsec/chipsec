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
from unittest.mock import patch, mock_open

from chipsec.library import defines


class TestBitHelpers(unittest.TestCase):
    """Cover the bit helpers in chipsec.library.defines."""

    def test_bit(self):
        self.assertEqual(defines.bit(0), 1)
        self.assertEqual(defines.bit(4), 0x10)

    def test_is_set(self):
        self.assertTrue(defines.is_set(0b1010, 0b0010))
        self.assertFalse(defines.is_set(0b1010, 0b0100))

    def test_scan_single_bit_mask_finds_bit(self):
        self.assertEqual(defines.scan_single_bit_mask(1), 0)
        self.assertEqual(defines.scan_single_bit_mask(1 << 3), 3)

    def test_scan_single_bit_mask_zero_returns_none(self):
        self.assertIsNone(defines.scan_single_bit_mask(0))

    def test_scan_single_bit_mask_out_of_range_returns_none(self):
        # Bit 7 is outside the scanned range(0, 7).
        self.assertIsNone(defines.scan_single_bit_mask(1 << 7))

    def test_get_bits(self):
        self.assertEqual(defines.get_bits(0xF0, 4, 4), 0xF)
        self.assertEqual(defines.get_bits(0b10110, 1, 3), 0b011)


class TestPackHelpers(unittest.TestCase):
    """Cover the byte pack helpers in chipsec.library.defines."""

    def test_DB(self):
        self.assertEqual(defines.DB(0xAB), struct.pack('<B', 0xAB))

    def test_DW(self):
        self.assertEqual(defines.DW(0x1234), struct.pack('<H', 0x1234))

    def test_DD(self):
        self.assertEqual(defines.DD(0x11223344), struct.pack('<L', 0x11223344))

    def test_DQ(self):
        self.assertEqual(defines.DQ(0x1122334455667788), struct.pack('<Q', 0x1122334455667788))

    def test_pack1_and_unpack1_roundtrip(self):
        for size in (1, 2, 4, 8):
            max_val = (1 << (size * 8)) - 1
            self.assertEqual(defines.unpack1(defines.pack1(max_val, size), size), max_val)


class TestStringByteHelpers(unittest.TestCase):
    """Cover string/byte conversions in chipsec.library.defines."""

    def test_bytestostring_from_bytes(self):
        self.assertEqual(defines.bytestostring(b'abc'), 'abc')

    def test_bytestostring_passthrough_for_str(self):
        self.assertEqual(defines.bytestostring('abc'), 'abc')

    def test_stringtobytes_from_str(self):
        self.assertEqual(defines.stringtobytes('abc'), b'abc')

    def test_stringtobytes_passthrough_for_bytes(self):
        self.assertEqual(defines.stringtobytes(b'abc'), b'abc')

    def test_is_printable(self):
        self.assertTrue(defines.is_printable('hello'))
        self.assertFalse(defines.is_printable(b'\x00\x01'))

    def test_is_hex(self):
        self.assertTrue(defines.is_hex('deadBEEF'))
        self.assertFalse(defines.is_hex('nothex'))


class TestValueHelpers(unittest.TestCase):
    """Cover value helpers in chipsec.library.defines."""

    def test_is_all_ones_true(self):
        self.assertTrue(defines.is_all_ones(0xFF, 1))
        self.assertTrue(defines.is_all_ones(0xFFFF, 2))

    def test_is_all_ones_false(self):
        self.assertFalse(defines.is_all_ones(0xFE, 1))

    def test_is_all_value_empty_is_false(self):
        self.assertFalse(defines.is_all_value([], 0))

    def test_is_all_value_true(self):
        self.assertTrue(defines.is_all_value([5, 5, 5], 5))

    def test_is_all_value_false(self):
        self.assertFalse(defines.is_all_value([5, 5, 6], 5))


class TestVersionHelpers(unittest.TestCase):
    """Cover version/OS helpers in chipsec.library.defines."""

    def test_get_version_returns_non_empty_string(self):
        version = defines.get_version()
        self.assertIsInstance(version, str)
        self.assertTrue(version)

    def test_os_version_returns_four_tuple(self):
        result = defines.os_version()
        self.assertEqual(len(result), 4)
        self.assertTrue(all(isinstance(item, str) for item in result))


class TestMessageHelper(unittest.TestCase):
    """Cover get_message file handling in chipsec.library.defines."""

    def test_get_message_reads_existing_file(self):
        with patch.object(defines.os.path, 'exists', return_value=True), \
                patch('builtins.open', mock_open(read_data='hello world')):
            self.assertEqual(defines.get_message(), 'hello world')

    def test_get_message_missing_file_returns_empty(self):
        with patch.object(defines.os.path, 'exists', return_value=False):
            self.assertEqual(defines.get_message(), '')


if __name__ == '__main__':
    unittest.main()
