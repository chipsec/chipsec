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

import re
import unittest
from unittest.mock import patch

from chipsec.library import strings


class TestGetDatetimeStr(unittest.TestCase):
    """Cover chipsec.library.strings.get_datetime_str."""

    def test_format_is_stable(self):
        value = strings.get_datetime_str()
        self.assertRegex(value, r'^[A-Za-z]{3}[A-Za-z]{3}\d{2}\d{2}-\d{6}$')

    def test_uses_strftime_pattern(self):
        with patch.object(strings, 'strftime', return_value='sentinel') as mock_strftime:
            self.assertEqual(strings.get_datetime_str(), 'sentinel')
        mock_strftime.assert_called_once_with('%a%b%d%y-%H%M%S')


class TestByteStringConversions(unittest.TestCase):
    """Cover the latin_1 round-trip helpers."""

    def test_bytestostring_decodes_bytes(self):
        self.assertEqual(strings.bytestostring(b'\x41\xff'), 'A\xff')

    def test_bytestostring_decodes_bytearray(self):
        self.assertEqual(strings.bytestostring(bytearray(b'chipsec')), 'chipsec')

    def test_bytestostring_passes_str_through(self):
        self.assertEqual(strings.bytestostring('already str'), 'already str')

    def test_stringtobytes_encodes_str(self):
        self.assertEqual(strings.stringtobytes('A\xff'), b'\x41\xff')

    def test_stringtobytes_passes_bytes_through(self):
        self.assertEqual(strings.stringtobytes(b'raw'), b'raw')

    def test_round_trip_preserves_all_byte_values(self):
        raw = bytes(range(256))
        self.assertEqual(strings.stringtobytes(strings.bytestostring(raw)), raw)


class TestJoinHexValues(unittest.TestCase):
    """Cover chipsec.library.strings.join_hex_values."""

    def test_default_pads_to_16_digits(self):
        self.assertEqual(strings.join_hex_values([0x1]), '0x0000000000000001')

    def test_multiple_values_use_default_delimiter(self):
        self.assertEqual(strings.join_hex_values([0xA, 0xB], size='2'), '0x0A, 0x0B')

    def test_custom_delimiter(self):
        self.assertEqual(strings.join_hex_values([1, 2], size='1', delimiter=';'), '0x1; 0x2')

    def test_uppercase_hex_digits(self):
        self.assertEqual(strings.join_hex_values([0xdeadbeef], size='8'), '0xDEADBEEF')

    def test_empty_list_returns_empty_string(self):
        self.assertEqual(strings.join_hex_values([]), '')


class TestJoinIntValues(unittest.TestCase):
    """Cover chipsec.library.strings.join_int_values."""

    def test_default_size_has_no_padding(self):
        self.assertEqual(strings.join_int_values([1, 22]), '1, 22')

    def test_size_pads_with_spaces(self):
        self.assertEqual(strings.join_int_values([1], size='4'), '   1')

    def test_custom_delimiter(self):
        self.assertEqual(strings.join_int_values([1, 2], delimiter='|'), '1| 2')

    def test_empty_list_returns_empty_string(self):
        self.assertEqual(strings.join_int_values([]), '')


class TestIsPrintable(unittest.TestCase):
    """Cover chipsec.library.strings.is_printable."""

    def test_printable_bytes(self):
        self.assertTrue(strings.is_printable(b'CHIPSEC 1.0'))

    def test_printable_str(self):
        self.assertTrue(strings.is_printable('CHIPSEC'))

    def test_non_printable_bytes(self):
        self.assertFalse(strings.is_printable(b'\x00\x01'))

    def test_empty_sequence_is_printable(self):
        self.assertTrue(strings.is_printable(b''))


class TestIsHex(unittest.TestCase):
    """Cover chipsec.library.strings.is_hex."""

    def test_lower_and_upper_hex_digits(self):
        self.assertTrue(strings.is_hex('deadBEEF0123'))

    def test_non_hex_character(self):
        self.assertFalse(strings.is_hex('12g4'))

    def test_leading_0x_prefix_is_not_hex(self):
        self.assertFalse(strings.is_hex('0x10'))

    def test_empty_string_is_hex(self):
        self.assertTrue(strings.is_hex(''))


class TestMakeHexKeyStr(unittest.TestCase):
    """Cover chipsec.library.strings.make_hex_key_str."""

    def test_pads_to_four_digits(self):
        self.assertEqual(strings.make_hex_key_str(0x1), '0001')

    def test_uses_uppercase(self):
        self.assertEqual(strings.make_hex_key_str(0xabcd), 'ABCD')

    def test_values_wider_than_four_digits_are_not_truncated(self):
        self.assertEqual(strings.make_hex_key_str(0x12345), '12345')

    def test_key_is_usable_as_regex_safe_token(self):
        self.assertIsNone(re.search(r'[^0-9A-F]', strings.make_hex_key_str(0x8086)))


if __name__ == '__main__':
    unittest.main()
