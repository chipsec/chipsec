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

from chipsec.library.structs import DB, DW, DD, DQ, pack1, unpack1, SIZE2FORMAT


class TestStructPackers(unittest.TestCase):
    """Cover the little-endian pack helpers in chipsec.library.structs."""

    def test_DB_packs_single_byte(self):
        self.assertEqual(DB(0xAB), b'\xab')

    def test_DW_packs_little_endian_word(self):
        self.assertEqual(DW(0x1234), b'\x34\x12')

    def test_DD_packs_little_endian_dword(self):
        self.assertEqual(DD(0x11223344), b'\x44\x33\x22\x11')

    def test_DQ_packs_little_endian_qword(self):
        self.assertEqual(DQ(0x1122334455667788), struct.pack('<Q', 0x1122334455667788))

    def test_DB_overflow_raises(self):
        with self.assertRaises(struct.error):
            DB(0x100)


class TestPack1Unpack1(unittest.TestCase):
    """Cover the size-driven pack1/unpack1 helpers."""

    def test_size_to_format_map(self):
        self.assertEqual(SIZE2FORMAT, {1: 'B', 2: 'H', 4: 'I', 8: 'Q'})

    def test_pack1_for_each_size(self):
        self.assertEqual(pack1(0xAB, 1), struct.pack('B', 0xAB))
        self.assertEqual(pack1(0x1234, 2), struct.pack('H', 0x1234))
        self.assertEqual(pack1(0x11223344, 4), struct.pack('I', 0x11223344))
        self.assertEqual(pack1(0x1122334455667788, 8), struct.pack('Q', 0x1122334455667788))

    def test_unpack1_for_each_size(self):
        self.assertEqual(unpack1(struct.pack('B', 0xAB), 1), 0xAB)
        self.assertEqual(unpack1(struct.pack('H', 0x1234), 2), 0x1234)
        self.assertEqual(unpack1(struct.pack('I', 0x11223344), 4), 0x11223344)
        self.assertEqual(unpack1(struct.pack('Q', 0xDEADBEEFCAFEBABE), 8), 0xDEADBEEFCAFEBABE)

    def test_pack_unpack_roundtrip_max_values(self):
        for size in (1, 2, 4, 8):
            max_val = (1 << (size * 8)) - 1
            self.assertEqual(unpack1(pack1(max_val, size), size), max_val)

    def test_pack1_invalid_size_raises_keyerror(self):
        with self.assertRaises(KeyError):
            pack1(0, 3)

    def test_unpack1_invalid_size_raises_keyerror(self):
        with self.assertRaises(KeyError):
            unpack1(b'\x00', 3)


if __name__ == '__main__':
    unittest.main()
