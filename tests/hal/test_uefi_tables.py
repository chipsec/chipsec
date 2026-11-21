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

"""Locating the EFI System Table without scanning memory."""

import struct
import unittest
from unittest.mock import MagicMock

from chipsec.hal.common import uefi as uefi_hal
from chipsec.library.exceptions import PhysicalMemoryAccessError
from chipsec.library.uefi.common import (
    EFI_SYSTEM_TABLE_SIGNATURE,
    EFI_TABLE_HEADER_FMT,
    EFI_SYSTEM_TABLE_FMT,
)

EST_ADDR = 0x7B932080
# With SMRAM at 3 MiB the fallback scan reads exactly one 1 MiB chunk at 2 MiB.
SMRAM_BASE = 0x300000
SCAN_PA = 0x200000
SCAN_SZ = 0x100000


def system_table_bytes(signature=EFI_SYSTEM_TABLE_SIGNATURE):
    """A plausible EFI System Table: header followed by its 12 qwords."""
    header = struct.pack(EFI_TABLE_HEADER_FMT, signature.encode('ascii'),
                         0x0002005A, struct.calcsize(EFI_TABLE_HEADER_FMT), 0x12345678, 0)
    body = struct.pack(EFI_SYSTEM_TABLE_FMT, *([0] * 12))
    return header + body


def make_uefi():
    """Real UEFI HAL over a mock chipset (helper comes from cs.helper)."""
    cs = MagicMock()
    hal = uefi_hal.UEFI(cs)
    return hal, cs


class TestFindEfiSystemTable(unittest.TestCase):

    def setUp(self):
        self.hal, self.cs = make_uefi()
        self.cs.hals.memory.read_physical_mem.return_value = system_table_bytes()

    def test_the_reported_address_is_used_instead_of_scanning(self):
        self.hal.helper.get_EFI_System_Table_address.return_value = EST_ADDR

        (found, pa, header, _table, _buf) = self.hal.find_EFI_Table(EFI_SYSTEM_TABLE_SIGNATURE)

        self.assertTrue(found)
        self.assertEqual(pa, EST_ADDR)
        # The signature is an 8 byte string in the header, not a packed integer.
        self.assertEqual(header.Signature.decode('ascii'), EFI_SYSTEM_TABLE_SIGNATURE)
        self.cs.hals.cpu.get_SMRAM.assert_not_called()

    def _set_scan_window(self):
        self.cs.hals.cpu.get_SMRAM.return_value = (SMRAM_BASE, 0, 0)
        self.cs.hals.cpu.get_TSEG.return_value = (0, 0, 0)

    def assert_scanned(self):
        self.cs.hals.memory.read_physical_mem.assert_any_call(SCAN_PA, SCAN_SZ)

    def test_a_wrong_signature_falls_back_to_scanning(self):
        self.hal.helper.get_EFI_System_Table_address.return_value = EST_ADDR
        self.cs.hals.memory.read_physical_mem.return_value = system_table_bytes('NOTATABL')
        self._set_scan_window()

        (found, _pa, _header, _table, _buf) = self.hal.find_EFI_Table(EFI_SYSTEM_TABLE_SIGNATURE)

        self.assertFalse(found)
        self.assert_scanned()

    def test_no_reported_address_falls_back_to_scanning(self):
        self.hal.helper.get_EFI_System_Table_address.return_value = None
        self._set_scan_window()

        (found, pa, _header, _table, _buf) = self.hal.find_EFI_Table(EFI_SYSTEM_TABLE_SIGNATURE)

        # The scan finds the table at the start of the chunk it read.
        self.assertTrue(found)
        self.assertEqual(pa, SCAN_PA)
        self.assert_scanned()

    def test_an_unreadable_address_falls_back_to_scanning(self):
        self.hal.helper.get_EFI_System_Table_address.return_value = EST_ADDR
        self.cs.hals.memory.read_physical_mem.side_effect = PhysicalMemoryAccessError('not accessible', 17)
        self._set_scan_window()

        (found, _pa, _header, _table, _buf) = self.hal.find_EFI_Table(EFI_SYSTEM_TABLE_SIGNATURE)

        self.assertFalse(found)
        self.assert_scanned()

    def test_a_short_read_falls_back_to_scanning(self):
        self.hal.helper.get_EFI_System_Table_address.return_value = EST_ADDR
        self.cs.hals.memory.read_physical_mem.side_effect = [system_table_bytes()[:-1], b'\x00' * SCAN_SZ]
        self._set_scan_window()

        (found, _pa, _header, _table, _buf) = self.hal.find_EFI_Table(EFI_SYSTEM_TABLE_SIGNATURE)

        self.assertFalse(found)
        self.assert_scanned()


if __name__ == '__main__':
    unittest.main()
