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

# To execute: python[3] -m unittest tests.library.test_linux_boot_params

import os
import struct
import tempfile
import unittest
from unittest.mock import patch

from chipsec.library import linux_boot_params as boot_params

BOOT_PARAMS_SIZE = 0x1000


def _boot_params(signature=b'EL64', systab=0, size=BOOT_PARAMS_SIZE):
    data = bytearray(size)
    efi_info = struct.pack(boot_params.EFI_INFO_FMT, signature, systab & 0xFFFFFFFF, 0x30, 1,
                           0x1000, 0x2000, systab >> 32, 0)
    data[boot_params.EFI_INFO_OFFSET:boot_params.EFI_INFO_OFFSET + len(efi_info)] = efi_info
    return bytes(data[:size])


class TestBootParamsSystemTable(unittest.TestCase):

    def setUp(self):
        patcher = patch.object(boot_params, 'logger')
        self.addCleanup(patcher.stop)
        patcher.start()
        fd, self.path = tempfile.mkstemp()
        os.close(fd)
        self.addCleanup(os.remove, self.path)

    def _write(self, data):
        with open(self.path, 'wb') as f:
            f.write(data)

    def test_returns_64bit_system_table_address(self):
        self._write(_boot_params(systab=0x1_7FEE0018))
        self.assertEqual(boot_params.get_efi_system_table_address(self.path), 0x1_7FEE0018)

    def test_non_efi_boot_returns_none(self):
        self._write(_boot_params(signature=b'\x00\x00\x00\x00', systab=0x7FEE0018))
        self.assertIsNone(boot_params.get_efi_system_table_address(self.path))

    def test_32bit_firmware_returns_none(self):
        self._write(_boot_params(signature=b'EL32', systab=0x7FEE0018))
        self.assertIsNone(boot_params.get_efi_system_table_address(self.path))

    def test_zero_address_returns_none(self):
        self._write(_boot_params(systab=0))
        self.assertIsNone(boot_params.get_efi_system_table_address(self.path))

    def test_truncated_file_returns_none(self):
        self._write(_boot_params(systab=0x7FEE0018)[:boot_params.EFI_INFO_OFFSET + 8])
        self.assertIsNone(boot_params.get_efi_system_table_address(self.path))

    def test_missing_file_returns_none(self):
        self.assertIsNone(boot_params.get_efi_system_table_address(self.path + '.missing'))


if __name__ == '__main__':
    unittest.main()
