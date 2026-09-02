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

import unittest

from unittest.mock import MagicMock
from chipsec.library.acpi_tables import RSDP
from chipsec.hal.common.acpi import ACPI
from chipsec.library.acpi_aml_parser import find_field_in_acpi_nvs

class TestACPI(unittest.TestCase):
    def test_apci_read_rsdp(self):
        mock_cs = MagicMock()
        rsdp_buf = b'RSD PTR \x93INTEL\x00\x02(\xd0^z'
        rsdp_buf_ext = b'RSD PTR \x93INTEL\x00\x02(\xd0^z$\x00\x00\x00\xc0\xd0^z\x00\x00\x00\x00t\x00\x00\x00'
        mock_cs.hals.memory.read_physical_mem.side_effect = [rsdp_buf, rsdp_buf_ext]
        pa = 983056
        test_acpi = ACPI(mock_cs)
        self.assertIsInstance(test_acpi.read_RSDP(pa), RSDP)

    def test_find_sbreg_in_acpi_nvs(self):
        # Synthetic AML:
        # Name(PNVB, 0x70000000)
        # OpRegion(PNVA, SystemMemory, PNVB, 0x80)
        # Field(PNVA, AnyAcc, Lock, Preserve) { SBRG, 64 }
        name_pnvb = b'\x08PNVB\x0c\x00\x00\x00\x70'  # Name(PNVB, 0x70000000)
        opreg_pnva = b'\x5b\x80PNVA\x00PNVB\x0a\x80'  # OpRegion(PNVA, SystemMemory, PNVB, 0x80)
        # Field(PNVA, DWordAcc) { SBRG, 64 }
        # 64-bit PkgLength in AML is encoded as 0x40 0x04 (2 bytes)
        field_pnva = b'\x5b\x81\x0cPNVA\x03SBRG\x40\x04'
        aml_body = name_pnvb + opreg_pnva + field_pnva
        fake_dsdt = b'DSDT' + b'\x00' * 32 + aml_body

        mock_mem = MagicMock()
        import struct
        mock_mem.read_physical_mem.return_value = struct.pack('<Q', 0xFD000000)

        sbreg = find_field_in_acpi_nvs([fake_dsdt], ['SBRG'], mock_mem)
        self.assertEqual(sbreg, 0xFD000000)
        mock_mem.read_physical_mem.assert_called_once_with(0x70000000, 8)
