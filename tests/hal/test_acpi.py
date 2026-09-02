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

from unittest.mock import MagicMock, patch
from chipsec.library.acpi_tables import RSDP
from chipsec.hal.common.acpi import ACPI, ACPI_TABLE_SIG_DSDT
from chipsec.library.acpi_aml_parser import (
    AMLFieldLocation,
    CRSExecutor,
    CRSResourceParser,
    find_fields_in_acpi_nvs,
    find_named_integers,
    find_named_objects,
    parse_aml_pkg_length,
)

class TestACPI(unittest.TestCase):
    def test_apci_read_rsdp(self):
        mock_cs = MagicMock()
        rsdp_buf = b'RSD PTR \x93INTEL\x00\x02(\xd0^z'
        rsdp_buf_ext = b'RSD PTR \x93INTEL\x00\x02(\xd0^z$\x00\x00\x00\xc0\xd0^z\x00\x00\x00\x00t\x00\x00\x00'
        mock_cs.hals.memory.read_physical_mem.side_effect = [rsdp_buf, rsdp_buf_ext]
        pa = 983056
        test_acpi = ACPI(mock_cs)
        self.assertIsInstance(test_acpi.read_RSDP(pa), RSDP)

    def test_find_sbreg_location_in_acpi_nvs(self):
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

        named_integers, fields = find_named_objects([fake_dsdt], ['PNVB', 'SBRG'])
        self.assertEqual(named_integers, [0x70000000])
        self.assertEqual(fields, [AMLFieldLocation('SBRG', 'PNVA', 0x70000000, 0, 64)])

    def test_find_root_qualified_named_objects(self):
        name_pnvb = b'\x08\\PNVB\x0c\x00\x00\x00\x70'
        opreg_pnva = b'\x5b\x80PNVA\x00PNVB\x0a\x80'
        field_pnva = b'\x5b\x81\x0cPNVA\x03SBRG\x40\x04'
        name_sbrg = b'\x08\\SBRG\x0c\x00\x00\x00\xfd'
        fake_dsdt = b'DSDT' + b'\x00' * 32 + name_pnvb + opreg_pnva + field_pnva + name_sbrg

        named_integers, fields = find_named_objects([fake_dsdt], ['SBRG'])
        self.assertEqual(named_integers, [0xFD000000])
        self.assertEqual(fields, [AMLFieldLocation('SBRG', 'PNVA', 0x70000000, 0, 64)])

    def test_named_object_compatibility_wrappers(self):
        name_pnvb = b'\x08PNVB\x0c\x00\x00\x00\x70'
        opreg_pnva = b'\x5b\x80PNVA\x00PNVB\x0a\x80'
        field_pnva = b'\x5b\x81\x0cPNVA\x03SBRG\x40\x04'
        fake_dsdt = b'DSDT' + b'\x00' * 32 + name_pnvb + opreg_pnva + field_pnva

        self.assertEqual(find_named_integers([fake_dsdt], ['PNVB']), [0x70000000])
        self.assertEqual(
            find_fields_in_acpi_nvs([fake_dsdt], ['SBRG']),
            [AMLFieldLocation('SBRG', 'PNVA', 0x70000000, 0, 64)])

    def test_field_region_name_does_not_cross_scopes(self):
        region_dev0 = b'\x5b\x80\x2eDEV0PNVA\x00\x0c\x00\x00\x00\x70\x0a\x80'
        region_dev1 = b'\x5b\x80\x2eDEV1PNVA\x00\x0c\x00\x00\x00\x71\x0a\x80'
        qualified_field = b'\x5b\x81\x11\x2eDEV0PNVA\x03SBRG\x40\x04'
        ambiguous_field = b'\x5b\x81\x0cPNVA\x03SBRG\x40\x04'

        qualified_dsdt = b'DSDT' + b'\x00' * 32 + region_dev0 + region_dev1 + qualified_field
        _, fields = find_named_objects([qualified_dsdt], ['SBRG'])
        self.assertEqual(
            fields,
            [AMLFieldLocation('SBRG', 'DEV0.PNVA', 0x70000000, 0, 64)])

        ambiguous_dsdt = b'DSDT' + b'\x00' * 32 + region_dev0 + region_dev1 + ambiguous_field
        _, fields = find_named_objects([ambiguous_dsdt], ['SBRG'])
        self.assertEqual(fields, [])

    def test_shared_aml_decoders(self):
        encoded_length = b'\xff\x41\x10'
        self.assertEqual(parse_aml_pkg_length(encoded_length, 1), (0x101, 2))
        self.assertEqual(CRSResourceParser.parse_pkg_length(encoded_length, 1), (0x101, 3))

        executor = CRSExecutor()
        self.assertEqual(executor._decode_simple_int(b'\x0c\x00\x00\x00\xfd', 0), (0xFD000000, 5))
        self.assertEqual(executor._decode_simple_name(b'SBRG', 0), ('SBRG', 4))

    def test_get_acpi_field_value_reads_field_from_memory(self):
        name_pnvb = b'\x08PNVB\x0c\x00\x00\x00\x70'
        opreg_pnva = b'\x5b\x80PNVA\x00PNVB\x0a\x80'
        field_pnva = b'\x5b\x81\x0cPNVA\x03SBRG\x40\x04'
        fake_dsdt = b'DSDT' + b'\x00' * 32 + name_pnvb + opreg_pnva + field_pnva

        mock_cs = MagicMock()
        mock_cs.hals.memory.read_physical_mem.return_value = struct.pack('<Q', 0xFD000000)
        test_acpi = ACPI(mock_cs)
        test_acpi.tableList = {ACPI_TABLE_SIG_DSDT: [0]}
        test_acpi.get_ACPI_table = MagicMock(return_value=[(fake_dsdt[:36], fake_dsdt[36:])])

        values = test_acpi.get_acpi_field_value([ACPI_TABLE_SIG_DSDT], ['SBRG'])
        self.assertEqual(values, [0xFD000000])
        test_acpi.get_ACPI_table.assert_called_once_with(ACPI_TABLE_SIG_DSDT)
        mock_cs.hals.memory.read_physical_mem.assert_called_once_with(0x70000000, 8)

    def test_get_sbreg_base_address_skips_invalid_candidates(self):
        mock_cs = MagicMock()
        test_acpi = ACPI(mock_cs)
        test_acpi.get_acpi_field_value = MagicMock(return_value=[0, 0xFD100000, 0xFD000000])

        self.assertEqual(test_acpi.get_sbreg_base_address(), 0xFD000000)

    def test_list_operation_regions_compatibility_wrapper(self):
        test_acpi = ACPI(MagicMock())
        test_acpi.list_dsdtssdt_operation_regions = MagicMock(return_value=['region'])

        self.assertEqual(test_acpi.list_operation_regions(False, False), ['region'])
        test_acpi.list_dsdtssdt_operation_regions.assert_called_once_with(False, False)

    @patch('chipsec.hal.common.acpi.logger')
    def test_get_acpi_field_value_logs_memory_read_failure(self, mock_logger):
        name_pnvb = b'\x08PNVB\x0c\x00\x00\x00\x70'
        opreg_pnva = b'\x5b\x80PNVA\x00PNVB\x0a\x80'
        field_pnva = b'\x5b\x81\x0cPNVA\x03SBRG\x40\x04'
        fake_dsdt = b'DSDT' + b'\x00' * 32 + name_pnvb + opreg_pnva + field_pnva
        mock_cs = MagicMock()
        mock_cs.hals.memory.read_physical_mem.side_effect = RuntimeError('unmapped')
        test_acpi = ACPI(mock_cs)
        mock_logger.reset_mock()
        test_acpi.tableList = {ACPI_TABLE_SIG_DSDT: [0]}
        test_acpi.get_ACPI_table = MagicMock(return_value=[(fake_dsdt[:36], fake_dsdt[36:])])

        self.assertEqual(test_acpi.get_acpi_field_value([ACPI_TABLE_SIG_DSDT], ['SBRG']), [])
        mock_logger().log_hal.assert_called_once_with(
            '[acpi] Error reading SBRG at 0x0000000070000000: unmapped')
