# CHIPSEC: Platform Security Assessment Framework

import unittest
from unittest.mock import Mock, patch

from chipsec import chipset
from tests.software import mock_helper


class DriverlessFirmwareHelper(mock_helper.TestHelper):
    def __init__(self):
        super().__init__()
        self.driver_loaded = False

    def firmware_vendor(self):
        return 'DriverlessVendor'

    def firmware_product(self):
        return 'DriverlessProduct'

    def firmware_version(self):
        return 'DriverlessVersion'

    def firmware_type(self):
        return 'UEFI'


class FirmwareInfoTest(unittest.TestCase):
    def tearDown(self):
        chipset.clear_cs()

    def test_driverless_firmware_info_uses_helper(self):
        cs = chipset.Chipset.basic_init_with_helper(DriverlessFirmwareHelper())

        self.assertEqual(cs.firmware_vendor(), 'DriverlessVendor')
        self.assertEqual(cs.firmware_product(), 'DriverlessProduct')
        self.assertEqual(cs.firmware_version(), 'DriverlessVersion')
        self.assertEqual(cs.firmware_type(), 'UEFI')

        cs.destroy_helper()

    @patch('chipsec.chipset.SMBIOS')
    def test_driver_mode_firmware_info_uses_smbios(self, mock_smbios):
        cs = chipset.Chipset.basic_init_with_helper(mock_helper.TestHelper())
        smbios = Mock()
        smbios.find_smbios_table.return_value = True
        smbios.get_decoded_structs.side_effect = [
            [Mock(vendor_str=1, version_str=2, strings=['SmbiosVendor', 'SmbiosVersion'])],
            [Mock(product_str=1, strings=['SmbiosProduct'])]
        ]
        mock_smbios.return_value = smbios
        cs.hals.uefi = Mock()
        cs.hals.uefi.find_EFI_Configuration_Table.return_value = (True, 0, object(), b'')

        self.assertEqual(cs.firmware_vendor(), 'SmbiosVendor')
        self.assertEqual(cs.firmware_product(), 'SmbiosProduct')
        self.assertEqual(cs.firmware_version(), 'SmbiosVersion')
        self.assertEqual(cs.firmware_type(), 'UEFI')

        cs.destroy_helper()