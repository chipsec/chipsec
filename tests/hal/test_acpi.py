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
from chipsec.hal.acpi_tables import RSDP
from chipsec.hal.acpi import ACPI

class TestACPI(unittest.TestCase):
    def test_apci_read_rsdp(self):
        mock_cs = MagicMock()
        rsdp_buf = b'RSD PTR \x93INTEL\x00\x02(\xd0^z'
        rsdp_buf_ext = b'RSD PTR \x93INTEL\x00\x02(\xd0^z$\x00\x00\x00\xc0\xd0^z\x00\x00\x00\x00t\x00\x00\x00'
        mock_cs.mem.read_physical_mem.side_effect = [rsdp_buf, rsdp_buf_ext]
        pa = 983056
        test_acpi = ACPI(mock_cs)
        self.assertIsInstance(test_acpi.read_RSDP(pa), RSDP)