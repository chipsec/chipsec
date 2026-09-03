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
from tests.helpers.acpi_utils import build_rsdp

class TestACPI(unittest.TestCase):
    def test_apci_read_rsdp(self):
        mock_cs = MagicMock()
        rsdp = build_rsdp(
            revision=2,
            rsdt_address=0x7A5ED028,
            xsdt_address=0x7A5ED0C0)
        mock_cs.hals.memory.read_physical_mem.side_effect = [rsdp[:20], rsdp]
        pa = 983056
        test_acpi = ACPI(mock_cs)
        self.assertIsInstance(test_acpi.read_RSDP(pa), RSDP)