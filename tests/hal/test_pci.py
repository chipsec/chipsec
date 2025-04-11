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
from chipsec.hal.common.pci import Pci
from chipsec.library.register import ObjList, Register
from chipsec.cfg.parsers.ip.pci_device import PCIConfig
from chipsec.cfg.parsers.registers.pci import PCIRegisters

class TestPCI(unittest.TestCase):
    def test_(self):
        mock_cs = MagicMock()
        vid = 0x8086
        did = 0x1234
        rid = 0xa
        mock_cs.helper.read_pci_reg.return_value = (did << 16) | vid
        pci_data = {'bus': 0, 'dev': 0, 'fun': 0, 'vid': vid, 'did': did,'rid': rid}
        pcilist = ObjList([PCIConfig(pci_data)])
        test_acpi = Pci(mock_cs)
        new_data = test_acpi.get_viddidrid_from_device_list(pcilist)
        self.assertEqual(len(new_data), 1)
        new_vid, new_did, new_rid, _ = new_data[0]
        self.assertEqual(new_vid, vid)
        self.assertEqual(new_did, did)
        self.assertEqual(new_rid, rid)
