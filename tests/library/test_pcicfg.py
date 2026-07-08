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

import unittest

from unittest.mock import MagicMock
from chipsec.library.registers.pcicfg import PCICfg


class TestPCICfg(unittest.TestCase):
    """Cover PCICfg.get_def and PCICfg.get_match against a mocked Cfg."""

    def _make_pcicfg(self, pci_devices, scope_tuple):
        cs = MagicMock()
        cs.Cfg.PCI_DEVICES = pci_devices
        cs.Cfg.get_scope.return_value = 'scope'
        cs.Cfg.convert_internal_scope.return_value = scope_tuple  # (vid, device, bar, _)
        return PCICfg(cs), cs

    # -- get_def --------------------------------------------------------------

    def test_get_def_returns_device_definition_when_present(self):
        devdef = {'name': 'HOSTCTL'}
        pci_devices = {'8086': {'HOSTCTL': {'0': devdef}}}
        pci, _ = self._make_pcicfg(pci_devices, ('8086', 'HOSTCTL', '0', None))
        self.assertIs(pci.get_def('8086.HOSTCTL.0'), devdef)

    def test_get_def_returns_none_when_device_missing(self):
        pci_devices = {'8086': {'HOSTCTL': {'0': {}}}}
        pci, _ = self._make_pcicfg(pci_devices, ('8086', 'MISSING', '0', None))
        self.assertIsNone(pci.get_def('8086.MISSING.0'))

    def test_get_def_returns_none_when_vid_missing(self):
        pci, _ = self._make_pcicfg({}, ('8086', 'HOSTCTL', '0', None))
        self.assertIsNone(pci.get_def('8086.HOSTCTL.0'))

    # -- get_match ------------------------------------------------------------

    def test_get_match_specific_identifier(self):
        pci_devices = {'8086': {'HOSTCTL': {'0': {}}}}
        pci, _ = self._make_pcicfg(pci_devices, ('8086', 'HOSTCTL', '0', None))
        self.assertEqual(pci.get_match('8086.HOSTCTL.0'), ['8086.HOSTCTL.0'])

    def test_get_match_wildcard_vid_matches_all_vendors(self):
        pci_devices = {
            '8086': {'HOSTCTL': {'0': {}}},
            '1022': {'DEV': {'0': {}}},
        }
        pci, _ = self._make_pcicfg(pci_devices, ('*', '*', '*', None))
        self.assertCountEqual(pci.get_match('*'), ['8086.HOSTCTL.0', '1022.DEV.0'])

    def test_get_match_none_treated_as_wildcard(self):
        pci_devices = {'8086': {'HOSTCTL': {'0': {}, '1': {}}}}
        pci, _ = self._make_pcicfg(pci_devices, (None, None, None, None))
        self.assertCountEqual(pci.get_match('anything'), ['8086.HOSTCTL.0', '8086.HOSTCTL.1'])

    def test_get_match_returns_empty_when_no_devices(self):
        pci, _ = self._make_pcicfg({}, ('8086', 'HOSTCTL', '0', None))
        self.assertEqual(pci.get_match('8086.HOSTCTL.0'), [])

    def test_get_match_skips_unknown_bar(self):
        pci_devices = {'8086': {'HOSTCTL': {'0': {}}}}
        pci, _ = self._make_pcicfg(pci_devices, ('8086', 'HOSTCTL', '9', None))
        self.assertEqual(pci.get_match('8086.HOSTCTL.9'), [])


if __name__ == '__main__':
    unittest.main()
