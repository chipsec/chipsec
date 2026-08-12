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

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock

from chipsec.chipset import Chipset


LIVE_DEVICES = {'8086': {'0x1234': {'bus': 0, 'dev': 0, 'fun': 0}}}


class TestInitCfgBusCacheFallback(unittest.TestCase):
    """Cover the PCI enumeration cache fallbacks in Chipset.init_cfg_bus()."""

    def setUp(self):
        self.cs = Chipset.__new__(Chipset)
        self.cs.logger = MagicMock(HAL=False, DEBUG=False, VERBOSE=False)
        self.cs.options = MagicMock()
        self.cs.hals = MagicMock()
        self.cs.hals.pci.enumerate_devices.return_value = LIVE_DEVICES
        self.cs.Cfg = MagicMock()
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(self._cleanup_tmpdir)

    def _cleanup_tmpdir(self):
        for name in os.listdir(self.tmpdir):
            os.remove(os.path.join(self.tmpdir, name))
        os.rmdir(self.tmpdir)

    def _set_options(self, reuse, filename):
        values = {
            ('PCI_Enum', 'reuse_platform_detection'): reuse,
            ('PCI_Enum', 'enum_devices_filename'): filename,
        }
        self.cs.options.get_section_data.side_effect = \
            lambda section, key, default=None: values.get((section, key), default)

    def _assert_live_scan_used(self):
        self.cs.hals.pci.enumerate_devices.assert_called_once_with()
        self.cs.Cfg.set_pci_data.assert_called_once_with(LIVE_DEVICES)

    def test_reuse_enabled_without_filename_falls_back_to_live_scan(self):
        self._set_options(reuse=True, filename=None)

        self.cs.init_cfg_bus()

        self._assert_live_scan_used()

    def test_reuse_enabled_with_empty_filename_falls_back_to_live_scan(self):
        self._set_options(reuse=True, filename='')

        self.cs.init_cfg_bus()

        self._assert_live_scan_used()

    def test_missing_cache_file_falls_back_to_live_scan_and_writes_cache(self):
        cache_path = os.path.join(self.tmpdir, 'missing.json')
        self._set_options(reuse=True, filename=cache_path)

        self.cs.init_cfg_bus()

        self._assert_live_scan_used()
        with open(cache_path) as cache_file:
            self.assertEqual(LIVE_DEVICES, json.load(cache_file))

    def test_invalid_cache_file_falls_back_to_live_scan(self):
        cache_path = os.path.join(self.tmpdir, 'invalid.json')
        with open(cache_path, 'w') as cache_file:
            cache_file.write('not valid json')
        self._set_options(reuse=True, filename=cache_path)

        self.cs.init_cfg_bus()

        self._assert_live_scan_used()

    def test_valid_cache_file_is_used_without_live_scan(self):
        cache_path = os.path.join(self.tmpdir, 'valid.json')
        with open(cache_path, 'w') as cache_file:
            json.dump(LIVE_DEVICES, cache_file)
        self._set_options(reuse=True, filename=cache_path)

        self.cs.init_cfg_bus()

        self.cs.hals.pci.enumerate_devices.assert_not_called()
        self.cs.Cfg.set_pci_data.assert_called_once_with(LIVE_DEVICES)


if __name__ == '__main__':
    unittest.main()
