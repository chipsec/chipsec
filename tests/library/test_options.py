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

import configparser
import os
import tempfile
import textwrap
import unittest
from unittest.mock import patch

from chipsec.library import options as options_module
from chipsec.library.options import Options, NoDefault
from chipsec.library.exceptions import CSConfigError


# Controlled fixture so the tests do not depend on the values shipped in the
# real chipsec/options/cmd_options.ini (which may legitimately change).
FIXTURE_CMD_OPTIONS_INI = textwrap.dedent("""\
    [Util_Config]
    smbios_get_type = raw
    """)


class TestOptions(unittest.TestCase):
    """Cover the cmd option reader in chipsec.library.options."""

    def setUp(self):
        # Build a minimal cmd_options.ini in a temp main dir and point
        # get_main_dir() at it so Options() reads our controlled fixture.
        self._main_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._main_dir.cleanup)
        options_dir = os.path.join(self._main_dir.name, 'chipsec', 'options')
        os.makedirs(options_dir)
        with open(os.path.join(options_dir, 'cmd_options.ini'), 'w') as ini_file:
            ini_file.write(FIXTURE_CMD_OPTIONS_INI)

        patcher = patch.object(options_module, 'get_main_dir', return_value=self._main_dir.name)
        patcher.start()
        self.addCleanup(patcher.stop)

        self.options = Options()

    def test_missing_options_dir_raises(self):
        with tempfile.TemporaryDirectory() as empty_dir:
            with patch.object(options_module, 'get_main_dir', return_value=empty_dir):
                with self.assertRaises(CSConfigError):
                    Options()

    def test_get_section_data_missing_returns_default(self):
        self.assertEqual(
            self.options.get_section_data('no_section', 'no_key', default='fallback'),
            'fallback')

    def test_get_section_data_missing_without_default_raises(self):
        with self.assertRaises(configparser.NoSectionError):
            self.options.get_section_data('no_section', 'no_key')

    def test_get_list_data_missing_returns_list_default(self):
        default = ['a', 'b']
        self.assertEqual(
            self.options.get_list_data('no_section', 'no_key', default),
            default)

    def test_get_section_data_existing_returns_value(self):
        self.assertEqual(
            self.options.get_section_data('Util_Config', 'smbios_get_type'),
            'raw')

    def test_get_list_data_existing_returns_parsed_list(self):
        self.assertEqual(
            self.options.get_list_data('Util_Config', 'smbios_get_type', ['fallback']),
            ['raw'])

    def test_explicit_no_default_sentinel_propagates_exception(self):
        # Passing the NoDefault class object as the sentinel must trigger the
        # identity comparison in get_section_data and re-raise the lookup error.
        with self.assertRaises(configparser.NoSectionError):
            self.options.get_section_data('no_section', 'no_key', default=NoDefault)


if __name__ == '__main__':
    unittest.main()
