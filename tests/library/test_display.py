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
from unittest.mock import MagicMock, patch

from chipsec.library import display


class TestChipsecBanner(unittest.TestCase):
    """Cover the banner builder in chipsec.library.display."""

    def test_banner_includes_arguments(self):
        with patch.object(display, 'get_version', return_value='0.0.0'), \
                patch.object(display, 'get_message', return_value=''):
            banner = display._chipsec_banner(['chipsec_main', '-m', 'common'])
        self.assertIn('CHIPSEC', banner)
        self.assertIn('chipsec_main -m common', banner)

    def test_banner_includes_custom_string(self):
        with patch.object(display, 'get_version', return_value='0.0.0'), \
                patch.object(display, 'get_message', return_value=''):
            banner = display._chipsec_banner(['chipsec_util'], custom_str='CUSTOM_MARKER')
        self.assertIn('CUSTOM_MARKER', banner)


class TestChipsecEnvironment(unittest.TestCase):
    """Cover the environment banner builder in chipsec.library.display."""

    def _make_cs(self):
        cs = MagicMock()
        cs.helper.get_info.return_value = ('TestHelper', '/path/to/driver')
        return cs

    def test_environment_includes_helper_info(self):
        cs = self._make_cs()
        with patch.object(display, 'os_version', return_value=('Linux', '6.0', '#1', 'x86_64')):
            banner = display._chipsec_environment(cs)
        self.assertIn('TestHelper', banner)
        self.assertIn('/path/to/driver', banner)
        self.assertIn('Linux', banner)

    def test_environment_flags_arch_mismatch(self):
        cs = self._make_cs()
        with patch.object(display, 'os_version', return_value=('Windows', '10', '#1', 'AMD64')), \
                patch.object(display.sys, 'maxsize', 2 ** 31):
            banner = display._chipsec_environment(cs)
        self.assertIn('Python architecture (32-bit) is different', banner)

    def test_environment_no_mismatch_when_arch_matches(self):
        cs = self._make_cs()
        with patch.object(display, 'os_version', return_value=('Windows', '10', '#1', 'AMD64')), \
                patch.object(display.sys, 'maxsize', 2 ** 63):
            banner = display._chipsec_environment(cs)
        self.assertNotIn('is different from OS architecture', banner)


if __name__ == '__main__':
    unittest.main()
