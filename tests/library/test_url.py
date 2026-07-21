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
from unittest.mock import patch

from chipsec.library.url import url


class TestUrl(unittest.TestCase):
    """Cover the module URL builder in chipsec.library.url."""

    FULL_INFO = {
        'base_url': 'https://example.com/modules/',
        'replace_find': r'\.',
        'replace_with': '/',
        'ends_with': '.html',
    }

    def _make_url(self, info):
        with patch.object(url, 'get_url_info', return_value=info):
            return url()

    def test_init_populates_fields_from_info(self):
        u = self._make_url(self.FULL_INFO)
        self.assertEqual(u.base_url, 'https://example.com/modules/')
        self.assertEqual(u.replace_find, r'\.')
        self.assertEqual(u.replace_with, '/')
        self.assertEqual(u.ends_with, '.html')

    def test_get_url_info_reads_real_json_file(self):
        u = url()
        info = u.get_url_info()
        self.assertIn('base_url', info)
        self.assertEqual(u.base_url, info['base_url'])

    def test_get_base_url_missing_raises(self):
        with self.assertRaisesRegex(Exception, r'^Missing Base URL in url file$'):
            self._make_url({'replace_find': '', 'replace_with': '', 'ends_with': ''})

    def test_optional_fields_default_to_empty(self):
        u = self._make_url({'base_url': 'https://example.com/'})
        self.assertEqual(u.replace_find, '')
        self.assertEqual(u.replace_with, '')
        self.assertEqual(u.ends_with, '')

    def test_get_module_url_applies_substitution(self):
        u = self._make_url(self.FULL_INFO)
        result = u.get_module_url('common.secureboot.variables')
        self.assertEqual(result, 'https://example.com/modules/common/secureboot/variables.html')

    def test_get_module_url_without_substitution(self):
        u = self._make_url({'base_url': 'https://example.com/'})
        result = u.get_module_url('common.secureboot')
        self.assertEqual(result, 'https://example.com/common.secureboot')


if __name__ == '__main__':
    unittest.main()
