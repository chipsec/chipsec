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

from chipsec.parsers import BaseConfigParser, BaseConfigHelper, Stage, parsers


class TestBaseConfigParser(unittest.TestCase):
    """Cover the default BaseConfigParser implementation in chipsec.parsers."""

    def setUp(self):
        self.cfg = object()
        self.parser = BaseConfigParser(self.cfg)

    def test_parser_name_defaults_to_class_name(self):
        self.assertEqual(self.parser.parser_name(), 'BaseConfigParser')

    def test_startup_returns_none(self):
        self.assertIsNone(self.parser.startup())

    def test_get_metadata_returns_template_handler(self):
        metadata = self.parser.get_metadata()
        self.assertEqual(metadata, {'template': self.parser.def_handler})

    def test_get_stage_defaults_to_none(self):
        self.assertEqual(self.parser.get_stage(), Stage.NONE)

    def test_def_handler_returns_none(self):
        self.assertIsNone(self.parser.def_handler(None))
        self.assertIsNone(self.parser.def_handler(None, stage_data='ignored'))

    def test_cfg_object_is_stored(self):
        self.assertIs(self.parser.cfg, self.cfg)

    def test_default_parsers_registry(self):
        self.assertIn(BaseConfigParser, parsers)


class TestBaseConfigHelper(unittest.TestCase):
    """Cover the default BaseConfigHelper implementation in chipsec.parsers."""

    def test_cfg_object_is_stored(self):
        cfg = object()
        helper = BaseConfigHelper(cfg)
        self.assertIs(helper.cfg, cfg)


if __name__ == '__main__':
    unittest.main()
