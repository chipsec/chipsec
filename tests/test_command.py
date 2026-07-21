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
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from chipsec.command import BaseCommand, toLoad
from chipsec.library.defines import CHIPSET_CODE_UNKNOWN
from chipsec.library.logger import logger


class _OkCommand(BaseCommand):
    def __init__(self, argv, cs=None):
        super().__init__(argv, cs)
        self.func = MagicMock()

    def requirements(self):
        return toLoad.All


class _FailingCommand(BaseCommand):
    def __init__(self, argv, cs=None):
        super().__init__(argv, cs)
        self.func = MagicMock(side_effect=RuntimeError('boom'))

    def requirements(self):
        return toLoad.Nil


class TestBaseCommandRun(unittest.TestCase):
    """Cover BaseCommand.run in chipsec.command."""

    def test_run_invokes_func(self):
        cmd = _OkCommand([], cs=MagicMock())
        cmd.run()
        cmd.func.assert_called_once()

    def test_run_swallows_exception_and_prints_when_debug(self):
        cmd = _FailingCommand([], cs=MagicMock())
        original_debug = logger().DEBUG
        logger().DEBUG = True
        try:
            # Should not raise even though func() raises, and must print the
            # traceback while DEBUG is enabled.
            with patch('chipsec.command.traceback.print_exc') as mock_print_exc:
                cmd.run()
        finally:
            logger().DEBUG = original_debug
        cmd.func.assert_called_once()
        mock_print_exc.assert_called_once()


class TestBaseCommandPrerun(unittest.TestCase):
    """Cover BaseCommand.prerun in chipsec.command."""

    def _cmd(self, requirement, code):
        cs = SimpleNamespace(Cfg=SimpleNamespace(code=code))
        cmd = BaseCommand([], cs=cs)
        cmd.requirements = lambda: requirement
        return cmd

    def test_prerun_fails_when_config_required_but_unknown(self):
        cmd = self._cmd(toLoad.All, CHIPSET_CODE_UNKNOWN)
        self.assertFalse(cmd.prerun())

    def test_prerun_passes_when_config_present(self):
        cmd = self._cmd(toLoad.All, 'CHIP')
        self.assertTrue(cmd.prerun())

    def test_prerun_passes_when_config_not_required(self):
        cmd = self._cmd(toLoad.Nil, CHIPSET_CODE_UNKNOWN)
        self.assertTrue(cmd.prerun())


class TestBaseCommandAbstract(unittest.TestCase):
    """Cover the not-implemented defaults and no-op hooks in chipsec.command."""

    def setUp(self):
        self.cmd = BaseCommand([], cs=MagicMock())

    def test_parse_arguments_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.cmd.parse_arguments()

    def test_requirements_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.cmd.requirements()

    def test_set_up_and_tear_down_are_noops(self):
        self.assertIsNone(self.cmd.set_up())
        self.assertIsNone(self.cmd.tear_down())


class TestToLoad(unittest.TestCase):
    """Cover the toLoad enum in chipsec.command."""

    def test_load_config_true_for_config_and_all(self):
        self.assertTrue(toLoad.Config.load_config())
        self.assertTrue(toLoad.All.load_config())

    def test_load_config_false_for_nil_and_driver(self):
        self.assertFalse(toLoad.Nil.load_config())
        self.assertFalse(toLoad.Driver.load_config())

    def test_load_driver_true_for_driver_and_all(self):
        self.assertTrue(toLoad.Driver.load_driver())
        self.assertTrue(toLoad.All.load_driver())

    def test_load_driver_false_for_nil_and_config(self):
        self.assertFalse(toLoad.Nil.load_driver())
        self.assertFalse(toLoad.Config.load_driver())


if __name__ == '__main__':
    unittest.main()
