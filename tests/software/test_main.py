# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2017, Google
# Copyright (c) 2018-2021, Intel Corporation
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
from unittest.mock import patch

import chipsec_main
from chipsec.testcase import ExitCode
from chipsec.library import module_helper


class TestChipsecMain(unittest.TestCase):
    """Test the main entry point script."""

    def test_help(self):
        """Run chipsec_main --help"""
        # Basic test. This should run without loading the driver.
        m = chipsec_main.main(['--help'])
        self.assertEqual(ExitCode.OK, m)

    def test_module_enumeration(self):
        """Run chipsec_main --enum_tools"""
        module_helper.enumerate_modules()

    def test_read_files_in_tool_folder(self):
        # default_options = {'help': False, '_module': None, '_module_exclude': None, '_module_argv': None, 'verbose': False, 'hal': False, 'debug': False, 'log': None, 'vverbose': False, '_platform': None, '_pch': None, '_no_driver': False, '_ignore_platform': False, '_json_out': None, '_xml_out': None, '_markdown_out': None, 'USER_MODULE_TAGS': [], '_list_tags': False, 'IMPORT_PATHS': [], 'failfast': False, 'no_time': False, '_deltas_file': None, '_helper': None, '_show_banner': True, '_load_config': True, '_autolog_disable': False, '_return_codes': False}
        # chipsecMain = chipsec_main.ChipsecMain(default_options, [])
        res = module_helper.enumerate_modules()
        expected = ['tools.generate_test_id', 'tools.wsmt', 'tools.cpu.sinkhole', 'tools.secureboot.te', 'tools.smm.rogue_mmio_bar', 'tools.smm.smm_ptr', 'tools.uefi.reputation', 'tools.uefi.s3script_modify', 'tools.uefi.scan_blocked', 'tools.uefi.scan_image', 'tools.uefi.uefivar_fuzz', 'tools.vmm.common', 'tools.vmm.cpuid_fuzz', 'tools.vmm.ept_finder', 'tools.vmm.hypercallfuzz', 'tools.vmm.iofuzz', 'tools.vmm.msr_fuzz', 'tools.vmm.pcie_fuzz', 'tools.vmm.pcie_overlap_fuzz', 'tools.vmm.venom', 'tools.vmm.hv.define', 'tools.vmm.hv.hypercall', 'tools.vmm.hv.hypercallfuzz', 'tools.vmm.hv.synth_dev', 'tools.vmm.hv.synth_kbd', 'tools.vmm.hv.vmbus', 'tools.vmm.hv.vmbusfuzz', 'tools.vmm.vbox.vbox_crash_apicbase', 'tools.vmm.xen.define', 'tools.vmm.xen.hypercall', 'tools.vmm.xen.hypercallfuzz', 'tools.vmm.xen.xsa188']
        self.assertEqual(res, expected)

    @patch("chipsec.library.module_helper.logger")
    def test_print_modules_empty_list(self, logger_mock):
        list = []
        module_helper.print_modules(list)
        self.assertTrue(logger_mock().log.called)

    @patch("chipsec.library.module_helper.logger")
    def test_print_modules_one_module(self, logger_mock):
        list = ['common.cpu.cpu_info']
        module_helper.print_modules(list)
        self.assertEqual(logger_mock().log.call_count, len(list) + 1)

    @patch("chipsec_main.print_modules")
    def test_chipsec_main_print_modules(self, print_modules_mock):
        list_module_option = ['-lm']  # default_options = {'help': False,'_list_modules': True, '_module': None, '_module_exclude': None, '_module_argv': None, 'verbose': False, 'hal': False, 'debug': False, 'log': None, 'vverbose': False, '_platform': None, '_pch': None, '_no_driver': False, '_ignore_platform': False, '_json_out': None, '_xml_out': None, '_markdown_out': None, 'USER_MODULE_TAGS': [], '_list_tags': False, 'IMPORT_PATHS': [], 'failfast': False, 'no_time': False, '_deltas_file': None, '_helper': None, '_show_banner': True, '_load_config': True, '_autolog_disable': False, '_return_codes': False}
        chipsec_main.parse_args(list_module_option)
        self.assertTrue(print_modules_mock.called)
        # chipsecMain = chipsec_main.ChipsecMain(default_options, [])