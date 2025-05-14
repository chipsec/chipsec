# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2ExitCode.OK23, Intel Corporation
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  ExitCode.OK211ExitCode.OK-13ExitCode.OK1, USA.
#
# Contact information:
# chipsec@intel.com
#

# To execute: python -m unittest tests.modules.test_tgl_modules

import unittest
import os

from chipsec.library.file import get_main_dir
from chipsec.testcase import ExitCode
from tests.modules.run_chipsec_module import setup_run_destroy_module_with_mock_logger


class TestTglModules(unittest.TestCase):
    def setUp(self) -> None:
        self.folder_path = os.path.join(get_main_dir(), "tests", "modules", "tgl")
        self.init_replay_file = os.path.join(self.folder_path, "enumeration.json")

    def derive_filename(self, module_name: str) -> str:
        return f"{module_name.replace('.', '-')}_test.json"

    def run_and_test_module(self, module_name: str, expected_returncode: int) -> None:
        test_recording = self.derive_filename(module_name)
        replay_file = os.path.join(self.folder_path, test_recording)
        retval = setup_run_destroy_module_with_mock_logger(self.init_replay_file, module_name, module_replay_file=replay_file)
        self.assertEqual(retval, expected_returncode, f"Expected: {expected_returncode} but got: {retval}")

    def test_tgl_module_bios_smi(self):
        self.run_and_test_module("common.bios_smi", ExitCode.OK)

    def test_tgl_module_bios_ts(self):
        self.run_and_test_module("common.bios_ts", ExitCode.OK)

    def test_tgl_module_bios_wp(self):
        self.run_and_test_module("common.bios_wp", ExitCode.OK)

    def test_tgl_module_cpu_cpu_info(self):
        self.run_and_test_module("common.cpu.cpu_info", ExitCode.INFORMATION)

    def test_tgl_module_cpu_ia_untrusted(self):
        self.run_and_test_module("common.cpu.ia_untrusted", ExitCode.OK)

    def test_tgl_module_cpu_spectre_v2(self):
        self.run_and_test_module("common.cpu.spectre_v2", ExitCode.OK)

    def test_tgl_module_debugenabled(self):
        self.run_and_test_module("common.debugenabled", ExitCode.OK)

    def test_tgl_module_ia32cfg(self):
        self.run_and_test_module("common.ia32cfg", ExitCode.OK)

    def test_tgl_module_memconfig(self):
        self.run_and_test_module("common.memconfig", ExitCode.OK)

    def test_tgl_module_memlock(self):
        self.run_and_test_module("common.memlock", ExitCode.NOTAPPLICABLE)

    def test_tgl_module_me_mfg_mode(self):
        self.run_and_test_module("common.me_mfg_mode", ExitCode.OK)

    def test_tgl_module_remap(self):
        self.run_and_test_module("common.remap", ExitCode.OK)

    def test_tgl_module_rtclock(self):
        self.run_and_test_module("common.rtclock", ExitCode.WARNING)

    def test_tgl_module_secureboot_variables(self):
        self.run_and_test_module("common.secureboot.variables", ExitCode.OK)

    def test_tgl_module_sgx_check(self):
        self.run_and_test_module("common.sgx_check", ExitCode.NOTAPPLICABLE)

    def test_tgl_module_smm_code_chk(self):
        self.run_and_test_module("common.smm_code_chk", ExitCode.OK)

    def test_tgl_module_smm_dma(self):
        self.run_and_test_module("common.smm_dma", ExitCode.OK)

    def test_tgl_module_smm(self):
        self.run_and_test_module("common.smm", ExitCode.NOTAPPLICABLE)

    def test_tgl_module_smrr(self):
        self.run_and_test_module("common.smrr", ExitCode.OK)

    def test_tgl_module_spd_wd(self):
        self.run_and_test_module("common.spd_wd", ExitCode.OK)

    def test_tgl_module_spi_access(self):
        self.run_and_test_module("common.spi_access", ExitCode.FAIL)

    def test_tgl_module_spi_desc(self):
        self.run_and_test_module("common.spi_desc", ExitCode.OK)

    def test_tgl_module_spi_fdopss(self):
        self.run_and_test_module("common.spi_fdopss", ExitCode.OK)

    def test_tgl_module_spi_lock(self):
        self.run_and_test_module("common.spi_lock", ExitCode.OK)

    def test_tgl_module_uefi_access_uefispec(self):
        self.run_and_test_module("common.uefi.access_uefispec", ExitCode.OK)

    @unittest.skip("S3bootscript module was archived")
    def test_tgl_module_uefi_s3bootscript(self):
        self.run_and_test_module("common.uefi.s3bootscript", ExitCode.WARNING)


if __name__ == '__main__':
    unittest.main()
