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
from tests.modules.run_chipsec_module import setup_run_destroy_modules_with_mock_logger_output as runmodules

class TestTglModules(unittest.TestCase):
    def setUp(self) -> None:
        self.folder_path = os.path.join(get_main_dir(), "tests", "modules", "tgl")
        self.init_replay_file = os.path.join(self.folder_path, "tglenumeration.json")
        
    def derive_filename(self, module_name:str) -> str:
        return f"{module_name.replace('.', '-')}_test.json"

    modules_results = [
        ("common.bios_smi", ExitCode.OK),
        ("common.bios_ts", ExitCode.OK),
        ("common.bios_wp", ExitCode.OK),
        ("common.cpu.cpu_info", ExitCode.INFORMATION),
        ("common.cpu.ia_untrusted", ExitCode.OK),
        ("common.cpu.spectre_v2", ExitCode.OK),
        ("common.debugenabled", ExitCode.OK),
        ("common.ia32cfg", ExitCode.OK),
        ("common.memconfig", ExitCode.OK),
        ("common.memlock", ExitCode.NOTAPPLICABLE),
        ("common.me_mfg_mode", ExitCode.OK),
        ("common.remap", ExitCode.OK),
        ("common.rtclock", ExitCode.WARNING),
        ("common.secureboot.variables", ExitCode.OK),
        ("common.sgx_check", ExitCode.NOTAPPLICABLE),
        ("common.smm_code_chk", ExitCode.OK),
        ("common.smm_dma", ExitCode.OK),
        ("common.smm", ExitCode.NOTAPPLICABLE),
        ("common.smrr", ExitCode.OK),
        ("common.spd_wd", ExitCode.OK),
        ("common.spi_access", ExitCode.FAIL),
        ("common.spi_desc", ExitCode.OK),
        ("common.spi_fdopss", ExitCode.OK),
        ("common.spi_lock", ExitCode.OK),
        ("common.uefi.access_uefispec", ExitCode.OK),
    ]

    def test_tgl_modules(self):
        module_runs = [
            (module, '', os.path.join(
                self.folder_path, self.derive_filename(module)))
            for module, _ in self.modules_results
        ]
        results = runmodules(self.init_replay_file, module_runs)
        failed = []
        for (module, expected), (retval, module_output) in zip(
                self.modules_results, results):
            if retval != expected:
                failed.append(
                    f"{module}: expected {expected}, got {retval}\n{module_output}")

        self.assertFalse(failed, "\n\n".join(failed))

    @unittest.skip("S3bootscript module was archived")
    def test_tgl_module_uefi_s3bootscript(self):
        self.run_and_test_module("common.uefi.s3bootscript", ExitCode.WARNING)
        


if __name__ == '__main__':
    unittest.main()
