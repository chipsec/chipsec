# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2020, Intel Corporation
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


"""
Checks for exposure of pre-boot passwords (BIOS/HDD/pre-bot authentication SW) in the BIOS keyboard buffer.

Reference:
    - DEFCON 16: `Bypassing Pre-boot Authentication Passwords by Instrumenting the BIOS Keyboard Buffer <https://www.defcon.org/images/defcon-16/dc16-presentations/brossard/defcon-16-brossard-wp.pdf>`_ by Jonathan Brossard

Usage:
    ``chipsec_main -m common.bios_kbrd_buffer``

Examples:
    >>> chipsec_main.py -m common.bios_kbrd_buffer

"""

from chipsec.module_common import BaseModule, MTAG_BIOS
from chipsec.library.returncode import ModuleResult
from chipsec.library.logger import print_buffer_bytes
from typing import List

TAGS = [MTAG_BIOS]

COMMON_FILL_PTRN = "".join([f'{(chr(x + 0x1E)):1}' for x in range(32)])


class bios_kbrd_buffer(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self) -> bool:
        return True

    def check_BIOS_keyboard_buffer(self) -> int:
        kbrd_buf_head = self.cs.mem.read_physical_mem_dword(0x41A) & 0x000000FF
        kbrd_buf_tail = self.cs.mem.read_physical_mem_dword(0x41C) & 0x000000FF
        self.logger.log(f"[*] Keyboard buffer head pointer = 0x{kbrd_buf_head:X} (at 0x41A), tail pointer = 0x{kbrd_buf_tail:X} (at 0x41C)")
        bios_kbrd_buf = self.cs.mem.read_physical_mem(0x41E, 32)
        self.logger.log("[*] Keyboard buffer contents (at 0x41E):")
        print_buffer_bytes(bios_kbrd_buf)
        bios_kbrd_buf = bios_kbrd_buf.decode('latin_1')

        has_contents = False

        if COMMON_FILL_PTRN == bios_kbrd_buf:
            self.logger.log_good("Keyboard buffer is filled with common fill pattern")
            self.result.setStatusBit(self.result.status.SUCCESS)
            return self.result.getReturnCode(ModuleResult.PASSED)

        for x in bios_kbrd_buf:
            if ("\x00" != x) and ("\x20" != x):
                has_contents = True
                break

        if (0x1E < kbrd_buf_tail) and (kbrd_buf_tail <= 0x1E + 32):
            self.logger.log_bad(f"Keyboard buffer tail points inside the buffer (= 0x{kbrd_buf_tail:X})")
            self.logger.log(f"    It may potentially expose lengths of pre-boot passwords. Was your password {(kbrd_buf_tail + 2 - 0x1E) // 2:d} characters long?")

        self.logger.log("[*] Checking contents of the keyboard buffer..\n")

        if has_contents:
            self.logger.log_warning("Keyboard buffer is not empty. The test cannot determine conclusively if it contains pre-boot passwords.")
            self.logger.log("  - The contents might have not been cleared by pre-boot firmware or overwritten with garbage.")
            self.logger.log("  - Visually inspect the contents of keyboard buffer for pre-boot passwords (BIOS, HDD, full-disk encryption).")
        else:
            self.logger.log_passed("Keyboard buffer looks empty. Pre-boot passwords don't seem to be exposed")

        if has_contents:
            self.result.setStatusBit(self.result.status.POTENTIALLY_VULNERABLE)
            return self.result.getReturnCode(ModuleResult.WARNING)
        else:
            self.result.setStatusBit(self.result.status.SUCCESS)
            return self.result.getReturnCode(ModuleResult.PASSED)

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test("Pre-boot Passwords in the BIOS Keyboard Buffer")
        self.res = self.check_BIOS_keyboard_buffer()
        return self.res
