# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
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
Checks protections of the S3 resume boot-script implemented by the UEFI based firmware

References:

`VU#976132 UEFI implementations do not properly secure the EFI S3 Resume Boot Path boot script <https://www.kb.cert.org/vuls/id/976132>`_

`Technical Details of the S3 Resume Boot Script Vulnerability <http://www.intelsecurity.com/advanced-threat-research/content/WP_Intel_ATR_S3_ResBS_Vuln.pdf>`_ by Intel Security's Advanced Threat Research team.

`Attacks on UEFI Security <https://events.ccc.de/congress/2014/Fahrplan/system/attachments/2557/original/AttacksOnUEFI_Slides.pdf>`_ by Rafal Wojtczuk and Corey Kallenberg.

`Attacking UEFI Boot Script <https://bromiumlabs.files.wordpress.com/2015/01/venamis_whitepaper.pdf>`_ by Rafal Wojtczuk and Corey Kallenberg.

`Exploiting UEFI boot script table vulnerability <http://blog.cr4.sh/2015/02/exploiting-uefi-boot-script-table.html>`_ by Dmytro Oleksiuk.

Usage:
    ``chipsec_main.py -m common.uefi.s3bootscript [-a <script_address>]``

    - ``-a <script_address>``: Specify the bootscript address

Where:
    - ``[]``: optional line

Examples:
    >>> chipsec_main.py -m common.uefi.s3bootscript
    >>> chipsec_main.py -m common.uefi.s3bootscript -a 0x00000000BDE10000

.. NOTE::
    Requires an OS with UEFI Runtime API support.
"""

from chipsec.module_common import BaseModule, MTAG_BIOS, MTAG_SMM, MTAG_SECUREBOOT
from chipsec.library.returncode import ModuleResult
from chipsec.library.defines import BOUNDARY_1MB, BOUNDARY_4GB
from chipsec.hal.uefi import UEFI, parse_script
from chipsec.hal.uefi_common import S3BootScriptOpcode, S3BOOTSCRIPT_ENTRY
from typing import List

TAGS = [MTAG_BIOS, MTAG_SMM, MTAG_SECUREBOOT]

########################################################################################################
#
# Main module functionality
#
########################################################################################################
BOOTSCRIPT_OK = 0x0
BOOTSCRIPT_INSIDE_SMRAM = 0x1
BOOTSCRIPT_OUTSIDE_SMRAM = 0x2
DISPATCH_OPCODES_UNPROTECTED = 0x4
DISPATCH_OPCODES_PROTECTED = 0x8

HIGH_BIOS_RANGE_SIZE = 2 * BOUNDARY_1MB


class s3bootscript(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self._uefi = UEFI(self.cs)
        self.result.url = 'https://chipsec.github.io/modules/chipsec.modules.common.uefi.s3bootscript.html'

    def is_supported(self) -> bool:
        supported = self.cs.helper.EFI_supported()
        if not supported:
            self.logger.log("OS does not support UEFI Runtime API")
        return supported

    def is_inside_SMRAM(self, pa: int) -> bool:
        return (pa >= self.smrambase and pa < self.smramlimit)

    def is_inside_SPI(self, pa: int) -> bool:
        return (pa >= (BOUNDARY_4GB - HIGH_BIOS_RANGE_SIZE) and pa < BOUNDARY_4GB)

    def check_dispatch_opcodes(self, bootscript_entries: List[S3BOOTSCRIPT_ENTRY]) -> bool:
        self.logger.log('[*] Checking entry-points of Dispatch opcodes..')
        dispatch_ep_ok = True
        n_dispatch = 0
        for e in bootscript_entries:
            if e.decoded_opcode is None:
                continue
            if S3BootScriptOpcode.EFI_BOOT_SCRIPT_DISPATCH_OPCODE == e.decoded_opcode.opcode:
                n_dispatch += 1
                dispatchstr = f"Dispatch opcode (off 0x{e.offset_in_script:04X}) with entry-point 0x{e.decoded_opcode.entrypoint:016X}"
                if not self.is_inside_SMRAM(e.decoded_opcode.entrypoint) and not self.is_inside_SPI(e.decoded_opcode.entrypoint):
                    dispatch_ep_ok = False
                    self.logger.log_bad(dispatchstr + " > UNPROTECTED")
                else:
                    self.logger.log_good(dispatchstr + " > PROTECTED")
        self.logger.log(f"[*] Found {n_dispatch:d} Dispatch opcodes")
        return dispatch_ep_ok

    def check_s3_bootscript(self, bootscript_pa: int) -> int:
        res = BOOTSCRIPT_OK
        self.logger.log(f"[*] Checking S3 boot-script at 0x{bootscript_pa:016X}")

        # Checking if it's in SMRAM
        scriptInsideSMRAM = self.is_inside_SMRAM(bootscript_pa)
        if scriptInsideSMRAM:
            res |= BOOTSCRIPT_INSIDE_SMRAM
            self.logger.log_good('S3 boot-script is in SMRAM')
            self.logger.log_important("Note: the test could not verify Dispatch opcodes because the script is in SMRAM. Entry-points of Dispatch opcodes also need to be protected.")
        else:
            res |= BOOTSCRIPT_OUTSIDE_SMRAM
            self.logger.log_bad('S3 boot-script is not in SMRAM')
            self.logger.log('[*] Reading S3 boot-script from memory..')
            script_all = self.cs.mem.read_physical_mem(bootscript_pa, 0x100000)
            self.logger.log('[*] Decoding S3 boot-script opcodes..')
            script_entries = parse_script(script_all, False)
            dispatch_opcodes_ok = self.check_dispatch_opcodes(script_entries)
            if dispatch_opcodes_ok:
                res |= DISPATCH_OPCODES_PROTECTED
                self.logger.log_important("S3 boot-script is not in protected memory but didn't find unprotected Dispatch entry-points")
            else:
                res |= DISPATCH_OPCODES_UNPROTECTED
                self.logger.log_bad('Entry-points of Dispatch opcodes in S3 boot-script are not in protected memory')
        return res

    def check_s3_bootscripts(self, bsaddress=None) -> int:
        res = 0
        scriptInsideSMRAM = False

        if bsaddress:
            bootscript_PAs = [bsaddress]
        else:
            found, bootscript_PAs = self._uefi.find_s3_bootscript()
            if not found:
                self.logger.log_good("Didn't find any S3 boot-scripts in EFI variables")
                self.logger.log_warning("S3 Boot-Script was not found. Firmware may be using other ways to store/locate it, or OS might be blocking access.")
                self.result.setStatusBit(self.result.status.VERIFY)
                return ModuleResult.WARNING


            self.logger.log_important(f'Found {len(bootscript_PAs):d} S3 boot-script(s) in EFI variables')

        for bootscript_pa in bootscript_PAs:
            if 0 == bootscript_pa:
                continue
            res |= self.check_s3_bootscript(bootscript_pa)

        self.logger.log('')

        if (res & BOOTSCRIPT_OUTSIDE_SMRAM) != 0:
            # BOOTSCRIPT_OUTSIDE_SMRAM
            if (res & DISPATCH_OPCODES_UNPROTECTED) != 0:
                # DISPATCH_OPCODES_UNPROTECTED
                status = ModuleResult.FAILED
                self.result.setStatusBit(self.result.status.PROTECTION)
                self.logger.log_failed('S3 Boot-Script and Dispatch entry-points do not appear to be protected')
            else:
                # DISPATCH_OPCODES_PROTECTED
                status = ModuleResult.WARNING
                self.result.setStatusBit(self.result.status.VERIFY)
                self.logger.log_warning('S3 Boot-Script is not in SMRAM but Dispatch entry-points appear to be protected. Recommend further testing')
        else:
            # BOOTSCRIPT_INSIDE_SMRAM
            status = ModuleResult.WARNING
            self.result.setStatusBit(self.result.status.VERIFY)
            self.logger.log_warning("S3 Boot-Script is inside SMRAM. The script is protected but Dispatch opcodes cannot be inspected")

        self.logger.log_important("Additional testing of the S3 boot-script can be done using tools.uefi.s3script_modify")

        return status

    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test("S3 Resume Boot-Script Protections")

        if len(module_argv) > 2:
            self.logger.log_error('Expected module options: -a <bootscript_address>')
            self.result.setStatusBit(self.result.status.UNSUPPORTED_OPTION)
            return self.result.getReturnCode(ModuleResult.ERROR)

        script_pa = None

        if len(module_argv) > 0:
            script_pa = int(module_argv[0], 16)
            self.logger.log(f'[*] Using manually assigned S3 Boot-Script table base: 0x{script_pa:016X}')
        (self.smrambase, self.smramlimit, self.smramsize) = self.cs.cpu.get_SMRAM()
        if (self.smrambase is not None) and (self.smramlimit is not None):
            self.logger.log(f'[*] SMRAM: Base = 0x{self.smrambase:016X}, Limit = 0x{self.smramlimit:016X}, Size = 0x{self.smramsize:08X}')

        try:
            if script_pa is not None:
                self.res = self.check_s3_bootscripts(script_pa)
            else:
                self.res = self.check_s3_bootscripts()
        except:
            self.logger.log_error("The module was not able to recognize the S3 resume boot script on this platform.")
            if self.logger.VERBOSE:
                raise
            self.res = ModuleResult.ERROR

        return self.result.getReturnCode(self.res)
