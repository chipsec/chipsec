# CHIPSEC: Platform Security Assessment Framework
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
Command-line utility providing access to Intel TXT (Trusted Execution Technology) registers

Usage:
    >>> chipsec_util txt dump
    >>> chipsec_util txt state
"""

from argparse import ArgumentParser
from chipsec.command import BaseCommand, toLoad
from chipsec.library.exceptions import HWAccessViolationError
from chipsec.testcase import ExitCode
import struct


class TXTCommand(BaseCommand):
    def __init__(self, argv, cs=None):
        super().__init__(argv, cs)
        self.cs.set_scope({
            None: "8086.TXT",
            "IA32_FEATURE_CONTROL": "8086.MSR"
        })

    def requirements(self) -> toLoad:
        return toLoad.All

    def parse_arguments(self) -> None:
        parser = ArgumentParser(usage=__doc__)
        subparsers = parser.add_subparsers()
        parser_state = subparsers.add_parser('dump')
        parser_state.set_defaults(func=self.txt_dump)
        parser_state = subparsers.add_parser('state')
        parser_state.set_defaults(func=self.txt_state)
        parser.parse_args(self.argv, namespace=self)

    def txt_dump(self):
        # Read TXT Public area as hexdump, with absolute address and skipping zeros
        txt_public = self.cs.hals.Memory.read_physical_mem(0xfed30000, 0x1000)
        has_skipped_line = False
        for offset in range(0, len(txt_public), 16):
            line_bytes = txt_public[offset:offset + 16]
            if all(b == 0 for b in line_bytes):
                has_skipped_line = True
                continue
            if has_skipped_line:
                self.logger.log("[CHIPSEC] *")
                has_skipped_line = False
            line_hex = " ".join("{:02X}".format(b) for b in line_bytes)
            self.logger.log("[CHIPSEC] {:08X}: {}".format(0xfed30000 + offset, line_hex))

    def _log_register(self, reg_name):
        """Log the content of a register with lines starting with [CHIPSEC]"""
        if not self.cs.register.is_defined(reg_name):
            return
        reg_object = self.cs.register.get_list_by_name(reg_name)
        reg_object.read_and_print()

    def txt_state(self):
        """Dump Intel TXT state

        This is similar to command "txt-stat" from Trusted Boot project
        https://sourceforge.net/p/tboot/code/ci/v2.0.0/tree/utils/txt-stat.c
        which was documented on
        https://www.intel.com/content/dam/www/public/us/en/documents/guides/dell-one-stop-txt-activation-guide.pdf
        and it is also similar to command "sl-stat" from TrenchBoot project
        https://github.com/TrenchBoot/sltools/blob/842cfd041b7454727b363b72b6d4dcca9c00daca/sl-stat/sl-stat.c
        """
        # Read bits in CPUID
        (eax, ebx, ecx, edx) = self.cs.hals.CPU.cpuid(0x01, 0x00)
        self.logger.log("[CHIPSEC] CPUID.01H.ECX[Bit 6] = {} << Safer Mode Extensions (SMX)".format((ecx >> 6) & 1))
        self.logger.log("[CHIPSEC] CPUID.01H.ECX[Bit 5] = {} << Virtual Machine Extensions (VMX)".format((ecx >> 5) & 1))

        # Read bits in CR4
        cr4 = self.cs.hals.CPU.read_cr(0, 4)
        self.logger.log("[CHIPSEC] CR4.SMXE[Bit 14] = {} << Safer Mode Extensions Enable".format((cr4 >> 14) & 1))
        self.logger.log("[CHIPSEC] CR4.VMXE[Bit 13] = {} << Virtual Machine Extensions Enable".format((cr4 >> 13) & 1))

        # Read bits in MSR IA32_FEATURE_CONTROL
        self._log_register("IA32_FEATURE_CONTROL")
        self.logger.log("")

        # Read TXT Device ID
        self._log_register("DIDVID")
        self.logger.log("")

        pub_list = self.cs.register.get_list_by_name("PUBLIC_KEY_*")
        pub_values = pub_list.read()
        # Read hashes of public keys
        txt_pubkey = struct.pack("<QQQQ", *pub_values)
        self.logger.log("[CHIPSEC] TXT Public Key Hash: {}".format(txt_pubkey.hex()))

        try:
            eax, edx = self.cs.hals.Msr.read_msr(0, 0x20)
            pubkey_in_msr = struct.pack("<II", eax, edx)
            eax, edx = self.cs.hals.Msr.read_msr(0, 0x21)
            pubkey_in_msr += struct.pack("<II", eax, edx)
            eax, edx = self.cs.hals.Msr.read_msr(0, 0x22)
            pubkey_in_msr += struct.pack("<II", eax, edx)
            eax, edx = self.cs.hals.Msr.read_msr(0, 0x23)
            pubkey_in_msr += struct.pack("<II", eax, edx)
            self.logger.log("[CHIPSEC] Public Key Hash in MSR[0x20...0x23]: {}".format(pubkey_in_msr.hex()))
        except HWAccessViolationError as exc:
            # Report the exception and continue
            self.logger.log("[CHIPSEC] Unable to read Public Key Hash in MSR[0x20...0x23]: {}".format(exc))
        self.logger.log("")

        # Read TXT status
        self._log_register("STS")
        self._log_register("ESTS")
        self._log_register("E2STS")
        self._log_register("ERRORCODE")
        self.logger.log("")
        self._log_register("SPAD")
        self._log_register("ACM_STATUS")
        self._log_register("FIT")
        self._log_register("SCRATCHPAD")
        self.logger.log("")

        # Read memory area for TXT components
        self._log_register("SINIT_BASE")
        self._log_register("SINIT_SIZE")
        self._log_register("MLE_JOIN")
        self._log_register("HEAP_BASE")
        self._log_register("HEAP_SIZE")
        self._log_register("MSEG_BASE")
        self._log_register("MSEG_SIZE")
        self.logger.log("")

        # Read other registers in the TXT memory area
        self._log_register("DPR")
        self._log_register("VER_FSBIF")
        self._log_register("VER_QPIIF")
        self._log_register("PCH_DIDVID")
        self._log_register("INSMM")

    def run(self):
        try:
            self.func()
        except Exception:
            self.ExitCode = ExitCode.ERROR
        else:
            self.ExitCode = ExitCode.OK


commands = {'txt': TXTCommand}
