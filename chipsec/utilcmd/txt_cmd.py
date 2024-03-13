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
        txt_public = self.cs.mem.read_physical_mem(0xfed30000, 0x1000)
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
        reg_def = self.cs.register.get_def(reg_name)
        value = self.cs.register.read(reg_name)
        desc = reg_def["desc"]
        if reg_def["type"] == "memory":
            addr = reg_def["address"] + reg_def["offset"]
            desc += ", at {:08X}".format(addr)
        self.logger.log("[CHIPSEC] {} = 0x{:0{width}X} ({})".format(
            reg_name, value, desc, width=reg_def['size'] * 2))

        if 'FIELDS' in reg_def:
            sorted_fields = sorted(reg_def['FIELDS'].items(), key=lambda field: int(field[1]['bit']))
            for field_name, field_attrs in sorted_fields:
                field_bit = int(field_attrs['bit'])
                field_size = int(field_attrs['size'])
                field_mask = (1 << field_size) - 1
                field_value = (value >> field_bit) & field_mask
                self.logger.log("[CHIPSEC]     [{:02d}] {:23} = {:X} << {}".format(
                    field_bit, field_name, field_value, field_attrs['desc']))

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
        (eax, ebx, ecx, edx) = self.cs.cpu.cpuid(0x01, 0x00)
        self.logger.log("[CHIPSEC] CPUID.01H.ECX[Bit 6] = {} << Safer Mode Extensions (SMX)".format((ecx >> 6) & 1))
        self.logger.log("[CHIPSEC] CPUID.01H.ECX[Bit 5] = {} << Virtual Machine Extensions (VMX)".format((ecx >> 5) & 1))

        # Read bits in CR4
        cr4 = self.cs.cpu.read_cr(0, 4)
        self.logger.log("[CHIPSEC] CR4.SMXE[Bit 14] = {} << Safer Mode Extensions Enable".format((cr4 >> 14) & 1))
        self.logger.log("[CHIPSEC] CR4.VMXE[Bit 13] = {} << Virtual Machine Extensions Enable".format((cr4 >> 13) & 1))

        # Read bits in MSR IA32_FEATURE_CONTROL
        self._log_register("IA32_FEATURE_CONTROL")
        self.logger.log("[CHIPSEC]")

        # Read TXT Device ID
        self._log_register("TXT_DIDVID")
        self.logger.log("[CHIPSEC]")

        # Read hashes of public keys
        txt_pubkey = struct.pack("<QQQQ",
                                 self.cs.register.read("TXT_PUBLIC_KEY_0"),
                                 self.cs.register.read("TXT_PUBLIC_KEY_1"),
                                 self.cs.register.read("TXT_PUBLIC_KEY_2"),
                                 self.cs.register.read("TXT_PUBLIC_KEY_3"),
                                 )
        self.logger.log("[CHIPSEC] TXT Public Key Hash: {}".format(txt_pubkey.hex()))

        try:
            eax, edx = self.cs.msr.read_msr(0, 0x20)
            pubkey_in_msr = struct.pack("<II", eax, edx)
            eax, edx = self.cs.msr.read_msr(0, 0x21)
            pubkey_in_msr += struct.pack("<II", eax, edx)
            eax, edx = self.cs.msr.read_msr(0, 0x22)
            pubkey_in_msr += struct.pack("<II", eax, edx)
            eax, edx = self.cs.msr.read_msr(0, 0x23)
            pubkey_in_msr += struct.pack("<II", eax, edx)
            self.logger.log("[CHIPSEC] Public Key Hash in MSR[0x20...0x23]: {}".format(pubkey_in_msr.hex()))
        except HWAccessViolationError as exc:
            # Report the exception and continue
            self.logger.log("[CHIPSEC] Unable to read Public Key Hash in MSR[0x20...0x23]: {}".format(exc))
        self.logger.log("[CHIPSEC]")

        # Read TXT status
        self._log_register("TXT_STS")
        self._log_register("TXT_ESTS")
        self._log_register("TXT_E2STS")
        self._log_register("TXT_ERRORCODE")
        self.logger.log("[CHIPSEC]")
        self._log_register("TXT_SPAD")
        self._log_register("TXT_ACM_STATUS")
        self._log_register("TXT_FIT")
        self._log_register("TXT_SCRATCHPAD")
        self.logger.log("[CHIPSEC]")

        # Read memory area for TXT components
        self._log_register("TXT_SINIT_BASE")
        self._log_register("TXT_SINIT_SIZE")
        self._log_register("TXT_MLE_JOIN")
        self._log_register("TXT_HEAP_BASE")
        self._log_register("TXT_HEAP_SIZE")
        self._log_register("TXT_MSEG_BASE")
        self._log_register("TXT_MSEG_SIZE")
        self.logger.log("[CHIPSEC]")

        # Read other registers in the TXT memory area
        self._log_register("TXT_DPR")
        self._log_register("TXT_VER_FSBIF")
        self._log_register("TXT_VER_QPIIF")
        self._log_register("TXT_PCH_DIDVID")
        self._log_register("INSMM")

    def run(self):
        try:
            self.func()
        except Exception:
            self.ExitCode = ExitCode.ERROR

commands = {'txt': TXTCommand}
