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
Checks protection of UEFI variables defined in the UEFI spec to have certain permissions.

Returns failure if variable attributes are not as defined in `table 11 "Global Variables" <http://uefi.org/>`_ of the UEFI spec.

usage:
    ``chipsec_main -m common.uefi.access_uefispec [-a modify]``

    - ``-a modify``: Attempt to modify each variable in addition to checking attributes

Where:
    - ``[]``: optional line

Examples:
    >>> chipsec_main.py -m common.uefi.access_uefispec
    >>> chipsec_main.py -m common.uefi.access_uefispec -a modify

NOTE:
Requires an OS with UEFI Runtime API support.
"""

from chipsec.module_common import BaseModule, MTAG_SECUREBOOT, MTAG_BIOS, OPT_MODIFY
from chipsec.library.returncode import ModuleResult
from chipsec.hal.uefi import UEFI, EFI_VARIABLE_NON_VOLATILE, EFI_VARIABLE_BOOTSERVICE_ACCESS, EFI_VARIABLE_RUNTIME_ACCESS, get_attr_string
from chipsec.hal.uefi import EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS, EFI_VARIABLE_APPEND_WRITE
from chipsec.hal.uefi_common import StatusCode
from typing import List


TAGS = [MTAG_BIOS, MTAG_SECUREBOOT]


class access_uefispec(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self._uefi = UEFI(self.cs)

        nv = EFI_VARIABLE_NON_VOLATILE
        bs = EFI_VARIABLE_BOOTSERVICE_ACCESS
        rt = EFI_VARIABLE_RUNTIME_ACCESS
        ta = EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS

        self.uefispec_vars = {
            # From UEFI Spec Table 11 "Global Variables"
            # Updated to version 2.10 Section 3.3 "Globally Defined Variables"
            # https://uefi.org/sites/default/files/resources/UEFI_Spec_2_10_Aug29.pdf
            # https://uefi.org/specs/UEFI/2.10/03_Boot_Manager.html#globally-defined-variables
            "LangCodes": bs | rt,
            "Lang": nv | bs | rt,
            "Timeout": nv | bs | rt,
            "PlatformLangCodes": bs | rt,
            "PlatformLang": nv | bs | rt,
            "ConIn": nv | bs | rt,
            "ConOut": nv | bs | rt,
            "ErrOut": nv | bs | rt,
            "ConInDev": bs | rt,
            "ConOutDev": bs | rt,
            "ErrOutDev": bs | rt,
            "Boot0001": nv | bs | rt,
            "Boot0002": nv | bs | rt,
            "BootOrder": nv | bs | rt,

            "AuditMode": bs | rt,
            "BootNext": nv | bs | rt,
            "BootCurrent": bs | rt,
            "BootOptionSupport": bs | rt,
            "CryptoIndications": nv | bs | rt,
            "CryptoIndicationsSupport": bs | rt,
            "CrytopIndicationsActive": bs | rt,
            "DeployedMode": bs | rt,
            "devAuthBoot": bs | rt,
            "devdbDefault": bs | rt,
            "Driver0001": nv | bs | rt,
            "DriverOrder": nv | bs | rt,
            "Key0001": nv | bs | rt,
            "HwErrRecSupport": nv | bs | rt,  # HwErrRecSupport should be RO
            "SetupMode": bs | rt,  # SetupMode should be RO
            "KEK": nv | bs | rt | ta,
            "OsRecoveryOrder": nv | bs | rt | ta,
            "PK": nv | bs | rt | ta,
            "SignatureSupport": bs | rt,  # RO
            "SecureBoot": bs | rt,  # RO
            "KEKDefault": bs | rt,  # RO
            "PKDefault": bs | rt,  # RO
            "dbDefault": bs | rt,  # RO
            "dbxDefault": bs | rt,  # RO
            "dbtDefault": bs | rt,  # RO
            "OsIndicationsSupported": bs | rt,  # RO
            "OsIndications": nv | bs | rt,
            "SysPrep0001": nv | bs | rt,
            "SysPrep0002": nv | bs | rt,
            "SysPrepOrder": nv | bs | rt,
            "VendorKeys": bs | rt  # RO
        }

        self.uefispec_ro_vars = ("HwErrRecSupport", "SetupMode", "SignatureSupport", "SecureBoot", "KEKDefault", "PKDefault", "dbDefault", "dbxDefault", "dbtDefault", "OsIndicationsSupported", "VendorKeys")

    def is_supported(self) -> bool:
        supported = self.cs.helper.EFI_supported()
        if not supported:
            self.logger.log("OS does not support UEFI Runtime API")
        return supported

    def diff_var(self, data1: int, data2: int) -> bool:
        if data1 is None or data2 is None:
            return data1 != data2

        oldstr = ":".join(f"{c:02x}" for c in data1)
        newstr = ":".join(f"{c:02x}" for c in data2)

        if oldstr != newstr:
            print(oldstr)
            print(newstr)
            return True
        else:
            return False

    def can_modify(self, name: str, guid: str, data: bytes) -> bool:
        ret = False

        #origdata = _uefi.get_EFI_variable(name, guid)
        origdata = data
        datalen = len(bytearray(data))
        baddata = 'Z' * datalen  # 0x5A is ASCII 'Z'
        if baddata == origdata:
            baddata = 'A' * datalen  # in case we failed to restore previously
        status = self._uefi.set_EFI_variable(name, guid, baddata)
        if status != StatusCode.EFI_SUCCESS:
            self.logger.log_good(f'Writing EFI variable {name} did not succeed.')
        newdata = self._uefi.get_EFI_variable(name, guid)
        if self.diff_var(newdata, origdata):
            self.logger.log_bad(f'Corruption of EFI variable of concern {name}. Trying to recover.')
            ret = True
            self._uefi.set_EFI_variable(name, guid, origdata)
            if self.diff_var(self._uefi.get_EFI_variable(name, guid), origdata):
                nameguid = name + ' (' + guid + ')'
                self.logger.log_bad(f'RECOVERY FAILED. Variable {nameguid} remains corrupted. Original data value: {origdata}')
        return ret

    def check_vars(self, do_modify: bool) -> int:
        res = ModuleResult.PASSED
        vars = self._uefi.list_EFI_variables()
        if vars is None:
            self.logger.log_warning('Could not enumerate UEFI Variables from runtime.')
            self.logger.log_important("Note that UEFI variables may still exist, OS just did not expose runtime UEFI Variable API to read them.\nYou can extract variables directly from ROM file via 'chipsec_util.py uefi nvram bios.bin' command and verify their attributes manually.")
            self.result.setStatusBit(self.result.status.VERIFY)
            return ModuleResult.WARNING

        uefispec_concern = []
        ro_concern = []
        rw_variables = []

        self.logger.log('[*] Testing UEFI variables ..')
        for name in vars.keys():
            if name is None:
                pass
            if vars[name] is None:
                pass

            if len(vars[name]) > 1:
                self.logger.log_important(f'Found two instances of the variable {name}.')
            for (off, buf, hdr, data, guid, attrs) in vars[name]:
                self.logger.log(f'[*] Variable {name} ({get_attr_string(attrs)}) Guid {guid} Size {hex(len(data))} ')
                perms = self.uefispec_vars.get(name)
                if perms is not None:
                    if perms != attrs:
                        attr_diffs = (perms ^ attrs)
                        extra_attr = attr_diffs & attrs
                        missing_attr = attr_diffs & ~extra_attr
                        uefispec_concern.append(name)
                        if extra_attr != 0:
                            self.logger.log_important('  Extra attributes:' + get_attr_string(extra_attr))
                            if (extra_attr & ~(EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS | EFI_VARIABLE_APPEND_WRITE) != 0):
                                res = ModuleResult.FAILED
                        if missing_attr != 0:
                            self.logger.log_important('  Missing attributes:' + get_attr_string(missing_attr))
                        if res != ModuleResult.FAILED:
                            res = ModuleResult.WARNING
                        self.result.setStatusBit(self.result.status.VERIFY)

                if do_modify:
                    self.logger.log(f"[*] Testing modification of {name} ..")
                    if name in self.uefispec_ro_vars:
                        if self.can_modify(name, guid, data):
                            ro_concern.append(name)
                            self.logger.log_bad(f"Variable {name} should be read only.")
                            self.result.setStatusBit(self.result.status.POTENTIALLY_VULNERABLE)
                            res = ModuleResult.FAILED
                    else:
                        if self.can_modify(name, guid, data):
                            rw_variables.append(name)

        if uefispec_concern:
            self.logger.log('')
            self.logger.log_bad('Variables with attributes that differ from UEFI spec:')
            for name in uefispec_concern:
                self.logger.log(f'    {name}')

        if do_modify:
            if ro_concern:
                self.logger.log('')
                self.logger.log_bad('Variables that should have been read-only and were not:')
                for name in ro_concern:
                    self.logger.log(f'    {name}')

            if rw_variables:
                self.logger.log('')
                self.logger.log_unknown('Variables that are read-write (manual investigation is required):')
                for name in rw_variables:
                    self.logger.log(f'    {name}')

        self.logger.log('')

        if ModuleResult.PASSED == res:
            self.logger.log_passed('All checked EFI variables are protected according to spec.')
        elif ModuleResult.FAILED == res:
            self.logger.log_failed('Some EFI variables were not protected according to spec.')
        return res

    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test("Access Control of EFI Variables")

        do_modify = (len(module_argv) > 0 and module_argv[0] == OPT_MODIFY)
        self.res = self.check_vars(do_modify)
        return self.result.getReturnCode(self.res)
