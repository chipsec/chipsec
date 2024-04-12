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
Verify that all Secure Boot key UEFI variables are authenticated (BS+RT+AT)
and protected from unauthorized modification.

Reference:
    - `UEFI 2.4 spec Section 28 <http://uefi.org/>`_

Usage:
    ``chipsec_main -m common.secureboot.variables [-a modify]``
    - ``-a`` : modify = will try to write/corrupt the variables

Where:
    - ``[]``: optional line

Examples:
    >>> chipsec_main.py -m common.secureboot.variables
    >>> chipsec_main.py -m common.secureboot.variables -a modify

.. note::
    - Module is not supported in all environments.

"""


from chipsec.module_common import BaseModule, MTAG_SECUREBOOT, OPT_MODIFY
from chipsec.library.returncode import ModuleResult
from chipsec.hal.uefi import UEFI, SECURE_BOOT_VARIABLES, IS_VARIABLE_ATTRIBUTE, EFI_VAR_NAME_SecureBoot, SECURE_BOOT_KEY_VARIABLES
from chipsec.hal.uefi import EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS
from chipsec.hal.uefi import SECURE_BOOT_OPTIONAL_VARIABLES
from chipsec.hal.uefi_common import StatusCode
from typing import AnyStr, List, Optional

# ############################################################
# SPECIFY PLATFORMS THIS MODULE IS APPLICABLE TO
# ############################################################
_MODULE_NAME = 'variables'


TAGS = [MTAG_SECUREBOOT]


class variables(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self._uefi = UEFI(self.cs)
        self.result.url ='https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html'

    def is_supported(self) -> bool:
        supported = self.cs.helper.EFI_supported()
        if not supported:
            self.logger.log_important('OS does not support UEFI Runtime API.  Skipping module.')
        return supported

    def can_modify(self, name: str, guid: Optional[AnyStr], data: Optional[bytes]) -> bool:
        if not guid or not data:
            self.logger.log(f'    > Missing GUID or Data. Unable to modify variable {guid}:{name} data:{data}')
            return False
        else:
            self.logger.log(f'    > Attempting to modify variable {guid}:{name}')

        baddata = (data[0] ^ 0xFF).to_bytes(1, 'little') + data[1:]
        status = self._uefi.set_EFI_variable(name, guid, baddata)
        if StatusCode.EFI_SUCCESS != status:
            self.logger.log(f'    < Modification of {name} returned error 0x{status:X}')
        else:
            self.logger.log(f'    < Modification of {name} returned success')

        self.logger.log(f'    > Checking variable {name} contents after modification..')
        newdata = self._uefi.get_EFI_variable(name, guid)

        _changed = data != newdata
        if _changed:
            self.logger.log_bad(f'EFI variable {name} has been modified. Restoring original contents..')
            self._uefi.set_EFI_variable(name, guid, data)

            # checking if restored correctly
            restoreddata = self._uefi.get_EFI_variable(name, guid)
            if (restoreddata != data):
                self.logger.log_important(f'Failed to restore contents of variable {name} failed!')
            else:
                self.logger.log(f'    Contents of variable {name} have been restored')
        else:
            self.logger.log_good(f'Could not modify UEFI variable {guid}:{name}')
        return _changed

    # check_secureboot_variable_attributes
    # checks authentication attributes of Secure Boot EFI variables
    def check_secureboot_variable_attributes(self, do_modify: bool) -> int:
        not_found = 0
        not_auth = 0
        not_wp = 0
        is_secureboot_enabled = False

        sbvars = self._uefi.list_EFI_variables()
        if sbvars is None:
            self.logger.log_warning('Could not enumerate UEFI variables.')
            self.result.setStatusBit(self.result.status.CONFIGURATION)
            return self.result.getReturnCode(ModuleResult.WARNING)

        for name in SECURE_BOOT_VARIABLES:

            if (name in sbvars.keys()) and (sbvars[name] is not None):
                if len(sbvars[name]) > 1:
                    self.logger.log_failed(f'There should only be one instance of variable {name}')
                    self.result.setStatusBit(self.result.status.VERIFY)
                    return self.result.getReturnCode(ModuleResult.FAILED)
                for (_, _, _, data, guid, attrs) in sbvars[name]:
                    self.logger.log(f'[*] Checking protections of UEFI variable {guid}:{name}')

                    # check the status of Secure Boot
                    if EFI_VAR_NAME_SecureBoot == name:
                        is_secureboot_enabled = (data is not None) and (len(data) == 1) and (ord(data) == 0x1)

                    #
                    # Verify if the Secure Boot key/database variable is authenticated
                    #
                    if name in SECURE_BOOT_KEY_VARIABLES:
                        if IS_VARIABLE_ATTRIBUTE(attrs, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS):
                            self.logger.log_good(f'Variable {guid}:{name} is authenticated (AUTHENTICATED_WRITE_ACCESS)')
                        elif IS_VARIABLE_ATTRIBUTE(attrs, EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS):
                            self.logger.log_good(f'Variable {guid}:{name} is authenticated (TIME_BASED_AUTHENTICATED_WRITE_ACCESS)')
                        else:
                            not_auth += 1
                            self.logger.log_bad(f'Variable {guid}:{name} is not authenticated')

                    #
                    # Attempt to modify contents of the variables
                    #
                    if do_modify:
                        if self.can_modify(name, guid, data):
                            not_wp += 1
            elif name in SECURE_BOOT_OPTIONAL_VARIABLES:
                self.logger.log_important(f'Secure Boot variable {name} is not found but is optional')
                continue
            else:
                not_found += 1
                self.logger.log_important(f'Secure Boot variable {name} is not found')
                continue

        self.logger.log('')
        prefix = 'en' if is_secureboot_enabled else 'dis'
        self.logger.log(f'[*] Secure Boot appears to be {prefix}abled')

        if len(SECURE_BOOT_VARIABLES) == not_found:
            # None of Secure Boot variables were not found
            self.logger.log_warning('None of required Secure Boot variables found.')
            self.logger.log_important('If Secure Boot is enabled, this could be a problem.')
            self.result.setStatusBit(self.result.status.VERIFY)
            return self.result.getReturnCode(ModuleResult.WARNING)
        else:
            # Some Secure Boot variables exist
            sb_vars_failed = (not_found > 0) or (not_auth > 0) or (not_wp > 0)
            if sb_vars_failed:
                if not_found > 0:
                    self.logger.log_bad('Some required Secure Boot variables are missing')
                if not_auth > 0:
                    self.logger.log_bad('Some Secure Boot keying variables are not authenticated')
                if not_wp > 0:
                    self.logger.log_bad('Some Secure Boot variables can be modified')

                if is_secureboot_enabled:
                    self.logger.log_failed('Not all Secure Boot UEFI variables are protected')
                    self.result.setStatusBit(self.result.status.PROTECTION)
                    return self.result.getReturnCode(ModuleResult.FAILED)
                else:
                    self.logger.log_warning('Not all Secure Boot UEFI variables are protected')
                    self.result.setStatusBit(self.result.status.FEATURE_DISABLED)
                    return self.result.getReturnCode(ModuleResult.WARNING)

            else:
                self.logger.log_passed('All Secure Boot UEFI variables are protected')
                self.result.setStatusBit(self.result.status.SUCCESS)
                return self.result.getReturnCode(ModuleResult.PASSED)

    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test('Attributes of Secure Boot EFI Variables')

        do_modify = (len(module_argv) > 0) and (module_argv[0] == OPT_MODIFY)

        self.res = self.check_secureboot_variable_attributes(do_modify)
        return self.res
