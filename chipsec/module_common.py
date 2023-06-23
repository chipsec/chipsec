# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2022, Intel Corporation
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
Common include file for modules


"""

import chipsec.chipset
from enum import Enum
from chipsec.defines import bit, is_set
from chipsec.logger import logger


class ModuleResult:
    # -------------------------------------------------------
    # Legacy results
    # -------------------------------------------------------
    FAILED = 0
    PASSED = 1
    WARNING = 2
    SKIPPED = 3
    DEPRECATED = 4
    INFORMATION = 5
    NOTAPPLICABLE = 6
    ERROR = -1
    # -------------------------------------------------------
    class status(Enum):
        SUCCESS = [0x0000000000000000, "Test module completed successfully"]
        LOCKS = [bit(31), "Locks are not set"] 
        MITIGATION = [bit(30), "Does not support mitigation"]
        CONFIGURATION = [bit(29), "Configuration not set"] 
        PROTECTION = [bit(28), "Protection not supported/enabled"]
        ACCESS_RW = [bit(27), "Read or write access issues"]
        ALL_FFS = [bit(19), "Read returned all 0xFFs"]
        ALL_00S = [bit(18), "Read returned all 0x00s"]
        DEVICE_DISABLED = [bit(17), "Device is disabled"]
        FEATURE_DISABLED = [bit(16), "Feature is disabled"]
        VERIFY = [bit(12), "Manual verification/further testing recommended"]
        UNSUPPORTED_FEATURE = [bit(11), "Feature not supported"] 
        DEBUG_FEATURE = [bit(10), "A debug feature is enabled or an unexpected debug state was discovered on this platform"]
        NOT_APPLICABLE = [bit(9), "Skipping module since it is not supported"]
        INFORMATION = [bit(0), "For your information"]
        INVALID = [0xFFFFFFFFFFFFFFFF, "Error running the test"]
    
    def __init__(self, ID: int = 0, url: str = ""):
        self._id = ID
        self._url = url
        self._result = 0x00000000
        self._return_code = self.status.SUCCESS.value[0]
        self._message = ''
        self.logger = logger()

    def setTestID(self) -> None:
        self._return_code ^= self._id << 4
    
    def setStatusBit(self, status) -> None:
        if is_set(self._result, status.value[0]) is not True:
            self._result ^= status.value[0]
            self._message += ' / ' + status.value[1]
            
    def setResultBits(self) -> None:
        self._return_code ^= self._result << 32

    def buildRC(self) -> int:
        self.setResultBits()
        self.setTestID()
        if self._result == self.status.SUCCESS.value[0]:   
            self.logger.log_good(f"RC 0x{self._return_code:016x}: {self.status.SUCCESS.value[1]}")
        else:  
            self.logger.log_important(f"For next steps: {self._url}")
            self.logger.log_important(f"RC 0x{self._return_code:016x}: {self._message}")
        
        return self._return_code

# -------------------------------------------------------
# Legacy results
# -------------------------------------------------------
result_priority = {
    ModuleResult.PASSED: 0,
    ModuleResult.NOTAPPLICABLE: 0,
    ModuleResult.DEPRECATED: 0,
    ModuleResult.SKIPPED: 0,
    ModuleResult.INFORMATION: 1,
    ModuleResult.WARNING: 2,
    ModuleResult.FAILED: 3,
    ModuleResult.ERROR: 4
}

ModuleResultName = {
    ModuleResult.FAILED: "Failed",
    ModuleResult.PASSED: "Passed",
    ModuleResult.WARNING: "Warning",
    ModuleResult.SKIPPED: "Skipped",
    ModuleResult.DEPRECATED: "Deprecated",
    ModuleResult.INFORMATION: "Information",
    ModuleResult.ERROR: "Error",
    ModuleResult.NOTAPPLICABLE: "NotApplicable"
}

def getModuleResultName(res) -> str:
    if chipsec.chipset.cs().using_return_codes:
        return "Passed" if (res & 0xFFFFFFFF00000000) == 0 else "Failed"
    return ModuleResultName[res] if res in ModuleResultName else ModuleResultName[ModuleResult.ERROR]
# -------------------------------------------------------

class BaseModule:
    def __init__(self):
        self.cs = chipsec.chipset.cs()
        self.logger = logger()
        # -------------------------------------------------------
        # Legacy results
        # -------------------------------------------------------
        self.res = ModuleResult.PASSED
        # -------------------------------------------------------

    def is_supported(self):
        """
        This method should be overwritten by the module returning True or False
        depending whether or not this module is supported in the currently running
        platform.
        To access the currently running platform use
        """
        return True

    # -------------------------------------------------------
    # Legacy results
    # -------------------------------------------------------
    def update_res(self, value):
        if value not in result_priority:
            self.logger.log_verbose(f'Attempting to set invalid result status: {value}')
            return
        cur_priority = result_priority[self.res]
        new_priority = result_priority[value]
        if new_priority >= cur_priority:
            self.res = value
    # -------------------------------------------------------

    def run(self, module_argv):
        raise NotImplementedError('Sub-class should overwrite the run() method')


MTAG_BIOS = "BIOS"
MTAG_SMM = "SMM"
MTAG_SECUREBOOT = "SECUREBOOT"
MTAG_HWCONFIG = "HWCONFIG"
MTAG_CPU = "CPU"


# ! [Available Tags]
MTAG_METAS = {
    MTAG_BIOS: "System Firmware (BIOS/UEFI) Modules",
    MTAG_SMM: "System Management Mode (SMM) Modules",
    MTAG_SECUREBOOT: "Secure Boot Modules",
    MTAG_HWCONFIG: "Hardware Configuration Modules",
    MTAG_CPU: "CPU Modules",
}
# ! [Available Tags]
MODULE_TAGS = dict([(_tag, []) for _tag in MTAG_METAS])

#
# Common module command line options
#
OPT_MODIFY = 'modify'
