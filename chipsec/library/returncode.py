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

from enum import Enum
from chipsec.library.defines import bit, is_set
from chipsec.library.logger import logger
from hashlib import sha256


class ReturnCode:
    class status(Enum):
        SUCCESS = [0x0000000000000000, 'Test module completed successfully']
        LOCKS = [bit(31), 'Locks are not set'] 
        MITIGATION = [bit(30), 'Does not support mitigation']
        CONFIGURATION = [bit(29), 'Configuration not valid'] 
        PROTECTION = [bit(28), 'Protection not supported/enabled']
        ACCESS_RW = [bit(27), 'Read or write access issues']
        RESTORE = [bit(26), 'Cannot restore binary/value']
        POTENTIALLY_VULNERABLE = [bit(25), 'Found potential vulnerabilities']
        MISMATCH = [bit(24), 'Data does not match expected value']
        REGISTER_NOT_DEFINED = [bit(20), 'Register not defined in Configuration']
        ALL_FFS = [bit(19), 'Read returned all 0xFFs']
        ALL_00S = [bit(18), 'Read returned all 0x00s']
        DEVICE_DISABLED = [bit(17), 'Device is disabled']
        FEATURE_DISABLED = [bit(16), 'Feature is disabled']
        PARSE_ERROR = [bit(15), 'Issue parsing the data']
        UNDEFINED_RANGES = [bit(14), 'Memory ranges are not defined']
        TIMEOUT = [bit(13), 'Operation timed out']
        VERIFY = [bit(12), 'Manual verification/further testing recommended']
        UNSUPPORTED_FEATURE = [bit(11), 'Feature not supported']
        UNSUPPORTED_OPTION = [bit(10), 'Option not supported'] 
        DEBUG_FEATURE = [bit(9), 'A debug feature is enabled or an unexpected debug state was discovered on this platform']
        NOT_APPLICABLE = [bit(8), 'Skipping module since it is not supported']
        INFORMATION = [bit(0), 'For your information']
        INVALID = [0xFFFFFFFFFFFFFFFF, 'Error running the test']
    
    def __init__(self, cs):
        self.id = 0x0
        self.url = ''
        self._result = 0x00000000
        self._return_code = self.status.SUCCESS.value[0]
        self._message = ''
        self.logger = logger()
        self.cs = cs

    def setStatusBit(self, status) -> None:
        if is_set(self._result, status.value[0]) is not True:
            self._result ^= status.value[0]
            self._message += ' / ' + status.value[1]
            
    def setResultBits(self) -> None:
        self._return_code ^= self._result << 32

    def setTestID(self) -> None:
        self._return_code ^= self.id << 4

    def printLogOutput(self) -> None:
        if self._result == self.status.SUCCESS.value[0]:   
            self.logger.log_good(f'RC 0x{self._return_code:016x}: {self.status.SUCCESS.value[1]}')
        else:  
            self.logger.log_important(f"For next steps: {self.url}")
            self.logger.log_important(f"RC 0x{self._return_code:016x}: {self._message}")

    def buildReturnCode(self) -> None:
        self.setResultBits()
        self.setTestID()
        self.printLogOutput()

    def resetReturnCodeValues(self):
        self.id = 0x0
        self._result = 0x00000000
        self._return_code = self.status.SUCCESS.value[0]

    def getReturnCode(self, result: int) -> int:
        if self.cs.using_return_codes:
            self.buildReturnCode()
        else:
            self._return_code = result
        ret_value = self._return_code
        self.resetReturnCodeValues()
        return ret_value

def generate_hash_id(className: str) -> int:
    generated_id = sha256(className.encode("utf-8")).hexdigest()[:7]
    return int(generated_id, 16)

# -------------------------------------------------------
# Legacy results
# -------------------------------------------------------
class ModuleResult(Enum):
    FAILED = 0
    PASSED = 1
    WARNING = 2
    DEPRECATED = 4
    INFORMATION = 5
    NOTAPPLICABLE = 6
    ERROR = -1

result_priority = {
    ModuleResult.PASSED: 0,
    ModuleResult.NOTAPPLICABLE: 0,
    ModuleResult.DEPRECATED: 0,
    ModuleResult.INFORMATION: 1,
    ModuleResult.WARNING: 2,
    ModuleResult.FAILED: 3,
    ModuleResult.ERROR: 4
}

ModuleResultName = {
    ModuleResult.FAILED: 'Failed',
    ModuleResult.PASSED: 'Passed',
    ModuleResult.WARNING: 'Warning',
    ModuleResult.DEPRECATED: 'Deprecated',
    ModuleResult.INFORMATION: 'Information',
    ModuleResult.ERROR: 'Error',
    ModuleResult.NOTAPPLICABLE: 'NotApplicable'
}

def max_result_priority(previous_result: ModuleResult, current_result: ModuleResult) -> ModuleResult:
    '''Accepts two results and returns either current_result (if equal) or the max of the two'''
    return previous_result if result_priority[previous_result] > result_priority[current_result] else current_result

def getModuleResultName(res, using_return_codes) -> str:
    if using_return_codes:
        result_mask = 0xFFFFFFFF00000000
        status = [ReturnCode.status.SUCCESS.value[0], ReturnCode.status.INFORMATION.value[0], ReturnCode.status.NOT_APPLICABLE.value[0]]
        return 'Passed' if ((res & result_mask) >> 32) in status else 'Failed'
    return ModuleResultName[res] if res in ModuleResultName else ModuleResultName[ModuleResult.ERROR]
# -------------------------------------------------------
