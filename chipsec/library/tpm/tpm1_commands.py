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
Definition for TPMv1.2 commands to use with TPM HAL

TCG PC Client TPM Specification
TCG TPM v1.2 Specification
"""

import struct
from typing import Tuple
from collections import namedtuple
from chipsec.library.logger import logger
from chipsec.library.tpm import tpm_defines


class TPM_RESPONSE_HEADER(namedtuple('TPM_RESPONSE_HEADER', 'ResponseTag DataSize ReturnCode')):
    __slots__ = ()
    def __str__(self) -> str:
        _str = f"""----------------------------------------------------------------
                     TPM response header
----------------------------------------------------------------
   Response TAG: 0x{self.ResponseTag:x}
   Data Size   : 0x{self.DataSize:x}
   Return Code : 0x{self.ReturnCode:x}
"""
        _str += "\t"
        try:
            _str += tpm_defines.STATUS[self.ReturnCode]
        except:
            _str += "Invalid return code"
        _str += "\n"
        return _str
    

def pcrread(*command_argv: str) -> Tuple[bytes, int]:
    """
    The TPM_PCRRead operation provides non-cryptographic reporting  of the contents of a named PCR
    """
    Size = 0x0E000000
    try:
        Pcr = tpm_defines.PCR[int(command_argv[0])]
    except:
        if logger().HAL:
            logger().log_bad("Invalid PCR value\n")
        return (b'', 0)
    command = struct.pack(tpm_defines.COMMAND_FORMAT, tpm_defines.TPM_TAG_RQU_COMMAND, Size, tpm_defines.TPM_ORD_PCRREAD, Pcr, 0, 0)
    size = Size >> 0x18
    return (command, size)


def nvread(*command_argv: str) -> Tuple[bytes, int]:
    """
    Read a value from the NV store
    Index, Offset, Size
    """
    Size = 0x18000000
    command = struct.pack(tpm_defines.COMMAND_FORMAT, tpm_defines.TPM_TAG_RQU_COMMAND, Size, tpm_defines.TPM_ORD_NV_READVALUE, int(command_argv[0], 16), int(command_argv[1], 16), int(command_argv[2], 16))
    size = Size >> 0x18
    return (command, size)


def startup(*command_argv: str) -> Tuple[bytes, int]:
    """
    Execute a tpm_startup command. TPM_Startup is always preceded by TPM_Init, which is the physical indication (a system wide reset) that TPM initialization is necessary
    Type of Startup to be used:
    1: TPM_ST_CLEAR
    2: TPM_ST_STATE
    3: TPM_ST_DEACTIVATED
    """
    try:
        startupType = tpm_defines.STARTUP[int(command_argv[0])]
    except:
        if logger().HAL:
            logger().log_bad("Invalid startup type option value\n")
        return (b'', 0)
    Size = 0x0E000000
    command = struct.pack(tpm_defines.COMMAND_FORMAT, tpm_defines.TPM_TAG_RQU_COMMAND, Size, tpm_defines.TPM_ORD_STARTUP, startupType, 0, 0)
    size = Size >> 0x18
    return (command, size)


def continueselftest(*command_argv: str) -> Tuple[bytes, int]:
    """
    TPM_ContinueSelfTest informs the TPM that it should complete self-test of all TPM functions. The TPM may return success immediately and then perform the self-test, or it may perform the self-test and then return success or failure.
    """
    Size = 0x0A000000
    command = struct.pack(tpm_defines.COMMAND_FORMAT, tpm_defines.TPM_TAG_RQU_COMMAND, Size, tpm_defines.TPM_ORD_CONTINUESELFTEST, 0, 0, 0)
    size = Size >> 0x18
    return (command, size)


def getcap(*command_argv: str) -> Tuple[bytes, int]:
    """
    Returns current information regarding the TPM
    CapArea    - Capabilities Area
    SubCapSize - Size of SubCapabilities
    SubCap     - Subcapabilities
    """
    Size = 0x18000000
    command = struct.pack(tpm_defines.COMMAND_FORMAT, tpm_defines.TPM_TAG_RQU_COMMAND, Size, tpm_defines.TPM_ORD_GETCAPABILITY, int(command_argv[0], 16), int(command_argv[1], 16), int(command_argv[2], 16))
    size = Size >> 0x18
    return (command, size)


def forceclear(*command_argv: str) -> Tuple[bytes, int]:
    Size = 0x0A000000
    command = struct.pack(tpm_defines.COMMAND_FORMAT, tpm_defines.TPM_TAG_RQU_COMMAND, Size, tpm_defines.TPM_ORD_FORCECLEAR, 0, 0, 0)
    size = Size >> 0x18
    return (command, size)
