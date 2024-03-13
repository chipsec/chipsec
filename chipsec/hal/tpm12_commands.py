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
from typing import Dict, Tuple
from chipsec.library.logger import logger

COMMAND_FORMAT = "=HIIIII"

TPM_TAG_RQU_COMMAND = 0xc100
TPM_TAG_RQU_AUTH1_COMMAND = 0xc200
TPM_TAG_RQU_AUTH2_COMMAND = 0xC300
TPM_TAG_RSP_COMMAND = 0xC400
TPM_TAG_RSP_AUTH1_COMMAND = 0xC500
TPM_TAG_RSP_AUTH2_COMMAND = 0xC600

TPM_ORD_CONTINUESELFTEST = 0x53000000
TPM_ORD_FORCECLEAR = 0x5D000000
TPM_ORD_GETCAPABILITY = 0x65000000
TPM_ORD_NV_DEFINESPACE = 0xCC000000
TPM_ORD_NV_READVALUE = 0xCF000000
TPM_ORD_NV_WRITEVALUE = 0xCD000000
TPM_ORD_PCRREAD = 0x15000000
TPM_ORD_PHYSICALDISABLE = 0x70000000
TPM_ORD_PHYSICALENABLE = 0x6F000000
TPM_ORD_PHYSICALSETDEACTIVATED = 0x72000000
TPM_ORD_STARTUP = 0x99000000
TPM_ORD_SAVESTATE = 0x98000000
TSC_ORD_PHYSICALPRESENCE = 0x0A000040
TSC_ORD_RESETESTABLISHMENTBIT = 0x0B000040

STARTUP: Dict[int, int] = {
    1: 0x0100,
    2: 0x0200,
    3: 0x0300
}

PCR: Dict[int, int] = {
    0: 0x00000000,
    1: 0x01000000,
    2: 0x02000000,
    3: 0x03000000,
    4: 0x04000000,
    5: 0x05000000,
    6: 0x06000000,
    7: 0x07000000,
    8: 0x08000000,
    9: 0x09000000,
    10: 0x0a000000,
    11: 0x0b000000,
    12: 0x0c000000,
    13: 0x0d000000,
    14: 0x0e000000,
    15: 0x0f000000,
    16: 0x10000000,
    17: 0x11000000,
    18: 0x12000000,
    19: 0x13000000,
    20: 0x14000000,
    21: 0x15000000,
    22: 0x16000000,
    23: 0x17000000,
    24: 0x18000000,
    25: 0x19000000,
    26: 0x1a000000,
    27: 0x1b000000,
    28: 0x1c000000,
    29: 0x1d000000,
    30: 0x1e000000
}


def pcrread(*command_argv: str) -> Tuple[bytes, int]:
    """
    The TPM_PCRRead operation provides non-cryptographic reporting  of the contents of a named PCR
    """
    Size = 0x0E000000
    try:
        Pcr = PCR[int(command_argv[0])]
    except:
        if logger().HAL:
            logger().log_bad("Invalid PCR value\n")
        return (b'', 0)
    command = struct.pack(COMMAND_FORMAT, TPM_TAG_RQU_COMMAND, Size, TPM_ORD_PCRREAD, Pcr, 0, 0)
    size = Size >> 0x18
    return (command, size)


def nvread(*command_argv: str) -> Tuple[bytes, int]:
    """
    Read a value from the NV store
    Index, Offset, Size
    """
    Size = 0x18000000
    command = struct.pack(COMMAND_FORMAT, TPM_TAG_RQU_COMMAND, Size, TPM_ORD_NV_READVALUE, int(command_argv[0], 16), int(command_argv[1], 16), int(command_argv[2], 16))
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
        startupType = STARTUP[int(command_argv[0])]
    except:
        if logger().HAL:
            logger().log_bad("Invalid startup type option value\n")
        return (b'', 0)
    Size = 0x0E000000
    command = struct.pack(COMMAND_FORMAT, TPM_TAG_RQU_COMMAND, Size, TPM_ORD_STARTUP, startupType, 0, 0)
    size = Size >> 0x18
    return (command, size)


def continueselftest(*command_argv: str) -> Tuple[bytes, int]:
    """
    TPM_ContinueSelfTest informs the TPM that it should complete self-test of all TPM functions. The TPM may return success immediately and then perform the self-test, or it may perform the self-test and then return success or failure.
    """
    Size = 0x0A000000
    command = struct.pack(COMMAND_FORMAT, TPM_TAG_RQU_COMMAND, Size, TPM_ORD_CONTINUESELFTEST, 0, 0, 0)
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
    command = struct.pack(COMMAND_FORMAT, TPM_TAG_RQU_COMMAND, Size, TPM_ORD_GETCAPABILITY, int(command_argv[0], 16), int(command_argv[1], 16), int(command_argv[2], 16))
    size = Size >> 0x18
    return (command, size)


def forceclear(*command_argv: str) -> Tuple[bytes, int]:
    Size = 0x0A000000
    command = struct.pack(COMMAND_FORMAT, TPM_TAG_RQU_COMMAND, Size, TPM_ORD_FORCECLEAR, 0, 0, 0)
    size = Size >> 0x18
    return (command, size)
