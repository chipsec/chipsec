#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2021, Intel Corporation
#
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#

from typing import Dict
from chipsec.library.tpm import tpm2_commands
from chipsec.library.tpm import tpm1_commands


# Common defines
TPM1 = '1'
TPM2 = '2'
TPM_CRB = 'crb'
TPM_FIFO = 'fifo'
TPM_FIFO_LEGACY = 'fifo_legacy'

TPM2_INTERFACE_ADDR = 0xFED40030

COMMAND_FORMAT = "=HIIIII"

COMMANDREADY = 0x40
TPMGO = 0x20
HEADERSIZE = 0x0A
HEADERFORMAT = '>HII'
BEENSEIZED  = 0x10
REQUESTUSE  = 0x2
ACTIVELOCALITY = 0x20
DATAAVAIL = 0x10

TPM_DATAFIFO = 0x0024
TPM_STS = 0x0018
TPM_DIDVID = 0x0F00
TPM_ACCESS = 0x0000
TPM_RID = 0x0F04
TPM_INTCAP = 0x0014
TPM_INTENABLE = 0x0008

list_of_registers = ['TPM_ACCESS', 
                    'TPM_STS', 
                    'TPM_DID_VID', 
                    'TPM_RID', 
                    'TPM_INTF_CAPABILITY', 
                    'TPM_INT_ENABLE']

LOCALITY: Dict[str, int] = {
    '0': 0x0000,
    '1': 0x1000,
    '2': 0x2000,
    '3': 0x3000,
    '4': 0x4000
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

vendor_ids = {
    0x1022: 'AMD',
    0x6688: 'Ant Group',
    0x1114: 'Atmel',
    0x14E4: 'Broadcom',
    0xC5C0: 'Cisco',
    0x232B: 'FlySlice Technologies',
    0x232A: 'Fuzhou Rockchip',
    0x6666: 'Google',
    0x103C: 'HPI',
    0x1590: 'HPE',
    0x8888: 'Huawei',
    0x1014: 'IBM',
    0x15D1: 'Infineon',
    0x8086: 'Intel',
    0x17AA: 'Lenovo',
    0x1414: 'Microsoft',
    0x100B: 'National Semi',
    0x1B4E:'Nationz',
    0x9999: 'NSING',
    0x1050: 'Nuvoton Technology1',
    0x1011: 'Qualcomm',
    0x144D: 'Samsung',
    0x5ECE: 'SecEdge',
    0x19FA: 'Sinosun',
    0x1055: 'SMSC',
    0x025E: 'Solidigm',
    0x104A: 'STMicroelectronics',
    0x104C: 'Texas Instruments',
    0x2406: 'Wisekey'
}


# TPM 1.2 defines
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

COMMANDS_12: Dict[str, callable] = {
        "pcrread": tpm1_commands.pcrread,
        "nvread": tpm1_commands.nvread,
        "startup": tpm1_commands.startup,
        "continueselftest": tpm1_commands.continueselftest,
        "forceclear": tpm1_commands.forceclear,
        'header': tpm1_commands.TPM_RESPONSE_HEADER
    }

STARTUP: Dict[int, int] = {
    1: 0x0100,
    2: 0x0200,
    3: 0x0300
}

STATUS: Dict[int, str] = {
    0x00: "Success",
    0x01: "ERROR: Authentication Failed",
    0x02: "ERROR: The index to a PCR, DIR or other register is incorrect",
    0x03: "ERROR: One or more parameter is bad",
    0x04: "ERROR: An operation completed successfully but the auditing of that operation failed",
    0x05: "ERROR: The clear disable flag is set and all clear operations now require physical access",
    0x06: "ERROR: The TPM is deactivated",
    0x07: "ERROR: The TPM is disabled",
    0x08: "ERROR: The target command has been disabled",
    0x09: "ERROR: The operation failed",
    0x0A: "ERROR: The ordinal was unknown or inconsistent",
    0x0B: "ERROR: The ability to install an owner is disabled",
    0x0C: "ERROR: The key handle can not be interpreted",
    0x0D: "ERROR: The key handle points to an invalid key",
    0x0E: "ERROR: Unacceptable encryption scheme",
    0x0F: "ERROR: Migration authorization failed",
    0x10: "ERROR: PCR information could not be interpreted",
    0x11: "ERROR: No room to load key",
    0x12: "ERROR: There is no SRK set",
    0x13: "ERROR: An encrypted blob is invalid or was not created by this TPM",
    0x14: "ERROR: There is already an Owner",
    0x15: "ERROR: The TPM has insufficient internal resources to perform the requested action",
    0x16: "ERROR: A random string was too short",
    0x17: "ERROR: The TPM does not have the space to perform the operation",
    0x18: "ERROR: The named PCR value does not match the current PCR value.",
    0x19: "ERROR: The paramSize argument to the command has the incorrect value",
    0x1A: "ERROR: There is no existing SHA-1 thread.",
    0x1B: "ERROR: The calculation is unable to proceed because the existing SHA-1 thread has already encountered an error",
    0x1C: "ERROR: Self-test has failed and the TPM has shut-down",
    0x1D: "ERROR: The authorization for the second key in a 2 key function failed authorization",
    0x1E: "ERROR: The tag value sent to for a command is invalid",
    0x1F: "ERROR: An IO error occurred transmitting information to the TPM",
    0x20: "ERROR: The encryption process had a problem",
    0x21: "ERROR: The decryption process did not complete",
    0x22: "ERROR: An invalid handle was used",
    0x23: "ERROR: The TPM does not a EK installed",
    0x24: "ERROR: The usage of a key is not allowed",
    0x25: "ERROR: The submitted entity type is not allowed",
    0x26: "ERROR: The command was received in the wrong sequence relative to TPM_Init and a subsequent TPM_Startup",
    0x27: "ERROR: Signed data cannot include additional DER information",
    0x28: "ERROR: The key properties in TPM_KEY_PARMs are not supported by this TPM",
    0x29: "ERROR: The migration properties of this key are incorrect",
    0x2A: "ERROR: The signature or encryption scheme for this key is incorrect or not permitted in this situation",
    0x2B: "ERROR: The size of the data (or blob) parameter is bad or inconsistent with the referenced key",
    0x2C: "ERROR: A parameter is bad",
    0x2D: "ERROR: Either the physicalPresence or physicalPresenceLock bits have the wrong value",
    0x2E: "ERROR: The TPM cannot perform this version of the capability",
    0x2F: "ERROR: The TPM does not allow for wrapped transport sessions",
    0x30: "ERROR: TPM audit construction failed and the underlying command was returning a failure code also",
    0x31: "ERROR: TPM audit construction failed and the underlying command was returning success",
    0x32: "ERROR: Attempt to reset a PCR register that does not have the resettable attribute",
    0x33: "ERROR: Attempt to reset a PCR register that requires locality and locality modifier not part of command transport",
    0x34: "ERROR: Make identity blob not properly typed",
    0x35: "ERROR: When saving context identified resource type does not match actual resource",
    0x36: "ERROR: The TPM is attempting to execute a command only available when in FIPS mode",
    0x37: "ERROR: The command is attempting to use an invalid family ID",
    0x38: "ERROR: The permission to manipulate the NV storage is not available",
    0x39: "ERROR: The operation requires a signed command",
    0x3A: "ERROR: Wrong operation to load an NV key",
    0x3B: "ERROR: NV_LoadKey blob requires both owner and blob authorization",
    0x3C: "ERROR: The NV area is locked and not writeable",
    0x3D: "ERROR: The locality is incorrect for the attempted operation",
    0x3E: "ERROR: The NV area is read only and can?t be written to",
    0x3F: "ERROR: There is no protection on the write to the NV area",
    0x40: "ERROR: The family count value does not match",
    0x41: "ERROR: The NV area has already been written to",
    0x42: "ERROR: The NV area attributes conflict",
    0x43: "ERROR: The structure tag and version are invalid or inconsistent",
    0x44: "ERROR: The key is under control of the TPM Owner and can only be evicted by the TPM Owner",
    0x45: "ERROR: The counter handle is incorrect",
    0x46: "ERROR: The write is not a complete write of the area",
    0x47: "ERROR: The gap between saved context counts is too large",
    0x48: "ERROR: The maximum number of NV writes without an owner has been exceeded",
    0x49: "ERROR: No operator AuthData value is set",
    0x4A: "ERROR: The resource pointed to by context is not loaded",
    0x4B: "ERROR: The delegate administration is locked",
    0x4C: "ERROR: Attempt to manage a family other then the delegated family",
    0x4D: "ERROR: Delegation table management not enabled",
    0x4E: "ERROR: There was a command executed outside of an exclusive transport session",
    0x4F: "ERROR: Attempt to context save a owner evict controlled key",
    0x50: "ERROR: The DAA command has no resources available to execute the command",
    0x51: "ERROR: The consistency check on DAA parameter inputData0 has failed",
    0x52: "ERROR: The consistency check on DAA parameter inputData1 has failed",
    0x53: "ERROR: The consistency check on DAA_issuerSettings has failed",
    0x54: "ERROR: The consistency check on DAA_tpmSpecific has failed",
    0x55: "ERROR: The atomic process indicated by the submitted DAA command is not the expected process",
    0x56: "ERROR: The issuer's validity check has detected an inconsistency",
    0x57: "ERROR: The consistency check on w has failed",
    0x58: "ERROR: The handle is incorrect",
    0x59: "ERROR: Delegation is not correct",
    0x5A: "ERROR: The context blob is invalid",
    0x5B: "ERROR: Too many contexts held by the TPM",
    0x5C: "ERROR: Migration authority signature validation failure",
    0x5D: "ERROR: Migration destination not authenticated",
    0x5E: "ERROR: Migration source incorrect",
    0x5F: "ERROR: Incorrect migration authority",
    0x60: "ERROR: TBD",
    0x61: "ERROR: Attempt to revoke the EK and the EK is not revocable",
    0x62: "ERROR: Bad signature of CMK ticket",
    0x63: "ERROR: There is no room in the context list for additional contexts",
    0x800: "NON-FATAL ERROR: The TPM is too busy to respond to the command immediately, but the command could be resubmitted at a later time",
    0x801: "NON-FATAL ERROR: TPM_ContinueSelfTest has not been run.",
    0x802: "NON-FATAL ERROR: The TPM is currently executing the actions of TPM_ContinueSelfTest because the ordinal required resources that have not been tested",
    0x803: "NON-FATAL ERROR: The TPM is defending against dictionary attacks and is in some time-out period."
}

STARTUP: Dict[int, int] = {
    1: 0x0100,
    2: 0x0200,
    3: 0x0300
}


# TPM 2.0 defines
TPM2_NVUNDEFINESPACE_COMMAND = 0x22010000
TPM2_NVDEFINESPACE_COMMAND = 0x2A010000
TPM2_NVWRITE_COMMAND = 0x37010000
TPM2_SELFTEST_COMMAND = 0x43010000
TPM2_STARTUP_COMMAND = 0x44010000
TPM2_SHUTDOWN_COMMAND = 0x45010000
TPM2_NVREAD_COMMAND = 0x4E010000
TPM2_PCRREAD_COMMAND = 0x7E010000

COMMANDS_20 = {
        "startup": tpm2_commands.startup,
        "shutdown": tpm2_commands.shutdown,
        "selftest": tpm2_commands.selftest,
        "nvread": tpm2_commands.nvread,
        "nvwrite": tpm2_commands.nvwrite,
        "pcrread": tpm2_commands.pcrread,
        "nvdefinespace": tpm2_commands.nvdefinespace,
        "nvundefinespace": tpm2_commands.nvundefinespace,
        'header': tpm2_commands.TPM_RESPONSE_HEADER
    }

TPM_ST_NO_SESSIONS = 0x0180
TPM_ST_SESSIONS = 0x0280

SESSIONS: Dict[int, int] = {
    0: TPM_ST_NO_SESSIONS,
    1: TPM_ST_SESSIONS
}

TPM_SU: Dict[int, int] = {
    0: 0x0000,  # TPM_SU_CLEAR
    1: 0x0001   # TPM_SU_STATE
}

TPMI_YES_NO: Dict[int, int] = {
    0: 0x00,
    1: 0x01
}

TPMI_RH_NV_AUTH: Dict[int, int] = {
    1: 0x4000000C,  # TPM_RH_PLATFORM
    2: 0x40000001   # TPM_RH_OWNER
}

NV_INDEX_FIRST = 0x01 << 24
NV_INDEX_LAST = NV_INDEX_FIRST + 0x00FFFFFF

RESPONSE_TAG = {}

RESPONSE_CODE = {
    0x000: ['TPM_RC_SUCCESS', ''],
    0x1E: ['TPM_RC_BAD_TAG', ''],
    # RC_VER1 0x100 (set for all format 0 responses)
    0x100: ['TPM_RC_INITIALIZE', ' TPM not initialized by TPM2_Startup() or already initialized'],
    0x101: ['TPM_RC_FAILURE', 'commands not being accepted because of a TPM failure'],
    0x103: ['TPM_RC_SEQUENCE', 'improper use of a sequence handle'],
    0x1DA: ['TPM_RC_EXPIRED', 'the policy has expired'],

    # 'TPM_RC_': 0x0,
    # 'TPM_RC_CANCELED': 0x0,
    # 'TPM_RC_CONTEXT_GAP': 0x0,
    # 'TPM_RC_LOCKOUT': 0x0,
    # 'TPM_RC_MEMORY': 0x0,
    # 'TPM_RC_NV_RATE': 0x0,
    # 'TPM_RC_NV_UNAVAILABLE': 0x0,
    # 'TPM_RC_OBJECT_HANDLES': 0x0,
    # 'TPM_RC_OBJECT_MEMORY': 0x0,
    # 'TPM_RC_REFERENCE_Hx (0-6)': 0x0,
    # 'TPM_RC_REFERENCE_Sx (0-6)': 0x0,
    # 'TPM_RC_RETRY': 0x0,
    # 'TPM_RC_SESSION_HANDLES': 0x0,
    # 'TPM_RC_SESSION_MEMORY': 0x0,
    
    # 'TPM_RC_TESTING': 0x0,
    # 'TPM_RC_YIELDED': 0x0
}