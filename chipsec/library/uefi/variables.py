# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2024, Intel Corporation
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

from typing import Dict, Tuple, List

from chipsec.library.logger import logger, print_buffer_bytes
from chipsec.library.types import EfiVariableType
from chipsec.library.uefi.uefi_platform import FWType
from chipsec.library.uefi.varstore import EfiTableType, EFI_VAR_DICT

#
# Variable Attributes
#
EFI_VARIABLE_NON_VOLATILE = 0x00000001  # Variable is non volatile
EFI_VARIABLE_BOOTSERVICE_ACCESS = 0x00000002  # Variable is boot time accessible
EFI_VARIABLE_RUNTIME_ACCESS = 0x00000004  # Variable is run-time accessible
EFI_VARIABLE_HARDWARE_ERROR_RECORD = 0x00000008
EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS = 0x00000010  # Variable is authenticated
EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS = 0x00000020  # Variable is time based authenticated
EFI_VARIABLE_APPEND_WRITE = 0x00000040  # Variable allows append
EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS = 0x00000080
UEFI23_1_AUTHENTICATED_VARIABLE_ATTRIBUTES = (EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS | EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS)


def IS_VARIABLE_ATTRIBUTE(_c: int, _Mask: int) -> bool:
    return ((_c & _Mask) != 0)


def IS_EFI_VARIABLE_AUTHENTICATED(attr: int) -> bool:
    return (IS_VARIABLE_ATTRIBUTE(attr, UEFI23_1_AUTHENTICATED_VARIABLE_ATTRIBUTES))


def get_auth_attr_string(attr: int) -> str:
    attr_str = ' '
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS):
        attr_str = f'{attr_str}AWS+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS):
        attr_str = f'{attr_str}TBAWS+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_APPEND_WRITE):
        attr_str = f'{attr_str}AW+'
    return attr_str[:-1].lstrip()


def get_attr_string(attr: int) -> str:
    attr_str = ' '
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_NON_VOLATILE):
        attr_str = f'{attr_str}NV+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_BOOTSERVICE_ACCESS):
        attr_str = f'{attr_str}BS+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_RUNTIME_ACCESS):
        attr_str = f'{attr_str}RT+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_HARDWARE_ERROR_RECORD):
        attr_str = f'{attr_str}HER+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS):
        attr_str = f'{attr_str}AWS+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS):
        attr_str = f'{attr_str}TBAWS+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_APPEND_WRITE):
        attr_str = f'{attr_str}AW+'
    return attr_str[:-1].lstrip()


###
#
# Common Variable Names
#
###

EFI_VAR_NAME_PK = 'PK'
EFI_VAR_NAME_KEK = 'KEK'
EFI_VAR_NAME_db = 'db'
EFI_VAR_NAME_dbx = 'dbx'
EFI_VAR_NAME_SecureBoot = 'SecureBoot'
EFI_VAR_NAME_SetupMode = 'SetupMode'
EFI_VAR_NAME_CustomMode = 'CustomMode'
EFI_VAR_NAME_SignatureSupport = 'SignatureSupport'
EFI_VAR_NAME_certdb = 'certdb'
EFI_VAR_NAME_AuthVarKeyDatabase = 'AuthVarKeyDatabase'


###
#
# Globally Defined Variables
#
###

EFI_GLOBAL_VARIABLES: Dict[str, int] = {
    'AuditMode': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'Boot': EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'BootCurrent': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'BootOrder': EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'BootOptionSupport': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'ConIn': EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'ConInDev': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'ConOut': EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'ConOutDev': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'dbDefault': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'dbrDefault': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'dbtDefault': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'dbxDefault': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'DeployedModed': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'devAuthBoot': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'devdbDefault': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'Driver': EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'DriverOrder': EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'ErrOut': EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'ErrOutDev': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'HwErrRecSupport': EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'KEK': EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS,
    'KEKDefault': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'Key': EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'OsIndications': EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'OsIndicationsSupported': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'OsRecoveryOrder': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS,
    'PK': EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS,
    'PKDefault': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'PlatformLangCodes': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'PlatformLang': EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'PlatformRecovery': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'SignatureSupport': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'SecureBoot': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'SetupMode': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'SysPrep': EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'SysPrepOrder': EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'Timeout': EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    'VendorKeys': EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS
}

# The following Global Variables are followed with HEX values
EFI_GLOBAL_VARIABLES_HEX: List[str] = [
    'Boot',
    'Driver',
    'Key',
    'PlatformRecovery',
    'SysPrep'
]

#
# \MdePkg\Include\Guid\ImageAuthentication.h
#
# define EFI_IMAGE_SECURITY_DATABASE_GUID \
#  { \
#    0xd719b2cb, 0x3d3a, 0x4596, { 0xa3, 0xbc, 0xda, 0xd0, 0xe, 0x67, 0x65, 0x6f } \
#  }
#
# \MdePkg\Include\Guid\GlobalVariable.h
#
# define EFI_GLOBAL_VARIABLE \
#  { \
#    0x8BE4DF61, 0x93CA, 0x11d2, {0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C } \
#  }
#
EFI_GLOBAL_VARIABLE_GUID = '8be4df61-93ca-11d2-aa0d-00e098032b8c'
EFI_IMAGE_SECURITY_DATABASE_GUID = 'd719b2cb-3d3a-4596-a3bc-dad00e67656f'
# EFI_VAR_GUID_SecureBoot = EFI_GLOBAL_VARIABLE
# EFI_VAR_GUID_db         = EFI_IMAGE_SECURITY_DATABASE_GUID

EFI_VARIABLE_DICT: Dict[str, str] = {
    EFI_VAR_NAME_PK: EFI_GLOBAL_VARIABLE_GUID,
    EFI_VAR_NAME_KEK: EFI_GLOBAL_VARIABLE_GUID,
    EFI_VAR_NAME_db: EFI_IMAGE_SECURITY_DATABASE_GUID,
    EFI_VAR_NAME_dbx: EFI_IMAGE_SECURITY_DATABASE_GUID,
    EFI_VAR_NAME_SecureBoot: EFI_GLOBAL_VARIABLE_GUID,
    EFI_VAR_NAME_SetupMode: EFI_GLOBAL_VARIABLE_GUID,
    EFI_VAR_NAME_CustomMode: EFI_GLOBAL_VARIABLE_GUID,
    EFI_VAR_NAME_SignatureSupport: EFI_GLOBAL_VARIABLE_GUID
}


SECURE_BOOT_KEY_VARIABLES = (EFI_VAR_NAME_PK, EFI_VAR_NAME_KEK, EFI_VAR_NAME_db)
SECURE_BOOT_OPTIONAL_VARIABLES = (EFI_VAR_NAME_dbx,)
SECURE_BOOT_VARIABLES = (EFI_VAR_NAME_SecureBoot, EFI_VAR_NAME_SetupMode) + SECURE_BOOT_KEY_VARIABLES + SECURE_BOOT_OPTIONAL_VARIABLES
SECURE_BOOT_VARIABLES_ALL = (EFI_VAR_NAME_CustomMode, EFI_VAR_NAME_SignatureSupport) + SECURE_BOOT_VARIABLES
AUTHENTICATED_VARIABLES = (EFI_VAR_NAME_AuthVarKeyDatabase, EFI_VAR_NAME_certdb) + SECURE_BOOT_KEY_VARIABLES


#
# Variable State flags
#
VAR_IN_DELETED_TRANSITION = 0xfe  # Variable is in obsolete transition
VAR_DELETED = 0xfd  # Variable is obsolete
VAR_ADDED = 0x7f  # Variable has been completely added


def IS_VARIABLE_STATE(_c: int, _Mask: int) -> bool:
    return ((((~_c) & 0xFF) & ((~_Mask) & 0xFF)) != 0)


def print_efi_variable(offset: int, var_buf: bytes, var_header: 'EfiTableType', var_name: str, var_data: bytes, var_guid: str, var_attrib: int) -> None:
    logger().log('\n--------------------------------')
    logger().log(f'EFI Variable (offset = 0x{offset:X}):')
    logger().log('--------------------------------')

    # Print Variable Name
    logger().log(f'Name      : {var_name}')
    # Print Variable GUID
    logger().log(f'Guid      : {var_guid}')

    # Print Variable State
    if var_header:
        if 'State' in var_header._fields:
            state = getattr(var_header, 'State')
            state_str = 'State     :'
            if IS_VARIABLE_STATE(state, VAR_IN_DELETED_TRANSITION):
                state_str = f'{state_str} IN_DELETED_TRANSITION +'
            if IS_VARIABLE_STATE(state, VAR_DELETED):
                state_str = f'{state_str} DELETED +'
            if IS_VARIABLE_STATE(state, VAR_ADDED):
                state_str = f'{state_str} ADDED +'
            logger().log(state_str)

        # Print Variable Complete Header
        if logger().VERBOSE:
            if var_header.__str__:
                logger().log(str(var_header))
            else:
                decoded_header = EFI_VAR_DICT[FWType.EFI_FW_TYPE_UEFI]['name']
                logger().log(f'Decoded Header ({decoded_header}):')
                for attr in var_header._fields:
                    attr_str = f'{attr:<16}'
                    attr_value = getattr(var_header, attr)
                    logger().log(f'{attr_str} = {attr_value:X}')

    attr_str = (f'Attributes: 0x{var_attrib:X} ( {get_attr_string(var_attrib)} )')
    logger().log(attr_str)

    # Print Variable Data
    logger().log('Data:')
    print_buffer_bytes(var_data)

    # Print Variable Full Contents
    if logger().VERBOSE:
        logger().log('Full Contents:')
        if var_buf is not None:
            print_buffer_bytes(var_buf)


def print_sorted_EFI_variables(variables: Dict[str, List['EfiVariableType']]) -> None:
    sorted_names = sorted(variables.keys())
    rec: Tuple[int, bytes, EfiTableType, bytes, str, int]
    for name in sorted_names:
        for rec in variables[name]:
            #                   off,    buf,     hdr,         data,   guid,   attrs
            print_efi_variable(rec[0], rec[1], rec[2], name, rec[3], rec[4], rec[5])
