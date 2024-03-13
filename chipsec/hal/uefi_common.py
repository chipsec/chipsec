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
Common UEFI/EFI functionality including UEFI variables, Firmware Volumes, Secure Boot variables, S3 boot-script, UEFI tables, etc.
"""

import os
import struct
import codecs
from collections import namedtuple
from uuid import UUID
from typing import Dict, List, Tuple, Optional, Any, Callable

from chipsec.library.file import read_file, write_file
from chipsec.library.logger import logger, dump_buffer, dump_buffer_bytes
from chipsec.library.defines import bytestostring

# from chipsec.helper.oshelper import helper


################################################################################################
#
# EFI Variable and Variable Store Defines
#
################################################################################################

# UDK2010.SR1\MdeModulePkg\Include\Guid\VariableFormat.h
#
# Variable data start flag.
#
VARIABLE_DATA = 0x55aa
VARIABLE_DATA_SIGNATURE = struct.pack('=H', VARIABLE_DATA)


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
    return (IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS) or 
            IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) or
            IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS))


MAX_VARIABLE_SIZE = 1024
MAX_NVRAM_SIZE = 1024 * 1024


def get_nvar_name(nvram: bytes, name_offset: int, isAscii: bool):
    if isAscii:
        nend = nvram.find(b'\x00', name_offset)
        name = nvram[name_offset:nend].decode('latin1')
        name_size = len(name) + 1
        return (name, name_size)
    else:
        nend = nvram.find(b'\x00\x00', name_offset)
        name = nvram[name_offset:nend].decode('utf-16le')
        name_size = len(name) + 2
        return (name, name_size)


VARIABLE_SIGNATURE_VSS = VARIABLE_DATA_SIGNATURE


VARIABLE_STORE_FV_GUID = UUID('FFF12B8D-7696-4C8B-A985-2747075B4F50')


################################################################################################
#
# Misc Defines
#
################################################################################################

#
# Status codes
# edk2: MdePkg/Include/Base.h
#

# @TODO
# define ENCODE_ERROR(StatusCode)     ((RETURN_STATUS)(MAX_BIT | (StatusCode)))
# define ENCODE_WARNING(a)            (a)

class StatusCode:
    EFI_SUCCESS = 0
    EFI_LOAD_ERROR = 1
    EFI_INVALID_PARAMETER = 2
    EFI_UNSUPPORTED = 3
    EFI_BAD_BUFFER_SIZE = 4
    EFI_BUFFER_TOO_SMALL = 5
    EFI_NOT_READY = 6
    EFI_DEVICE_ERROR = 7
    EFI_WRITE_PROTECTED = 8
    EFI_OUT_OF_RESOURCES = 9
    EFI_VOLUME_CORRUPTED = 10
    EFI_VOLUME_FULL = 11
    EFI_NO_MEDIA = 12
    EFI_MEDIA_CHANGED = 13
    EFI_NOT_FOUND = 14
    EFI_ACCESS_DENIED = 15
    EFI_NO_RESPONSE = 16
    EFI_NO_MAPPING = 17
    EFI_TIMEOUT = 18
    EFI_NOT_STARTED = 19
    EFI_ALREADY_STARTED = 20
    EFI_ABORTED = 21
    EFI_ICMP_ERROR = 22
    EFI_TFTP_ERROR = 23
    EFI_PROTOCOL_ERROR = 24
    EFI_INCOMPATIBLE_VERSION = 25
    EFI_SECURITY_VIOLATION = 26
    EFI_CRC_ERROR = 27
    EFI_END_OF_MEDIA = 28
    EFI_END_OF_FILE = 31
    EFI_INVALID_LANGUAGE = 32
    EFI_COMPROMISED_DATA = 33
    EFI_HTTP_ERROR = 35
    '''
  EFI_WARN_UNKNOWN_GLYPH    = 1
  EFI_WARN_DELETE_FAILURE   = 2
  EFI_WARN_WRITE_FAILURE    = 3
  EFI_WARN_BUFFER_TOO_SMALL = 4
  EFI_WARN_STALE_DATA       = 5
  EFI_WARN_FILE_SYSTEM      = 6
  '''


EFI_STATUS_DICT: Dict[int, str] = {
    StatusCode.EFI_SUCCESS: "EFI_SUCCESS",
    StatusCode.EFI_LOAD_ERROR: "EFI_LOAD_ERROR",
    StatusCode.EFI_INVALID_PARAMETER: "EFI_INVALID_PARAMETER",
    StatusCode.EFI_UNSUPPORTED: "EFI_UNSUPPORTED",
    StatusCode.EFI_BAD_BUFFER_SIZE: "EFI_BAD_BUFFER_SIZE",
    StatusCode.EFI_BUFFER_TOO_SMALL: "EFI_BUFFER_TOO_SMALL",
    StatusCode.EFI_NOT_READY: "EFI_NOT_READY",
    StatusCode.EFI_DEVICE_ERROR: "EFI_DEVICE_ERROR",
    StatusCode.EFI_WRITE_PROTECTED: "EFI_WRITE_PROTECTED",
    StatusCode.EFI_OUT_OF_RESOURCES: "EFI_OUT_OF_RESOURCES",
    StatusCode.EFI_VOLUME_CORRUPTED: "EFI_VOLUME_CORRUPTED",
    StatusCode.EFI_VOLUME_FULL: "EFI_VOLUME_FULL",
    StatusCode.EFI_NO_MEDIA: "EFI_NO_MEDIA",
    StatusCode.EFI_MEDIA_CHANGED: "EFI_MEDIA_CHANGED",
    StatusCode.EFI_NOT_FOUND: "EFI_NOT_FOUND",
    StatusCode.EFI_ACCESS_DENIED: "EFI_ACCESS_DENIED",
    StatusCode.EFI_NO_RESPONSE: "EFI_NO_RESPONSE",
    StatusCode.EFI_NO_MAPPING: "EFI_NO_MAPPING",
    StatusCode.EFI_TIMEOUT: "EFI_TIMEOUT",
    StatusCode.EFI_NOT_STARTED: "EFI_NOT_STARTED",
    StatusCode.EFI_ALREADY_STARTED: "EFI_ALREADY_STARTED",
    StatusCode.EFI_ABORTED: "EFI_ABORTED",
    StatusCode.EFI_ICMP_ERROR: "EFI_ICMP_ERROR",
    StatusCode.EFI_TFTP_ERROR: "EFI_TFTP_ERROR",
    StatusCode.EFI_PROTOCOL_ERROR: "EFI_PROTOCOL_ERROR",
    StatusCode.EFI_INCOMPATIBLE_VERSION: "EFI_INCOMPATIBLE_VERSION",
    StatusCode.EFI_SECURITY_VIOLATION: "EFI_SECURITY_VIOLATION",
    StatusCode.EFI_CRC_ERROR: "EFI_CRC_ERROR",
    StatusCode.EFI_END_OF_MEDIA: "EFI_END_OF_MEDIA",
    StatusCode.EFI_END_OF_FILE: "EFI_END_OF_FILE",
    StatusCode.EFI_INVALID_LANGUAGE: "EFI_INVALID_LANGUAGE",
    StatusCode.EFI_COMPROMISED_DATA: "EFI_COMPROMISED_DATA",
    StatusCode.EFI_HTTP_ERROR: "EFI_HTTP_ERROR"
}

EFI_MAX_BIT = 0x8000000000000000


def EFI_ERROR_STR(error: int) -> str:
    """
    Translates an EFI_STATUS value into its corresponding textual representation.
    """
    error &= ~EFI_MAX_BIT
    try:
        return EFI_STATUS_DICT[error]
    except KeyError:
        return "UNKNOWN"


EFI_GUID_FMT = "16s"
EFI_GUID_SIZE = struct.calcsize(EFI_GUID_FMT)


def EFI_GUID_STR(guid: bytes) -> str:
    guid_str = UUID(bytes_le=guid)
    return str(guid_str).upper()


def align(of:int, size: int) -> int:
    of = (((of + size - 1) // size) * size)
    return of


def bit_set(value: int, mask: int, polarity: bool = False) -> bool:
    if polarity:
        value = ~value
    return ((value & mask) == mask)


def get_3b_size(s_data: bytes) -> int:
    s_str = bytestostring(s_data)
    return (ord(s_str[0]) + (ord(s_str[1]) << 8) + (ord(s_str[2]) << 16))


# #################################################################################################
#
# UEFI Variable (NVRAM) Parsing Functionality
#
# #################################################################################################

SIGNATURE_LIST = "<16sIII"
SIGNATURE_LIST_size = struct.calcsize(SIGNATURE_LIST)


def parse_sha256(data):
    return


def parse_rsa2048(data):
    return


def parse_rsa2048_sha256(data):
    return


def parse_sha1(data):
    return


def parse_rsa2048_sha1(data):
    return


def parse_x509(data):
    return


def parse_sha224(data):
    return


def parse_sha384(data):
    return


def parse_sha512(data):
    return


def parse_x509_sha256(data):
    return


def parse_x509_sha384(data):
    return


def parse_x509_sha512(data):
    return


def parse_external(data):
    return


def parse_pkcs7(data):
    return


sig_types: Dict[str, Tuple[str, Callable, int, str]] = {
    "C1C41626-504C-4092-ACA9-41F936934328": ("EFI_CERT_SHA256_GUID", parse_sha256, 0x30, "SHA256"),
    "3C5766E8-269C-4E34-AA14-ED776E85B3B6": ("EFI_CERT_RSA2048_GUID", parse_rsa2048, 0x110, "RSA2048"),
    "E2B36190-879B-4A3D-AD8D-F2E7BBA32784": ("EFI_CERT_RSA2048_SHA256_GUID", parse_rsa2048_sha256, 0x110, "RSA2048_SHA256"),
    "826CA512-CF10-4AC9-B187-BE01496631BD": ("EFI_CERT_SHA1_GUID", parse_sha1, 0x24, "SHA1"),
    "67F8444F-8743-48F1-A328-1EAAB8736080": ("EFI_CERT_RSA2048_SHA1_GUID", parse_rsa2048_sha1, 0x110, "RSA2048_SHA1"),
    "A5C059A1-94E4-4AA7-87B5-AB155C2BF072": ("EFI_CERT_X509_GUID", parse_x509, 0, "X509"),
    "0B6E5233-A65C-44C9-9407-D9AB83BFC8BD": ("EFI_CERT_SHA224_GUID", parse_sha224, 0x2c, "SHA224"),
    "FF3E5307-9FD0-48C9-85F1-8AD56C701E01": ("EFI_CERT_SHA384_GUID", parse_sha384, 0x40, "SHA384"),
    "093E0FAE-A6C4-4F50-9F1B-D41E2B89C19A": ("EFI_CERT_SHA512_GUID", parse_sha512, 0x50, "SHA512"),
    "3bd2a492-96c0-4079-b420-fcf98ef103ed": ("EFI_CERT_X509_SHA256_GUID", parse_x509_sha256, 0x40, "X509_SHA256"),
    "7076876e-80c2-4ee6-aad2-28b349a6865b": ("EFI_CERT_X509_SHA384_GUID", parse_x509_sha384, 0x50, "X509_SHA384"),
    "446dbf63-2502-4cda-bcfa-2465d2b0fe9d": ("EFI_CERT_X509_SHA512_GUID", parse_x509_sha512, 0x60, "X509_SHA512"),
    "452e8ced-dfff-4b8c-ae01-5118862e682c": ("EFI_CERT_EXTERNAL_MANAGEMENT_GUID", parse_external, 0x11, "EXTERNAL_MANAGEMENT"),
    "4AAFD29D-68DF-49EE-8AA9-347D375665A7": ("EFI_CERT_TYPE_PKCS7_GUID", parse_pkcs7, 0, "PKCS7"),
    }


def parse_sb_db(db: bytes, decode_dir: str) -> List[bytes]:
    entries = []
    dof = 0
    nsig = 0
    db_size = len(db)
    if 0 == db_size:
        return entries

    # some platforms have 0's in the beginnig, skip all 0 (no known SignatureType starts with 0x00):
    while (dof + SIGNATURE_LIST_size) < db_size:
        SignatureType0, SignatureListSize, SignatureHeaderSize, SignatureSize \
            = struct.unpack(SIGNATURE_LIST, db[dof:dof + SIGNATURE_LIST_size])

        # prevent infinite loop when parsing malformed var
        if SignatureListSize == 0:
            logger().log_bad("db parsing failed!")
            return entries

        # Determine the signature type
        SignatureType = EFI_GUID_STR(SignatureType0)
        sig_parse_f = None
        sig_size = 0
        if (SignatureType in sig_types.keys()):
            sig_name, sig_parse_f, sig_size, short_name = sig_types[SignatureType]
        else:
            logger().log_bad(f'Unknown signature type {SignatureType}, skipping signature decode.')
            dof += SignatureListSize
            continue

        # Extract signature data blobs
        if (((sig_size > 0) and (sig_size == SignatureSize)) or ((sig_size == 0) and (SignatureSize >= 0x10))):
            sof = 0
            sig_list = db[dof + SIGNATURE_LIST_size + SignatureHeaderSize:dof + SignatureListSize]
            sig_list_size = len(sig_list)
            while ((sof + EFI_GUID_SIZE) < sig_list_size):
                sig_data = sig_list[sof:sof + SignatureSize]
                owner0 = struct.unpack(EFI_GUID_FMT, sig_data[:EFI_GUID_SIZE])[0]
                owner = EFI_GUID_STR(owner0)
                data = sig_data[EFI_GUID_SIZE:]
                entries.append(data)
                sig_file_name = f'{short_name}-{owner}-{nsig:02d}.bin'
                sig_file_name = os.path.join(decode_dir, sig_file_name)
                write_file(sig_file_name, data)
                if (sig_parse_f is not None):
                    sig_parse_f(data)
                sof = sof + SignatureSize
                nsig = nsig + 1
        else:
            err_str = f'Wrong SignatureSize for {SignatureType} type: 0x{SignatureSize:X}.'
            if (sig_size > 0):
                err_str = err_str + f' Must be 0x{sig_size:X}.'
            else:
                err_str = err_str + " Must be >= 0x10."
            logger().log_error(err_str)
            logger().log_error('Skipping signature decode for this list.')
        dof = dof + SignatureListSize

    return entries


#
#  "certdb" variable stores the signer's certificates for non PK/KEK/DB/DBX
# variables with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS|EFI_VARIABLE_NON_VOLATILE set.
#  "certdbv" variable stores the signer's certificates for non PK/KEK/DB/DBX
# variables with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS set
#
# GUID: gEfiCertDbGuid
#
# We need maintain atomicity.
#
# Format:
# +----------------------------+
# | UINT32                     | <-- CertDbListSize, including this UINT32
# +----------------------------+
# | AUTH_CERT_DB_DATA          | <-- First CERT
# +----------------------------+
# | ........                   |
# +----------------------------+
# | AUTH_CERT_DB_DATA          | <-- Last CERT
# +----------------------------+
#
# typedef struct {
#   EFI_GUID    VendorGuid;
#   UINT32      CertNodeSize;
#   UINT32      NameSize;
#   UINT32      CertDataSize;
#   /// CHAR16  VariableName[NameSize];
#   /// UINT8   CertData[CertDataSize];
# } AUTH_CERT_DB_DATA;
#
AUTH_CERT_DB_LIST_HEAD = "<I"
AUTH_CERT_DB_LIST_HEAD_size = struct.calcsize(AUTH_CERT_DB_LIST_HEAD)
AUTH_CERT_DB_DATA = "<16sIII"
AUTH_CERT_DB_DATA_size = struct.calcsize(AUTH_CERT_DB_DATA)


def parse_auth_var(db: bytes, decode_dir: str) -> List[bytes]:
    entries = []
    dof = 0
    nsig = 0
    db_size = len(db)

    # Verify that list makes sense
    if db_size < AUTH_CERT_DB_LIST_HEAD_size:
        logger().log_warning("Cert list empty.")
        return entries
    expected_size = struct.unpack(AUTH_CERT_DB_LIST_HEAD, db[dof:dof + AUTH_CERT_DB_LIST_HEAD_size])[0]
    if db_size != expected_size:
        logger().log_error("Expected size of cert list did not match actual size.")
        return entries
    dof += AUTH_CERT_DB_LIST_HEAD_size

    # Loop through all the certs in the list.
    while dof + AUTH_CERT_DB_DATA_size < db_size:
        ven_guid0, cert_node_size, name_size, cert_data_size = struct.unpack(AUTH_CERT_DB_DATA, db[dof:dof + AUTH_CERT_DB_DATA_size])
        vendor_guid = EFI_GUID_STR(ven_guid0)
        name_size *= 2  # Name size is actually the number of CHAR16 in the name array
        tof = dof + AUTH_CERT_DB_DATA_size
        try:
            var_name = codecs.decode(db[tof:tof + name_size], 'utf-16')
        except UnicodeDecodeError:
            logger().log_warning(f'Unable to decode {db[tof:tof + name_size]}')
            var_name = "chipsec.library.exceptions!"
        tof += name_size
        sig_data = db[tof:tof + cert_data_size]
        entries.append(sig_data)
        sig_file_name = f'{vendor_guid}-{codecs.encode(var_name)}-{nsig:02X}.bin'
        sig_file_name = os.path.join(decode_dir, sig_file_name)
        write_file(sig_file_name, sig_data)
        dof += cert_node_size
        nsig += 1

    return entries


ESAL_SIG_SIZE = 256


def parse_esal_var(db: bytes, decode_dir: str) -> List[bytes]:
    entries = []
    dof = 0
    nsig = 0
    db_size = len(db)

    # Check to see how many signatures exist
    if db_size < ESAL_SIG_SIZE:
        logger().log('No signatures present.')
        return entries

    # Extract signatures
    while dof + ESAL_SIG_SIZE <= db_size:
        key_data = db[dof:dof + ESAL_SIG_SIZE]
        entries.append(key_data)
        key_file_name = os.path.join(decode_dir, f'AuthVarKeyDatabase-cert-{nsig:02X}.bin')
        write_file(key_file_name, key_data)
        dof += ESAL_SIG_SIZE
        nsig += 1

    return entries


SECURE_BOOT_SIG_VAR = 1
AUTH_SIG_VAR = 2
ESAL_SIG_VAR = 3


def parse_efivar_file(fname: str, var: Optional[bytes] = None, var_type: int = SECURE_BOOT_SIG_VAR) -> None:
    logger().log(f'Processing certs in file: {fname}')
    if not var:
        var = read_file(fname)
    var_path = fname + '.dir'
    if not os.path.exists(var_path):
        os.makedirs(var_path)
    if var_type == SECURE_BOOT_SIG_VAR:
        parse_sb_db(var, var_path)
    elif var_type == AUTH_SIG_VAR:
        parse_auth_var(var, var_path)
    elif var_type == ESAL_SIG_VAR:
        parse_esal_var(var, var_path)
    else:
        logger().log_warning(f'Unsupported variable type requested: {var_type}')


########################################################################################################
#
# S3 Resume Boot-Script Parsing Functionality
#
########################################################################################################

BOOTSCRIPT_TABLE_OFFSET = 24
RUNTIME_SCRIPT_TABLE_BASE_OFFSET = 32
ACPI_VARIABLE_SET_STRUCT_SIZE = 0x48
S3_BOOTSCRIPT_VARIABLES = ['AcpiGlobalVariable']

MAX_S3_BOOTSCRIPT_ENTRY_LENGTH = 0x200


#
# MdePkg\Include\Pi\PiS3BootScript.h
#
# //*******************************************
# // EFI Boot Script Opcode definitions
# //*******************************************

class S3BootScriptOpcode:
    EFI_BOOT_SCRIPT_IO_WRITE_OPCODE = 0x00
    EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE = 0x01
    EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE = 0x02
    EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE = 0x03
    EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE = 0x04
    EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE = 0x05
    EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE = 0x06
    EFI_BOOT_SCRIPT_STALL_OPCODE = 0x07
    EFI_BOOT_SCRIPT_DISPATCH_OPCODE = 0x08
    EFI_BOOT_SCRIPT_TERMINATE_OPCODE = 0xFF


class S3BootScriptOpcode_MDE (S3BootScriptOpcode):
    EFI_BOOT_SCRIPT_DISPATCH_2_OPCODE = 0x09
    EFI_BOOT_SCRIPT_INFORMATION_OPCODE = 0x0A
    EFI_BOOT_SCRIPT_PCI_CONFIG2_WRITE_OPCODE = 0x0B
    EFI_BOOT_SCRIPT_PCI_CONFIG2_READ_WRITE_OPCODE = 0x0C
    EFI_BOOT_SCRIPT_IO_POLL_OPCODE = 0x0D
    EFI_BOOT_SCRIPT_MEM_POLL_OPCODE = 0x0E
    EFI_BOOT_SCRIPT_PCI_CONFIG_POLL_OPCODE = 0x0F
    EFI_BOOT_SCRIPT_PCI_CONFIG2_POLL_OPCODE = 0x10

#
# EdkCompatibilityPkg\Foundation\Framework\Include\EfiBootScript.h
#


class S3BootScriptOpcode_EdkCompat (S3BootScriptOpcode):
    EFI_BOOT_SCRIPT_MEM_POLL_OPCODE = 0x09
    EFI_BOOT_SCRIPT_INFORMATION_OPCODE = 0x0A
    EFI_BOOT_SCRIPT_PCI_CONFIG2_WRITE_OPCODE = 0x0B
    EFI_BOOT_SCRIPT_PCI_CONFIG2_READ_WRITE_OPCODE = 0x0C
    EFI_BOOT_SCRIPT_TABLE_OPCODE = 0xAA


#
# Names of S3 Boot Script Opcodes
#
script_opcodes: Dict[int, str] = {
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_WRITE_OPCODE: "S3_BOOTSCRIPT_IO_WRITE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE: "S3_BOOTSCRIPT_IO_READ_WRITE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE: "S3_BOOTSCRIPT_MEM_WRITE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE: "S3_BOOTSCRIPT_MEM_READ_WRITE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE: "S3_BOOTSCRIPT_PCI_CONFIG_WRITE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE: "S3_BOOTSCRIPT_PCI_CONFIG_READ_WRITE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE: "S3_BOOTSCRIPT_SMBUS_EXECUTE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_STALL_OPCODE: "S3_BOOTSCRIPT_STALL",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_DISPATCH_OPCODE: "S3_BOOTSCRIPT_DISPATCH",
    # S3BootScriptOpcode.EFI_BOOT_SCRIPT_DISPATCH_2_OPCODE:             "S3_BOOTSCRIPT_DISPATCH_2",
    # S3BootScriptOpcode.EFI_BOOT_SCRIPT_INFORMATION_OPCODE:            "S3_BOOTSCRIPT_INFORMATION",
    # S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG2_WRITE_OPCODE:      "S3_BOOTSCRIPT_PCI_CONFIG2_WRITE",
    # S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG2_READ_WRITE_OPCODE: "S3_BOOTSCRIPT_PCI_CONFIG2_READ_WRITE",
    # S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_POLL_OPCODE:                "S3_BOOTSCRIPT_IO_POLL",
    # S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_POLL_OPCODE:               "S3_BOOTSCRIPT_MEM_POLL",
    # S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_POLL_OPCODE:        "S3_BOOTSCRIPT_PCI_CONFIG_POLL",
    # S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG2_POLL_OPCODE:       "S3_BOOTSCRIPT_PCI_CONFIG2_POLL",
    # S3BootScriptOpcode.EFI_BOOT_SCRIPT_TABLE_OPCODE:                  "S3_BOOTSCRIPT_TABLE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_TERMINATE_OPCODE: "S3_BOOTSCRIPT_TERMINATE"
}


# //*******************************************
# // EFI_BOOT_SCRIPT_WIDTH
# //*******************************************
# typedef enum {
# EfiBootScriptWidthUint8,
# EfiBootScriptWidthUint16,
# EfiBootScriptWidthUint32,
# EfiBootScriptWidthUint64,
# EfiBootScriptWidthFifoUint8,
# EfiBootScriptWidthFifoUint16,
# EfiBootScriptWidthFifoUint32,
# EfiBootScriptWidthFifoUint64,
# EfiBootScriptWidthFillUint8,
# EfiBootScriptWidthFillUint16,
# EfiBootScriptWidthFillUint32,
# EfiBootScriptWidthFillUint64,
# EfiBootScriptWidthMaximum
# } EFI_BOOT_SCRIPT_WIDTH;

class S3BootScriptWidth:
    EFI_BOOT_SCRIPT_WIDTH_UINT8 = 0x00
    EFI_BOOT_SCRIPT_WIDTH_UINT16 = 0x01
    EFI_BOOT_SCRIPT_WIDTH_UINT32 = 0x02
    EFI_BOOT_SCRIPT_WIDTH_UINT64 = 0x03


script_width_sizes: Dict[int, int] = {
    S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT8: 1,
    S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT16: 2,
    S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT32: 4,
    S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT64: 8
}

script_width_values: Dict[int, int] = {
    1: S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT8,
    2: S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT16,
    4: S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT32,
    8: S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT64
}

script_width_formats: Dict[int, str] = {
    S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT8: 'B',
    S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT16: 'H',
    S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT32: 'I',
    S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT64: 'Q'
}

# //************************************************
# // EFI_SMBUS_DEVICE_ADDRESS
# //************************************************
# typedef struct _EFI_SMBUS_DEVICE_ADDRESS {
# UINTN SmbusDeviceAddress:7;
# } EFI_SMBUS_DEVICE_ADDRESS;
# //************************************************
# // EFI_SMBUS_DEVICE_COMMAND
# //************************************************
# typedef UINTN EFI_SMBUS_DEVICE_COMMAND;
#
# //************************************************
# // EFI_SMBUS_OPERATION
# //************************************************
# typedef enum _EFI_SMBUS_OPERATION {
# EfiSmbusQuickRead,
# EfiSmbusQuickWrite,
# EfiSmbusReceiveByte,
# EfiSmbusSendByte,
# EfiSmbusReadByte,
# EfiSmbusWriteByte,
# EfiSmbusReadWord,
# EfiSmbusWriteWord,
# EfiSmbusReadBlock,
# EfiSmbusWriteBlock,
# EfiSmbusProcessCall,
# EfiSmbusBWBRProcessCall
# } EFI_SMBUS_OPERATION;


class S3BootScriptSmbusOperation:
    QUICK_READ = 0x00
    QUICK_WRITE = 0x01
    RECEIVE_BYTE = 0x02
    SEND_BYTE = 0x03
    READ_BYTE = 0x04
    WRITE_BYTE = 0x05
    READ_WORD = 0x06
    WRITE_WORD = 0x07
    READ_BLOCK = 0x08
    WRITE_BLOCK = 0x09
    PROCESS_CALL = 0x0A
    BWBR_PROCESS_CALL = 0x0B


class op_io_pci_mem:
    def __init__(self, opcode: int, size: int, width: int, address: int, unknown: Optional[int], count: Optional[int], 
                 buffer: Optional[bytes], value: Optional[int] = None, mask: Optional[int] = None):
        self.opcode = opcode
        self.size = size
        self.width = width
        self.address = address
        self.unknown = unknown
        self.count = count
        self.value = value
        self.mask = mask
        self.name = script_opcodes[opcode]
        self.buffer = buffer  # data[ self.size : ]
        self.values = None
        if self.count is not None and self.count > 0 and self.buffer is not None:
            sz = self.count * script_width_sizes[self.width]
            if len(self.buffer) != sz:
                logger().log(f'[?] buffer size (0x{len(self.buffer):X}) != Width x Count (0x{sz:X})')
            else:
                self.values = list(struct.unpack((f'<{self.count:d}{script_width_formats[self.width]:1}'), self.buffer))

    def __str__(self) -> str:
        str_r = f'  Opcode : {self.name} (0x{self.opcode:04X})\n'
        str_r += f'  Width  : 0x{self.width:02X} ({script_width_sizes[self.width]:X} bytes)\n'
        str_r += f'  Address: 0x{self.address:08X}\n'
        if self.value is not None:
            str_r += f'  Value  : 0x{self.value:08X}\n'
        if self.mask is not None:
            str_r += f'  Mask   : 0x{self.mask:08X}\n'
        if self.unknown is not None:
            str_r += f'  Unknown: 0x{self.unknown:04X}\n'
        if self.count is not None:
            str_r += f'  Count  : 0x{self.count:X}\n'
        if self.values is not None:
            fmt = f'0x{{:0{script_width_sizes[self.width] * 2:d}X}}'
            values_str = '  '.join([fmt.format(v) for v in self.values])
            str_r += f'  Values : {values_str}\n'
        elif self.buffer is not None:
            str_r += f'  Buffer (size = 0x{len(self.buffer):X}):\n{dump_buffer(self.buffer, 16)}'
        return str_r


class op_smbus_execute:
    def __init__(self, opcode: int, size: int, address: int, command: int, operation: int, peccheck: int):
        self.opcode = opcode
        self.size = size
        self.address = address
        self.command = command
        self.operation = operation
        self.peccheck = peccheck
        self.name = script_opcodes[opcode]

    def __str__(self) -> str:
        str_r = f'  Opcode           : {self.name} (0x{self.opcode:04X})\n'
        str_r += f'  Secondary Address: 0x{self.address:02X}\n'
        str_r += f'  Command          : 0x{self.command:08X}\n'
        str_r += f'  Operation        : 0x{self.operation:02X}\n'
        str_r += f'  PEC Check        : {self.peccheck:d}\n'
        return str_r

# typedef struct {
#  UINT16  OpCode;
#  UINT8   Length;
#  UINT64  Duration;
# } EFI_BOOT_SCRIPT_STALL;


class op_stall:
    def __init__(self, opcode: int, size: int, duration: int):
        self.opcode = opcode
        self.size = size
        self.duration = duration
        self.name = script_opcodes[self.opcode]

    def __str__(self) -> str:
        str_r = f'  Opcode  : {self.name} (0x{self.opcode:04X})\n'
        str_r += f'  Duration: 0x{self.duration:08X} (us)\n'
        return str_r

# typedef struct {
#  UINT16                OpCode;
#  UINT8                 Length;
#  EFI_PHYSICAL_ADDRESS  EntryPoint;
# } EFI_BOOT_SCRIPT_DISPATCH;


class op_dispatch:
    def __init__(self, opcode: int, size: int, entrypoint: int, context: Optional[int] = None):
        self.opcode = opcode
        self.size = size
        self.entrypoint = entrypoint
        self.context = context
        self.name = script_opcodes[self.opcode]

    def __str__(self) -> str:
        str_r = f'  Opcode     : {self.name} (0x{self.opcode:04X})\n'
        str_r += f'  Entry Point: 0x{self.entrypoint:016X}\n'
        if self.context is not None:
            str_r += f'  Context    : 0x{self.context:016X}\n'
        return str_r

# typedef struct {
#  UINT16  OpCode;
#  UINT8   Length;
#  UINT32  Width;
#  UINT64  Address;
#  UINT64  Duration;
#  UINT64  LoopTimes;
# } EFI_BOOT_SCRIPT_MEM_POLL;


class op_mem_poll:
    def __init__(self, opcode: int, size: int, width: int, address: int, duration: int, looptimes: int):
        self.opcode = opcode
        self.size = size
        self.width = width
        self.address = address
        self.duration = duration
        self.looptimes = looptimes
        self.name = 'S3_BOOTSCRIPT_MEM_POLL'

    def __str__(self) -> str:
        str_r = f'  Opcode    : {self.name} (0x{self.opcode:04X})\n'
        str_r += f'  Width     : 0x{self.width:02X} ({script_width_sizes[self.width]:X} bytes)\n'
        str_r += f'  Address   : 0x{self.address:016X}\n'
        str_r += f'  Duration? : 0x{self.duration:016X}\n'
        str_r += f'  LoopTimes?: 0x{self.looptimes:016X}\n'
        return str_r


class op_terminate:
    def __init__(self, opcode: int, size: int):
        self.opcode = opcode
        self.size = size
        self.name = script_opcodes[self.opcode]

    def __str__(self) -> str:
        return f'  Opcode     : {self.name} (0x{self.opcode:02X})\n'


class op_unknown:
    def __init__(self, opcode: int, size: int):
        self.opcode = opcode
        self.size = size

    def __str__(self) -> str:
        return f'  Opcode     : unknown (0x{self.opcode:02X})\n'


class S3BOOTSCRIPT_ENTRY:
    def __init__(self, script_type: int, index: Optional[int], offset_in_script: int, length: int, data: Optional[bytes] = None):
        self.script_type = script_type
        self.index = index
        self.offset_in_script = offset_in_script
        self.length = length
        self.data = data
        self.decoded_opcode = None
        self.header_length = 0

    def __str__(self) -> str:
        entry_str = '' if self.index is None else (f'[{self.index:03d}] ')
        entry_str += f'Entry at offset 0x{self.offset_in_script:04X} (len = 0x{self.length:X}, header len = 0x{self.header_length:X}):'
        if self.data:
            entry_str = entry_str + f'\nData:\n{dump_buffer_bytes(self.data, 16)}'
        if self.decoded_opcode:
            entry_str = entry_str + f'Decoded:\n{str(self.decoded_opcode)}'
        return entry_str


# #################################################################################################
#
# UEFI Table Parsing Functionality
#
# #################################################################################################
MAX_EFI_TABLE_SIZE = 0x1000

# typedef struct {
#   UINT64  Signature;
#   UINT32  Revision;
#   UINT32  HeaderSize;
#   UINT32  CRC32;
#   UINT32  Reserved;
# } EFI_TABLE_HEADER;

EFI_TABLE_HEADER_FMT = '=8sIIII'
EFI_TABLE_HEADER_SIZE = 0x18


class EFI_TABLE_HEADER(namedtuple('EFI_TABLE_HEADER', 'Signature Revision HeaderSize CRC32 Reserved')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""Header:
  Signature     : {bytestostring(self.Signature)}
  Revision      : {EFI_SYSTEM_TABLE_REVISION(self.Revision)}
  HeaderSize    : 0x{self.HeaderSize:08X}
  CRC32         : 0x{self.CRC32:08X}
  Reserved      : 0x{self.Reserved:08X}"""


# #################################################################################################
# EFI System Table
# #################################################################################################
#
# \MdePkg\Include\Uefi\UefiSpec.h

EFI_SYSTEM_TABLE_SIGNATURE = 'IBI SYST'

EFI_2_80_SYSTEM_TABLE_REVISION = ((2 << 16) | (80))
EFI_2_70_SYSTEM_TABLE_REVISION = ((2 << 16) | (70))
EFI_2_60_SYSTEM_TABLE_REVISION = ((2 << 16) | (60))
EFI_2_50_SYSTEM_TABLE_REVISION = ((2 << 16) | (50))
EFI_2_40_SYSTEM_TABLE_REVISION = ((2 << 16) | (40))
EFI_2_31_SYSTEM_TABLE_REVISION = ((2 << 16) | (31))
EFI_2_30_SYSTEM_TABLE_REVISION = ((2 << 16) | (30))
EFI_2_20_SYSTEM_TABLE_REVISION = ((2 << 16) | (20))
EFI_2_10_SYSTEM_TABLE_REVISION = ((2 << 16) | (10))
EFI_2_00_SYSTEM_TABLE_REVISION = ((2 << 16) | (00))
EFI_1_10_SYSTEM_TABLE_REVISION = ((1 << 16) | (10))
EFI_1_02_SYSTEM_TABLE_REVISION = ((1 << 16) | (0o2))
EFI_REVISIONS: List[int] = [
    EFI_2_80_SYSTEM_TABLE_REVISION,
    EFI_2_70_SYSTEM_TABLE_REVISION, 
    EFI_2_60_SYSTEM_TABLE_REVISION, 
    EFI_2_50_SYSTEM_TABLE_REVISION, 
    EFI_2_40_SYSTEM_TABLE_REVISION, 
    EFI_2_31_SYSTEM_TABLE_REVISION,
    EFI_2_30_SYSTEM_TABLE_REVISION, 
    EFI_2_20_SYSTEM_TABLE_REVISION, 
    EFI_2_10_SYSTEM_TABLE_REVISION, 
    EFI_2_00_SYSTEM_TABLE_REVISION, 
    EFI_1_10_SYSTEM_TABLE_REVISION, 
    EFI_1_02_SYSTEM_TABLE_REVISION
    ]


def EFI_SYSTEM_TABLE_REVISION(revision: int) -> str:
    return f'{revision >> 16:d}.{revision & 0xFFFF:d}'


EFI_SYSTEM_TABLE_FMT = '=12Q'


class EFI_SYSTEM_TABLE(namedtuple('EFI_SYSTEM_TABLE', 'FirmwareVendor FirmwareRevision ConsoleInHandle ConIn ConsoleOutHandle ConOut StandardErrorHandle StdErr RuntimeServices BootServices NumberOfTableEntries ConfigurationTable')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""EFI System Table:
  FirmwareVendor      : 0x{self.FirmwareVendor:016X}
  FirmwareRevision    : 0x{self.FirmwareRevision:016X}
  ConsoleInHandle     : 0x{self.ConsoleInHandle:016X}
  ConIn               : 0x{self.ConIn:016X}
  ConsoleOutHandle    : 0x{self.ConsoleOutHandle:016X}
  ConOut              : 0x{self.ConOut:016X}
  StandardErrorHandle : 0x{self.StandardErrorHandle:016X}
  StdErr              : 0x{self.StdErr:016X}
  RuntimeServices     : 0x{self.RuntimeServices:016X}
  BootServices        : 0x{self.BootServices:016X}
  NumberOfTableEntries: 0x{self.NumberOfTableEntries:016X}
  ConfigurationTable  : 0x{self.ConfigurationTable:016X}
"""


# #################################################################################################
# EFI Runtime Services Table
# #################################################################################################
#
# \MdePkg\Include\Uefi\UefiSpec.h

EFI_RUNTIME_SERVICES_SIGNATURE = 'RUNTSERV'
EFI_RUNTIME_SERVICES_REVISION = EFI_2_31_SYSTEM_TABLE_REVISION

EFI_RUNTIME_SERVICES_TABLE_FMT = '=14Q'


class EFI_RUNTIME_SERVICES_TABLE(namedtuple('EFI_RUNTIME_SERVICES_TABLE', 'GetTime SetTime GetWakeupTime SetWakeupTime SetVirtualAddressMap ConvertPointer GetVariable GetNextVariableName SetVariable GetNextHighMonotonicCount ResetSystem UpdateCapsule QueryCapsuleCapabilities QueryVariableInfo')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""Runtime Services:
  GetTime                  : 0x{self.GetTime:016X}
  SetTime                  : 0x{self.SetTime:016X}
  GetWakeupTime            : 0x{self.GetWakeupTime:016X}
  SetWakeupTime            : 0x{self.SetWakeupTime:016X}
  SetVirtualAddressMap     : 0x{self.SetVirtualAddressMap:016X}
  ConvertPointer           : 0x{self.ConvertPointer:016X}
  GetVariable              : 0x{self.GetVariable:016X}
  GetNextVariableName      : 0x{self.GetNextVariableName:016X}
  SetVariable              : 0x{self.SetVariable:016X}
  GetNextHighMonotonicCount: 0x{self.GetNextHighMonotonicCount:016X}
  ResetSystem              : 0x{self.ResetSystem:016X}
  UpdateCapsule            : 0x{self.UpdateCapsule:016X}
  QueryCapsuleCapabilities : 0x{self.QueryCapsuleCapabilities:016X}
  QueryVariableInfo        : 0x{self.QueryVariableInfo:016X}
"""


# #################################################################################################
# EFI Boot Services Table
# #################################################################################################
#
# \MdePkg\Include\Uefi\UefiSpec.h

EFI_BOOT_SERVICES_SIGNATURE = 'BOOTSERV'
EFI_BOOT_SERVICES_REVISION = EFI_2_31_SYSTEM_TABLE_REVISION

EFI_BOOT_SERVICES_TABLE_FMT = '=44Q'


class EFI_BOOT_SERVICES_TABLE(namedtuple('EFI_BOOT_SERVICES_TABLE', 'RaiseTPL RestoreTPL AllocatePages FreePages GetMemoryMap AllocatePool FreePool CreateEvent SetTimer WaitForEvent SignalEvent CloseEvent CheckEvent InstallProtocolInterface ReinstallProtocolInterface UninstallProtocolInterface HandleProtocol Reserved RegisterProtocolNotify LocateHandle LocateDevicePath InstallConfigurationTable LoadImage StartImage Exit UnloadImage ExitBootServices GetNextMonotonicCount Stall SetWatchdogTimer ConnectController DisconnectController OpenProtocol CloseProtocol OpenProtocolInformation ProtocolsPerHandle LocateHandleBuffer LocateProtocol InstallMultipleProtocolInterfaces UninstallMultipleProtocolInterfaces CalculateCrc32 CopyMem SetMem CreateEventEx')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""Boot Services:
  RaiseTPL                           : 0x{self.RaiseTPL:016X}
  RestoreTPL                         : 0x{self.RestoreTPL:016X}
  AllocatePages                      : 0x{self.AllocatePages:016X}
  FreePages                          : 0x{self.FreePages:016X}
  GetMemoryMap                       : 0x{self.GetMemoryMap:016X}
  AllocatePool                       : 0x{self.AllocatePool:016X}
  FreePool                           : 0x{self.FreePool:016X}
  CreateEvent                        : 0x{self.CreateEvent:016X}
  SetTimer                           : 0x{self.SetTimer:016X}
  WaitForEvent                       : 0x{self.WaitForEvent:016X}
  SignalEvent                        : 0x{self.SignalEvent:016X}
  CloseEvent                         : 0x{self.CloseEvent:016X}
  CheckEvent                         : 0x{self.CheckEvent:016X}
  InstallProtocolInterface           : 0x{self.InstallProtocolInterface:016X}
  ReinstallProtocolInterface         : 0x{self.ReinstallProtocolInterface:016X}
  UninstallProtocolInterface         : 0x{self.UninstallProtocolInterface:016X}
  HandleProtocol                     : 0x{self.HandleProtocol:016X}
  Reserved                           : 0x{self.Reserved:016X}
  RegisterProtocolNotify             : 0x{self.RegisterProtocolNotify:016X}
  LocateHandle                       : 0x{self.LocateHandle:016X}
  LocateDevicePath                   : 0x{self.LocateDevicePath:016X}
  InstallConfigurationTable          : 0x{self.InstallConfigurationTable:016X}
  LoadImage                          : 0x{self.LoadImage:016X}
  StartImage                         : 0x{self.StartImage:016X}
  Exit                               : 0x{self.Exit:016X}
  UnloadImage                        : 0x{self.UnloadImage:016X}
  ExitBootServices                   : 0x{self.ExitBootServices:016X}
  GetNextMonotonicCount              : 0x{self.GetNextMonotonicCount:016X}
  Stall                              : 0x{self.Stall:016X}
  SetWatchdogTimer                   : 0x{self.SetWatchdogTimer:016X}
  ConnectController                  : 0x{self.ConnectController:016X}
  DisconnectController               : 0x{self.DisconnectController:016X}
  OpenProtocol                       : 0x{self.OpenProtocol:016X}
  CloseProtocol                      : 0x{self.CloseProtocol:016X}
  OpenProtocolInformation            : 0x{self.OpenProtocolInformation:016X}
  ProtocolsPerHandle                 : 0x{self.ProtocolsPerHandle:016X}
  LocateHandleBuffer                 : 0x{self.LocateHandleBuffer:016X}
  LocateProtocol                     : 0x{self.LocateProtocol:016X}
  InstallMultipleProtocolInterfaces  : 0x{self.InstallMultipleProtocolInterfaces:016X}
  UninstallMultipleProtocolInterfaces: 0x{self.UninstallMultipleProtocolInterfaces:016X}
  CalculateCrc32                     : 0x{self.CalculateCrc32:016X}
  CopyMem                            : 0x{self.CopyMem:016X}
  SetMem                             : 0x{self.SetMem:016X}
  CreateEventEx                      : 0x{self.CreateEventEx:016X}
"""


# #################################################################################################
# EFI System Configuration Table
# #################################################################################################
#
# \MdePkg\Include\Uefi\UefiSpec.h
# -------------------------------

EFI_VENDOR_TABLE_FORMAT = '<' + EFI_GUID_FMT + 'Q'
EFI_VENDOR_TABLE_SIZE = struct.calcsize(EFI_VENDOR_TABLE_FORMAT)


class EFI_VENDOR_TABLE(namedtuple('EFI_VENDOR_TABLE', 'VendorGuidData VendorTable')):
    __slots__ = ()

    def VendorGuid(self) -> str:
        return EFI_GUID_STR(self.VendorGuidData)


class EFI_CONFIGURATION_TABLE:
    def __init__(self):
        self.VendorTables = {}

    def __str__(self) -> str:
        vendor_table_str = ''.join([f'{{{vt}}} : 0x{self.VendorTables[vt]:016X}\n' for vt in self.VendorTables])
        return f'Vendor Tables:\n{vendor_table_str}'


# #################################################################################################
# EFI DXE Services Table
# #################################################################################################
#
# \MdePkg\Include\Pi\PiDxeCis.h
# -----------------------------
#
EFI_DXE_SERVICES_TABLE_SIGNATURE = 'DXE_SERV'  # 0x565245535f455844
EFI_DXE_SERVICES_TABLE_FMT = '=17Q'


class EFI_DXE_SERVICES_TABLE(namedtuple('EFI_DXE_SERVICES_TABLE', 'AddMemorySpace AllocateMemorySpace FreeMemorySpace RemoveMemorySpace GetMemorySpaceDescriptor SetMemorySpaceAttributes GetMemorySpaceMap AddIoSpace AllocateIoSpace FreeIoSpace RemoveIoSpace GetIoSpaceDescriptor GetIoSpaceMap Dispatch Schedule Trust ProcessFirmwareVolume')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""DXE Services:
  AddMemorySpace          : 0x{self.AddMemorySpace:016X}
  AllocateMemorySpace     : 0x{self.AllocateMemorySpace:016X}
  FreeMemorySpace         : 0x{self.FreeMemorySpace:016X}
  RemoveMemorySpace       : 0x{self.RemoveMemorySpace:016X}
  GetMemorySpaceDescriptor: 0x{self.GetMemorySpaceDescriptor:016X}
  SetMemorySpaceAttributes: 0x{self.SetMemorySpaceAttributes:016X}
  GetMemorySpaceMap       : 0x{self.GetMemorySpaceMap:016X}
  AddIoSpace              : 0x{self.AddIoSpace:016X}
  AllocateIoSpace         : 0x{self.AllocateIoSpace:016X}
  FreeIoSpace             : 0x{self.FreeIoSpace:016X}
  RemoveIoSpace           : 0x{self.RemoveIoSpace:016X}
  GetIoSpaceDescriptor    : 0x{self.GetIoSpaceDescriptor:016X}
  GetIoSpaceMap           : 0x{self.GetIoSpaceMap:016X}
  Dispatch                : 0x{self.Dispatch:016X}
  Schedule                : 0x{self.Schedule:016X}
  Trust                   : 0x{self.Trust:016X}
  ProcessFirmwareVolume   : 0x{self.ProcessFirmwareVolume:016X}
"""


# #################################################################################################
# EFI PEI Services Table
# #################################################################################################
EFI_FRAMEWORK_PEI_SERVICES_TABLE_SIGNATURE = 0x5652455320494550
FRAMEWORK_PEI_SPECIFICATION_MAJOR_REVISION = 0
FRAMEWORK_PEI_SPECIFICATION_MINOR_REVISION = 91
FRAMEWORK_PEI_SERVICES_REVISION = ((FRAMEWORK_PEI_SPECIFICATION_MAJOR_REVISION << 16) | (FRAMEWORK_PEI_SPECIFICATION_MINOR_REVISION))

# #################################################################################################
# EFI System Management System Table
# #################################################################################################

EFI_SMM_SYSTEM_TABLE_SIGNATURE = 'SMST'
EFI_SMM_SYSTEM_TABLE_REVISION = (0 << 16) | (0x09)


EFI_TABLES: Dict[str, Dict[str, Any]] = {
    EFI_SYSTEM_TABLE_SIGNATURE: {'name': 'EFI System Table', 'struct': EFI_SYSTEM_TABLE, 'fmt': EFI_SYSTEM_TABLE_FMT},
    EFI_RUNTIME_SERVICES_SIGNATURE: {'name': 'EFI Runtime Services Table', 'struct': EFI_RUNTIME_SERVICES_TABLE, 'fmt': EFI_RUNTIME_SERVICES_TABLE_FMT},
    EFI_BOOT_SERVICES_SIGNATURE: {'name': 'EFI Boot Services Table', 'struct': EFI_BOOT_SERVICES_TABLE, 'fmt': EFI_BOOT_SERVICES_TABLE_FMT},
    EFI_DXE_SERVICES_TABLE_SIGNATURE: {'name': 'EFI DXE Services Table', 'struct': EFI_DXE_SERVICES_TABLE, 'fmt': EFI_DXE_SERVICES_TABLE_FMT}
    # EFI_FRAMEWORK_PEI_SERVICES_TABLE_SIGNATURE : {'name' : 'EFI Framework PEI Services Table', 'struct' : EFI_FRAMEWORK_PEI_SERVICES_TABLE, 'fmt' : EFI_FRAMEWORK_PEI_SERVICES_TABLE_FMT },
    # EFI_SMM_SYSTEM_TABLE_SIGNATURE             : {'name' : 'EFI SMM System Table',             'struct' : EFI_SMM_SYSTEM_TABLE,             'fmt' : EFI_SMM_SYSTEM_TABLE_FMT             },
    # EFI_CONFIG_TABLE_SIGNATURE                 : {'name' : 'EFI Configuration Table',          'struct' : EFI_CONFIG_TABLE,                 'fmt' : EFI_CONFIG_TABLE_FMT                 }
}
