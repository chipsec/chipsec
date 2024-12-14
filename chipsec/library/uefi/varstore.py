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

import codecs
import os
import struct
from collections import namedtuple
from collections.abc import Callable
from uuid import UUID
from typing import Dict, Tuple, List, Optional, Any, Union

from chipsec.library import defines
from chipsec.library.file import read_file, write_file
from chipsec.library.logger import logger
from chipsec.library.types import EfiVariableType
from chipsec.library.uefi.uefi_common import EFI_GUID_FMT, EFI_GUID_SIZE, EFI_GUID_STR, bit_set
from chipsec.library.uefi.uefi_platform import FWType, NVAR_NVRAM_FS_FILE, NVRAM_ATTR_VLD, NVRAM_ATTR_DATA, NVRAM_ATTR_GUID, NVRAM_ATTR_DESC_ASCII, NVRAM_ATTR_EXTHDR, NVRAM_ATTR_RT
from chipsec.library.uefi.uefi_platform import NVRAM_ATTR_HER, NVRAM_ATTR_AUTHWR, get_3b_size, ADDITIONAL_NV_STORE_GUID
from chipsec.library.uefi.uefi_fv import NextFwVolume, NextFwFile, EFI_FVB2_ERASE_POLARITY, EFI_FV_FILETYPE_RAW
from chipsec.library.uefi.variables import EFI_VARIABLE_BOOTSERVICE_ACCESS, EFI_VARIABLE_NON_VOLATILE, EFI_VARIABLE_RUNTIME_ACCESS, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS
from chipsec.library.uefi.variables import EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, EFI_VARIABLE_HARDWARE_ERROR_RECORD, IS_VARIABLE_ATTRIBUTE, print_sorted_EFI_variables
from chipsec.library.uefi.variables import get_attr_string, SECURE_BOOT_KEY_VARIABLES, EFI_VAR_NAME_AuthVarKeyDatabase, EFI_VAR_NAME_certdb
from chipsec.library.uefi.uefi_platform import fw_types

################################################################################################
#
# EFI Variable and Variable Store Defines
#
################################################################################################

# edk2\MdeModulePkg\Include\Guid\VariableFormat.h
#
# Variable data start flag.
#
VARIABLE_DATA = 0x55aa
VARIABLE_DATA_SIGNATURE = struct.pack('=H', VARIABLE_DATA)


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


#
# This Variable header is defined by UEFI
#

#
# Variable Store Status
#
# typedef enum {
#  EfiRaw,
#  EfiValid,
#  EfiInvalid,
#  EfiUnknown
# } VARIABLE_STORE_STATUS;
VARIABLE_STORE_STATUS_RAW = 0
VARIABLE_STORE_STATUS_VALID = 1
VARIABLE_STORE_STATUS_INVALID = 2
VARIABLE_STORE_STATUS_UNKNOWN = 3


#
# typedef struct {
#  UINT16    StartId;
#  UINT8     State;
#  UINT8     Reserved;
#  UINT32    Attributes;
#  UINT32    NameSize;
#  UINT32    DataSize;
#  EFI_GUID  VendorGuid;
# } VARIABLE_HEADER;
#
# typedef struct {
#  UINT32  Data1;
#  UINT16  Data2;
#  UINT16  Data3;
#  UINT8   Data4[8];
# } EFI_GUID;
#
UEFI_VARIABLE_HEADER_SIZE = 28


class UEFI_VARIABLE_HEADER(namedtuple('UEFI_VARIABLE_HEADER', 'StartId State Reserved Attributes NameSize DataSize VendorGuid0 VendorGuid1 VendorGuid2 VendorGuid3')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
Header (UEFI)
-------------
StartId    : 0x{self.StartId:04X}
State      : 0x{self.State:02X}
Reserved   : 0x{self.Reserved:02X}
Attributes : 0x{self.Attributes:08X}
NameSize   : 0x{self.NameSize:08X}
DataSize   : 0x{self.DataSize:08X}
VendorGuid : {{0x{self.VendorGuid0:08X}-0x{self.VendorGuid1:04X}-0x{self.VendorGuid2:04X}-0x{self.VendorGuid3:08X}}}
"""


UEFI_VARIABLE_STORE_HEADER = "<16sIBBHI"
UEFI_VARIABLE_STORE_HEADER_SIZE = struct.calcsize(UEFI_VARIABLE_STORE_HEADER)
'''
EFI_VARIABLE_HEADER_AUTH = "<HBBI28sIIIHH8s"
EFI_VARIABLE_HEADER_AUTH_SIZE = struct.calcsize(EFI_VARIABLE_HEADER_AUTH)

EFI_VARIABLE_HEADER = "<HBBIIIIHH8s"
EFI_VARIABLE_HEADER_SIZE = struct.calcsize(EFI_VARIABLE_HEADER)
'''
VARIABLE_STORE_FORMATTED = 0x5a
VARIABLE_STORE_HEALTHY = 0xfe

NvStore = Tuple[int, int, None]


def _getNVstore_EFI(nvram_buf: bytes, efi_type: str) -> NvStore:
    nv_store = (-1, -1, None)
    FvOffset = 0
    FvLength = 0
    fv = NextFwVolume(nvram_buf, FvOffset, FvLength)
    while True:
        if (fv is None):
            break
        if (fv.Guid == VARIABLE_STORE_FV_GUID):
            nvram_start = fv.HeaderSize
            _, _, Format, State, _, _ = struct.unpack(UEFI_VARIABLE_STORE_HEADER, fv.Image[nvram_start:nvram_start + UEFI_VARIABLE_STORE_HEADER_SIZE])
            if ((Format == VARIABLE_STORE_FORMATTED) and (State == VARIABLE_STORE_HEALTHY)):
                if (isCorrectVSStype(fv.Image[nvram_start:], efi_type)):
                    nv_store = (fv.Offset + nvram_start, fv.Size - nvram_start, None)
                break
        fv = NextFwVolume(nvram_buf, fv.Offset, fv.Size)
    return nv_store


def getNVstore_EFI(nvram_buf: bytes) -> NvStore:
    return _getNVstore_EFI(nvram_buf, FWType.EFI_FW_TYPE_VSS)


def getNVstore_EFI_AUTH(nvram_buf: bytes) -> NvStore:
    return _getNVstore_EFI(nvram_buf, FWType.EFI_FW_TYPE_VSS_AUTH)


def getEFIvariables_UEFI(nvram_buf: bytes) -> Dict[str, List[EfiVariableType]]:
    return _getEFIvariables_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS)


def getEFIvariables_UEFI_AUTH(nvram_buf: bytes) -> Dict[str, List[EfiVariableType]]:
    return _getEFIvariables_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS_AUTH)


'''
def getEFIvariables_UEFI_Ex( nvram_buf, auth = False ):
    dof = 0
    length = len(nvram_buf)
    storen = 0
    variables = dict()
    while ((dof+UEFI_VARIABLE_STORE_HEADER_SIZE) < length):
        store_start = dof
        StoreGuid0, StoreGuid1, StoreGuid2, StoreGuid03, Size, Format, State, R0, R1 = \
            struct.unpack(UEFI_VARIABLE_STORE_HEADER, nvram_buf[dof:dof + UEFI_VARIABLE_STORE_HEADER_SIZE])
        dof = align(dof + UEFI_VARIABLE_STORE_HEADER_SIZE, 4)
        if ((Format != VARIABLE_STORE_FORMATTED) or (State != VARIABLE_STORE_HEALTHY)):
            break
        if ((store_start + Size) >= length): break
        while ((dof + EFI_VARIABLE_HEADER_SIZE) <= (store_start + Size)):
            StartId, State, R0, Attributes, Auth, NameSize, DataSize, VendorGuid0, VendorGuid1, VendorGuid2, VendorGuid3 = \
                struct.unpack(EFI_VARIABLE_HEADER, nvram_buf[dof:dof+EFI_VARIABLE_HEADER_SIZE]);
            if (StartId != VARIABLE_DATA): break
            dof += EFI_VARIABLE_HEADER_SIZE
            if ((State == 0xff) and (DataSize == 0xffffffff) and (NameSize == 0xffffffff) and (Attributes == 0xffffffff)):
                NameSize = 0
                DataSize = 0
                # just skip variable with empty name and data for now
            else:
                guid = guid_str(VendorGuid0, VendorGuid1, VendorGuid2, VendorGuid3)
                Name = nvram_buf[dof:dof+NameSize]
                NameStr = unicode(Name, "utf-16-le").split('\x00')[0]
                VarData = nvram_buf[dof+NameSize:dof+NameSize+DataSize]
                if NameStr not in variables.keys():
                    variables[NameStr] = []
                #                          off, buf,  hdr,  data,    guid, attrs
                variables[NameStr].append((dof, None, None, VarData, guid, Attributes))
            dof = align(dof+NameSize+DataSize, 4)
        dof = store_start + Size
        storen += 1
    return variables
'''
##################################################################################################
#
# Platform/Vendor Specific EFI NVRAM Parsing Functions
#
# For each platform, EFI NVRAM parsing functionality includes:
# 1. Function to parse EFI variable within NVRAM binary (func_getefivariables)
#    May define/use platform specific EFI Variable Header
#    Function arguments:
#      In : binary buffer (as a string)
#      Out:
#        start           - offset in the buffer to the current EFI variable
#        next_var_offset - offset in the buffer to the next EFI variable
#        efi_var_buf     - full EFI variable buffer
#        efi_var_hdr     - EFI variable header object
#        efi_var_name    - EFI variable name
#        efi_var_data    - EFI variable data contents
#        efi_var_guid    - EFI variable GUID
#        efi_var_attr    - EFI variable attributes
# 2. [Optional] Function to find EFI NVRAM within arbitrary binary (func_getnvstore)
#    If this function is not defined, 'chipsec_util uefi' searches EFI variables from the beginning of the binary
#    Function arguments:
#      In : NVRAM binary buffer (as a string)
#      Out:
#        start        - offset of NVRAM     (-1 means NVRAM not found)
#        size         - size of NVRAM       (-1 means NVRAM is entire binary)
#        nvram_header - NVRAM header object
#
##################################################################################################

##################################################################################################
# NVAR format of NVRAM
#


class EFI_HDR_NVAR1(namedtuple('EFI_HDR_NVAR1', 'StartId TotalSize Reserved1 Reserved2 Reserved3 Attributes State')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
Header (NVAR)
------------
StartId    : 0x{self.StartId:04X}
TotalSize  : 0x{self.TotalSize:04X}
Reserved1  : 0x{self.Reserved1:02X}
Reserved2  : 0x{self.Reserved2:02X}
Reserved3  : 0x{self.Reserved3:02X}
Attributes : 0x{self.Attributes:02X}
State      : 0x{self.State:02X}
"""


NVAR_EFIvar_signature = b'NVAR'


def getNVstore_NVAR(nvram_buf: bytes) -> NvStore:
    nv_store = (-1, -1, None)
    fv = NextFwVolume(nvram_buf)
    if (fv is None):
        return nv_store
    if (fv.Offset >= len(nvram_buf)):
        return nv_store
    if (fv.Offset + fv.Size) > len(nvram_buf):
        fv.Size = len(nvram_buf) - fv.Offset
    while fv is not None:
        polarity = bit_set(fv.Attributes, EFI_FVB2_ERASE_POLARITY)
        fwbin = NextFwFile(fv.Image, fv.Size, fv.HeaderSize, polarity)
        while fwbin is not None:
            if (fwbin.Type == EFI_FV_FILETYPE_RAW) and (fwbin.Guid == NVAR_NVRAM_FS_FILE):
                nv_store = ((fv.Offset + fwbin.Offset + fwbin.HeaderSize), fwbin.Size - fwbin.HeaderSize, None)
                if (not fwbin.UD):
                    return nv_store
            fwbin = NextFwFile(fv.Image, fv.Size, fwbin.Size + fwbin.Offset, polarity)
        fv = NextFwVolume(nvram_buf, fv.Offset, fv.Size)
    return nv_store


def _ord(c: Union[str, int]) -> int:
    return ord(c) if isinstance(c, str) else c


def getEFIvariables_NVAR(nvram_buf: bytes) -> Dict[str, List[EfiVariableType]]:
    name = ''
    nvram_size = len(nvram_buf)
    EFI_HDR_NVAR = "<4sH3sB"
    nvar_size = struct.calcsize(EFI_HDR_NVAR)
    variables = dict()
    nof = 0  # start
    EMPTY = 0xffffffff
    while (nof + nvar_size) < nvram_size:
        start_id, size, next, attributes = struct.unpack(EFI_HDR_NVAR, nvram_buf[nof:nof + nvar_size])
        if size == 0:
            break
        next = get_3b_size(next)
        valid = (bit_set(attributes, NVRAM_ATTR_VLD) and (not bit_set(attributes, NVRAM_ATTR_DATA)))
        if not valid:
            nof = nof + size
            continue
        isvar = (start_id == NVAR_EFIvar_signature)
        if (not isvar) or (size == (EMPTY & 0xffff)):
            break
        var_name_off = 1
        if bit_set(attributes, NVRAM_ATTR_GUID):
            guid = UUID(bytes_le=nvram_buf[nof + nvar_size: nof + nvar_size + EFI_GUID_SIZE])
            guid = str(guid).upper()
            var_name_off = EFI_GUID_SIZE
        else:
            guid_idx = _ord(nvram_buf[nof + nvar_size])
            guid_off = (nvram_size - EFI_GUID_SIZE) - guid_idx * EFI_GUID_SIZE
            guid = UUID(bytes_le=nvram_buf[guid_off: guid_off + EFI_GUID_SIZE])
            guid = str(guid).upper()
        name_size = 0
        name_offset = nof + nvar_size + var_name_off
        if not bit_set(attributes, NVRAM_ATTR_DATA):
            name, name_size = get_nvar_name(nvram_buf, name_offset, bit_set(attributes, NVRAM_ATTR_DESC_ASCII))
        esize = 0
        eattrs = 0
        if bit_set(attributes, NVRAM_ATTR_EXTHDR):
            esize, = struct.unpack("<H", nvram_buf[nof + size - 2:nof + size])
            eattrs = _ord(nvram_buf[nof + size - esize])
        attribs = EFI_VARIABLE_BOOTSERVICE_ACCESS
        attribs = attribs | EFI_VARIABLE_NON_VOLATILE
        if bit_set(attributes, NVRAM_ATTR_RT):
            attribs = attribs | EFI_VARIABLE_RUNTIME_ACCESS
        if bit_set(attributes, NVRAM_ATTR_HER):
            attribs = attribs | EFI_VARIABLE_HARDWARE_ERROR_RECORD
        if bit_set(attributes, NVRAM_ATTR_AUTHWR):
            if bit_set(eattrs, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS):
                attribs = attribs | EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS
            if bit_set(eattrs, EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS):
                attribs = attribs | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
        # Get variable data
        lof = nof
        lnext = next
        lattributes = attributes
        lsize = size
        lesize = esize
        while lnext != (0xFFFFFF & EMPTY):
            lof = lof + lnext
            lstart_id, lsize, lnext, lattributes = struct.unpack(EFI_HDR_NVAR, nvram_buf[lof:lof + nvar_size])
            lnext = get_3b_size(lnext)
        dataof = lof + nvar_size
        if not bit_set(lattributes, NVRAM_ATTR_DATA):
            lnameof = 1
            if bit_set(lattributes, NVRAM_ATTR_GUID):
                lnameof = EFI_GUID_SIZE
            name_offset = lof + nvar_size + lnameof
            name, name_size = get_nvar_name(nvram_buf, name_offset, bit_set(attributes, NVRAM_ATTR_DESC_ASCII))
            dataof = name_offset + name_size
        if bit_set(lattributes, NVRAM_ATTR_EXTHDR):
            lesize, = struct.unpack("<H", nvram_buf[lof + lsize - 2:lof + lsize])
        data = nvram_buf[dataof:lof + lsize - lesize]
        if name not in variables.keys():
            variables[name] = []
        #                       off, buf,  hdr,  data, guid, attrs
        variables[name].append((nof, b'', None, data, guid, attribs))
        nof = nof + size
    return variables


NVAR_HDR_FMT = '=IHBBBBB'
NVAR_HDR_SIZE = struct.calcsize(NVAR_HDR_FMT)


#
# Linear/simple NVAR format parsing
#
def getNVstore_NVAR_simple(nvram_buf: bytes) -> Tuple[Optional[int], int, None]:
    return (nvram_buf.find(NVAR_EFIvar_signature), -1, None)


def getEFIvariables_NVAR_simple(nvram_buf: bytes) -> Dict[str, Tuple[int, bytes, bytes, int, str, int]]:
    nvsize = len(nvram_buf)
    hdr_fmt = NVAR_HDR_FMT
    hdr_size = struct.calcsize(hdr_fmt)
    variables = dict()
    start = nvram_buf.find(NVAR_EFIvar_signature)
    if -1 == start:
        return variables

    while (start + hdr_size) < nvsize:
        efi_var_hdr = EFI_HDR_NVAR1(*struct.unpack_from(hdr_fmt, nvram_buf[start:]))
        name_size = 0
        efi_var_name = "NA"
        if not IS_VARIABLE_ATTRIBUTE(efi_var_hdr.Attributes, EFI_VARIABLE_HARDWARE_ERROR_RECORD):
            name_size = nvram_buf[start + hdr_size:].find(b'\x00')
            efi_var_name = nvram_buf[start + hdr_size: start + hdr_size + name_size].decode('latin1')

        next_var_offset = start + efi_var_hdr.TotalSize
        efi_var_buf = nvram_buf[start: next_var_offset]
        efi_var_data = nvram_buf[start + hdr_size + name_size: next_var_offset]

        if efi_var_name not in variables.keys():
            variables[efi_var_name] = []
        #                               off,   buf,         hdr,         data,         guid, attrs
        variables[efi_var_name].append((start, efi_var_buf, efi_var_hdr, efi_var_data, '', efi_var_hdr.Attributes))

        if start >= next_var_offset:
            break
        start = next_var_offset

    return variables


#######################################################################
#
# VSS NVRAM (signature = '$VSS')
#
#

# define VARIABLE_STORE_SIGNATURE  EFI_SIGNATURE_32 ('$', 'V', 'S', 'S')
VARIABLE_STORE_SIGNATURE_VSS = b'$VSS'
VARIABLE_STORE_HEADER_FMT_VSS = '=IIBBHI'  # Signature is '$VSS'


class VARIABLE_STORE_HEADER_VSS(namedtuple('VARIABLE_STORE_HEADER_VSS', 'Signature Size Format State Reserved Reserved1')):
    __slots__ = ()

    def __str__(self) -> str:
        sig_str = struct.pack('=I', self.Signature)
        return f"""
EFI Variable Store
-----------------------------
Signature : {sig_str} (0x{self.Signature:08X})
Size      : 0x{self.Size:08X} bytes
Format    : 0x{self.Format:02X}
State     : 0x{self.State:02X}
Reserved  : 0x{self.Reserved:04X}
Reserved1 : 0x{self.Reserved1:08X}
"""


VARIABLE_STORE_SIGNATURE_VSS2 = UUID('DDCF3617-3275-4164-98B6-FE85707FFE7D').bytes_le
VARIABLE_STORE_SIGNATURE_VSS2_AUTH = UUID('AAF32C78-947B-439A-A180-2E144EC37792').bytes_le

VARIABLE_STORE_HEADER_FMT_VSS2 = '=16sIBBHI'


class VARIABLE_STORE_HEADER_VSS2(namedtuple('VARIABLE_STORE_HEADER_VSS2', 'Signature Size Format State Reserved Reserved1')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
EFI Variable Store
-----------------------------
Signature : {UUID(bytes_le=self.Signature)}
Size      : 0x{self.Size:08X} bytes
Format    : 0x{self.Format:02X}
State     : 0x{self.State:02X}
Reserved  : 0x{self.Reserved:04X}
Reserved1 : 0x{self.Reserved1:08X}
"""


HDR_FMT_VSS = '<HBBIII16s'
# HDR_SIZE_VSS                  = struct.calcsize( HDR_FMT_VSS )
# NAME_OFFSET_IN_VAR_VSS        = HDR_SIZE_VSS


class EFI_HDR_VSS(namedtuple('EFI_HDR_VSS', 'StartId State Reserved Attributes NameSize DataSize guid')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
Header (VSS)
------------
VendorGuid : {{{EFI_GUID_STR(self.guid)}}}
StartId    : 0x{self.StartId:04X}
State      : 0x{self.State:02X}
Reserved   : 0x{self.Reserved:02X}
Attributes : 0x{self.Attributes:08X}
NameSize   : 0x{self.NameSize:08X}
DataSize   : 0x{self.DataSize:08X}
"""


HDR_FMT_VSS_AUTH = '<HBBIQQQIII16s'


class EFI_HDR_VSS_AUTH(namedtuple('EFI_HDR_VSS_AUTH', 'StartId State Reserved Attributes MonotonicCount TimeStamp1 TimeStamp2 PubKeyIndex NameSize DataSize guid')):
    __slots__ = ()
    # if you don't re-define __str__ method, initialize is to None
    # __str__ = None

    def __str__(self) -> str:
        return f"""
Header (VSS_AUTH)
----------------
VendorGuid     : {{{EFI_GUID_STR(self.guid)}}}
StartId        : 0x{self.StartId:04X}
State          : 0x{self.State:02X}
Reserved       : 0x{self.Reserved:02X}
Attributes     : 0x{self.Attributes:08X}
MonotonicCount : 0x{self.MonotonicCount:016X}
TimeStamp1     : 0x{self.TimeStamp1:016X}
TimeStamp2     : 0x{self.TimeStamp2:016X}
PubKeyIndex    : 0x{self.PubKeyIndex:08X}
NameSize       : 0x{self.NameSize:08X}
DataSize       : 0x{self.DataSize:08X}
"""


HDR_FMT_VSS_APPLE = '<HBBIII16sI'


class EFI_HDR_VSS_APPLE(namedtuple('EFI_HDR_VSS_APPLE', 'StartId State Reserved Attributes NameSize DataSize guid unknown')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
Header (VSS_APPLE)
------------
VendorGuid : {{{EFI_GUID_STR(self.guid)}}}
StartId    : 0x{self.StartId:04X}
State      : 0x{self.State:02X}
Reserved   : 0x{self.Reserved:02X}
Attributes : 0x{self.Attributes:08X}
NameSize   : 0x{self.NameSize:08X}
DataSize   : 0x{self.DataSize:08X}
Unknown    : 0x{self.unknown:08X}
"""


def _getNVstore_VSS(nvram_buf: bytes, vss_type) -> Tuple[int, int, Union[VARIABLE_STORE_HEADER_VSS, VARIABLE_STORE_HEADER_VSS2, None]]:
    if vss_type == FWType.EFI_FW_TYPE_VSS2:
        sign = VARIABLE_STORE_SIGNATURE_VSS2
    elif vss_type == FWType.EFI_FW_TYPE_VSS2_AUTH:
        sign = VARIABLE_STORE_SIGNATURE_VSS2_AUTH
    else:
        sign = VARIABLE_STORE_SIGNATURE_VSS

    nvram_start = nvram_buf.find(sign)
    if -1 == nvram_start:
        return (-1, 0, None)
    buf = nvram_buf[nvram_start:]
    if (not isCorrectVSStype(buf, vss_type)):
        return (-1, 0, None)
    if vss_type in (FWType.EFI_FW_TYPE_VSS2, FWType.EFI_FW_TYPE_VSS2_AUTH):
        nvram_hdr = VARIABLE_STORE_HEADER_VSS2(*struct.unpack_from(VARIABLE_STORE_HEADER_FMT_VSS2, buf))
    else:
        nvram_hdr = VARIABLE_STORE_HEADER_VSS(*struct.unpack_from(VARIABLE_STORE_HEADER_FMT_VSS, buf))
    return (nvram_start, nvram_hdr.Size, nvram_hdr)


def getNVstore_VSS(nvram_buf: bytes):
    return _getNVstore_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS)


def getNVstore_VSS_AUTH(nvram_buf: bytes):
    return _getNVstore_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS_AUTH)


def getNVstore_VSS2(nvram_buf: bytes):
    return _getNVstore_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS2)


def getNVstore_VSS2_AUTH(nvram_buf: bytes):
    return _getNVstore_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS2_AUTH)


def getNVstore_VSS_APPLE(nvram_buf: bytes):
    return _getNVstore_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS_APPLE)


VSS_TYPES = (FWType.EFI_FW_TYPE_VSS, FWType.EFI_FW_TYPE_VSS_AUTH, FWType.EFI_FW_TYPE_VSS2, FWType.EFI_FW_TYPE_VSS2_AUTH, FWType.EFI_FW_TYPE_VSS_APPLE)
MAX_VSS_VAR_ALIGNMENT = 8


def isCorrectVSStype(nvram_buf: bytes, vss_type: str):
    if (vss_type not in VSS_TYPES):
        return False

    buf_size = len(nvram_buf)
    start = nvram_buf.find(VARIABLE_SIGNATURE_VSS)
    if (-1 == start):
        return False

    next_var = nvram_buf.find(VARIABLE_SIGNATURE_VSS, start + struct.calcsize(HDR_FMT_VSS))  # skip the minimum bytes required for the header
    if (-1 == next_var):
        next_var = buf_size

    buf_size -= start

    if (vss_type in (FWType.EFI_FW_TYPE_VSS, FWType.EFI_FW_TYPE_VSS2)):
        hdr_fmt = HDR_FMT_VSS
        efi_var_hdr = EFI_HDR_VSS(*struct.unpack_from(hdr_fmt, nvram_buf[start:]))
    elif (vss_type in (FWType.EFI_FW_TYPE_VSS_AUTH, FWType.EFI_FW_TYPE_VSS2_AUTH)):
        hdr_fmt = HDR_FMT_VSS_AUTH
        efi_var_hdr = EFI_HDR_VSS_AUTH(*struct.unpack_from(hdr_fmt, nvram_buf[start:]))
    elif (vss_type == FWType.EFI_FW_TYPE_VSS_APPLE):
        hdr_fmt = HDR_FMT_VSS_APPLE
        efi_var_hdr = EFI_HDR_VSS_APPLE(*struct.unpack_from(hdr_fmt, nvram_buf[start:]))

    hdr_size = struct.calcsize(hdr_fmt)
    # check NameSize and DataSize
    name_offset = start + hdr_size
    if ((name_offset < next_var) and ((name_offset + efi_var_hdr.NameSize) < next_var)):
        valid_name = False
        if (efi_var_hdr.NameSize > 0):
            name = nvram_buf[name_offset: name_offset + efi_var_hdr.NameSize]
            try:
                name = name.decode("utf-16-le").split('\x00')[0]
                valid_name = defines.is_printable(name)
            except Exception:
                pass
        if (valid_name):
            end_var_offset = name_offset + efi_var_hdr.NameSize + efi_var_hdr.DataSize
            off_diff = next_var - end_var_offset
            if (off_diff == 0):
                return True
            elif (off_diff > 0):
                if (next_var == len(nvram_buf)) or (off_diff <= (MAX_VSS_VAR_ALIGNMENT - 1)):
                    return True
            else:
                if (next_var < len(nvram_buf)):
                    new_nex_var = nvram_buf.find(VARIABLE_SIGNATURE_VSS, next_var, next_var + len(VARIABLE_SIGNATURE_VSS) + (MAX_VSS_VAR_ALIGNMENT - 1))
                    if (new_nex_var != -1):
                        return True

    return False


def _getEFIvariables_VSS(nvram_buf: bytes, _fwtype: str) -> Dict[str, List[EfiVariableType]]:
    variables = dict()
    nvsize = len(nvram_buf)
    if _fwtype in (FWType.EFI_FW_TYPE_VSS, FWType.EFI_FW_TYPE_VSS2):
        hdr_fmt = HDR_FMT_VSS
    elif _fwtype in (FWType.EFI_FW_TYPE_VSS_AUTH, FWType.EFI_FW_TYPE_VSS2_AUTH):
        hdr_fmt = HDR_FMT_VSS_AUTH
    elif (FWType.EFI_FW_TYPE_VSS_APPLE == _fwtype):
        hdr_fmt = HDR_FMT_VSS_APPLE
    else:
        return variables
    hdr_size = struct.calcsize(hdr_fmt)
    start = nvram_buf.find(VARIABLE_SIGNATURE_VSS)
    if -1 == start:
        return variables

    while (start + hdr_size) < nvsize:
        efi_var_hdr = None
        variables = {}
        if _fwtype in (FWType.EFI_FW_TYPE_VSS, FWType.EFI_FW_TYPE_VSS2):
            efi_var_hdr = EFI_HDR_VSS(*struct.unpack_from(hdr_fmt, nvram_buf[start:]))
        elif _fwtype in (FWType.EFI_FW_TYPE_VSS_AUTH, FWType.EFI_FW_TYPE_VSS2_AUTH):
            efi_var_hdr = EFI_HDR_VSS_AUTH(*struct.unpack_from(hdr_fmt, nvram_buf[start:]))
        elif (FWType.EFI_FW_TYPE_VSS_APPLE == _fwtype):
            efi_var_hdr = EFI_HDR_VSS_APPLE(*struct.unpack_from(hdr_fmt, nvram_buf[start:]))

        if efi_var_hdr is None:
            return variables
        if (efi_var_hdr.StartId != VARIABLE_DATA):
            break

        if ((efi_var_hdr.State == 0xff) and (efi_var_hdr.DataSize == 0xffffffff) and (efi_var_hdr.NameSize == 0xffffffff) and (efi_var_hdr.Attributes == 0xffffffff)):
            name_size = 0
            data_size = 0
            # just skip variable with empty name and data for now
            next_var_offset = nvram_buf.find(VARIABLE_SIGNATURE_VSS, start + hdr_size, start + hdr_size + len(VARIABLE_SIGNATURE_VSS) + (MAX_VSS_VAR_ALIGNMENT - 1))
            if (next_var_offset == -1) or (next_var_offset > nvsize):
                break
        else:
            name_size = efi_var_hdr.NameSize
            data_size = efi_var_hdr.DataSize
            efi_var_name = "<not defined>"

            end_var_offset = start + hdr_size + name_size + data_size
            efi_var_buf = nvram_buf[start: end_var_offset]

            name_offset = hdr_size
            Name = efi_var_buf[name_offset: name_offset + name_size]
            if Name:
                efi_var_name = Name.decode("utf-16-le").split('\x00')[0]

            efi_var_data = efi_var_buf[name_offset + name_size: name_offset + name_size + data_size]
            guid = EFI_GUID_STR(efi_var_hdr.guid)
            if efi_var_name not in variables.keys():
                variables[efi_var_name] = []
            #                                off,   buf,         hdr,         data,         guid, attrs
            variables[efi_var_name].append((start, efi_var_buf, efi_var_hdr, efi_var_data, guid, efi_var_hdr.Attributes))

            # deal with different alignments (1-8)
            next_var_offset = nvram_buf.find(VARIABLE_SIGNATURE_VSS, end_var_offset, end_var_offset + len(VARIABLE_SIGNATURE_VSS) + (MAX_VSS_VAR_ALIGNMENT - 1))
            if (next_var_offset == -1) or (next_var_offset > nvsize):
                break

        if start >= next_var_offset:
            break
        start = next_var_offset

    return variables


def getEFIvariables_VSS(nvram_buf: bytes) -> Dict[str, List[EfiVariableType]]:
    return _getEFIvariables_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS)


def getEFIvariables_VSS_AUTH(nvram_buf: bytes) -> Dict[str, List[EfiVariableType]]:
    return _getEFIvariables_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS_AUTH)


def getEFIvariables_VSS2(nvram_buf: bytes) -> Dict[str, List[EfiVariableType]]:
    return _getEFIvariables_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS2)


def getEFIvariables_VSS2_AUTH(nvram_buf: bytes) -> Dict[str, List[EfiVariableType]]:
    return _getEFIvariables_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS2_AUTH)


def getEFIvariables_VSS_APPLE(nvram_buf: bytes) -> Dict[str, List[EfiVariableType]]:
    return _getEFIvariables_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS_APPLE)


#######################################################################
#
# EVSA NVRAM (signature = 'EVSA')
#
#
VARIABLE_STORE_SIGNATURE_EVSA = b'EVSA'

TLV_HEADER = "<BBH"
tlv_h_size = struct.calcsize(TLV_HEADER)


def getNVstore_EVSA(nvram_buf: bytes) -> NvStore:
    nv_store = (-1, -1, None)
    fv = NextFwVolume(nvram_buf)
    while fv is not None:
        if (fv.Guid == VARIABLE_STORE_FV_GUID):
            nvram_start = fv.Image.find(VARIABLE_STORE_SIGNATURE_EVSA)
            if (nvram_start != -1) and (nvram_start >= tlv_h_size):
                nvram_start = nvram_start - tlv_h_size
                nv_store = (fv.Offset + nvram_start, fv.Size - nvram_start, None)
                break
        if (fv.Guid == ADDITIONAL_NV_STORE_GUID):
            nvram_start = fv.Image.find(VARIABLE_STORE_SIGNATURE_EVSA)
            if (nvram_start != -1) and (nvram_start >= tlv_h_size):
                nvram_start = nvram_start - tlv_h_size
                nv_store = (fv.Offset + nvram_start, fv.Size - nvram_start, None)
        fv = NextFwVolume(nvram_buf, fv.Offset, fv.Size)
    return nv_store


def EFIvar_EVSA(nvram_buf: bytes) -> Dict[str, List[EfiVariableType]]:
    image_size = len(nvram_buf)
    EVSA_RECORD = "<IIII"
    GUID_RECORD = "<H16s"
    fof = 0
    variables = dict()
    while fof < image_size:
        fof = nvram_buf.find(VARIABLE_STORE_SIGNATURE_EVSA, fof)
        if fof == -1:
            break
        if fof < tlv_h_size:
            fof = fof + 4
            continue
        start = fof - tlv_h_size
        Tag0, Tag1, Size = struct.unpack(TLV_HEADER, nvram_buf[start: start + tlv_h_size])
        if Tag0 != 0xEC:  # Wrong EVSA block
            fof = fof + 4
            continue
        value = nvram_buf[start + tlv_h_size:start + Size]
        _, _, Length, _ = struct.unpack(EVSA_RECORD, value)
        if start + Length > image_size:  # Wrong EVSA record
            fof = fof + 4
            continue
        # NV storage EVSA found
        bof = 0
        guid_map = dict()
        var_list = list()
        value_list = dict()
        while (bof + tlv_h_size) < Length:
            Tag0, Tag1, Size = struct.unpack(TLV_HEADER, nvram_buf[start + bof: start + bof + tlv_h_size])
            if (Size < tlv_h_size):
                break
            value = nvram_buf[start + bof + tlv_h_size:start + bof + Size]
            bof = bof + Size
            if (Tag0 == 0xED) or (Tag0 == 0xE1):  # guid
                GuidId, guid0 = struct.unpack(GUID_RECORD, value)
                g = EFI_GUID_STR(guid0)
                guid_map[GuidId] = g
            elif (Tag0 == 0xEE) or (Tag0 == 0xE2):  # var name
                VAR_NAME_RECORD = f'<H{Size - tlv_h_size - 2:d}s'
                VarId, Name = struct.unpack(VAR_NAME_RECORD, value)
                Name = Name.decode("utf-16-le")[:-1]
                var_list.append((Name, VarId, Tag0, Tag1))
            elif (Tag0 == 0xEF) or (Tag0 == 0xE3) or (Tag0 == 0x83):  # values
                VAR_VALUE_RECORD = f'<HHI{Size - tlv_h_size - 8:d}s'
                GuidId, VarId, Attributes, Data = struct.unpack(VAR_VALUE_RECORD, value)
                value_list[VarId] = (GuidId, Attributes, Data, Tag0, Tag1)
            elif not ((Tag0 == 0xff) and (Tag1 == 0xff) and (Size == 0xffff)):
                pass
        var_list.sort()
        for i in var_list:
            name = i[0]
            VarId = i[1]
            if VarId in value_list:
                var_value = value_list[VarId]
            else:
                #  Value not found for VarId
                continue
            GuidId = var_value[0]
            guid = "NONE"
            if GuidId not in guid_map:
                # Guid not found for GuidId
                pass
            else:
                guid = guid_map[GuidId]
            if name not in variables.keys():
                variables[name] = []
            #                       off,   buf,  hdr,  data,         guid, attrs
            variables[name].append((start, b'', None, var_value[2], guid, var_value[1]))
        fof = fof + Length
    return variables


#
# Uncomment if you want to parse output buffer returned by NtEnumerateSystemEnvironmentValuesEx
# using 'chipsec_util uefi nvram' command
#
#
# Windows 8 NtEnumerateSystemEnvironmentValuesEx (infcls = 2)
#
# def guid_str(guid0, guid1, guid2, guid3):
#        return ( f'{guid0:08X}-{guid1:04X}-{guid2:04X}-{guid3[:2].encode('hex').upper():4}-{guid3[-6::].encode('hex').upper():6}')
#
# class EFI_HDR_WIN( namedtuple('EFI_HDR_WIN', 'Size DataOffset DataSize Attributes guid0 guid1 guid2 guid3') ):
#        __slots__ = ()
#        def __str__(self):
#            return f"""
# Header (Windows)
# ----------------
# VendorGuid= {{self.guid0:08X}-{self.guid1:04X}-{self.guid2:04X}-{self.guid3[:2].encode('hex').upper():4}-{self.guid3[-6::].encode('hex').upper():6}}
# Size      = 0x{self.Size:08X}
# DataOffset= 0x{self.DataOffset:08X}
# DataSize  = 0x{self.DataSize:08X}
# Attributes= 0x{self.Attributes:08X}
# """
"""
def getEFIvariables_NtEnumerateSystemEnvironmentValuesEx2( nvram_buf ):
        start = 0
        buffer = nvram_buf
        bsize = len(buffer)
        header_fmt = "<IIIIIHH8s"
        header_size = struct.calcsize( header_fmt )
        variables = dict()
        off = 0
        while (off + header_size) < bsize:
           efi_var_hdr = EFI_HDR_WIN( *struct.unpack_from( header_fmt, buffer[ off : off + header_size ] ) )

           next_var_offset = off + efi_var_hdr.Size
           efi_var_buf     = buffer[ off : next_var_offset ]
           efi_var_data    = buffer[ off + efi_var_hdr.DataOffset : off + efi_var_hdr.DataOffset + efi_var_hdr.DataSize ]

           #efi_var_name = "".join( buffer[ start + header_size : start + efi_var_hdr.DataOffset ] ).decode('utf-16-le')
           str_fmt = f'{efi_var_hdr.DataOffset - header_size:d}s'
           s, = struct.unpack( str_fmt, buffer[ off + header_size : off + efi_var_hdr.DataOffset ] )
           efi_var_name = unicode(s, "utf-16-le", errors="replace").split(u'\u0000')[0]

           if efi_var_name not in variables.keys():
               variables[efi_var_name] = []
           #                                off, buf,         hdr,         data,         guid,                                                                                 attrs
           variables[efi_var_name].append( (off, efi_var_buf, efi_var_hdr, efi_var_data, guid_str(efi_var_hdr.guid0, efi_var_hdr.guid1, efi_var_hdr.guid2, efi_var_hdr.guid3), efi_var_hdr.Attributes) )

           if 0 == efi_var_hdr.Size: break
           off = next_var_offset

        return variables
#    return (start, next_var_offset, efi_var_buf, efi_var_hdr, efi_var_name, efi_var_data, guid_str(efi_var_hdr.guid0, efi_var_hdr.guid1, efi_var_hdr.guid2, efi_var_hdr.guid3), efi_var_hdr.Attributes)
"""


#
# EFI Variable Header Dictionary
#
#
# Add your EFI variable details to the dictionary
#
# Fields:
# name          func_getefivariables            func_getnvstore
#
EFI_VAR_DICT: Dict[str, Dict[str, Any]] = {
    # UEFI
    FWType.EFI_FW_TYPE_UEFI: {'name': 'UEFI', 'func_getefivariables': getEFIvariables_UEFI, 'func_getnvstore': getNVstore_EFI},
    FWType.EFI_FW_TYPE_UEFI_AUTH: {'name': 'UEFI_AUTH', 'func_getefivariables': getEFIvariables_UEFI_AUTH, 'func_getnvstore': getNVstore_EFI_AUTH},
    # Windows 8 NtEnumerateSystemEnvironmentValuesEx (infcls = 2)
    # FWType.EFI_FW_TYPE_WIN     : {'name' : 'WIN',     'func_getefivariables' : getEFIvariables_NtEnumerateSystemEnvironmentValuesEx2, 'func_getnvstore' : None },
    # NVAR format
    FWType.EFI_FW_TYPE_NVAR: {'name': 'NVAR', 'func_getefivariables': getEFIvariables_NVAR, 'func_getnvstore': getNVstore_NVAR},
    # $VSS NVRAM format
    FWType.EFI_FW_TYPE_VSS: {'name': 'VSS', 'func_getefivariables': getEFIvariables_VSS, 'func_getnvstore': getNVstore_VSS},
    # $VSS Authenticated NVRAM format
    FWType.EFI_FW_TYPE_VSS_AUTH: {'name': 'VSS_AUTH', 'func_getefivariables': getEFIvariables_VSS_AUTH, 'func_getnvstore': getNVstore_VSS_AUTH},
    # VSS2 NVRAM format
    FWType.EFI_FW_TYPE_VSS2: {'name': 'VSS2', 'func_getefivariables': getEFIvariables_VSS2, 'func_getnvstore': getNVstore_VSS2},
    # VSS2 Authenticated NVRAM format
    FWType.EFI_FW_TYPE_VSS2_AUTH: {'name': 'VSS2_AUTH', 'func_getefivariables': getEFIvariables_VSS2_AUTH, 'func_getnvstore': getNVstore_VSS2_AUTH},
    # Apple $VSS formart
    FWType.EFI_FW_TYPE_VSS_APPLE: {'name': 'VSS_APPLE', 'func_getefivariables': getEFIvariables_VSS_APPLE, 'func_getnvstore': getNVstore_VSS_APPLE},
    # EVSA
    FWType.EFI_FW_TYPE_EVSA: {'name': 'EVSA', 'func_getefivariables': EFIvar_EVSA, 'func_getnvstore': getNVstore_EVSA},
}


def decode_EFI_variables(efi_vars: Dict[str, List[EfiVariableType]], nvram_pth: str) -> None:
    # print decoded and sorted EFI variables into a log file
    print_sorted_EFI_variables(efi_vars)
    # write each EFI variable into its own binary file
    for name in efi_vars.keys():
        n = 0
        data: bytes
        guid: str
        attrs: int
        for (_, _, _, data, guid, attrs) in efi_vars[name]:  # Type: EfiVariableType
            attr_str = get_attr_string(attrs)
            var_fname = os.path.join(nvram_pth, f'{name}_{guid}_{attr_str.strip()}_{n:d}.bin')
            write_file(var_fname, data)
            if name in SECURE_BOOT_KEY_VARIABLES:
                parse_efivar_file(var_fname, data, SECURE_BOOT_SIG_VAR)
            elif name == EFI_VAR_NAME_certdb:
                parse_efivar_file(var_fname, data, AUTH_SIG_VAR)
            elif name == EFI_VAR_NAME_AuthVarKeyDatabase:
                parse_efivar_file(var_fname, data, ESAL_SIG_VAR)
            n = n + 1


def identify_EFI_NVRAM(buffer: bytes) -> str:
    b = buffer
    for fw_type in fw_types:
        if EFI_VAR_DICT[fw_type]['func_getnvstore']:
            (offset, _, _) = EFI_VAR_DICT[fw_type]['func_getnvstore'](b)
            if offset != -1:
                return fw_type
    return ''


def parse_EFI_variables(fname: str, rom: bytes, authvars: bool, _fw_type: Optional[str] = None) -> bool:
    if (_fw_type in fw_types) and (_fw_type is not None):
        logger().log(f'[uefi] Using FW type (NVRAM format): {_fw_type}')
    else:
        logger().log_error(f"Unrecognized FW type '{_fw_type}' (NVRAM format) '{_fw_type}'.")
        return False

    logger().log('[uefi] Searching for NVRAM in the binary..')
    efi_vars_store = find_EFI_variable_store(rom, _fw_type)
    if efi_vars_store:
        nvram_fname = f'{fname}.nvram.bin'
        write_file(nvram_fname, efi_vars_store)
        nvram_pth = f'{fname}.nvram.dir'
        if not os.path.exists(nvram_pth):
            os.makedirs(nvram_pth)
        logger().log('[uefi] Extracting EFI Variables in the NVRAM..')
        efi_vars = EFI_VAR_DICT[_fw_type]['func_getefivariables'](efi_vars_store)
        decode_EFI_variables(efi_vars, nvram_pth)
    else:
        logger().log_error('Did not find NVRAM')
        return False

    return True


def find_EFI_variable_store(rom_buffer: Optional[bytes], _FWType: Optional[str]) -> bytes:
    if rom_buffer is None:
        logger().log_error('rom_buffer is None')
        return b''

    rom = rom_buffer
    offset = 0
    size = len(rom_buffer)
    nvram_header = None
    if _FWType is None:
        logger().log_hal('[uefi] find_EFI_variable_store(): _FWType is None. Bypassing find_EFI_variable_store().')
        return b''
    if EFI_VAR_DICT[_FWType]['func_getnvstore']:
        (offset, size, nvram_header) = EFI_VAR_DICT[_FWType]['func_getnvstore'](rom)
        if (-1 == offset):
            logger().log_error("'func_getnvstore' is defined but could not find EFI NVRAM. Exiting..")
            return b''
    else:
        logger().log("[uefi] 'func_getnvstore' is not defined in EFI_VAR_DICT. Assuming start offset 0.")

    if -1 == size:
        size = len(rom_buffer)
    nvram_buf = rom[offset: offset + size]

    if logger().UTIL_TRACE:
        logger().log(f'[uefi] Found EFI NVRAM at offset 0x{offset:08X}')
        logger().log("""
==================================================================
NVRAM: EFI Variable Store
==================================================================""")
        if nvram_header:
            logger().log(nvram_header)
    return nvram_buf
