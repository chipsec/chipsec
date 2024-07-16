# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2020-2021, Intel Corporation
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
UEFI Firmware Volume Parsing/Modification Functionality
"""

import hashlib
import struct
from typing import Optional, Tuple
from uuid import UUID
from chipsec.library.defines import bytestostring
from chipsec.hal.uefi_common import get_3b_size, bit_set, align
from chipsec.library.logger import logger

################################################################################################
#
# EFI Firmware Volume Defines
#
################################################################################################

FFS_ATTRIB_LARGE_FILE = 0x01
FFS_ATTRIB_FIXED = 0x04
FFS_ATTRIB_DATA_ALIGNMENT = 0x38
FFS_ATTRIB_CHECKSUM = 0x40

EFI_FILE_HEADER_CONSTRUCTION = 0x01
EFI_FILE_HEADER_VALID = 0x02
EFI_FILE_DATA_VALID = 0x04
EFI_FILE_MARKED_FOR_UPDATE = 0x08
EFI_FILE_DELETED = 0x10
EFI_FILE_HEADER_INVALID = 0x20

FFS_FIXED_CHECKSUM = 0xAA

EFI_FVB2_ERASE_POLARITY = 0x00000800

EFI_FV_FILETYPE_ALL = 0x00
EFI_FV_FILETYPE_RAW = 0x01
EFI_FV_FILETYPE_FREEFORM = 0x02
EFI_FV_FILETYPE_SECURITY_CORE = 0x03
EFI_FV_FILETYPE_PEI_CORE = 0x04
EFI_FV_FILETYPE_DXE_CORE = 0x05
EFI_FV_FILETYPE_PEIM = 0x06
EFI_FV_FILETYPE_DRIVER = 0x07
EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER = 0x08
EFI_FV_FILETYPE_APPLICATION = 0x09
EFI_FV_FILETYPE_MM = 0x0a
EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE = 0x0b
EFI_FV_FILETYPE_COMBINED_MM_DXE = 0x0c
EFI_FV_FILETYPE_MM_CORE = 0x0d
EFI_FV_FILETYPE_MM_STANDALONE = 0x0e
EFI_FV_FILETYPE_MM_CORE_STANDALONE = 0x0f
EFI_FV_FILETYPE_FFS_PAD = 0xf0

FILE_TYPE_NAMES = {
    0x00: 'FV_ALL',
    0x01: 'FV_RAW',
    0x02: 'FV_FREEFORM',
    0x03: 'FV_SECURITY_CORE',
    0x04: 'FV_PEI_CORE',
    0x05: 'FV_DXE_CORE',
    0x06: 'FV_PEIM',
    0x07: 'FV_DRIVER',
    0x08: 'FV_COMBINED_PEIM_DRIVER',
    0x09: 'FV_APPLICATION',
    0x0A: 'FV_MM',
    0x0B: 'FV_FVIMAGE',
    0x0C: 'FV_COMBINED_MM_DXE',
    0x0D: 'FV_MM_CORE',
    0x0E: 'FV_MM_STANDALONE',
    0x0F: 'FV_MM_CORE_STANDALONE',
    0xF0: 'FV_FFS_PAD'
}

EFI_SECTION_ALL = 0x00
EFI_SECTION_COMPRESSION = 0x01
EFI_SECTION_GUID_DEFINED = 0x02
EFI_SECTION_PE32 = 0x10
EFI_SECTION_PIC = 0x11
EFI_SECTION_TE = 0x12
EFI_SECTION_DXE_DEPEX = 0x13
EFI_SECTION_VERSION = 0x14
EFI_SECTION_USER_INTERFACE = 0x15
EFI_SECTION_COMPATIBILITY16 = 0x16
EFI_SECTION_FIRMWARE_VOLUME_IMAGE = 0x17
EFI_SECTION_FREEFORM_SUBTYPE_GUID = 0x18
EFI_SECTION_RAW = 0x19
EFI_SECTION_PEI_DEPEX = 0x1B
EFI_SECTION_MM_DEPEX = 0x1C

SECTION_NAMES = {
    0x00: 'S_ALL',
    0x01: 'S_COMPRESSION',
    0x02: 'S_GUID_DEFINED',
    0x10: 'S_PE32',
    0x11: 'S_PIC',
    0x12: 'S_TE',
    0x13: 'S_DXE_DEPEX',
    0x14: 'S_VERSION',
    0x15: 'S_USER_INTERFACE',
    0x16: 'S_COMPATIBILITY16',
    0x17: 'S_FV_IMAGE',
    0x18: 'S_FREEFORM_SUBTYPE_GUID',
    0x19: 'S_RAW',
    0x1B: 'S_PEI_DEPEX',
    0x1C: 'S_MM_DEPEX'
}

EFI_SECTIONS_EXE = [EFI_SECTION_PE32, EFI_SECTION_TE, EFI_SECTION_PIC, EFI_SECTION_COMPATIBILITY16]

EFI_FIRMWARE_VOLUME_HEADER = "<16s16sQIIHHHBB"
EFI_FIRMWARE_VOLUME_HEADER_size = struct.calcsize(EFI_FIRMWARE_VOLUME_HEADER)
EFI_FV_BLOCK_MAP_ENTRY = "<II"
EFI_FFS_FILE_HEADER = "<16sHBB3sB"
EFI_FFS_FILE_HEADER2 = "<16sHBB3sBQ"
EFI_COMMON_SECTION_HEADER = "<3sB"
EFI_COMPRESSION_SECTION = "<IB"
EFI_COMPRESSION_SECTION_size = struct.calcsize(EFI_COMPRESSION_SECTION)
EFI_GUID_DEFINED_SECTION = "<16sHH"
EFI_GUID_DEFINED_SECTION_size = struct.calcsize(EFI_GUID_DEFINED_SECTION)

WIN_CERTIFICATE = "<IHH16s"
WIN_CERTIFICATE_size = struct.calcsize(WIN_CERTIFICATE)

WIN_CERT_TYPE_EFI_GUID = 0x0EF1

EFI_CRC32_GUIDED_SECTION_EXTRACTION_PROTOCOL_GUID = UUID("FC1BCDB0-7D31-49AA-936A-A4600D9DD083")
EFI_CERT_TYPE_RSA_2048_SHA256_GUID = UUID("A7717414-C616-4977-9420-844712A735BF")
EFI_CERT_TYPE_RSA_2048_SHA256_GUID_size = struct.calcsize("16s256s256s")
EFI_FIRMWARE_CONTENTS_SIGNED_GUID = UUID("0F9D89E8-9259-4F76-A5AF-0C89E34023DF")
EFI_FIRMWARE_FILE_SYSTEM_GUID = UUID("7A9354D9-0468-444A-81CE-0BF617D890DF")
EFI_FIRMWARE_FILE_SYSTEM2_GUID = UUID("8C8CE578-8A3D-4F1C-9935-896185C32DD3")
EFI_FIRMWARE_FILE_SYSTEM3_GUID = UUID("5473C07A-3DCB-4DCA-BD6F-1E9689E7349A")

EFI_FS_GUIDS = [EFI_FIRMWARE_FILE_SYSTEM3_GUID, EFI_FIRMWARE_FILE_SYSTEM2_GUID, EFI_FIRMWARE_FILE_SYSTEM_GUID]

LZMAF86_DECOMPRESS_GUID = UUID('D42AE6BD-1352-4BFB-909A-CA72A6EAE889')
LZMA_CUSTOM_DECOMPRESS_GUID = UUID("EE4E5898-3914-4259-9D6E-DC7BD79403CF")
TIANO_DECOMPRESSED_GUID = UUID("A31280AD-481E-41B6-95E8-127F4C984779")

FIRMWARE_VOLUME_GUID = UUID("24400798-3807-4A42-B413-A1ECEE205DD8")
VOLUME_SECTION_GUID = UUID("367AE684-335D-4671-A16D-899DBFEA6B88")
EFI_FFS_VOLUME_TOP_FILE_GUID = UUID("1BA0062E-C779-4582-8566-336AE8F78F09")

DEF_INDENT = "    "


class EFI_MODULE:
    def __init__(self, Offset: int, Guid: Optional[UUID], HeaderSize: int, Attributes: int, Image: bytes):
        self.Offset = Offset
        self.Guid = Guid
        self.HeaderSize = HeaderSize
        self.Attributes = Attributes
        self.Image = Image
        self.ui_string = ''
        self.isNVRAM = False
        self.NVRAMType = ''

        self.indent = ''

        self.MD5 = None
        self.SHA1 = None
        self.SHA256 = None

        # a list of children EFI_MODULE nodes to build the EFI_MODULE object model
        self.children = []

    def name(self) -> str:
        _name = type(self).__name__.encode('ascii', 'ignore')
        _guid = str(self.Guid).upper()
        _ui_str = self.ui_string.encode('ascii', 'ignore') if self.ui_string else ''
        return f'{_name} {{{_guid}}} {_ui_str}'

    def __str__(self) -> str:
        _ind = self.indent + DEF_INDENT
        _s = ''
        if self.MD5:
            _s = f'\n{_ind}MD5   : {self.MD5}'
        if self.SHA1:
            _s += f'\n{_ind}SHA1  : {self.SHA1}'
        if self.SHA256:
            _s += f'\n{_ind}SHA256: {self.SHA256}'
        return bytestostring(_s)

    def calc_hashes(self, off: int = 0) -> None:
        if self.Image is None:
            return
        hmd5 = hashlib.md5()
        hmd5.update(self.Image[off:])
        self.MD5 = hmd5.hexdigest()
        hsha1 = hashlib.sha1()
        hsha1.update(self.Image[off:])
        self.SHA1 = hsha1.hexdigest()
        hsha256 = hashlib.sha256()
        hsha256.update(self.Image[off:])
        self.SHA256 = hsha256.hexdigest()


class EFI_FV(EFI_MODULE):
    def __init__(self, Offset: int, Guid: UUID, Size: int, Attributes: int, HeaderSize: int, Checksum: int, ExtHeaderOffset: int, Image: bytes, CalcSum: int):
        super(EFI_FV, self).__init__(Offset, Guid, HeaderSize, Attributes, Image)
        self.Size = Size
        self.Checksum = Checksum
        self.ExtHeaderOffset = ExtHeaderOffset
        self.CalcSum = CalcSum

    def __str__(self) -> str:
        schecksum = f'{self.Checksum:04X}h ({self.CalcSum:04X}h) *** checksum mismatch ***' if self.CalcSum != self.Checksum else f'{self.Checksum:04X}h'
        _s = f'\n{self.indent}{type(self).__name__} +{self.Offset:08X}h {{{self.Guid}}}: '
        _s += f"Size {self.Size:08X}h, Attr {self.Attributes:08X}h, HdrSize {self.HeaderSize:04X}h, ExtHdrOffset {self.ExtHeaderOffset:08X}h, Checksum {schecksum}"
        _s += super(EFI_FV, self).__str__()
        return bytestostring(_s)


class EFI_FILE(EFI_MODULE):
    def __init__(self, Offset: int, Guid: UUID, Type: int, Attributes: int, State: int, Checksum: int, Size: int, Image: bytes, HeaderSize: int, UD: bool, CalcSum: int):
        super(EFI_FILE, self).__init__(Offset, Guid, HeaderSize, Attributes, Image)
        self.Name = Guid
        self.Type = Type
        self.State = State
        self.Size = Size
        self.Checksum = Checksum
        self.UD = UD
        self.CalcSum = CalcSum

    def __str__(self) -> str:
        schecksum = f'{self.Checksum:04X}h ({self.CalcSum:04X}h) *** checksum mismatch ***' if self.CalcSum != self.Checksum else f'{self.Checksum:04X}h'
        _s = f'\n{self.indent}+{self.Offset:08X}h {self.name()}\n{self.indent}Type {self.Type:02X}h, Attr {self.Attributes:08X}h, State {self.State:02X}h, Size {self.Size:06X}h, Checksum {schecksum}'
        _s += (super(EFI_FILE, self).__str__() + '\n')
        return bytestostring(_s)


class EFI_SECTION(EFI_MODULE):
    def __init__(self, Offset: int, Name: str, Type: int, Image: bytes, HeaderSize: int, Size: int):
        super(EFI_SECTION, self).__init__(Offset, None, HeaderSize, 0, Image)
        self.Name = Name
        self.Type = Type
        self.DataOffset = 0
        self.Comments = ''
        self.Size = Size

        # parent GUID used in search, export to JSON/log
        self.parentGuid = None

    def name(self) -> str:
        _name = self.Name.encode('ascii', 'ignore')
        _guid = self.parentGuid
        _ui_str = self.ui_string.encode('ascii', 'ignore') if self.ui_string else ''
        return f'{_name} section of binary {{{_guid}}} {_ui_str}'

    def __str__(self) -> str:
        _s = f'{self.indent}+{self.Offset:08X}h {self.name()}: Type {self.Type:02X}h'
        if self.Guid:
            _s += f' GUID {{{self.Guid}}}'
        if self.Attributes:
            _s += f' Attr {self.Attributes:04X}h'
        if self.DataOffset:
            _s += f' DataOffset {self.DataOffset:04X}h'
        if self.Comments:
            _s += f' Comments {self.Comments}'
        _s += super(EFI_SECTION, self).__str__()
        return bytestostring(_s)


def FvSum8(buffer: bytes) -> int:
    sum8 = 0
    for b in bytestostring(buffer):
        sum8 = (sum8 + ord(b)) & 0xff
    return sum8


def FvChecksum8(buffer: bytes) -> int:
    return ((0x100 - FvSum8(buffer)) & 0xff)


def FvSum16(buffer: bytes) -> int:
    sum16 = 0
    buffer_str = bytestostring(buffer)
    blen = len(buffer) // 2
    i = 0
    while i < blen:
        el16 = ord(buffer_str[2 * i]) | (ord(buffer_str[2 * i + 1]) << 8)
        sum16 = (sum16 + el16) & 0xffff
        i = i + 1
    return sum16


def FvChecksum16(buffer: bytes) -> int:
    return ((0x10000 - FvSum16(buffer)) & 0xffff)


def ValidateFwVolumeHeader(ZeroVector: str, FsGuid: UUID, FvLength: int, HeaderLength: int, ExtHeaderOffset: int, Reserved: int, size: int, Calcsum: int, Checksum: int) -> bool:
    fv_rsvd = (Reserved == 0)
    fv_len = (FvLength <= size)
    fv_header_len = (ExtHeaderOffset < FvLength) and (HeaderLength < FvLength)
    if Checksum != Calcsum:
        logger().log_hal(f'WARNING: Firmware Volume {{{FsGuid}}} checksum does not match calculated checksum')
    return fv_rsvd and fv_len and fv_header_len


def NextFwVolume(buffer: bytes, off: int = 0, last_fv_size: int = 0) -> Optional[EFI_FV]:
    fof = off if last_fv_size == 0 else off + max(last_fv_size, EFI_FIRMWARE_VOLUME_HEADER_size)
    size = len(buffer)
    while ((fof + EFI_FIRMWARE_VOLUME_HEADER_size) < size):
        fof = bytestostring(buffer).find("_FVH", fof)
        if fof == -1 or size - fof < EFI_FIRMWARE_VOLUME_HEADER_size:
            break
        elif fof < 0x28:
            # continue searching for signature if header is not valid
            fof += 0x4
            continue
        fof = fof - 0x28
        ZeroVector, FileSystemGuid0, \
            FvLength, Signature, Attributes, HeaderLength, Checksum, ExtHeaderOffset,    \
            Reserved, Revision = struct.unpack(EFI_FIRMWARE_VOLUME_HEADER, buffer[fof:fof + EFI_FIRMWARE_VOLUME_HEADER_size])
        fvh = struct.pack(EFI_FIRMWARE_VOLUME_HEADER, ZeroVector,
                          FileSystemGuid0,
                          FvLength, Signature, Attributes, HeaderLength, 0, ExtHeaderOffset,
                          Reserved, Revision)
        if (len(fvh) < HeaderLength):
            tail = buffer[fof + len(fvh):fof + HeaderLength]
            fvh = fvh + tail
        CalcSum = FvChecksum16(fvh)
        FsGuid = UUID(bytes_le=FileSystemGuid0)
        if (ValidateFwVolumeHeader(ZeroVector, FsGuid, FvLength, HeaderLength, ExtHeaderOffset, Reserved, size, CalcSum, Checksum)):
            return EFI_FV(fof, FsGuid, FvLength, Attributes, HeaderLength, Checksum, ExtHeaderOffset, buffer[fof:fof + FvLength], CalcSum)
        else:
            fof += 0x2C
    return None


def GetFvHeader(buffer: bytes, off: int = 0) -> Tuple[int, int, int]:
    EFI_FV_BLOCK_MAP_ENTRY_SZ = struct.calcsize(EFI_FV_BLOCK_MAP_ENTRY)
    header_size = EFI_FIRMWARE_VOLUME_HEADER_size + struct.calcsize(EFI_FV_BLOCK_MAP_ENTRY)
    if (len(buffer) < header_size):
        return (0, 0, 0)
    size = 0
    fof = off + EFI_FIRMWARE_VOLUME_HEADER_size
    ZeroVector, FileSystemGuid0, \
        FvLength, _, Attributes, HeaderLength, Checksum, ExtHeaderOffset,    \
        Reserved, Revision = struct.unpack(EFI_FIRMWARE_VOLUME_HEADER, buffer[off:off + EFI_FIRMWARE_VOLUME_HEADER_size])
    numblocks, lenblock = struct.unpack(EFI_FV_BLOCK_MAP_ENTRY, buffer[fof:fof + struct.calcsize(EFI_FV_BLOCK_MAP_ENTRY)])
    fv_header_str = f'''
    \nFV volume offset: 0x{fof:08X}
    \tFvLength:         0x{FvLength:08X}
    \tAttributes:       0x{Attributes:08X}
    \tHeaderLength:     0x{HeaderLength:04X}
    \tChecksum:         0x{Checksum:04X}
    \tRevision:         0x{Revision:02X}
    \tExtHeaderOffset:  0x{ExtHeaderOffset:02X}
    \tReserved:         0x{Reserved:02X}
    FFS Guid:    {UUID(bytes_le=FileSystemGuid0)}
    '''
    logger().log_hal(fv_header_str)

    while not (numblocks == 0 and lenblock == 0):
        fof += EFI_FV_BLOCK_MAP_ENTRY_SZ
        if (fof + EFI_FV_BLOCK_MAP_ENTRY_SZ) >= len(buffer):
            return (0, 0, 0)
        if numblocks != 0:
            logger().log_hal(f'Num blocks:   0x{numblocks:08X}\n')
            logger().log_hal(f'block Len:    0x{lenblock:08X}\n')
            size = size + (numblocks * lenblock)
        numblocks, lenblock = struct.unpack(EFI_FV_BLOCK_MAP_ENTRY, buffer[fof:fof + EFI_FV_BLOCK_MAP_ENTRY_SZ])
    if FvLength != size:
        logger().log_hal("ERROR: Volume Size not consistent with Block Maps")
        return (0, 0, 0)
    if size >= 0x40000000 or size == 0:
        logger().log_hal("ERROR: Volume is corrupted")
        return (0, 0, 0)
    return (size, HeaderLength, Attributes)


def NextFwFile(FvImage: bytes, FvLength: int, fof: int, polarity: bool) -> Optional[EFI_FILE]:
    file_header_size = struct.calcsize(EFI_FFS_FILE_HEADER)
    fof = align(fof, 8)
    cur_offset = fof
    res = None
    update_or_deleted = False

    while cur_offset + file_header_size < min(FvLength, len(FvImage)):
        fsize = 0
    # if (fof + file_header_size) <= min(FvLength, len(FvImage)):
        # Check for a blank header
        if polarity:
            blank = b"\xff" * file_header_size
        else:
            blank = b"\x00" * file_header_size

        if (blank == FvImage[cur_offset:cur_offset + file_header_size]):
            #next_offset = fof + 8
            cur_offset += 8
            continue
        Name0, IntegrityCheck, Type, Attributes, Size, State = struct.unpack(EFI_FFS_FILE_HEADER, FvImage[cur_offset:cur_offset + file_header_size])
        # Get File Header Size
        if Attributes & FFS_ATTRIB_LARGE_FILE:
            header_size = struct.calcsize(EFI_FFS_FILE_HEADER2)
        else:
            header_size = struct.calcsize(EFI_FFS_FILE_HEADER)

        # Get File size
        if Attributes & FFS_ATTRIB_LARGE_FILE and len(FvImage) > fof + struct.calcsize(EFI_FFS_FILE_HEADER2):
            fsize = struct.unpack("Q", FvImage[fof + file_header_size:fof + file_header_size + struct.calcsize("Q")])[0]
            fsize &= 0xFFFFFFFF
        if fsize == 0 or fsize > FvLength - cur_offset:
            fsize = get_3b_size(Size)

        # Validate fsize is a legal value
        if fsize == 0 or fsize > FvLength - cur_offset:
            logger().log_hal("WARNING: Unable to get correct file size for NextFwFile corrupt header information")
            break
        # Get next_offset
        update_or_deleted = (bit_set(State, EFI_FILE_MARKED_FOR_UPDATE, polarity)) or (bit_set(State, EFI_FILE_DELETED, polarity))
        if not ((bit_set(State, EFI_FILE_DATA_VALID, polarity)) or update_or_deleted):
            # else:
            cur_offset = align(cur_offset + 1, 8)
            continue
        Name = UUID(bytes_le=Name0)
        # TODO need to fix up checksum?
        fheader = struct.pack(EFI_FFS_FILE_HEADER, Name0, 0, Type, Attributes, Size, 0)
        hsum = FvChecksum8(fheader)
        if (Attributes & FFS_ATTRIB_CHECKSUM):
            fsum = FvChecksum8(FvImage[cur_offset + file_header_size:cur_offset + fsize])
        else:
            fsum = FFS_FIXED_CHECKSUM
        CalcSum = (hsum | (fsum << 8))
        _image = FvImage[cur_offset:cur_offset + fsize]
        res = EFI_FILE(cur_offset, Name, Type, Attributes, State, IntegrityCheck, fsize, _image, header_size, update_or_deleted, CalcSum)
        break
    return res


def NextFwFileSection(sections: bytes, ssize: int, sof: int, polarity: bool) -> Optional[EFI_SECTION]:
    EFI_COMMON_SECTION_HEADER_size = struct.calcsize(EFI_COMMON_SECTION_HEADER)
    res = None
    curr_offset = sof
    ssize = min(ssize, len(sections))
    while curr_offset + EFI_COMMON_SECTION_HEADER_size < ssize:
        Size, Type = struct.unpack(EFI_COMMON_SECTION_HEADER, sections[curr_offset:curr_offset + EFI_COMMON_SECTION_HEADER_size])
        Size = get_3b_size(Size)
        Header_Size = EFI_COMMON_SECTION_HEADER_size
        if Size == 0xFFFFFF and (curr_offset + EFI_COMMON_SECTION_HEADER_size + struct.calcsize("I")) < ssize:
            _start = curr_offset + EFI_COMMON_SECTION_HEADER_size
            _finish = _start + struct.calcsize("I")
            Size = struct.unpack("I", sections[_start:_finish])[0]
            Header_Size = EFI_COMMON_SECTION_HEADER_size + struct.calcsize("I")
        if Type in SECTION_NAMES.keys():
            sec_name = SECTION_NAMES[Type]
        else:
            sec_name = f'S_UNKNOWN_{Type:02X}'
        if (Size == 0xffffff and Type == 0xff) or (Size == 0):
            curr_offset = align(curr_offset + 4, 4)
            continue
        sec_body = sections[curr_offset:curr_offset + Size]
        res = EFI_SECTION(curr_offset, sec_name, Type, sec_body, Header_Size, align(Size, 4))
        break
    return res

# #################################################################################################
#
# UEFI Firmware Volume Parsing/Modification Functionality
#
# #################################################################################################


def align_image(image: bytes, size: int = 8, fill: bytes = b'\x00') -> bytes:
    return image.ljust(((len(image) + size - 1) // size) * size, fill)


def get_guid_bin(guid: UUID) -> bytes:
    values = str(guid).split('-')
    if [len(x) for x in values] == [8, 4, 4, 4, 12]:
        values = values[0:3] + [values[3][0:2], values[3][2:4]] + [values[4][x:x + 2] for x in range(0, 12, 2)]
        values = [int(x, 16) for x in values]
        return struct.pack('<LHHBBBBBBBB', *tuple(values))
    return b''


def assemble_uefi_file(guid: UUID, image: bytes) -> bytes:
    EFI_FFS_FILE_HEADER = "<16sHBBL"
    FileHeaderSize = struct.calcsize(EFI_FFS_FILE_HEADER)

    Type = EFI_FV_FILETYPE_FREEFORM
    CheckSum = 0x0000
    Attributes = 0x40
    Size = FileHeaderSize + len(image)
    State = 0xF8

    SizeState = (Size & 0x00FFFFFF) | (State << 24)
    FileHeader = struct.pack(EFI_FFS_FILE_HEADER, get_guid_bin(guid), CheckSum, Type, Attributes, (Size & 0x00FFFFFF))

    hsum = FvChecksum8(FileHeader)
    if (Attributes & FFS_ATTRIB_CHECKSUM):
        fsum = FvChecksum8(image)
    else:
        fsum = FFS_FIXED_CHECKSUM
    CheckSum = (hsum | (fsum << 8))

    return struct.pack(EFI_FFS_FILE_HEADER, get_guid_bin(guid), CheckSum, Type, Attributes, SizeState) + image


def assemble_uefi_section(image: bytes, uncomressed_size: int, compression_type: int) -> bytes:
    EFI_COMPRESSION_SECTION_HEADER = "<LLB"
    SectionType = EFI_SECTION_COMPRESSION
    SectionSize = struct.calcsize(EFI_COMPRESSION_SECTION_HEADER) + len(image)
    SectionHeader = struct.pack(EFI_COMPRESSION_SECTION_HEADER, (SectionSize & 0x00FFFFFF) | (SectionType << 24), uncomressed_size, compression_type)
    return SectionHeader + image


def assemble_uefi_raw(image: bytes) -> bytes:
    return align_image(struct.pack('<L', ((len(image) + 4) & 0x00FFFFFF) + (EFI_SECTION_RAW << 24)) + image)


def DecodeSection(SecType, SecBody, SecHeaderSize) -> None:
    pass
