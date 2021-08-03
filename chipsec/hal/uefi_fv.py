#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2020-2021, Intel Corporation
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

import hashlib
import struct
from uuid import UUID
from chipsec.defines import bytestostring
from chipsec.hal.uefi_common import get_3b_size, bit_set, align
from chipsec.logger import logger

################################################################################################
#
# EFI Firmware Volume Defines
#
################################################################################################

FFS_ATTRIB_LARGE_FILE         = 0x01
FFS_ATTRIB_FIXED              = 0x04
FFS_ATTRIB_DATA_ALIGNMENT     = 0x38
FFS_ATTRIB_CHECKSUM           = 0x40

EFI_FILE_HEADER_CONSTRUCTION  = 0x01
EFI_FILE_HEADER_VALID         = 0x02
EFI_FILE_DATA_VALID           = 0x04
EFI_FILE_MARKED_FOR_UPDATE    = 0x08
EFI_FILE_DELETED              = 0x10
EFI_FILE_HEADER_INVALID       = 0x20

FFS_FIXED_CHECKSUM            = 0xAA

EFI_FVB2_ERASE_POLARITY       = 0x00000800

EFI_FV_FILETYPE_ALL                     = 0x00
EFI_FV_FILETYPE_RAW                     = 0x01
EFI_FV_FILETYPE_FREEFORM                = 0x02
EFI_FV_FILETYPE_SECURITY_CORE           = 0x03
EFI_FV_FILETYPE_PEI_CORE                = 0x04
EFI_FV_FILETYPE_DXE_CORE                = 0x05
EFI_FV_FILETYPE_PEIM                    = 0x06
EFI_FV_FILETYPE_DRIVER                  = 0x07
EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER    = 0x08
EFI_FV_FILETYPE_APPLICATION             = 0x09
EFI_FV_FILETYPE_MM                      = 0x0a
EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE   = 0x0b
EFI_FV_FILETYPE_COMBINED_MM_DXE         = 0x0c
EFI_FV_FILETYPE_MM_CORE                 = 0x0d
EFI_FV_FILETYPE_MM_STANDALONE           = 0x0e
EFI_FV_FILETYPE_MM_CORE_STANDALONE      = 0x0f
EFI_FV_FILETYPE_FFS_PAD                 = 0xf0

FILE_TYPE_NAMES = {0x00: 'FV_ALL', 0x01: 'FV_RAW', 0x02: 'FV_FREEFORM', 0x03: 'FV_SECURITY_CORE', 0x04: 'FV_PEI_CORE', \
    0x05: 'FV_DXE_CORE', 0x06: 'FV_PEIM', 0x07: 'FV_DRIVER', 0x08: 'FV_COMBINED_PEIM_DRIVER', 0x09: 'FV_APPLICATION', \
    0x0A: 'FV_MM', 0x0B: 'FV_FVIMAGE', 0x0C: 'FV_COMBINED_MM_DXE', 0x0D: 'FV_MM_CORE', 0x0E: 'FV_MM_STANDALONE', \
    0x0F: 'FV_MM_CORE_STANDALONE', 0xF0: 'FV_FFS_PAD'}

EFI_SECTION_ALL                   = 0x00
EFI_SECTION_COMPRESSION           = 0x01
EFI_SECTION_GUID_DEFINED          = 0x02
EFI_SECTION_PE32                  = 0x10
EFI_SECTION_PIC                   = 0x11
EFI_SECTION_TE                    = 0x12
EFI_SECTION_DXE_DEPEX             = 0x13
EFI_SECTION_VERSION               = 0x14
EFI_SECTION_USER_INTERFACE        = 0x15
EFI_SECTION_COMPATIBILITY16       = 0x16
EFI_SECTION_FIRMWARE_VOLUME_IMAGE = 0x17
EFI_SECTION_FREEFORM_SUBTYPE_GUID = 0x18
EFI_SECTION_RAW                   = 0x19
EFI_SECTION_PEI_DEPEX             = 0x1B
EFI_SECTION_MM_DEPEX              = 0x1C

SECTION_NAMES = {0x00: 'S_ALL', 0x01: 'S_COMPRESSION', 0x02: 'S_GUID_DEFINED', 0x10: 'S_PE32', 0x11: 'S_PIC', 0x12: 'S_TE', 0x13: 'S_DXE_DEPEX', 0x14: 'S_VERSION', 0x15: 'S_USER_INTERFACE', 0x16: 'S_COMPATIBILITY16', 0x17: 'S_FV_IMAGE', 0x18: 'S_FREEFORM_SUBTYPE_GUID', 0x19: 'S_RAW', 0x1B: 'S_PEI_DEPEX', 0x1C: 'S_MM_DEPEX'}

EFI_SECTIONS_EXE = [EFI_SECTION_PE32, EFI_SECTION_TE, EFI_SECTION_PIC, EFI_SECTION_COMPATIBILITY16]

EFI_FIRMWARE_VOLUME_HEADER = "<16s16sQIIHHHBB"
EFI_FV_BLOCK_MAP_ENTRY = "<II"
EFI_FFS_FILE_HEADER = "<16sHBB3sB"
EFI_FFS_FILE_HEADER2 = "<16sHBB3sBQ"
EFI_COMMON_SECTION_HEADER = "<3sB"
EFI_COMPRESSION_SECTION = "<IB"
EFI_COMPRESSION_SECTION_size = struct.calcsize(EFI_COMPRESSION_SECTION)
EFI_GUID_DEFINED_SECTION = "<16sHH"
EFI_GUID_DEFINED_SECTION_size = struct.calcsize(EFI_GUID_DEFINED_SECTION)

EFI_CRC32_GUIDED_SECTION_EXTRACTION_PROTOCOL_GUID = UUID("FC1BCDB0-7D31-49AA-936A-A4600D9DD083")
EFI_CERT_TYPE_RSA_2048_SHA256_GUID = UUID("A7717414-C616-4977-9420-844712A735BF")
EFI_CERT_TYPE_RSA_2048_SHA256_GUID_size = struct.calcsize("16s256s256s")
EFI_FIRMWARE_FILE_SYSTEM_GUID  = UUID("7A9354D9-0468-444A-81CE-0BF617D890DF")
EFI_FIRMWARE_FILE_SYSTEM2_GUID = UUID("8C8CE578-8A3D-4F1C-9935-896185C32DD3")
EFI_FIRMWARE_FILE_SYSTEM3_GUID = UUID("5473C07A-3DCB-4DCA-BD6F-1E9689E7349A")

EFI_FS_GUIDS = [EFI_FIRMWARE_FILE_SYSTEM3_GUID, EFI_FIRMWARE_FILE_SYSTEM2_GUID, EFI_FIRMWARE_FILE_SYSTEM_GUID]

LZMA_CUSTOM_DECOMPRESS_GUID = UUID("EE4E5898-3914-4259-9D6E-DC7BD79403CF")
TIANO_DECOMPRESSED_GUID = UUID("A31280AD-481E-41B6-95E8-127F4C984779")

FIRMWARE_VOLUME_GUID = UUID("24400798-3807-4A42-B413-A1ECEE205DD8")
VOLUME_SECTION_GUID = UUID("367AE684-335D-4671-A16D-899DBFEA6B88")
EFI_FFS_VOLUME_TOP_FILE_GUID = UUID("1BA0062E-C779-4582-8566-336AE8F78F09")

DEF_INDENT = "    "
class EFI_MODULE(object):
    def __init__(self, Offset, Guid, HeaderSize, Attributes, Image):
        self.Offset     = Offset
        self.Guid       = Guid
        self.HeaderSize = HeaderSize
        self.Attributes = Attributes
        self.Image      = Image
        self.ui_string  = None
        self.isNVRAM    = False
        self.NVRAMType  = None

        self.indent     = ''

        self.MD5        = None
        self.SHA1       = None
        self.SHA256     = None

        # a list of children EFI_MODULE nodes to build the EFI_MODULE object model
        self.children   = []

    def name(self):
        return "{} {{{}}} {}".format(type(self).__name__.encode('ascii', 'ignore'), str(self.Guid).upper(), self.ui_string.encode('ascii', 'ignore') if self.ui_string else '')

    def __str__(self):
        _ind = self.indent + DEF_INDENT
        _s = ''
        if self.MD5: _s  = "\n{}MD5   : {}".format(_ind, self.MD5)
        if self.SHA1: _s += "\n{}SHA1  : {}".format(_ind, self.SHA1)
        if self.SHA256: _s += "\n{}SHA256: {}".format(_ind, self.SHA256)
        return bytestostring(_s)

    def calc_hashes( self, off=0 ):
        if self.Image is None: return
        hmd5 = hashlib.md5()
        hmd5.update( self.Image[off:] )
        self.MD5 = hmd5.hexdigest()
        hsha1 = hashlib.sha1()
        hsha1.update( self.Image[off:] )
        self.SHA1   = hsha1.hexdigest()
        hsha256 = hashlib.sha256()
        hsha256.update( self.Image[off:] )
        self.SHA256 = hsha256.hexdigest()

class EFI_FV(EFI_MODULE):
    def __init__(self, Offset, Guid, Size, Attributes, HeaderSize, Checksum, ExtHeaderOffset, Image, CalcSum):
        super(EFI_FV, self).__init__(Offset, Guid, HeaderSize, Attributes, Image)
        self.Size            = Size
        self.Checksum        = Checksum
        self.ExtHeaderOffset = ExtHeaderOffset
        self.CalcSum         = CalcSum

    def __str__(self):
        schecksum = ('{:04X}h ({:04X}h) *** checksum mismatch ***'.format(self.Checksum, self.CalcSum)) if self.CalcSum != self.Checksum else ('{:04X}h'.format(self.Checksum))
        _s = "\n{}{} +{:08X}h {{{}}}: ".format(self.indent, type(self).__name__, self.Offset, self.Guid)
        _s += "Size {:08X}h, Attr {:08X}h, HdrSize {:04X}h, ExtHdrOffset {:08X}h, Checksum {}".format(self.Size, self.Attributes, self.HeaderSize, self.ExtHeaderOffset, schecksum)
        _s += super(EFI_FV, self).__str__()
        return bytestostring(_s)

class EFI_FILE(EFI_MODULE):
    def __init__(self, Offset, Guid, Type, Attributes, State, Checksum, Size, Image, HeaderSize, UD, CalcSum):
        super(EFI_FILE, self).__init__(Offset, Guid, HeaderSize, Attributes, Image)
        self.Name        = Guid
        self.Type        = Type
        self.State       = State
        self.Size        = Size
        self.Checksum    = Checksum
        self.UD          = UD
        self.CalcSum     = CalcSum

    def __str__(self):
        schecksum = ('{:04X}h ({:04X}h) *** checksum mismatch ***'.format(self.Checksum, self.CalcSum)) if self.CalcSum != self.Checksum else ('{:04X}h'.format(self.Checksum))
        _s = "\n{}+{:08X}h {}\n{}Type {:02X}h, Attr {:08X}h, State {:02X}h, Size {:06X}h, Checksum {}".format(self.indent, self.Offset, self.name(), self.indent, self.Type, self.Attributes, self.State, self.Size, schecksum)
        _s += (super(EFI_FILE, self).__str__() + '\n')
        return bytestostring(_s)

class EFI_SECTION(EFI_MODULE):
    def __init__(self, Offset, Name, Type, Image, HeaderSize, Size):
        super(EFI_SECTION, self).__init__(Offset, None, HeaderSize, None, Image)
        self.Name        = Name
        self.Type        = Type
        self.DataOffset  = None
        self.Comments    = None
        self.Size        = Size

        # parent GUID used in search, export to JSON/log
        self.parentGuid  = None

    def name(self):
        return "{} section of binary {{{}}} {}".format(self.Name.encode('ascii', 'ignore'), self.parentGuid, self.ui_string.encode('ascii', 'ignore') if self.ui_string else '')

    def __str__(self):
        _s = "{}+{:08X}h {}: Type {:02X}h".format(self.indent, self.Offset, self.name(), self.Type)
        if self.Guid: _s += " GUID {{{}}}".format(self.Guid)
        if self.Attributes: _s += " Attr {:04X}h".format(self.Attributes)
        if self.DataOffset: _s += " DataOffset {:04X}h".format(self.DataOffset)
        if self.Comments: _s += "Comments {}".format(self.Comments)
        _s += super(EFI_SECTION, self).__str__()
        return bytestostring(_s)

def FvSum8(buffer):
    sum8 = 0
    for b in bytestostring(buffer):
        sum8 = (sum8 + ord(b)) & 0xff
    return sum8

def FvChecksum8(buffer):
    return ((0x100 - FvSum8(buffer)) & 0xff)

def FvSum16(buffer):
    sum16 = 0
    buffer = bytestostring(buffer)
    blen = len(buffer) //2
    i = 0
    while i < blen:
        el16 = ord(buffer[2 *i]) | (ord(buffer[2 *i +1]) << 8)
        sum16 = (sum16 + el16) & 0xffff
        i = i + 1
    return sum16

def FvChecksum16(buffer):
    return ((0x10000 - FvSum16(buffer)) & 0xffff)

def ValidateFwVolumeHeader(ZeroVector, FsGuid, FvLength, HeaderLength, ExtHeaderOffset, Reserved, size):
    # zero_vector = (ZeroVector == '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    fv_rsvd = (Reserved == 0)
    # fs_guid = (FsGuid in (EFI_FS_GUIDS + [VARIABLE_STORE_FV_GUID]))
    fv_len = (FvLength <= size)
    fv_header_len = (ExtHeaderOffset < FvLength) and (HeaderLength < FvLength)
    return fv_rsvd and fv_len and fv_header_len

def NextFwVolume(buffer, off = 0):
    fof = off
    vf_header_size = struct.calcsize(EFI_FIRMWARE_VOLUME_HEADER)
    size = len(buffer)
    while ((fof + vf_header_size) < size):
        fof =   bytestostring(buffer).find("_FVH", fof)
        if fof == -1 or size - fof < vf_header_size:
            break
        elif fof < 0x28:
            #continue searching for signature if header is not valid
            fof += 0x4
            continue
        fof = fof - 0x28
        ZeroVector, FileSystemGuid0, \
          FvLength, Signature, Attributes, HeaderLength, Checksum, ExtHeaderOffset,    \
           Reserved, Revision = struct.unpack(EFI_FIRMWARE_VOLUME_HEADER, buffer[fof:fof +vf_header_size])
        fvh = struct.pack(EFI_FIRMWARE_VOLUME_HEADER, ZeroVector, \
                          FileSystemGuid0, \
                          FvLength, Signature, Attributes, HeaderLength, 0, ExtHeaderOffset,    \
                          Reserved, Revision)
        if (len(fvh) < HeaderLength):
            tail = buffer[fof +len(fvh):fof +HeaderLength]
            fvh = fvh + tail
        CalcSum = FvChecksum16(fvh)
        FsGuid = UUID(bytes_le=FileSystemGuid0)
        if (ValidateFwVolumeHeader(ZeroVector, FsGuid, FvLength, HeaderLength, ExtHeaderOffset, Reserved, size)):
            return EFI_FV(fof, FsGuid, FvLength, Attributes, HeaderLength, Checksum, ExtHeaderOffset, buffer[fof:fof +FvLength], CalcSum)
        else:
            fof += 0x2C
    return None

def GetFvHeader(buffer, off = 0):
    EFI_FV_BLOCK_MAP_ENTRY_SZ = struct.calcsize(EFI_FV_BLOCK_MAP_ENTRY)
    header_size = struct.calcsize(EFI_FIRMWARE_VOLUME_HEADER) + struct.calcsize(EFI_FV_BLOCK_MAP_ENTRY)
    if (len(buffer) < header_size):
        return (0, 0, 0)
    size = 0
    fof = off + struct.calcsize(EFI_FIRMWARE_VOLUME_HEADER)
    ZeroVector, FileSystemGuid0, \
    FvLength, Signature, Attributes, HeaderLength, Checksum, ExtHeaderOffset,    \
    Reserved, Revision = struct.unpack(EFI_FIRMWARE_VOLUME_HEADER, buffer[off:off +struct.calcsize(EFI_FIRMWARE_VOLUME_HEADER)])
    numblocks, lenblock = struct.unpack(EFI_FV_BLOCK_MAP_ENTRY, buffer[fof:fof +struct.calcsize(EFI_FV_BLOCK_MAP_ENTRY)])
    if logger().HAL:
        logger().log('{}'.format(
        '''
        \nFV volume offset: 0x{:08X}
        \tFvLength:         0x{:08X}
        \tAttributes:       0x{:08X}
        \tHeaderLength:     0x{:04X}
        \tChecksum:         0x{:04X}
        \tRevision:         0x{:02X}
        \tExtHeaderOffset:  0x{:02X}
        \tReserved:         0x{:02X}
        FFS Guid:    {}
        '''.format(fof, FvLength, Attributes, HeaderLength, Checksum, Revision, ExtHeaderOffset, Reserved, UUID(bytes_le=FileSystemGuid0))
        ))
    while not (numblocks == 0 and lenblock == 0):
        fof += EFI_FV_BLOCK_MAP_ENTRY_SZ
        if (fof + EFI_FV_BLOCK_MAP_ENTRY_SZ) >= len(buffer):
            return (0, 0, 0)
        if numblocks != 0:
            if logger().HAL:
                logger().log("Num blocks:   0x{:08X}\n".format(numblocks))
                logger().log( "block Len:    0x{:08X}\n".format(lenblock))
            size = size + (numblocks * lenblock)
        numblocks, lenblock = struct.unpack(EFI_FV_BLOCK_MAP_ENTRY, buffer[fof:fof +EFI_FV_BLOCK_MAP_ENTRY_SZ])
    if FvLength != size:
        logger().log("ERROR: Volume Size not consistant with Block Maps")
        return (0, 0, 0)
    if size >= 0x40000000 or size == 0:
        logger().log("ERROR: Volume is corrupted")
        return (0, 0, 0)
    return (size, HeaderLength, Attributes)

def NextFwFile(FvImage, FvLength, fof, polarity):
    file_header_size = struct.calcsize(EFI_FFS_FILE_HEADER)
    fof = align(fof, 8)
    cur_offset = fof
    res = None
    update_or_deleted = False

    while cur_offset + file_header_size < min(FvLength, len(FvImage)):
        fsize = 0
    #if (fof + file_header_size) <= min(FvLength, len(FvImage)):
        #Check for a blank header
        if polarity:
            blank = b"\xff" * file_header_size
        else:
            blank = b"\x00" * file_header_size

        if (blank == FvImage[cur_offset:cur_offset +file_header_size]):
            #next_offset = fof + 8
            cur_offset += 8
            continue
        Name0, IntegrityCheck, Type, Attributes, Size, State = struct.unpack(EFI_FFS_FILE_HEADER, FvImage[cur_offset:cur_offset +file_header_size])
        #Get File Header Size
        if Attributes & FFS_ATTRIB_LARGE_FILE:
            header_size = struct.calcsize(EFI_FFS_FILE_HEADER2)
        else:
            header_size = struct.calcsize(EFI_FFS_FILE_HEADER)

        #Get File size
        if Attributes & FFS_ATTRIB_LARGE_FILE and len(FvImage) > fof + struct.calcsize(EFI_FFS_FILE_HEADER2):
            fsize = struct.unpack("Q", FvImage[fof +file_header_size:fof +file_header_size +struct.calcsize("Q")])[0]
            fsize &= 0xFFFFFFFF
        if fsize == 0 or fsize > FvLength -cur_offset:
            fsize = get_3b_size(Size)

        #Validate fsize is a legal value
        if fsize == 0 or fsize > FvLength -cur_offset:
            logger().log("Unable to get correct file size for NextFwFile corrupt header information")
            break
        #Get next_offset
        update_or_deleted = (bit_set(State, EFI_FILE_MARKED_FOR_UPDATE, polarity)) or (bit_set(State, EFI_FILE_DELETED, polarity))
        if not((bit_set(State, EFI_FILE_DATA_VALID, polarity)) or update_or_deleted):
        #else:
            cur_offset = align(cur_offset + 1, 8)
            continue
        Name = UUID(bytes_le=Name0)
        #TODO need to fix up checksum?
        fheader = struct.pack(EFI_FFS_FILE_HEADER, Name0, 0, Type, Attributes, Size, 0)
        hsum = FvChecksum8(fheader)
        if (Attributes & FFS_ATTRIB_CHECKSUM):
            fsum = FvChecksum8(FvImage[cur_offset +file_header_size:cur_offset +fsize])
        else:
            fsum = FFS_FIXED_CHECKSUM
        CalcSum = (hsum | (fsum << 8))
        res = EFI_FILE(cur_offset, Name, Type, Attributes, State, IntegrityCheck, fsize, FvImage[cur_offset:cur_offset +fsize], header_size, update_or_deleted, CalcSum)
        break
    return res

def NextFwFileSection(sections, ssize, sof, polarity):
    EFI_COMMON_SECTION_HEADER_size = struct.calcsize(EFI_COMMON_SECTION_HEADER)
    res = None
    curr_offset = sof
    ssize = min(ssize, len(sections))
    while curr_offset + EFI_COMMON_SECTION_HEADER_size < ssize:
        Size, Type = struct.unpack(EFI_COMMON_SECTION_HEADER, sections[curr_offset:curr_offset +EFI_COMMON_SECTION_HEADER_size])
        Size = get_3b_size(Size)
        Header_Size = EFI_COMMON_SECTION_HEADER_size
        if Size == 0xFFFFFF and (curr_offset + EFI_COMMON_SECTION_HEADER_size + struct.calcsize("I")) < ssize:
            Size = struct.unpack("I", sections[curr_offset +EFI_COMMON_SECTION_HEADER_size:curr_offset +EFI_COMMON_SECTION_HEADER_size +struct.calcsize("I")])[0]
            Header_Size = EFI_COMMON_SECTION_HEADER_size + struct.calcsize("I")
        if Type in SECTION_NAMES.keys():
            sec_name = SECTION_NAMES[Type]
        else:
            sec_name = "S_UNKNOWN_{:02X}".format(Type)
        if (Size == 0xffffff and Type == 0xff) or (Size == 0):
            curr_offset = align(curr_offset + 4, 4)
            continue
        sec_body = sections[curr_offset:curr_offset +Size]
        res = EFI_SECTION(curr_offset, sec_name, Type, sec_body, Header_Size, align(Size, 4))
        break
    return res

# #################################################################################################
#
# UEFI Firmware Volume Parsing/Modification Functionality
#
# #################################################################################################

def align_image(image, size=8, fill='\x00'):
    return image.ljust(((len(image) + size - 1) / size) * size, fill)

def get_guid_bin(guid):
    values = guid.split('-')
    if [len(x) for x in values] == [8, 4, 4, 4, 12]:
        values = values[0:3] + [values[3][0:2], values[3][2:4]] + [values[4][x:x +2] for x in range(0, 12, 2)]
        values = [int(x, 16) for x in values]
        return struct.pack('<LHHBBBBBBBB', *tuple(values))
    return ''

def assemble_uefi_file(guid, image):
    EFI_FFS_FILE_HEADER = "<16sHBBL"
    FileHeaderSize      = struct.calcsize(EFI_FFS_FILE_HEADER)

    Type       = EFI_FV_FILETYPE_FREEFORM
    CheckSum   = 0x0000;
    Attributes = 0x40
    Size       = FileHeaderSize + len(image)
    State      = 0xF8

    SizeState  = (Size & 0x00FFFFFF) | (State << 24)
    FileHeader = struct.pack(EFI_FFS_FILE_HEADER, get_guid_bin(guid), CheckSum, Type, Attributes, (Size & 0x00FFFFFF))

    hsum = FvChecksum8(FileHeader)
    if (Attributes & FFS_ATTRIB_CHECKSUM):
        fsum = FvChecksum8(image)
    else:
        fsum = FFS_FIXED_CHECKSUM
    CheckSum = (hsum | (fsum << 8))

    return struct.pack(EFI_FFS_FILE_HEADER, get_guid_bin(guid), CheckSum, Type, Attributes, SizeState) + image

def assemble_uefi_section(image, uncomressed_size, compression_type):
    EFI_COMPRESSION_SECTION_HEADER = "<LLB"
    SectionType   = EFI_SECTION_COMPRESSION
    SectionSize   = struct.calcsize(EFI_COMPRESSION_SECTION_HEADER) + len(image)
    SectionHeader = struct.pack(EFI_COMPRESSION_SECTION_HEADER, (SectionSize & 0x00FFFFFF) | (SectionType << 24), uncomressed_size, compression_type)
    return SectionHeader + image

def assemble_uefi_raw(image):
    return align_image(struct.pack('<L', ((len(image) + 4) & 0x00FFFFFF) + (EFI_SECTION_RAW << 24)) + image)

def DecodeSection(SecType, SecBody, SecHeaderSize):
    pass
