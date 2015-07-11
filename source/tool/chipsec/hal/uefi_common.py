#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2015, Intel Corporation
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



# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
# (c) 2010-2012 Intel Corporation
#
# -------------------------------------------------------------------------------

"""
Common UEFI/EFI functionality including UEFI variables, Firmware Volumes, Secure Boot variables, S3 boot-script, UEFI tables, etc.
"""

__version__ = '1.0'

import os
import struct
from collections import namedtuple

from chipsec.file import *
from chipsec.logger import *

#from chipsec.helper.oshelper import helper


################################################################################################
#
# EFI Variable and Variable Store Defines
#
################################################################################################

# UDK2010.SR1\MdeModulePkg\Include\Guid\VariableFormat.h
# 
# #ifndef __VARIABLE_FORMAT_H__
# #define __VARIABLE_FORMAT_H__
# 
# #define EFI_VARIABLE_GUID \
#   { 0xddcf3616, 0x3275, 0x4164, { 0x98, 0xb6, 0xfe, 0x85, 0x70, 0x7f, 0xfe, 0x7d } }
# 
# extern EFI_GUID gEfiVariableGuid;
# 
# ///
# /// Alignment of variable name and data, according to the architecture:
# /// * For IA-32 and Intel(R) 64 architectures: 1.
# /// * For IA-64 architecture: 8.
# ///
# #if defined (MDE_CPU_IPF)
# #define ALIGNMENT         8
# #else
# #define ALIGNMENT         1
# #endif
# 
# //
# // GET_PAD_SIZE calculates the miminal pad bytes needed to make the current pad size satisfy the alignment requirement.
# //
# #if (ALIGNMENT == 1)
# #define GET_PAD_SIZE(a) (0)
# #else
# #define GET_PAD_SIZE(a) (((~a) + 1) & (ALIGNMENT - 1))
# #endif
# 
# ///
# /// Alignment of Variable Data Header in Variable Store region.
# ///
# #define HEADER_ALIGNMENT  4
# #define HEADER_ALIGN(Header)  (((UINTN) (Header) + HEADER_ALIGNMENT - 1) & (~(HEADER_ALIGNMENT - 1)))
# 
# ///
# /// Status of Variable Store Region.
# ///
# typedef enum {
#   EfiRaw,
#   EfiValid,
#   EfiInvalid,
#   EfiUnknown
# } VARIABLE_STORE_STATUS;
# 
# #pragma pack(1)
# 
# #define VARIABLE_STORE_SIGNATURE  EFI_VARIABLE_GUID
# 
# ///
# /// Variable Store Header Format and State.
# ///
# #define VARIABLE_STORE_FORMATTED          0x5a
# #define VARIABLE_STORE_HEALTHY            0xfe
# 
# ///
# /// Variable Store region header.
# ///
# typedef struct {
#   ///
#   /// Variable store region signature.
#   ///
#   EFI_GUID  Signature;
#   ///
#   /// Size of entire variable store,
#   /// including size of variable store header but not including the size of FvHeader.
#   ///
#   UINT32  Size;
#   ///
#   /// Variable region format state.
#   ///
#   UINT8   Format;
#   ///
#   /// Variable region healthy state.
#   ///
#   UINT8   State;
#   UINT16  Reserved;
#   UINT32  Reserved1;
# } VARIABLE_STORE_HEADER;
# 
# ///
# /// Variable data start flag.
# ///
# #define VARIABLE_DATA                     0x55AA
# 
# ///
# /// Variable State flags.
# ///
# #define VAR_IN_DELETED_TRANSITION     0xfe  ///< Variable is in obsolete transition.
# #define VAR_DELETED                   0xfd  ///< Variable is obsolete.
# #define VAR_HEADER_VALID_ONLY         0x7f  ///< Variable header has been valid.
# #define VAR_ADDED                     0x3f  ///< Variable has been completely added.
# 
# ///
# /// Single Variable Data Header Structure.
# ///
# typedef struct {
#   ///
#   /// Variable Data Start Flag.
#   ///
#   UINT16      StartId;
#   ///
#   /// Variable State defined above.
#   ///
#   UINT8       State;
#   UINT8       Reserved;
#   ///
#   /// Attributes of variable defined in UEFI specification.
#   ///
#   UINT32      Attributes;
#   ///
#   /// Size of variable null-terminated Unicode string name.
#   ///
#   UINT32      NameSize;
#   ///
#   /// Size of the variable data without this header.
#   ///
#   UINT32      DataSize;
#   ///
#   /// A unique identifier for the vendor that produces and consumes this varaible.
#   ///
#   EFI_GUID    VendorGuid;
# } VARIABLE_HEADER;
# 
# #pragma pack()
# 
# typedef struct _VARIABLE_INFO_ENTRY  VARIABLE_INFO_ENTRY;
# 
# ///
# /// This structure contains the variable list that is put in EFI system table.
# /// The variable driver collects all variables that were used at boot service time and produces this list.
# /// This is an optional feature to dump all used variables in shell environment.
# ///
# struct _VARIABLE_INFO_ENTRY {
#   VARIABLE_INFO_ENTRY *Next;       ///< Pointer to next entry.
#   EFI_GUID            VendorGuid;  ///< Guid of Variable.
#   CHAR16              *Name;       ///< Name of Variable.
#   UINT32              Attributes;  ///< Attributes of variable defined in UEFI specification.
#   UINT32              ReadCount;   ///< Number of times to read this variable.
#   UINT32              WriteCount;  ///< Number of times to write this variable.
#   UINT32              DeleteCount; ///< Number of times to delete this variable.
#   UINT32              CacheCount;  ///< Number of times that cache hits this variable.
#   BOOLEAN             Volatile;    ///< TRUE if volatile, FALSE if non-volatile.
# };
# 
# #endif // _EFI_VARIABLE_H_


#
# Variable Store Header Format and State.
#
VARIABLE_STORE_FORMATTED = 0x5a
VARIABLE_STORE_HEALTHY   = 0xfe

#
# Variable Store region header.
#
#typedef struct {
#  ///
#  /// Variable store region signature.
#  ///
#  EFI_GUID  Signature;
#  ///
#  /// Size of entire variable store,
#  /// including size of variable store header but not including the size of FvHeader.
#  ///
#  UINT32  Size;
#  ///
#  /// Variable region format state.
#  ///
#  UINT8   Format;
#  ///
#  /// Variable region healthy state.
#  ///
#  UINT8   State;
#  UINT16  Reserved;
#  UINT32  Reserved1;
#} VARIABLE_STORE_HEADER;
#
# Signature is EFI_GUID (guid0 guid1 guid2 guid3)
VARIABLE_STORE_HEADER_FMT  = '<8sIBBHI'
VARIABLE_STORE_HEADER_SIZE = struct.calcsize( VARIABLE_STORE_HEADER_FMT )
class VARIABLE_STORE_HEADER( namedtuple('VARIABLE_STORE_HEADER', 'guid0 guid1 guid2 guid3 Size Format State Reserved Reserved1') ):
    __slots__ = ()
    def __str__(self):
        return """
EFI Variable Store
-----------------------------
Signature : {%08X-%04X-%04X-%04s-%06s}
Size      : 0x%08X bytes
Format    : 0x%02X
State     : 0x%02X
Reserved  : 0x%04X
Reserved1 : 0x%08X
""" % ( self.guid0, self.guid1, self.guid2, self.guid3[:2].encode('hex').upper(), self.guid3[-6::].encode('hex').upper(), self.Size, self.Format, self.State, self.Reserved, self.Reserved1 )

#
# Variable data start flag.
#
VARIABLE_DATA_SIGNATURE    = struct.pack('=H', 0x55AA )

#
# Variable Attributes
#
EFI_VARIABLE_NON_VOLATILE                          = 0x00000001 # Variable is non volatile
EFI_VARIABLE_BOOTSERVICE_ACCESS                    = 0x00000002 # Variable is boot time accessible
EFI_VARIABLE_RUNTIME_ACCESS                        = 0x00000004 # Variable is run-time accessible
EFI_VARIABLE_HARDWARE_ERROR_RECORD                 = 0x00000008 #
EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS            = 0x00000010 # Variable is authenticated
EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS = 0x00000020 # Variable is time based authenticated
EFI_VARIABLE_APPEND_WRITE                          = 0x00000040 # Variable allows append
UEFI23_1_AUTHENTICATED_VARIABLE_ATTRIBUTES         = (EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
def IS_VARIABLE_ATTRIBUTE(_c, _Mask):
    return ( (_c & _Mask) != 0 )

def IS_EFI_VARIABLE_AUTHENTICATED( attr ):
    return ( IS_VARIABLE_ATTRIBUTE( attr, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS ) or IS_VARIABLE_ATTRIBUTE( attr, EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS ) )

MAX_VARIABLE_SIZE = 1024
MAX_NVRAM_SIZE    = 1024*1024

def get_nvar_name(nvram, name_offset, isAscii):
    if isAscii:
        nend = nvram.find('\x00', name_offset)
        name_size = nend - name_offset + 1 # add trailing zero symbol
        name = nvram[name_offset:nend]
        return (name, name_size)
    else:
        nend = nvram.find('\x00\x00', name_offset)
        while (nend & 1) == 1:
            nend = nend + 1
            nend = nvram.find('\x00\x00', nend)
        name_size = nend - name_offset + 2 # add trailing zero symbol
        name = unicode(nvram[name_offset:nend], "utf-16-le")
        return (name, name_size)


VARIABLE_SIGNATURE_VSS = VARIABLE_DATA_SIGNATURE


################################################################################################
#
# EFI Firmware Volume Defines
#
################################################################################################

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
EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE   = 0x0b
EFI_FV_FILETYPE_FFS_PAD                 = 0xf0

FILE_TYPE_NAMES = {0x00: 'FV_ALL', 0x01: 'FV_RAW', 0x02: 'FV_FREEFORM', 0x03: 'FV_SECURITY_CORE', 0x04: 'FV_PEI_CORE', 0x05: 'FV_DXE_CORE', 0x06: 'FV_PEIM', 0x07: 'FV_DRIVER', 0x08: 'FV_COMBINED_PEIM_DRIVER', 0x09: 'FV_APPLICATION', 0x0B: 'FV_FVIMAGE', 0x0F: 'FV_FFS_PAD'}

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
EFI_SECTION_SMM_DEPEX             = 0x1C

SECTION_NAMES = {0x00: 'S_ALL', 0x01: 'S_COMPRESSION', 0x02: 'S_GUID_DEFINED', 0x10: 'S_PE32', 0x11: 'S_PIC', 0x12: 'S_TE', 0x13: 'S_DXE_DEPEX', 0x14: 'S_VERSION', 0x15: 'S_USER_INTERFACE', 0x16: 'S_COMPATIBILITY16', 0x17: 'S_FV_IMAGE', 0x18: 'S_FREEFORM_SUBTYPE_GUID', 0x19: 'S_RAW', 0x1B: 'S_PEI_DEPEX', 0x1C: 'S_SMM_DEPEX'}

GUID = "<IHH8s"
guid_size = struct.calcsize(GUID)

EFI_COMPRESSION_SECTION = "<IB"
EFI_COMPRESSION_SECTION_size = struct.calcsize(EFI_COMPRESSION_SECTION)

EFI_GUID_DEFINED_SECTION = "<IHH8sHH"
EFI_GUID_DEFINED_SECTION_size = struct.calcsize(EFI_GUID_DEFINED_SECTION)

EFI_CRC32_GUIDED_SECTION_EXTRACTION_PROTOCOL_GUID = "FC1BCDB0-7D31-49AA-936A-A4600D9DD083"

EFI_FIRMWARE_FILE_SYSTEM_GUID  = "7A9354D9-0468-444A-81CE-0BF617D890DF"
EFI_FIRMWARE_FILE_SYSTEM2_GUID = "8C8CE578-8A3D-4F1C-9935-896185C32DD3"

LZMA_CUSTOM_DECOMPRESS_GUID = "EE4E5898-3914-4259-9D6E-DC7BD79403CF"

#
# Compression Types
#
COMPRESSION_TYPE_TIANO = 1
COMPRESSION_TYPE_LZMA  = 2
COMPRESSION_TYPES = [COMPRESSION_TYPE_TIANO, COMPRESSION_TYPE_LZMA]


################################################################################################
#
# Misc Defines
#
################################################################################################

#
# Status codes
#
class StatusCode:
  EFI_SUCCESS            = 0
  EFI_LOAD_ERROR         = 1
  EFI_INVALID_PARAMETER  = 2
  EFI_UNSUPPORTED        = 3
  EFI_BAD_BUFFER_SIZE    = 4
  EFI_BUFFER_TOO_SMALL   = 5
  EFI_NOT_READY          = 6
  EFI_DEVICE_ERROR       = 7
  EFI_WRITE_PROTECTED    = 8
  EFI_OUT_OF_RESOURCES   = 9
  EFI_NOT_FOUND          = 14
  EFI_SECURITY_VIOLATION = 26

EFI_STATUS_DICT = { 
  StatusCode.EFI_SUCCESS           :"EFI_SUCCESS",
  StatusCode.EFI_LOAD_ERROR        :"EFI_LOAD_ERROR",
  StatusCode.EFI_INVALID_PARAMETER :"EFI_INVALID_PARAMETER",
  StatusCode.EFI_UNSUPPORTED       :"EFI_UNSUPPORTED",
  StatusCode.EFI_BAD_BUFFER_SIZE   :"EFI_BAD_BUFFER_SIZE",
  StatusCode.EFI_BUFFER_TOO_SMALL  :"EFI_BUFFER_TOO_SMALL",
  StatusCode.EFI_NOT_READY         :"EFI_NOT_READY",
  StatusCode.EFI_DEVICE_ERROR      :"EFI_DEVICE_ERROR",
  StatusCode.EFI_WRITE_PROTECTED   :"EFI_WRITE_PROTECTED",
  StatusCode.EFI_OUT_OF_RESOURCES  :"EFI_OUT_OF_RESOURCES",
  StatusCode.EFI_NOT_FOUND         :"EFI_NOT_FOUND",
  StatusCode.EFI_SECURITY_VIOLATION:"EFI_SECURITY_VIOLATION"
}


EFI_GUID_FMT = "IHH8s"
def EFI_GUID( guid0, guid1, guid2, guid3 ):
    return ("%08X-%04X-%04X-%04s-%06s" % (guid0, guid1, guid2, guid3[:2].encode('hex').upper(), guid3[-6::].encode('hex').upper()) )


def align(of, size):
    of = (((of + size - 1)/size) * size)
    return of

def bit_set(value, mask, polarity = False):
    if polarity: value = ~value
    return ( (value & mask) == mask )

def get_3b_size(s):
    return (ord(s[0]) + (ord(s[1]) << 8) + (ord(s[2]) << 16))

def guid_str(guid0, guid1, guid2, guid3):
    guid = "%08X-%04X-%04X-%04s-%06s" % (guid0, guid1, guid2, guid3[:2].encode('hex').upper(), guid3[-6::].encode('hex').upper())
    return guid


# #################################################################################################
#
# UEFI Firmware Volume Parsing Functionality
#
# #################################################################################################

def FvSum8(buffer):
    sum8 = 0
    for b in buffer:
        sum8 = (sum8 + ord(b)) & 0xff
    return sum8

def FvChecksum8(buffer):
    return ((0x100 - FvSum8(buffer)) & 0xff)

def FvSum16(buffer):
    sum16 = 0
    blen = len(buffer)/2
    i = 0
    while i < blen:
        el16 = ord(buffer[2*i]) | (ord(buffer[2*i+1]) << 8)
        sum16 = (sum16 + el16) & 0xffff
        i = i + 1
    return sum16

def FvChecksum16(buffer):
    return ((0x10000 - FvSum16(buffer)) & 0xffff)

def NextFwVolume(buffer, off = 0):
    fof = off
    EFI_FIRMWARE_VOLUME_HEADER = "<16sIHH8sQIIHHHBB"
    vf_header_size = struct.calcsize(EFI_FIRMWARE_VOLUME_HEADER)
    EFI_FV_BLOCK_MAP_ENTRY = "<II"
    size = len(buffer)
    res = (None, None, None, None, None, None, None, None, None)
    if (fof + vf_header_size) < size:
        fof =  buffer.find("_FVH", fof)
        if fof < 0x28: return res
        fof = fof - 0x28
        ZeroVector, FileSystemGuid0, FileSystemGuid1,FileSystemGuid2,FileSystemGuid3, \
          FvLength, Signature, Attributes, HeaderLength, Checksum, ExtHeaderOffset,    \
           Reserved, Revision = struct.unpack(EFI_FIRMWARE_VOLUME_HEADER, buffer[fof:fof+vf_header_size])
        '''
        print "\nFV volume offset: 0x%08X" % fof
        print "\tFvLength:         0x%08X" % FvLength
        print "\tAttributes:       0x%08X" % Attributes
        print "\tHeaderLength:     0x%04X" % HeaderLength
        print "\tChecksum:         0x%04X" % Checksum
        print "\tRevision:         0x%02X" % Revision
        '''
        #print "FFS Guid:     %s" % guid_str(FileSystemGuid0, FileSystemGuid1,FileSystemGuid2, FileSystemGuid3)
        #print "FV Checksum:  0x%04X (0x%04X)" % (Checksum, FvChecksum16(buffer[fof:fof+HeaderLength]))
        #'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        fvh = struct.pack(EFI_FIRMWARE_VOLUME_HEADER, ZeroVector, \
                          FileSystemGuid0, FileSystemGuid1,FileSystemGuid2,FileSystemGuid3,     \
                          FvLength, Signature, Attributes, HeaderLength, 0, ExtHeaderOffset,    \
                          Reserved, Revision)
        if (len(fvh) < HeaderLength):
            #print "len(fvh)=%d, HeaderLength=%d" % (len(fvh), HeaderLength)
            tail = buffer[fof+len(fvh):fof+HeaderLength]
            fvh = fvh + tail
        CalcSum = FvChecksum16(fvh)
        FsGuid = guid_str(FileSystemGuid0, FileSystemGuid1,FileSystemGuid2,FileSystemGuid3)
        res = (fof, FsGuid, FvLength, Attributes, HeaderLength, Checksum, ExtHeaderOffset, buffer[fof:fof+FvLength], CalcSum)
        return res
    return res

def NextFwFile(FvImage, FvLength, fof, polarity):
    EFI_FFS_FILE_HEADER = "<IHH8sHBB3sB"
    file_header_size = struct.calcsize(EFI_FFS_FILE_HEADER)
    fof = align(fof, 8)
    cur_offset = fof
#    polarity = True
    next_offset = None
    res = None
    update_or_deleted = False
    if (fof + file_header_size) < FvLength:
        fheader = FvImage[fof:fof+file_header_size]
        Name0, Name1, Name2, Name3, IntegrityCheck, Type, Attributes, Size, State = struct.unpack(EFI_FFS_FILE_HEADER, fheader)
        fsize = get_3b_size(Size);
        update_or_deleted = (bit_set(State, EFI_FILE_MARKED_FOR_UPDATE, polarity)) or (bit_set(State, EFI_FILE_DELETED, polarity))
        if   (not bit_set(State, EFI_FILE_HEADER_VALID, polarity))   or (bit_set(State, EFI_FILE_HEADER_INVALID, polarity)):
            next_offset = align(fof + 1, 8)
        #elif  (bit_set(State, EFI_FILE_MARKED_FOR_UPDATE, polarity)) or (bit_set(State, EFI_FILE_DELETED, polarity)):
        #  if fsize == 0: fsize = 1
        #  next_offset = align(fof + fsize, 8)
            update_or_deleted = True
        elif (not bit_set(State, EFI_FILE_DATA_VALID, polarity)):
            next_offset = align(fof + 1, 8)
        elif fsize == 0:
            next_offset = align(fof + 1, 8)
        else:
            next_offset = fof + fsize
            next_offset = align(next_offset, 8)
            Name = guid_str(Name0, Name1, Name2, Name3)
            fheader = struct.pack(EFI_FFS_FILE_HEADER, Name0, Name1, Name2, Name3, 0, Type, Attributes, Size, 0)
            hsum = FvChecksum8(fheader)
            if (Attributes & FFS_ATTRIB_CHECKSUM):
                fsum = FvChecksum8(FvImage[fof+file_header_size:fof+fsize])
            else:
                fsum = FFS_FIXED_CHECKSUM
            CalcSum = (hsum | (fsum << 8))
            res = (cur_offset, next_offset, Name, Type, Attributes, State, IntegrityCheck, fsize, FvImage[fof:fof+fsize], file_header_size, update_or_deleted, CalcSum)
    if res == None: return (cur_offset, next_offset, None, None, None, None, None, None, None, None, update_or_deleted, None)
    else:           return res

EFI_COMMON_SECTION_HEADER = "<3sB"
EFI_COMMON_SECTION_HEADER_size = struct.calcsize(EFI_COMMON_SECTION_HEADER)

def NextFwFileSection(sections, ssize, sof, polarity):
    # offset, next_offset, SecName, SecType, SecBody, SecHeaderSize
    cur_offset = sof
    if (sof + EFI_COMMON_SECTION_HEADER_size) < ssize:
        header = sections[sof:sof+EFI_COMMON_SECTION_HEADER_size]
        if len(header) < EFI_COMMON_SECTION_HEADER_size: return (None, None, None, None, None, None)
        Size, Type = struct.unpack(EFI_COMMON_SECTION_HEADER, header)
        Size = get_3b_size(Size)
        sec_name = "S_UNKNOWN_%02X" % Type
        if Type in SECTION_NAMES.keys():
            sec_name = SECTION_NAMES[Type]
        if (Size == 0xffffff and Type == 0xff) or (Size == 0):
            sof = align(sof + 4, 4)
            return (cur_offset, sof, None, None, None, None)
        sec_body = sections[sof:sof+Size]
        sof = align(sof + Size, 4)
        return (cur_offset, sof, sec_name, Type, sec_body, EFI_COMMON_SECTION_HEADER_size)
    return (None, None, None, None, None, None)

def DecodeSection(SecType, SecBody, SecHeaderSize):
    pass


# #################################################################################################
#
# UEFI Variable (NVRAM) Parsing Functionality
#
# #################################################################################################

# typedef struct {
#   ///
#   /// Type of the signature. GUID signature types are defined in below.
#   ///
#   EFI_GUID            SignatureType;
#   ///
#   /// Total size of the signature list, including this header.
#   ///
#   UINT32              SignatureListSize;
#   ///
#   /// Size of the signature header which precedes the array of signatures.
#   ///
#   UINT32              SignatureHeaderSize;
#   ///
#   /// Size of each signature.
#   ///
#   UINT32              SignatureSize;
#   ///
#   /// Header before the array of signatures. The format of this header is specified
#   /// by the SignatureType.
#   /// UINT8           SignatureHeader[SignatureHeaderSize];
#   ///
#   /// An array of signatures. Each signature is SignatureSize bytes in length.
#   /// EFI_SIGNATURE_DATA Signatures[][SignatureSize];
#   ///
# } EFI_SIGNATURE_LIST;

SIGNATURE_LIST = "<IHH8sIII"
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

def parse_pkcs7(data):
    return

sig_types = {"C1C41626-504C-4092-ACA9-41F936934328": ("EFI_CERT_SHA256_GUID", parse_sha256, 0x30, "SHA256"), \
             "3C5766E8-269C-4E34-AA14-ED776E85B3B6": ("EFI_CERT_RSA2048_GUID", parse_rsa2048, 0x110, "RSA2048"), \
             "E2B36190-879B-4A3D-AD8D-F2E7BBA32784": ("EFI_CERT_RSA2048_SHA256_GUID", parse_rsa2048_sha256, 0x110, "RSA2048_SHA256"), \
             "826CA512-CF10-4AC9-B187-BE01496631BD": ("EFI_CERT_SHA1_GUID", parse_sha1, 0x24, "SHA1"), \
             "67F8444F-8743-48F1-A328-1EAAB8736080": ("EFI_CERT_RSA2048_SHA1_GUID", parse_rsa2048_sha1, 0x110, "RSA2048_SHA1"), \
             "A5C059A1-94E4-4AA7-87B5-AB155C2BF072": ("EFI_CERT_X509_GUID", parse_x509, 0, "X509"), \
             "0B6E5233-A65C-44C9-9407-D9AB83BFC8BD": ("EFI_CERT_SHA224_GUID", parse_sha224, 0x2c, "SHA224"), \
             "FF3E5307-9FD0-48C9-85F1-8AD56C701E01": ("EFI_CERT_SHA384_GUID", parse_sha384, 0x40, "SHA384"), \
             "093E0FAE-A6C4-4F50-9F1B-D41E2B89C19A": ("EFI_CERT_SHA512_GUID", parse_sha512, 0x50, "SHA512"), \
             "4AAFD29D-68DF-49EE-8AA9-347D375665A7": ("EFI_CERT_TYPE_PKCS7_GUID", parse_pkcs7, 0, "PKCS7") }


#def parse_db(db, var_name, path):
def parse_db( db, decode_dir ):
    db_size = len(db)
    if 0 == db_size:
        return
    dof = 0
    nsig = 0
    entries = []
    # some platforms have 0's in the beginnig, skip all 0 (no known SignatureType starts with 0x00):
    while (dof < db_size and db[dof] == '\x00'): dof = dof + 1
    while (dof + SIGNATURE_LIST_size) < db_size:
        SignatureType0, SignatureType1, SignatureType2, SignatureType3, SignatureListSize, SignatureHeaderSize, SignatureSize \
         = struct.unpack(SIGNATURE_LIST, db[dof:dof+SIGNATURE_LIST_size])
        # prevent infinite loop when parsing malformed var
        if SignatureListSize == 0:
            logger().log_bad("db parsing failed!")
            return entries
        SignatureType = guid_str(SignatureType0, SignatureType1, SignatureType2, SignatureType3)
        short_name = "UNKNOWN"
        sig_parse_f = None
        sig_size = 0
        if (SignatureType in sig_types.keys()):
            sig_name, sig_parse_f, sig_size, short_name = sig_types[SignatureType]
        #logger().log( "SignatureType       : %s (%s)" % (SignatureType, sig_name) )
        #logger().log( "SignatureListSize   : 0x%08X" % SignatureListSize )
        #logger().log( "SignatureHeaderSize : 0x%08X" % SignatureHeaderSize )
        #logger().log( "SignatureSize       : 0x%08X" % SignatureSize )
        #logger().log( "Parsing..." )
        if (((sig_size > 0) and (sig_size == SignatureSize)) or ((sig_size == 0) and (SignatureSize >= 0x10))):
            sof = 0
            sig_list = db[dof+SIGNATURE_LIST_size+SignatureHeaderSize:dof+SignatureListSize]
            sig_list_size = len(sig_list)
            while ((sof + guid_size) < sig_list_size):
                sig_data = sig_list[sof:sof+SignatureSize]
                owner0, owner1, owner2, owner3 = struct.unpack(GUID, sig_data[:guid_size])
                owner = guid_str(owner0, owner1, owner2, owner3)
                data = sig_data[guid_size:]
                #logger().log(  "owner: %s" % owner )
                entries.append( data )
                sig_file_name = "%s-%s-%02d.bin" % (short_name, owner, nsig)
                sig_file_name = os.path.join(decode_dir, sig_file_name)
                write_file(sig_file_name, data)
                if (sig_parse_f != None):
                    sig_parse_f(data)
                sof = sof + SignatureSize
                nsig = nsig + 1
        else:
            err_str = "Wrong SignatureSize for %s type: 0x%X."  % (SignatureType, SignatureSize)
            if (sig_size > 0): err_str = err_str + " Must be 0x%X." % (sig_size)
            else:              err_str = err_str + " Must be >= 0x10."
            logger().error( err_str )
            entries.append( data )
            sig_file_name = "%s-%s-%02d.bin" % (short_name, SignatureType, nsig)
            sig_file_name = os.path.join(decode_dir, sig_file_name)
            write_file(sig_file_name, data)
            nsig = nsig + 1
        dof = dof + SignatureListSize

    return entries

def parse_efivar_file( fname, var=None ):
    if not var:
        var = read_file( fname )
    #path, var_name = os.path.split( fname )
    #var_name, ext = os.path.splitext( var_name )
    var_path = fname + '.dir'
    if not os.path.exists( var_path ):
        os.makedirs( var_path )

    parse_db( var, var_path )


########################################################################################################
#
# S3 Resume Boot-Script Parsing Functionality
#
########################################################################################################

BOOTSCRIPT_TABLE_OFFSET          = 24
RUNTIME_SCRIPT_TABLE_BASE_OFFSET = 32
ACPI_VARIABLE_SET_STRUCT_SIZE    = 0x48
S3_BOOTSCRIPT_VARIABLES          = [ 'AcpiGlobalVariable' ]

MAX_S3_BOOTSCRIPT_ENTRY_LENGTH   = 0x200


#define EFI_BOOT_SCRIPT_IO_WRITE_OPCODE 0x00
#define EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE 0x01
#define EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE 0x02
#define EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE 0x03
#define EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE 0x04
#define EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE 0x05
#define EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE 0x06
#define EFI_BOOT_SCRIPT_STALL_OPCODE 0x07
#define EFI_BOOT_SCRIPT_DISPATCH_OPCODE 0x08
#define EFI_BOOT_SCRIPT_DISPATCH_2_OPCODE 0x09
#define EFI_BOOT_SCRIPT_INFORMATION_OPCODE 0x0A
#define EFI_BOOT_SCRIPT_PCI_CONFIG2_WRITE_OPCODE 0x0B
#define EFI_BOOT_SCRIPT_PCI_CONFIG2_READ_WRITE_OPCODE 0x0C
#define EFI_BOOT_SCRIPT_IO_POLL_OPCODE 0x0D
#define EFI_BOOT_SCRIPT_MEM_POLL_OPCODE 0x0E
#define EFI_BOOT_SCRIPT_PCI_CONFIG_POLL_OPCODE 0x0F
#define EFI_BOOT_SCRIPT_PCI_CONFIG2_POLL_OPCODE 0x10

class S3BootScriptOpcode:
  EFI_BOOT_SCRIPT_IO_WRITE_OPCODE               = 0x00
  EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE          = 0x01
  EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE              = 0x02
  EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE         = 0x03
  EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE       = 0x04
  EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE  = 0x05
  EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE          = 0x06
  EFI_BOOT_SCRIPT_STALL_OPCODE                  = 0x07
  EFI_BOOT_SCRIPT_DISPATCH_OPCODE               = 0x08
  EFI_BOOT_SCRIPT_DISPATCH_2_OPCODE             = 0x09
  EFI_BOOT_SCRIPT_INFORMATION_OPCODE            = 0x0A
  EFI_BOOT_SCRIPT_PCI_CONFIG2_WRITE_OPCODE      = 0x0B
  EFI_BOOT_SCRIPT_PCI_CONFIG2_READ_WRITE_OPCODE = 0x0C
  EFI_BOOT_SCRIPT_IO_POLL_OPCODE                = 0x0D
  EFI_BOOT_SCRIPT_MEM_POLL_OPCODE               = 0x0E
  EFI_BOOT_SCRIPT_PCI_CONFIG_POLL_OPCODE        = 0x0F
  EFI_BOOT_SCRIPT_PCI_CONFIG2_POLL_OPCODE       = 0x10
  EFI_BOOT_SCRIPT_TABLE_OPCODE                  = 0xAA
  EFI_BOOT_SCRIPT_TERMINATE_OPCODE              = 0xFF

script_opcodes = {
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_WRITE_OPCODE:               "S3_BOOTSCRIPT_IO_WRITE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE:          "S3_BOOTSCRIPT_IO_READ_WRITE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE:              "S3_BOOTSCRIPT_MEM_WRITE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE:         "S3_BOOTSCRIPT_MEM_READ_WRITE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE:       "S3_BOOTSCRIPT_PCI_CONFIG_WRITE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE:  "S3_BOOTSCRIPT_PCI_CONFIG_READ_WRITE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE:          "S3_BOOTSCRIPT_SMBUS_EXECUTE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_STALL_OPCODE:                  "S3_BOOTSCRIPT_STALL",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_DISPATCH_OPCODE:               "S3_BOOTSCRIPT_DISPATCH",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_DISPATCH_2_OPCODE:             "S3_BOOTSCRIPT_DISPATCH_2_OPCODE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_INFORMATION_OPCODE:            "S3_BOOTSCRIPT_INFORMATION",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG2_WRITE_OPCODE:      "S3_BOOTSCRIPT_PCI_CONFIG2_WRITE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG2_READ_WRITE_OPCODE: "S3_BOOTSCRIPT_PCI_CONFIG2_READ_WRITE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_POLL_OPCODE:                "S3_BOOTSCRIPT_IO_POLL",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_POLL_OPCODE:               "S3_BOOTSCRIPT_MEM_POLL", 
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_POLL_OPCODE:        "S3_BOOTSCRIPT_PCI_CONFIG_POLL_OPCODE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG2_POLL_OPCODE:       "S3_BOOTSCRIPT_PCI_CONFIG2_POLL_OPCODE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_TABLE_OPCODE:                  "S3_BOOTSCRIPT_TABLE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_TERMINATE_OPCODE:              "S3_BOOTSCRIPT_TERMINATE"
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
  EFI_BOOT_SCRIPT_WIDTH_UINT8  = 0x00
  EFI_BOOT_SCRIPT_WIDTH_UINT16 = 0x01
  EFI_BOOT_SCRIPT_WIDTH_UINT32 = 0x02
  EFI_BOOT_SCRIPT_WIDTH_UINT64 = 0x03

script_width_sizes = {
  S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT8   : 1,
  S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT16  : 2,
  S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT32  : 4,
  S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT64  : 8
}
script_width_formats = {
  S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT8   : 'B',
  S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT16  : 'H',
  S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT32  : 'I',
  S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT64  : 'Q'
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
  QUICK_READ        = 0x00
  QUICK_WRITE       = 0x01
  RECEIVE_BYTE      = 0x02
  SEND_BYTE         = 0x03
  READ_BYTE         = 0x04
  WRITE_BYTE        = 0x05
  READ_WORD         = 0x06
  WRITE_WORD        = 0x07
  READ_BLOCK        = 0x08
  WRITE_BLOCK       = 0x09
  PROCESS_CALL      = 0x0A
  BWBR_PROCESS_CALL = 0x0B

class op_io_pci_mem():
    def __init__(self, opcode, size, width, address, count, buffer, value=None, mask=None):
        self.opcode  = opcode
        self.size    = size
        self.width   = width
        self.address = address
        self.count   = count
        self.value   = value
        self.mask    = mask
        self.name    = script_opcodes[ opcode ] 
        self.buffer  = buffer # data[ self.size : ]
        self.values  = None
        if self.count is not None and self.count > 0:
            sz = self.count * script_width_sizes[ self.width ]
            if len(self.buffer) != sz:
                logger().log( '[?] buffer size (0x%X) != Width x Count (0x%X)' % (len(self.buffer), sz) )
            else:
                self.values = struct.unpack( ( '%d%c' % (self.count, script_width_formats[self.width]) ), self.buffer )
    def __str__(self):
        str_r =          "  Opcode : %s (0x%02X)\n" % (self.name, self.opcode)
        str_r = str_r +  "  Width  : 0x%02X (%X bytes)\n" % (self.width, script_width_sizes[self.width])
        str_r = str_r +  "  Address: 0x%08X\n" % self.address
        if self.value  is not None: str_r = str_r +  "  Value  : 0x%08X\n" % self.value
        if self.mask   is not None: str_r = str_r +  "  Mask   : 0x%08X\n" % self.mask
        if self.count  is not None: str_r = str_r +  "  Count  : 0x%X\n" % self.count
        if self.values is not None:
            fmt = '0x%0' + ( '%dX' % (script_width_sizes[self.width]*2) )
            str_r = str_r + "  Values : %s\n" % ("  ".join( [fmt % v for v in self.values] ))
        elif self.buffer is not None:
            str_r = str_r + ("  Buffer (size = 0x%X):\n" % len(self.buffer)) + dump_buffer( self.buffer, 16 )
        return str_r

class op_smbus_execute():
    def __init__(self, opcode, size, slave_address, command, operation, peccheck):
        self.opcode        = opcode
        self.size          = size
        self.slave_address = slave_address
        self.command       = command
        self.operation     = operation
        self.peccheck      = peccheck
        self.name          = script_opcodes[ opcode ] 
    def __str__(self):
        str_r =          "  Opcode       : %s (0x%02X)\n" % (self.name, self.opcode)
        str_r = str_r +  "  Slave Address: 0x%02X\n" % self.slave_address
        str_r = str_r +  "  Command      : 0x%08X\n" % self.command
        str_r = str_r +  "  Operation    : 0x%02X\n" % self.operation
        str_r = str_r +  "  PEC Check    : %d\n" % self.peccheck
        return str_r


class op_stall():
    def __init__(self, opcode, size, duration):
        self.opcode   = opcode
        self.size     = size
        self.duration = duration
        self.name     = script_opcodes[ self.opcode ] 
    def __str__(self):
        str_r =          "  Opcode  : %s (0x%02X)\n" % (self.name, self.opcode)
        str_r = str_r +  "  Duration: 0x%08X (us)\n" % self.duration
        return str_r

class op_dispatch():
    def __init__(self, opcode, size, entrypoint):
        self.opcode     = opcode
        self.size       = size
        self.entrypoint = entrypoint
        self.name       = script_opcodes[ self.opcode ] 
    def __str__(self):
        str_r =          "  Opcode     : %s (0x%02X)\n" % (self.name, self.opcode)
        str_r = str_r +  "  Entry Point: 0x%08X\n" % self.entrypoint
        return str_r

class op_terminate():
    def __init__(self, opcode, size):
        self.opcode     = opcode
        self.size       = size
        self.name       = script_opcodes[ self.opcode ] 
    def __str__(self):
        return "  Opcode     : %s (0x%02X)\n" % (self.name, self.opcode)

class op_unknown():
    def __init__(self, opcode, size):
        self.opcode     = opcode
        self.size       = size
    def __str__(self):
        return "  Opcode     : unknown (0x%02X)\n" % self.opcode



class S3BOOTSCRIPT_ENTRY():
    def __init__( self, script_type, index, offset_in_script, length, data=None ):
        self.script_type      = script_type
        self.index            = index
        self.offset_in_script = offset_in_script
        self.length           = length
        self.data             = data
        self.decoded_opcode   = None
        self.header_length    = 0

    def __str__(self):
        entry_str = '' if self.index is None else ('[%03d] ' % self.index)
        entry_str += ( 'Entry at offset 0x%04X (len = 0x%X, header len = 0x%X):' % (self.offset_in_script, self.length, self.header_length) )
        if self.data: entry_str = entry_str + '\nData:\n' + dump_buffer(self.data, 16)
        if self.decoded_opcode: entry_str = entry_str + 'Decoded:\n' + str(self.decoded_opcode)
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

EFI_TABLE_HEADER_FMT  = '=8sIIII'
EFI_TABLE_HEADER_SIZE = 0x18

class EFI_TABLE_HEADER( namedtuple('EFI_TABLE_HEADER', 'Signature Revision HeaderSize CRC32 Reserved') ):
    __slots__ = ()
    def __str__(self):
        return """Header:
  Signature     : %s
  Revision      : %s
  HeaderSize    : 0x%08X
  CRC32         : 0x%08X
  Reserved      : 0x%08X""" % ( self.Signature, EFI_SYSTEM_TABLE_REVISION(self.Revision), self.HeaderSize, self.CRC32, self.Reserved )


# #################################################################################################
# EFI System Table
# #################################################################################################
#
# \MdePkg\Include\Uefi\UefiSpec.h
# -------------------------------
# 
# //
# // EFI Runtime Services Table
# //
# #define EFI_SYSTEM_TABLE_SIGNATURE      SIGNATURE_64 ('I','B','I',' ','S','Y','S','T')
# #define EFI_2_31_SYSTEM_TABLE_REVISION  ((2 << 16) | (31))
# #define EFI_2_30_SYSTEM_TABLE_REVISION  ((2 << 16) | (30))
# #define EFI_2_20_SYSTEM_TABLE_REVISION  ((2 << 16) | (20))
# #define EFI_2_10_SYSTEM_TABLE_REVISION  ((2 << 16) | (10))
# #define EFI_2_00_SYSTEM_TABLE_REVISION  ((2 << 16) | (00))
# #define EFI_1_10_SYSTEM_TABLE_REVISION  ((1 << 16) | (10))
# #define EFI_1_02_SYSTEM_TABLE_REVISION  ((1 << 16) | (02))
# #define EFI_SYSTEM_TABLE_REVISION       EFI_2_31_SYSTEM_TABLE_REVISION
# 
# \EdkCompatibilityPkg\Foundation\Efi\Include\EfiApi.h
# ----------------------------------------------------
# 
# //
# // EFI Configuration Table
# //
# typedef struct {
#   EFI_GUID  VendorGuid;
#   VOID      *VendorTable;
# } EFI_CONFIGURATION_TABLE;
# 
# 
# #define EFI_SYSTEM_TABLE_SIGNATURE      0x5453595320494249ULL
# struct _EFI_SYSTEM_TABLE {
#   EFI_TABLE_HEADER              Hdr;
# 
#   CHAR16                        *FirmwareVendor;
#   UINT32                        FirmwareRevision;
# 
#   EFI_HANDLE                    ConsoleInHandle;
#   EFI_SIMPLE_TEXT_IN_PROTOCOL   *ConIn;
# 
#   EFI_HANDLE                    ConsoleOutHandle;
#   EFI_SIMPLE_TEXT_OUT_PROTOCOL  *ConOut;
# 
#   EFI_HANDLE                    StandardErrorHandle;
#   EFI_SIMPLE_TEXT_OUT_PROTOCOL  *StdErr;
# 
#   EFI_RUNTIME_SERVICES          *RuntimeServices;
#   EFI_BOOT_SERVICES             *BootServices;
# 
#   UINTN                         NumberOfTableEntries;
#   EFI_CONFIGURATION_TABLE       *ConfigurationTable;
# 
# };

EFI_SYSTEM_TABLE_SIGNATURE     = 'IBI SYST'

EFI_2_50_SYSTEM_TABLE_REVISION = ((2 << 16) | (50))
EFI_2_40_SYSTEM_TABLE_REVISION = ((2 << 16) | (40))
EFI_2_31_SYSTEM_TABLE_REVISION = ((2 << 16) | (31))
EFI_2_30_SYSTEM_TABLE_REVISION = ((2 << 16) | (30))
EFI_2_20_SYSTEM_TABLE_REVISION = ((2 << 16) | (20))
EFI_2_10_SYSTEM_TABLE_REVISION = ((2 << 16) | (10))
EFI_2_00_SYSTEM_TABLE_REVISION = ((2 << 16) | (00))
EFI_1_10_SYSTEM_TABLE_REVISION = ((1 << 16) | (10))
EFI_1_02_SYSTEM_TABLE_REVISION = ((1 << 16) | (02))
EFI_REVISIONS = [EFI_2_50_SYSTEM_TABLE_REVISION, EFI_2_40_SYSTEM_TABLE_REVISION, EFI_2_31_SYSTEM_TABLE_REVISION, EFI_2_30_SYSTEM_TABLE_REVISION, EFI_2_20_SYSTEM_TABLE_REVISION, EFI_2_10_SYSTEM_TABLE_REVISION, EFI_2_00_SYSTEM_TABLE_REVISION, EFI_1_10_SYSTEM_TABLE_REVISION, EFI_1_02_SYSTEM_TABLE_REVISION ]

def EFI_SYSTEM_TABLE_REVISION(revision):
    return ('%d.%d' % (revision>>16,revision&0xFFFF) )

EFI_SYSTEM_TABLE_FMT  = '=12Q'
class EFI_SYSTEM_TABLE( namedtuple('EFI_SYSTEM_TABLE', 'FirmwareVendor FirmwareRevision ConsoleInHandle ConIn ConsoleOutHandle ConOut StandardErrorHandle StdErr RuntimeServices BootServices NumberOfTableEntries ConfigurationTable') ):
    __slots__ = ()
    def __str__(self):
        return """EFI System Table:
  FirmwareVendor      : 0x%016X
  FirmwareRevision    : 0x%016X
  ConsoleInHandle     : 0x%016X
  ConIn               : 0x%016X
  ConsoleOutHandle    : 0x%016X
  ConOut              : 0x%016X
  StandardErrorHandle : 0x%016X
  StdErr              : 0x%016X
  RuntimeServices     : 0x%016X
  BootServices        : 0x%016X
  NumberOfTableEntries: 0x%016X
  ConfigurationTable  : 0x%016X
""" % ( self.FirmwareVendor, self.FirmwareRevision, self.ConsoleInHandle, self.ConIn, self.ConsoleOutHandle, self.ConOut, self.StandardErrorHandle, self.StdErr, self.RuntimeServices, self.BootServices, self.NumberOfTableEntries, self.ConfigurationTable )


# #################################################################################################
# EFI Runtime Services Table
# #################################################################################################
#
# \MdePkg\Include\Uefi\UefiSpec.h
# -------------------------------
# 
# #define EFI_RUNTIME_SERVICES_SIGNATURE  SIGNATURE_64 ('R','U','N','T','S','E','R','V')
# #define EFI_RUNTIME_SERVICES_REVISION   EFI_2_31_SYSTEM_TABLE_REVISION
# 
# ///
# /// EFI Runtime Services Table.
# ///
# typedef struct {
#   ///
#   /// The table header for the EFI Runtime Services Table.
#   ///
#   EFI_TABLE_HEADER                Hdr;
# 
#   //
#   // Time Services
#   //
#   EFI_GET_TIME                    GetTime;
#   EFI_SET_TIME                    SetTime;
#   EFI_GET_WAKEUP_TIME             GetWakeupTime;
#   EFI_SET_WAKEUP_TIME             SetWakeupTime;
# 
#   //
#   // Virtual Memory Services
#   //
#   EFI_SET_VIRTUAL_ADDRESS_MAP     SetVirtualAddressMap;
#   EFI_CONVERT_POINTER             ConvertPointer;
# 
#   //
#   // Variable Services
#   //
#   EFI_GET_VARIABLE                GetVariable;
#   EFI_GET_NEXT_VARIABLE_NAME      GetNextVariableName;
#   EFI_SET_VARIABLE                SetVariable;
# 
#   //
#   // Miscellaneous Services
#   //
#   EFI_GET_NEXT_HIGH_MONO_COUNT    GetNextHighMonotonicCount;
#   EFI_RESET_SYSTEM                ResetSystem;
# 
#   //
#   // UEFI 2.0 Capsule Services
#   //
#   EFI_UPDATE_CAPSULE              UpdateCapsule;
#   EFI_QUERY_CAPSULE_CAPABILITIES  QueryCapsuleCapabilities;
# 
#   //
#   // Miscellaneous UEFI 2.0 Service
#   //
#   EFI_QUERY_VARIABLE_INFO         QueryVariableInfo;
# } EFI_RUNTIME_SERVICES;

EFI_RUNTIME_SERVICES_SIGNATURE  = 'RUNTSERV'
EFI_RUNTIME_SERVICES_REVISION   = EFI_2_31_SYSTEM_TABLE_REVISION

EFI_RUNTIME_SERVICES_TABLE_FMT  = '=14Q'

class EFI_RUNTIME_SERVICES_TABLE( namedtuple('EFI_RUNTIME_SERVICES_TABLE', 'GetTime SetTime GetWakeupTime SetWakeupTime SetVirtualAddressMap ConvertPointer GetVariable GetNextVariableName SetVariable GetNextHighMonotonicCount ResetSystem UpdateCapsule QueryCapsuleCapabilities QueryVariableInfo') ):
    __slots__ = ()
    def __str__(self):
        return """Runtime Services:
  GetTime                  : 0x%016X
  SetTime                  : 0x%016X
  GetWakeupTime            : 0x%016X
  SetWakeupTime            : 0x%016X
  SetVirtualAddressMap     : 0x%016X
  ConvertPointer           : 0x%016X
  GetVariable              : 0x%016X
  GetNextVariableName      : 0x%016X
  SetVariable              : 0x%016X
  GetNextHighMonotonicCount: 0x%016X
  ResetSystem              : 0x%016X
  UpdateCapsule            : 0x%016X
  QueryCapsuleCapabilities : 0x%016X
  QueryVariableInfo        : 0x%016X
""" % ( self.GetTime, self.SetTime, self.GetWakeupTime, self.SetWakeupTime, self.SetVirtualAddressMap, self.ConvertPointer, self.GetVariable, self.GetNextVariableName, self.SetVariable, self.GetNextHighMonotonicCount, self.ResetSystem, self.UpdateCapsule, self.QueryCapsuleCapabilities, self.QueryVariableInfo )


# #################################################################################################
# EFI Boot Services Table
# #################################################################################################
#
# \MdePkg\Include\Uefi\UefiSpec.h
# -------------------------------
# 
# #define EFI_BOOT_SERVICES_SIGNATURE   SIGNATURE_64 ('B','O','O','T','S','E','R','V')
# #define EFI_BOOT_SERVICES_REVISION    EFI_2_31_SYSTEM_TABLE_REVISION
# 
# ///
# /// EFI Boot Services Table.
# ///
# typedef struct {
#   ///
#   /// The table header for the EFI Boot Services Table.
#   ///
#   EFI_TABLE_HEADER                Hdr;
# 
#   //
#   // Task Priority Services
#   //
#   EFI_RAISE_TPL                   RaiseTPL;
#   EFI_RESTORE_TPL                 RestoreTPL;
# 
#   //
#   // Memory Services
#   //
#   EFI_ALLOCATE_PAGES              AllocatePages;
#   EFI_FREE_PAGES                  FreePages;
#   EFI_GET_MEMORY_MAP              GetMemoryMap;
#   EFI_ALLOCATE_POOL               AllocatePool;
#   EFI_FREE_POOL                   FreePool;
# 
#   //
#   // Event & Timer Services
#   //
#   EFI_CREATE_EVENT                  CreateEvent;
#   EFI_SET_TIMER                     SetTimer;
#   EFI_WAIT_FOR_EVENT                WaitForEvent;
#   EFI_SIGNAL_EVENT                  SignalEvent;
#   EFI_CLOSE_EVENT                   CloseEvent;
#   EFI_CHECK_EVENT                   CheckEvent;
# 
#   //
#   // Protocol Handler Services
#   //
#   EFI_INSTALL_PROTOCOL_INTERFACE    InstallProtocolInterface;
#   EFI_REINSTALL_PROTOCOL_INTERFACE  ReinstallProtocolInterface;
#   EFI_UNINSTALL_PROTOCOL_INTERFACE  UninstallProtocolInterface;
#   EFI_HANDLE_PROTOCOL               HandleProtocol;
#   VOID                              *Reserved;
#   EFI_REGISTER_PROTOCOL_NOTIFY      RegisterProtocolNotify;
#   EFI_LOCATE_HANDLE                 LocateHandle;
#   EFI_LOCATE_DEVICE_PATH            LocateDevicePath;
#   EFI_INSTALL_CONFIGURATION_TABLE   InstallConfigurationTable;
# 
#   //
#   // Image Services
#   //
#   EFI_IMAGE_LOAD                    LoadImage;
#   EFI_IMAGE_START                   StartImage;
#   EFI_EXIT                          Exit;
#   EFI_IMAGE_UNLOAD                  UnloadImage;
#   EFI_EXIT_BOOT_SERVICES            ExitBootServices;
# 
#   //
#   // Miscellaneous Services
#   //
#   EFI_GET_NEXT_MONOTONIC_COUNT      GetNextMonotonicCount;
#   EFI_STALL                         Stall;
#   EFI_SET_WATCHDOG_TIMER            SetWatchdogTimer;
# 
#   //
#   // DriverSupport Services
#   //
#   EFI_CONNECT_CONTROLLER            ConnectController;
#   EFI_DISCONNECT_CONTROLLER         DisconnectController;
# 
#   //
#   // Open and Close Protocol Services
#   //
#   EFI_OPEN_PROTOCOL                 OpenProtocol;
#   EFI_CLOSE_PROTOCOL                CloseProtocol;
#   EFI_OPEN_PROTOCOL_INFORMATION     OpenProtocolInformation;
# 
#   //
#   // Library Services
#   //
#   EFI_PROTOCOLS_PER_HANDLE          ProtocolsPerHandle;
#   EFI_LOCATE_HANDLE_BUFFER          LocateHandleBuffer;
#   EFI_LOCATE_PROTOCOL               LocateProtocol;
#   EFI_INSTALL_MULTIPLE_PROTOCOL_INTERFACES    InstallMultipleProtocolInterfaces;
#   EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES  UninstallMultipleProtocolInterfaces;
# 
#   //
#   // 32-bit CRC Services
#   //
#   EFI_CALCULATE_CRC32               CalculateCrc32;
# 
#   //
#   // Miscellaneous Services
#   //
#   EFI_COPY_MEM                      CopyMem;
#   EFI_SET_MEM                       SetMem;
#   EFI_CREATE_EVENT_EX               CreateEventEx;
# } EFI_BOOT_SERVICES;

EFI_BOOT_SERVICES_SIGNATURE = 'BOOTSERV'
EFI_BOOT_SERVICES_REVISION  = EFI_2_31_SYSTEM_TABLE_REVISION

EFI_BOOT_SERVICES_TABLE_FMT  = '=44Q'

class EFI_BOOT_SERVICES_TABLE( namedtuple('EFI_BOOT_SERVICES_TABLE', 'RaiseTPL RestoreTPL AllocatePages FreePages GetMemoryMap AllocatePool FreePool CreateEvent SetTimer WaitForEvent SignalEvent CloseEvent CheckEvent InstallProtocolInterface ReinstallProtocolInterface UninstallProtocolInterface HandleProtocol Reserved RegisterProtocolNotify LocateHandle LocateDevicePath InstallConfigurationTable LoadImage StartImage Exit UnloadImage ExitBootServices GetNextMonotonicCount Stall SetWatchdogTimer ConnectController DisconnectController OpenProtocol CloseProtocol OpenProtocolInformation ProtocolsPerHandle LocateHandleBuffer LocateProtocol InstallMultipleProtocolInterfaces UninstallMultipleProtocolInterfaces CalculateCrc32 CopyMem SetMem CreateEventEx') ):
    __slots__ = ()
    def __str__(self):
        return """Boot Services:
  RaiseTPL                           : 0x%016X
  RestoreTPL                         : 0x%016X
  AllocatePages                      : 0x%016X
  FreePages                          : 0x%016X
  GetMemoryMap                       : 0x%016X
  AllocatePool                       : 0x%016X
  FreePool                           : 0x%016X
  CreateEvent                        : 0x%016X
  SetTimer                           : 0x%016X
  WaitForEvent                       : 0x%016X
  SignalEvent                        : 0x%016X
  CloseEvent                         : 0x%016X
  CheckEvent                         : 0x%016X
  InstallProtocolInterface           : 0x%016X
  ReinstallProtocolInterface         : 0x%016X
  UninstallProtocolInterface         : 0x%016X
  HandleProtocol                     : 0x%016X
  Reserved                           : 0x%016X
  RegisterProtocolNotify             : 0x%016X
  LocateHandle                       : 0x%016X
  LocateDevicePath                   : 0x%016X
  InstallConfigurationTable          : 0x%016X
  LoadImage                          : 0x%016X
  StartImage                         : 0x%016X
  Exit                               : 0x%016X
  UnloadImage                        : 0x%016X
  ExitBootServices                   : 0x%016X
  GetNextMonotonicCount              : 0x%016X
  Stall                              : 0x%016X
  SetWatchdogTimer                   : 0x%016X
  ConnectController                  : 0x%016X
  DisconnectController               : 0x%016X
  OpenProtocol                       : 0x%016X
  CloseProtocol                      : 0x%016X
  OpenProtocolInformation            : 0x%016X
  ProtocolsPerHandle                 : 0x%016X
  LocateHandleBuffer                 : 0x%016X
  LocateProtocol                     : 0x%016X
  InstallMultipleProtocolInterfaces  : 0x%016X
  UninstallMultipleProtocolInterfaces: 0x%016X
  CalculateCrc32                     : 0x%016X
  CopyMem                            : 0x%016X
  SetMem                             : 0x%016X
  CreateEventEx                      : 0x%016X
""" % ( self.RaiseTPL, self.RestoreTPL, self.AllocatePages, self.FreePages, self.GetMemoryMap, self.AllocatePool, self.FreePool, self.CreateEvent, self.SetTimer, self.WaitForEvent, self.SignalEvent, self.CloseEvent, self.CheckEvent, self.InstallProtocolInterface, self.ReinstallProtocolInterface, self.UninstallProtocolInterface, self.HandleProtocol, self.Reserved, self.RegisterProtocolNotify, self.LocateHandle, self.LocateDevicePath, self.InstallConfigurationTable, self.LoadImage, self.StartImage, self.Exit, self.UnloadImage, self.ExitBootServices, self.GetNextMonotonicCount, self.Stall, self.SetWatchdogTimer, self.ConnectController, self.DisconnectController, self.OpenProtocol, self.CloseProtocol, self.OpenProtocolInformation, self.ProtocolsPerHandle, self.LocateHandleBuffer, self.LocateProtocol, self.InstallMultipleProtocolInterfaces, self.UninstallMultipleProtocolInterfaces, self.CalculateCrc32, self.CopyMem, self.SetMem, self.CreateEventEx )


# #################################################################################################
# EFI System Configuration Table
# #################################################################################################
#
# \MdePkg\Include\Uefi\UefiSpec.h
# -------------------------------
#
#///
#/// Contains a set of GUID/pointer pairs comprised of the ConfigurationTable field in the
#/// EFI System Table.
#///
#typedef struct {
#  ///
#  /// The 128-bit GUID value that uniquely identifies the system configuration table.
#  ///
#  EFI_GUID                          VendorGuid;
#  ///
#  /// A pointer to the table associated with VendorGuid.
#  ///
#  VOID                              *VendorTable;
#} EFI_CONFIGURATION_TABLE;
#

EFI_VENDOR_TABLE_FORMAT = '<' + EFI_GUID_FMT + 'Q'
EFI_VENDOR_TABLE_SIZE   = struct.calcsize(EFI_VENDOR_TABLE_FORMAT)

class EFI_VENDOR_TABLE( namedtuple('EFI_VENDOR_TABLE', 'VendorGuid0 VendorGuid1 VendorGuid2 VendorGuid3 VendorTable') ):
    __slots__ = ()
    def VendorGuid(self):
        return EFI_GUID(self.VendorGuid0,self.VendorGuid1,self.VendorGuid2,self.VendorGuid3)

class EFI_CONFIGURATION_TABLE():
    def __init__( self ):
        self.VendorTables = {}
    def __str__(self):
        return ( 'Vendor Tables:\n%s' % (''.join( ['{%s} : 0x%016X\n' % (vt,self.VendorTables[vt]) for vt in self.VendorTables])) )


# #################################################################################################
# EFI DXE Services Table
# #################################################################################################
#
# \MdePkg\Include\Pi\PiDxeCis.h
# -----------------------------
# 
# //
# // DXE Services Table
# //
# #define DXE_SERVICES_SIGNATURE            0x565245535f455844ULL
# #define DXE_SPECIFICATION_MAJOR_REVISION  1
# #define DXE_SPECIFICATION_MINOR_REVISION  20
# #define DXE_SERVICES_REVISION             ((DXE_SPECIFICATION_MAJOR_REVISION<<16) | (DXE_SPECIFICATION_MINOR_REVISION))
# 
# typedef struct {
#   ///
#   /// The table header for the DXE Services Table.
#   /// This header contains the DXE_SERVICES_SIGNATURE and DXE_SERVICES_REVISION values.
#   ///
#   EFI_TABLE_HEADER                Hdr;
# 
#   //
#   // Global Coherency Domain Services
#   //
#   EFI_ADD_MEMORY_SPACE            AddMemorySpace;
#   EFI_ALLOCATE_MEMORY_SPACE       AllocateMemorySpace;
#   EFI_FREE_MEMORY_SPACE           FreeMemorySpace;
#   EFI_REMOVE_MEMORY_SPACE         RemoveMemorySpace;
#   EFI_GET_MEMORY_SPACE_DESCRIPTOR GetMemorySpaceDescriptor;
#   EFI_SET_MEMORY_SPACE_ATTRIBUTES SetMemorySpaceAttributes;
#   EFI_GET_MEMORY_SPACE_MAP        GetMemorySpaceMap;
#   EFI_ADD_IO_SPACE                AddIoSpace;
#   EFI_ALLOCATE_IO_SPACE           AllocateIoSpace;
#   EFI_FREE_IO_SPACE               FreeIoSpace;
#   EFI_REMOVE_IO_SPACE             RemoveIoSpace;
#   EFI_GET_IO_SPACE_DESCRIPTOR     GetIoSpaceDescriptor;
#   EFI_GET_IO_SPACE_MAP            GetIoSpaceMap;
# 
#   //
#   // Dispatcher Services
#   //
#   EFI_DISPATCH                    Dispatch;
#   EFI_SCHEDULE                    Schedule;
#   EFI_TRUST                       Trust;
#   //
#   // Service to process a single firmware volume found in a capsule
#   //
#   EFI_PROCESS_FIRMWARE_VOLUME     ProcessFirmwareVolume;
# } DXE_SERVICES;

#DXE_SERVICES_SIGNATURE           = 0x565245535f455844
#DXE_SPECIFICATION_MAJOR_REVISION = 1
#DXE_SPECIFICATION_MINOR_REVISION = 20
#DXE_SERVICES_REVISION            = ((DXE_SPECIFICATION_MAJOR_REVISION<<16) | (DXE_SPECIFICATION_MINOR_REVISION))


EFI_DXE_SERVICES_TABLE_SIGNATURE  = 'DXE_SERV' # 0x565245535f455844
EFI_DXE_SERVICES_TABLE_FMT        = '=17Q'
class EFI_DXE_SERVICES_TABLE( namedtuple('EFI_DXE_SERVICES_TABLE', 'AddMemorySpace AllocateMemorySpace FreeMemorySpace RemoveMemorySpace GetMemorySpaceDescriptor SetMemorySpaceAttributes GetMemorySpaceMap AddIoSpace AllocateIoSpace FreeIoSpace RemoveIoSpace GetIoSpaceDescriptor GetIoSpaceMap Dispatch Schedule Trust ProcessFirmwareVolume') ):
    __slots__ = ()
    def __str__(self):
        return """DXE Services:
  AddMemorySpace          : 0x%016X
  AllocateMemorySpace     : 0x%016X
  FreeMemorySpace         : 0x%016X
  RemoveMemorySpace       : 0x%016X
  GetMemorySpaceDescriptor: 0x%016X
  SetMemorySpaceAttributes: 0x%016X
  GetMemorySpaceMap       : 0x%016X
  AddIoSpace              : 0x%016X
  AllocateIoSpace         : 0x%016X
  FreeIoSpace             : 0x%016X
  RemoveIoSpace           : 0x%016X
  GetIoSpaceDescriptor    : 0x%016X
  GetIoSpaceMap           : 0x%016X
  Dispatch                : 0x%016X
  Schedule                : 0x%016X
  Trust                   : 0x%016X
  ProcessFirmwareVolume   : 0x%016X
""" % ( self.AddMemorySpace, self.AllocateMemorySpace, self.FreeMemorySpace, self.RemoveMemorySpace, self.GetMemorySpaceDescriptor, self.SetMemorySpaceAttributes, self.GetMemorySpaceMap, self.AddIoSpace, self.AllocateIoSpace, self.FreeIoSpace, self.RemoveIoSpace, self.GetIoSpaceDescriptor, self.GetIoSpaceMap, self.Dispatch, self.Schedule, self.Trust, self.ProcessFirmwareVolume )



# #################################################################################################
# EFI PEI Services Table
# #################################################################################################
#
# //
# // Framework PEI Specification Revision information
# //
# #define FRAMEWORK_PEI_SPECIFICATION_MAJOR_REVISION    0
# #define FRAMEWORK_PEI_SPECIFICATION_MINOR_REVISION    91
# 
# 
# //
# // PEI services signature and Revision defined in Framework PEI spec
# //
# #define FRAMEWORK_PEI_SERVICES_SIGNATURE               0x5652455320494550ULL
# #define FRAMEWORK_PEI_SERVICES_REVISION               ((FRAMEWORK_PEI_SPECIFICATION_MAJOR_REVISION<<16) | (FRAMEWORK_PEI_SPECIFICATION_MINOR_REVISION))
# 
# ///
# ///  FRAMEWORK_EFI_PEI_SERVICES is a collection of functions whose implementation is provided by the PEI
# ///  Foundation. The table may be located in the temporary or permanent memory, depending upon the capabilities 
# ///  and phase of execution of PEI.
# ///  
# ///  These services fall into various classes, including the following:
# ///  - Managing the boot mode.
# ///  - Allocating both early and permanent memory.
# ///  - Supporting the Firmware File System (FFS).
# ///  - Abstracting the PPI database abstraction.
# ///  - Creating Hand-Off Blocks (HOBs).
# ///        
# struct _FRAMEWORK_EFI_PEI_SERVICES {
#   EFI_TABLE_HEADER                  Hdr;
#   //
#   // PPI Functions
#   //
#   EFI_PEI_INSTALL_PPI               InstallPpi;
#   EFI_PEI_REINSTALL_PPI             ReInstallPpi;
#   EFI_PEI_LOCATE_PPI                LocatePpi;
#   EFI_PEI_NOTIFY_PPI                NotifyPpi;
#   //
#   // Boot Mode Functions
#   //
#   EFI_PEI_GET_BOOT_MODE             GetBootMode;
#   EFI_PEI_SET_BOOT_MODE             SetBootMode;
#   //
#   // HOB Functions
#   //
#   EFI_PEI_GET_HOB_LIST              GetHobList;
#   EFI_PEI_CREATE_HOB                CreateHob;
#   //
#   // Firmware Volume Functions
#   //
#   EFI_PEI_FFS_FIND_NEXT_VOLUME      FfsFindNextVolume;
#   EFI_PEI_FFS_FIND_NEXT_FILE        FfsFindNextFile;
#   EFI_PEI_FFS_FIND_SECTION_DATA     FfsFindSectionData;
#   //
#   // PEI Memory Functions
#   //
#   EFI_PEI_INSTALL_PEI_MEMORY        InstallPeiMemory;
#   EFI_PEI_ALLOCATE_PAGES            AllocatePages;
#   EFI_PEI_ALLOCATE_POOL             AllocatePool;
#   EFI_PEI_COPY_MEM                  CopyMem;
#   EFI_PEI_SET_MEM                   SetMem;
#   //
#   // (the following interfaces are installed by publishing PEIM)
#   // Status Code
#   //
#   EFI_PEI_REPORT_STATUS_CODE        ReportStatusCode;
#   //
#   // Reset
#   //
#   EFI_PEI_RESET_SYSTEM              ResetSystem;
#   ///
#   /// Inconsistent with specification here: 
#   /// In Framework Spec, PeiCis0.91, CpuIo and PciCfg are NOT pointers. 
#   ///
#   
#   //
#   // I/O Abstractions
#   //
#   EFI_PEI_CPU_IO_PPI                *CpuIo;
#   EFI_PEI_PCI_CFG_PPI               *PciCfg;
# };

EFI_FRAMEWORK_PEI_SERVICES_TABLE_SIGNATURE = 0x5652455320494550
#FRAMEWORK_PEI_SERVICES_SIGNATURE           = 0x5652455320494550
FRAMEWORK_PEI_SPECIFICATION_MAJOR_REVISION = 0
FRAMEWORK_PEI_SPECIFICATION_MINOR_REVISION = 91
FRAMEWORK_PEI_SERVICES_REVISION            = ((FRAMEWORK_PEI_SPECIFICATION_MAJOR_REVISION<<16) | (FRAMEWORK_PEI_SPECIFICATION_MINOR_REVISION))

# #################################################################################################
# EFI System Management System Table
# #################################################################################################
#
#define SMM_SMST_SIGNATURE            EFI_SIGNATURE_32 ('S', 'M', 'S', 'T')
#define EFI_SMM_SYSTEM_TABLE_REVISION (0 << 16) | (0x09)
# //
# // System Management System Table (SMST)
# //
# struct _EFI_SMM_SYSTEM_TABLE {
#   ///
#   /// The table header for the System Management System Table (SMST). 
#   ///
#   EFI_TABLE_HEADER                    Hdr;
# 
#   ///
#   /// A pointer to a NULL-terminated Unicode string containing the vendor name. It is
#   /// permissible for this pointer to be NULL.
#   ///
#   CHAR16                              *SmmFirmwareVendor;
#   ///
#   /// The particular revision of the firmware.
#   ///
#   UINT32                              SmmFirmwareRevision;
# 
#   ///
#   /// Adds, updates, or removes a configuration table entry from the SMST. 
#   ///
#   EFI_SMM_INSTALL_CONFIGURATION_TABLE SmmInstallConfigurationTable;
# 
#   //
#   // I/O Services
#   //
#   ///
#   /// A GUID that designates the particular CPU I/O services. 
#   ///
#   EFI_GUID                            EfiSmmCpuIoGuid;
#   ///
#   /// Provides the basic memory and I/O interfaces that are used to abstract accesses to
#   /// devices.
#   ///
#   EFI_SMM_CPU_IO_INTERFACE            SmmIo;
# 
#   //
#   // Runtime memory service
#   //
#   ///
#   ///
#   /// Allocates pool memory from SMRAM for IA-32 or runtime memory for the
#   /// Itanium processor family.
#   ///
#   EFI_SMMCORE_ALLOCATE_POOL           SmmAllocatePool;
#   ///
#   /// Returns pool memory to the system. 
#   ///
#   EFI_SMMCORE_FREE_POOL               SmmFreePool;
#   ///
#   /// Allocates memory pages from the system. 
#   ///
#   EFI_SMMCORE_ALLOCATE_PAGES          SmmAllocatePages;
#   ///
#   /// Frees memory pages for the system.
#   ///
#   EFI_SMMCORE_FREE_PAGES              SmmFreePages;
# 
#   //
#   // MP service
#   //
#   
#   /// Inconsistent with specification here:
#   ///  In Framework Spec, this definition does not exist. This method is introduced in PI1.1 specification for 
#   ///  the implementation needed.
#   EFI_SMM_STARTUP_THIS_AP             SmmStartupThisAp;
# 
#   //
#   // CPU information records
#   //
#   ///
#   /// A 1-relative number between 1 and the NumberOfCpus field. This field designates
#   /// which processor is executing the SMM infrastructure. This number also serves as an
#   /// index into the CpuSaveState and CpuOptionalFloatingPointState
#   /// fields.
#   ///
#   UINTN                               CurrentlyExecutingCpu;
#   ///
#   /// The number of EFI Configuration Tables in the buffer
#   /// SmmConfigurationTable.
#   ///
#   UINTN                               NumberOfCpus;
#   ///
#   /// A pointer to the EFI Configuration Tables. The number of entries in the table is
#   /// NumberOfTableEntries.
#   ///
#   EFI_SMM_CPU_SAVE_STATE              *CpuSaveState;
#   ///
#   /// A pointer to a catenation of the EFI_SMM_FLOATING_POINT_SAVE_STATE.
#   /// The size of this entire table is NumberOfCpus* size of the
#   /// EFI_SMM_FLOATING_POINT_SAVE_STATE. These fields are populated only if
#   /// there is at least one SMM driver that has registered for a callback with the
#   /// FloatingPointSave field in EFI_SMM_BASE_PROTOCOL.RegisterCallback() set to TRUE.
#   ///
#   EFI_SMM_FLOATING_POINT_SAVE_STATE   *CpuOptionalFloatingPointState;
# 
#   //
#   // Extensibility table
#   //
#   ///
#   /// The number of EFI Configuration Tables in the buffer
#   /// SmmConfigurationTable.
#   ///
#   UINTN                               NumberOfTableEntries;
#   ///
#   /// A pointer to the EFI Configuration Tables. The number of entries in the table is
#   /// NumberOfTableEntries.
#   ///
#   EFI_CONFIGURATION_TABLE             *SmmConfigurationTable;
# };

EFI_SMM_SYSTEM_TABLE_SIGNATURE = 'SMST'
EFI_SMM_SYSTEM_TABLE_REVISION = (0 << 16) | (0x09)




EFI_TABLES = {
  EFI_SYSTEM_TABLE_SIGNATURE                 : {'name' : 'EFI System Table',                 'struct' : EFI_SYSTEM_TABLE,                 'fmt' : EFI_SYSTEM_TABLE_FMT                 },
  EFI_RUNTIME_SERVICES_SIGNATURE             : {'name' : 'EFI Runtime Services Table',       'struct' : EFI_RUNTIME_SERVICES_TABLE,       'fmt' : EFI_RUNTIME_SERVICES_TABLE_FMT       },
  EFI_BOOT_SERVICES_SIGNATURE                : {'name' : 'EFI Boot Services Table',          'struct' : EFI_BOOT_SERVICES_TABLE,          'fmt' : EFI_BOOT_SERVICES_TABLE_FMT          },
  EFI_DXE_SERVICES_TABLE_SIGNATURE           : {'name' : 'EFI DXE Services Table',           'struct' : EFI_DXE_SERVICES_TABLE,           'fmt' : EFI_DXE_SERVICES_TABLE_FMT           }
  #EFI_FRAMEWORK_PEI_SERVICES_TABLE_SIGNATURE : {'name' : 'EFI Framework PEI Services Table', 'struct' : EFI_FRAMEWORK_PEI_SERVICES_TABLE, 'fmt' : EFI_FRAMEWORK_PEI_SERVICES_TABLE_FMT },
  #EFI_SMM_SYSTEM_TABLE_SIGNATURE             : {'name' : 'EFI SMM System Table',             'struct' : EFI_SMM_SYSTEM_TABLE,             'fmt' : EFI_SMM_SYSTEM_TABLE_FMT             },
  #EFI_CONFIG_TABLE_SIGNATURE                 : {'name' : 'EFI Configuration Table',          'struct' : EFI_CONFIG_TABLE,                 'fmt' : EFI_CONFIG_TABLE_FMT                 } 
}
