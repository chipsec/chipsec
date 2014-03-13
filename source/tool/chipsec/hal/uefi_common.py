#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2014, Intel Corporation
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
## \addtogroup hal
# chipsec/hal/uefi_common.py
# ==========================
# Common UEFI functionality (EFI variables, db/dbx decode, etc.)
#
#
__version__ = '1.0'

import os
import struct
from collections import namedtuple

from chipsec.file import *
from chipsec.logger import *

################################################################################################
# EFI Variable and Variable Store Defines
#

"""
UDK2010.SR1\MdeModulePkg\Include\Guid\VariableFormat.h 

#ifndef __VARIABLE_FORMAT_H__
#define __VARIABLE_FORMAT_H__

#define EFI_VARIABLE_GUID \
  { 0xddcf3616, 0x3275, 0x4164, { 0x98, 0xb6, 0xfe, 0x85, 0x70, 0x7f, 0xfe, 0x7d } }

extern EFI_GUID gEfiVariableGuid;

///
/// Alignment of variable name and data, according to the architecture:
/// * For IA-32 and Intel(R) 64 architectures: 1.
/// * For IA-64 architecture: 8.
///
#if defined (MDE_CPU_IPF)
#define ALIGNMENT         8
#else
#define ALIGNMENT         1
#endif

//
// GET_PAD_SIZE calculates the miminal pad bytes needed to make the current pad size satisfy the alignment requirement.
//
#if (ALIGNMENT == 1)
#define GET_PAD_SIZE(a) (0)
#else
#define GET_PAD_SIZE(a) (((~a) + 1) & (ALIGNMENT - 1))
#endif

///
/// Alignment of Variable Data Header in Variable Store region.
///
#define HEADER_ALIGNMENT  4
#define HEADER_ALIGN(Header)  (((UINTN) (Header) + HEADER_ALIGNMENT - 1) & (~(HEADER_ALIGNMENT - 1)))

///
/// Status of Variable Store Region.
///
typedef enum {
  EfiRaw,
  EfiValid,
  EfiInvalid,
  EfiUnknown
} VARIABLE_STORE_STATUS;

#pragma pack(1)

#define VARIABLE_STORE_SIGNATURE  EFI_VARIABLE_GUID

///
/// Variable Store Header Format and State.
///
#define VARIABLE_STORE_FORMATTED          0x5a
#define VARIABLE_STORE_HEALTHY            0xfe

///
/// Variable Store region header.
///
typedef struct {
  ///
  /// Variable store region signature.
  ///
  EFI_GUID  Signature;
  ///
  /// Size of entire variable store, 
  /// including size of variable store header but not including the size of FvHeader.
  ///
  UINT32  Size;
  ///
  /// Variable region format state.
  ///
  UINT8   Format;
  ///
  /// Variable region healthy state.
  ///
  UINT8   State;
  UINT16  Reserved;
  UINT32  Reserved1;
} VARIABLE_STORE_HEADER;

///
/// Variable data start flag.
///
#define VARIABLE_DATA                     0x55AA

///
/// Variable State flags.
///
#define VAR_IN_DELETED_TRANSITION     0xfe  ///< Variable is in obsolete transition.
#define VAR_DELETED                   0xfd  ///< Variable is obsolete.
#define VAR_HEADER_VALID_ONLY         0x7f  ///< Variable header has been valid.
#define VAR_ADDED                     0x3f  ///< Variable has been completely added.

///
/// Single Variable Data Header Structure.
///
typedef struct {
  ///
  /// Variable Data Start Flag.
  ///
  UINT16      StartId;
  ///
  /// Variable State defined above.
  ///
  UINT8       State;
  UINT8       Reserved;
  ///
  /// Attributes of variable defined in UEFI specification.
  ///
  UINT32      Attributes;
  ///
  /// Size of variable null-terminated Unicode string name.
  ///
  UINT32      NameSize;
  ///
  /// Size of the variable data without this header.
  ///
  UINT32      DataSize;
  ///
  /// A unique identifier for the vendor that produces and consumes this varaible.
  ///
  EFI_GUID    VendorGuid;
} VARIABLE_HEADER;

#pragma pack()

typedef struct _VARIABLE_INFO_ENTRY  VARIABLE_INFO_ENTRY;

///
/// This structure contains the variable list that is put in EFI system table.
/// The variable driver collects all variables that were used at boot service time and produces this list.
/// This is an optional feature to dump all used variables in shell environment. 
///
struct _VARIABLE_INFO_ENTRY {
  VARIABLE_INFO_ENTRY *Next;       ///< Pointer to next entry.
  EFI_GUID            VendorGuid;  ///< Guid of Variable.
  CHAR16              *Name;       ///< Name of Variable. 
  UINT32              Attributes;  ///< Attributes of variable defined in UEFI specification.
  UINT32              ReadCount;   ///< Number of times to read this variable.
  UINT32              WriteCount;  ///< Number of times to write this variable.
  UINT32              DeleteCount; ///< Number of times to delete this variable.
  UINT32              CacheCount;  ///< Number of times that cache hits this variable.
  BOOLEAN             Volatile;    ///< TRUE if volatile, FALSE if non-volatile.
};

#endif // _EFI_VARIABLE_H_
"""


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


#################################################################################################

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

#################################################################################################

GUID = "<IHH8s"
guid_size = struct.calcsize(GUID)

EFI_COMPRESSION_SECTION = "<IB"
EFI_COMPRESSION_SECTION_size = struct.calcsize(EFI_COMPRESSION_SECTION)

EFI_GUID_DEFINED_SECTION = "<IHH8sHH"
EFI_GUID_DEFINED_SECTION_size = struct.calcsize(EFI_GUID_DEFINED_SECTION)

EFI_CRC32_GUIDED_SECTION_EXTRACTION_PROTOCOL_GUID = "FC1BCDB0-7D31-49AA-936A-A4600D9DD083"

EFI_FIRMWARE_FILE_SYSTEM_GUID  = "7A9354D9-0468-444A-81CE-0BF617D890DF"
EFI_FIRMWARE_FILE_SYSTEM2_GUID = "8C8CE578-8A3D-4F1C-9935-896185C32DD3"

#################################################################################################

MAX_VARIABLE_SIZE = 1024
MAX_NVRAM_SIZE    = 1024*1024

#################################################################################################
# Helper functions
#################################################################################################

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

#################################################################################################
# Common NVRAM functions
#################################################################################################

VARIABLE_SIGNATURE_VSS = VARIABLE_DATA_SIGNATURE


#################################################################################################
# Common Firmware Volume functions
#################################################################################################

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

# this line breaks uefi shell
#from array import array

def DecompressSection(CompressedFileName, OutputFileName, CompressionType):
    from subprocess import call
    from chipsec.file import read_file
    decompressed = None
    edk2path = os.path.join('..','..','tools','edk2','win')
    exe = None
    try:
        if   (CompressionType == 1):
            exe = os.path.join(edk2path,'TianoCompress.exe')
        elif (CompressionType == 2):
            exe = os.path.join(edk2path,'LzmaCompress.exe')
        else:
            pass
        if exe:
            call('%s -d -o %s %s' % (exe, OutputFileName, CompressedFileName))
        decompressed = read_file( OutputFileName )
    except:
       pass
    return decompressed

'''
typedef struct {
  ///
  /// Type of the signature. GUID signature types are defined in below.
  ///
  EFI_GUID            SignatureType;
  ///
  /// Total size of the signature list, including this header.
  ///
  UINT32              SignatureListSize;
  ///
  /// Size of the signature header which precedes the array of signatures.
  ///
  UINT32              SignatureHeaderSize;
  ///
  /// Size of each signature.
  ///
  UINT32              SignatureSize; 
  ///
  /// Header before the array of signatures. The format of this header is specified 
  /// by the SignatureType.
  /// UINT8           SignatureHeader[SignatureHeaderSize];
  ///
  /// An array of signatures. Each signature is SignatureSize bytes in length. 
  /// EFI_SIGNATURE_DATA Signatures[][SignatureSize];
  ///
} EFI_SIGNATURE_LIST;
'''
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


#################################################################################################



