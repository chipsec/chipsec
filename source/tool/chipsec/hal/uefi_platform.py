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
Platform specific UEFI functionality (parsing platform specific EFI NVRAM, capsules, etc.)
"""

__version__ = '1.0'

import struct
from collections import namedtuple

from chipsec.hal.uefi_common import *


#################################################################################################3
# List of supported types of EFI NVRAM format (platform/vendor specific)
#################################################################################################3

class FWType:
    EFI_FW_TYPE_UEFI     = 'uefi'
#    EFI_FW_TYPE_WIN      = 'win'     # Windows 8 GetFirmwareEnvironmentVariable format
    EFI_FW_TYPE_VSS      = 'vss'     # NVRAM using format with '$VSS' signature
    EFI_FW_TYPE_VSS_NEW  = 'vss_new' # NVRAM using format with '$VSS' signature (Newer one?)
    EFI_FW_TYPE_NVAR     = 'nvar'    # 'NVAR' NVRAM format
    EFI_FW_TYPE_EVSA     = 'evsa'    # 'EVSA' NVRAM format


fw_types = []
for i in [t for t in dir(FWType) if not callable(getattr(FWType, t))]:
    if not i.startswith('__'):
        fw_types.append( getattr(FWType, i) )


NVRAM_ATTR_RT         = 1
NVRAM_ATTR_DESC_ASCII = 2
NVRAM_ATTR_GUID       = 4
NVRAM_ATTR_DATA       = 8
NVRAM_ATTR_EXTHDR     = 0x10
NVRAM_ATTR_AUTHWR     = 0x40
NVRAM_ATTR_HER        = 0x20
NVRAM_ATTR_VLD        = 0x80

VARIABLE_STORE_FV_GUID = 'FFF12B8D-7696-4C8B-A985-2747075B4F50'

#################################################################################################3
# This Variable header is defined by UEFI
#################################################################################################3

#
# Variable Store Status
#
#typedef enum {
#  EfiRaw,
#  EfiValid,
#  EfiInvalid,
#  EfiUnknown
# } VARIABLE_STORE_STATUS;
VARIABLE_STORE_STATUS_RAW     = 0
VARIABLE_STORE_STATUS_VALID   = 1
VARIABLE_STORE_STATUS_INVALID = 2
VARIABLE_STORE_STATUS_UNKNOWN = 3

#
# Variable State flags
#
VAR_IN_DELETED_TRANSITION     = 0xfe  # Variable is in obsolete transistion
VAR_DELETED                   = 0xfd  # Variable is obsolete
VAR_ADDED                     = 0x7f  # Variable has been completely added
#IS_VARIABLE_STATE(_c, _Mask)  (BOOLEAN) (((~_c) & (~_Mask)) != 0)
def IS_VARIABLE_STATE(_c, _Mask):
    return ( ( ((~_c)&0xFF) & ((~_Mask)&0xFF) ) != 0 )

#
#typedef struct {
#  UINT16    StartId;
#  UINT8     State;
#  UINT8     Reserved;
#  UINT32    Attributes;
#  UINT32    NameSize;
#  UINT32    DataSize;
#  EFI_GUID  VendorGuid;
#} VARIABLE_HEADER;
#
#typedef struct {
#  UINT32  Data1;
#  UINT16  Data2;
#  UINT16  Data3;
#  UINT8   Data4[8];
#} EFI_GUID;
#
UEFI_VARIABLE_HEADER_SIZE = 28
class UEFI_VARIABLE_HEADER( namedtuple('UEFI_VARIABLE_HEADER', 'StartId State Reserved Attributes NameSize DataSize VendorGuid0 VendorGuid1 VendorGuid2 VendorGuid3') ):
    __slots__ = ()
    def __str__(self):
        return """
Header (UEFI)
-------------
StartId    : 0x%04X
State      : 0x%02X
Reserved   : 0x%02X
Attributes : 0x%08X
NameSize   : 0x%08X
DataSize   : 0x%08X
VendorGuid : {0x%08X-0x%04X-0x%04X-0x%08X}
""" % ( self.StartId, self.State, self.Reserved, self.Attributes, self.NameSize, self.DataSize, self.VendorGuid0, self.VendorGuid1, self.VendorGuid2, self.VendorGuid3 )


UEFI_VARIABLE_STORE_HEADER = "<IHH8sIBBHI"
UEFI_VARIABLE_STORE_HEADER_SIZE = struct.calcsize(UEFI_VARIABLE_STORE_HEADER)

EFI_VARIABLE_HEADER = "<HBBI28sIIIHH8s"
EFI_VARIABLE_HEADER_SIZE = struct.calcsize(EFI_VARIABLE_HEADER)

VARIABLE_STORE_FORMATTED = 0x5a
VARIABLE_STORE_HEALTHY   = 0xfe
VARIABLE_DATA            = 0x55aa

def getNVstore_EFI( nvram_buf ):
    l = (-1, -1, None)
    FvOffset = 0
    FvLength = 0
    while True:
        FvOffset, FsGuid, FvLength, Attributes, HeaderLength, Checksum, ExtHeaderOffset, FvImage, CalcSum = NextFwVolume(nvram_buf, FvOffset+FvLength)
        if (FvOffset == None): break
        if (FsGuid != VARIABLE_STORE_FV_GUID): continue
        nvram_start = HeaderLength
        StoreGuid0, StoreGuid1, StoreGuid2, StoreGuid03, Size, Format, State, R0, R1 = \
            struct.unpack(UEFI_VARIABLE_STORE_HEADER, FvImage[nvram_start:nvram_start + UEFI_VARIABLE_STORE_HEADER_SIZE])
        if ((Format == VARIABLE_STORE_FORMATTED) and (State == VARIABLE_STORE_HEALTHY)):
            l = (FvOffset + nvram_start, FvLength - nvram_start, None)
            break
    return l

def getEFIvariables_UEFI( nvram_buf ):
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

from chipsec.logger import *
class EFI_HDR_NVAR1( namedtuple('EFI_HDR_NVAR1', 'StartId TotalSize Reserved1 Reserved2 Reserved3 Attributes State') ):
    __slots__ = ()
    def __str__(self):
        return """
Header (NVAR)
------------
StartId    : 0x%04X
TotalSize  : 0x%04X
Reserved1  : 0x%02X
Reserved2  : 0x%02X
Reserved3  : 0x%02X
Attributes : 0x%02X
State      : 0x%02X
""" % ( self.StartId, self.TotalSize, self.Reserved1, self.Reserved2, self.Reserved3, self.Attributes, self.State )

NVAR_EFIvar_signature   = 'NVAR'
NVAR_NVRAM_FS_FILE      = "CEF5B9A3-476D-497F-9FDC-E98143E0422C"

def getNVstore_NVAR( nvram_buf ):
    l = (-1, -1, None)
    FvOffset, FsGuid, FvLength, FvAttributes, FvHeaderLength, FvChecksum, ExtHeaderOffset, FvImage, CalcSum = NextFwVolume(nvram_buf)
    while FvOffset != None:
        polarity = bit_set(FvAttributes, EFI_FVB2_ERASE_POLARITY)
        cur_offset, next_offset, Name, Type, Attributes, State, Checksum, Size, FileImage, HeaderSize, UD, fCalcSum = NextFwFile(FvImage, FvLength, FvHeaderLength, polarity)
        while next_offset != None:
            if (Type == EFI_FV_FILETYPE_RAW) and (Name == NVAR_NVRAM_FS_FILE):
                l = ((FvOffset + cur_offset + HeaderSize), Size - HeaderSize, None)
                if (not UD): break
            cur_offset, next_offset, Name, Type, Attributes, State, Checksum, Size, FileImage, HeaderSize, UD, fCalcSum = NextFwFile(FvImage, FvLength, next_offset, polarity)
        FvOffset, FsGuid, FvLength, Attributes, HeaderLength, Checksum, ExtHeaderOffset, FvImage, CalcSum = NextFwVolume(nvram_buf, FvOffset+FvLength)
    return l

def getEFIvariables_NVAR( nvram_buf ):
    start = nvram_buf.find( NVAR_EFIvar_signature )
    nvram_size = len(nvram_buf)
    EFI_HDR_NVAR = "<4sH3sB"
    nvar_size = struct.calcsize(EFI_HDR_NVAR)
    variables = dict()
    nof = 0 #start
#   EMPTY = 0
    EMPTY = 0xffffffff
    while (nof+nvar_size) < nvram_size:
        start_id, size, next, attributes = struct.unpack(EFI_HDR_NVAR, nvram_buf[nof:nof+nvar_size])
        next = get_3b_size(next)
        valid = (bit_set(attributes, NVRAM_ATTR_VLD) and (not bit_set(attributes, NVRAM_ATTR_DATA)))
        if not valid:
            nof = nof + size
            continue
        isvar = (start_id == NVAR_EFIvar_signature)
        if (not isvar) or (size == (EMPTY & 0xffff)): break
        var_name_off = 1
        if bit_set(attributes, NVRAM_ATTR_GUID):
            guid0, guid1, guid2, guid3 = struct.unpack(GUID, nvram_buf[nof+nvar_size:nof+nvar_size+guid_size])
            guid = guid_str(guid0, guid1, guid2, guid3)
            var_name_off = guid_size
        else:
            guid_idx = ord(nvram_buf[nof+nvar_size])
            guid0, guid1, guid2, guid3 = struct.unpack(GUID, nvram_buf[nvram_size - guid_size - guid_idx:nvram_size - guid_idx])
            guid = guid_str(guid0, guid1, guid2, guid3)
        name_size = 0
        name_offset = nof+nvar_size+var_name_off
        if not bit_set(attributes, NVRAM_ATTR_DATA):
            name, name_size = get_nvar_name(nvram_buf, name_offset, bit_set(attributes, NVRAM_ATTR_DESC_ASCII))
        esize = 0
        eattrs = 0
        if bit_set(attributes, NVRAM_ATTR_EXTHDR):
            esize, = struct.unpack("<H", nvram_buf[nof+size-2:nof+size])
            eattrs = ord(nvram_buf[nof+size-esize])
        attribs = EFI_VARIABLE_BOOTSERVICE_ACCESS
        attribs = attribs | EFI_VARIABLE_NON_VOLATILE
        if bit_set(attributes, NVRAM_ATTR_RT):  attribs = attribs | EFI_VARIABLE_RUNTIME_ACCESS
        if bit_set(attributes, NVRAM_ATTR_HER): attribs = attribs | EFI_VARIABLE_HARDWARE_ERROR_RECORD
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
            lstart_id, lsize, lnext, lattributes = struct.unpack(EFI_HDR_NVAR, nvram_buf[lof:lof+nvar_size])
            lnext = get_3b_size(lnext)
        dataof = lof + nvar_size
        if not bit_set(lattributes, NVRAM_ATTR_DATA):
            lnameof = 1
            if bit_set(lattributes, NVRAM_ATTR_GUID): lnameof = guid_size
            name_offset = lof+nvar_size+lnameof
            name, name_size = get_nvar_name(nvram_buf, name_offset, bit_set(attributes, NVRAM_ATTR_DESC_ASCII))
            dataof = name_offset + name_size
        if bit_set(lattributes, NVRAM_ATTR_EXTHDR):
            lesize, = struct.unpack("<H", nvram_buf[lof+lsize-2:lof+lsize])
        data = nvram_buf[dataof:lof+lsize-lesize]
        if name not in variables.keys():
            variables[name] = []
        #                       off, buf,  hdr,  data, guid, attrs
        variables[name].append((nof, None, None, data, guid, attribs))
        nof = nof + size
    return variables

NVAR_HDR_FMT          = '=IHBBBBB'
NVAR_HDR_SIZE         = struct.calcsize( NVAR_HDR_FMT )


#
# Linear/simple NVAR format parsing
#
def getNVstore_NVAR_simple( nvram_buf ):
    return (nvram_buf.find( NVAR_EFIvar_signature ), -1, None)

def getEFIvariables_NVAR_simple( nvram_buf ):
    nvsize = len(nvram_buf)
    hdr_fmt = NVAR_HDR_FMT
    hdr_size = struct.calcsize( hdr_fmt )
    variables = dict()
    start = nvram_buf.find( NVAR_EFIvar_signature )
    if -1 == start: return variables

    while (start + hdr_size) < nvsize:
        efi_var_hdr = EFI_HDR_NVAR1( *struct.unpack_from( hdr_fmt, nvram_buf[start:] ) )
        name_size = 0
        efi_var_name = "NA"
        if not IS_VARIABLE_ATTRIBUTE( efi_var_hdr.Attributes, EFI_VARIABLE_HARDWARE_ERROR_RECORD ):
            name_size = nvram_buf[ start + hdr_size : ].find( '\0' )
            efi_var_name = "".join( nvram_buf[ start + hdr_size : start + hdr_size + name_size ] )

        next_var_offset = start + efi_var_hdr.TotalSize
        data_size = efi_var_hdr.TotalSize - name_size - hdr_size
        efi_var_buf  = nvram_buf[ start : next_var_offset ]
        efi_var_data = nvram_buf[ start + hdr_size + name_size : next_var_offset ]

        if efi_var_name not in variables.keys(): variables[efi_var_name] = []
        #                               off,   buf,         hdr,         data,         guid, attrs
        variables[efi_var_name].append((start, efi_var_buf, efi_var_hdr, efi_var_data, '',   efi_var_hdr.Attributes))

        if start >= next_var_offset: break
        start = next_var_offset

    return variables


#######################################################################
#
# VSS NVRAM (signature = '$VSS')
#
#

#define VARIABLE_STORE_SIGNATURE  EFI_SIGNATURE_32 ('$', 'V', 'S', 'S')
VARIABLE_STORE_SIGNATURE_VSS  = '$VSS'
VARIABLE_STORE_HEADER_FMT_VSS = '=IIBBHI' # Signature is '$VSS'
class VARIABLE_STORE_HEADER_VSS( namedtuple('VARIABLE_STORE_HEADER_VSS', 'Signature Size Format State Reserved Reserved1') ):
    __slots__ = ()
    def __str__(self):
        return """
EFI Variable Store
-----------------------------
Signature : %s (0x%08X)
Size      : 0x%08X bytes
Format    : 0x%02X
State     : 0x%02X
Reserved  : 0x%04X
Reserved1 : 0x%08X
""" % ( struct.pack('=I',self.Signature), self.Signature, self.Size, self.Format, self.State, self.Reserved, self.Reserved1 )


HDR_FMT_VSS                   = '<HBBIIIIHH8s'
#HDR_SIZE_VSS                  = struct.calcsize( HDR_FMT_VSS )
#NAME_OFFSET_IN_VAR_VSS        = HDR_SIZE_VSS
class EFI_HDR_VSS( namedtuple('EFI_HDR_VSS', 'StartId State Reserved Attributes NameSize DataSize guid0 guid1 guid2 guid3') ):
    __slots__ = ()
    def __str__(self):
        return """
Header (VSS)
------------
VendorGuid : {%08X-%04X-%04X-%04s-%06s}
StartId    : 0x%04X
State      : 0x%02X
Reserved   : 0x%02X
Attributes : 0x%08X
NameSize   : 0x%08X
DataSize   : 0x%08X
""" % ( self.guid0, self.guid1, self.guid2, self.guid3[:2].encode('hex').upper(), self.guid3[-6::].encode('hex').upper(), self.StartId, self.DataOffset, self.DataSize, self.Attributes )


HDR_FMT_VSS_NEW  = '<HBBIQQQIIIIHH8s'
class EFI_HDR_VSS_NEW( namedtuple('EFI_HDR_VSS_NEW', 'StartId State Reserved Attributes wtf1 wtf2 wtf3 wtf4 NameSize DataSize guid0 guid1 guid2 guid3') ):
    __slots__ = ()
    # if you don't re-define __str__ method, initialize is to None
    #__str__ = None
    def __str__(self):
        return """
Header (VSS_NEW)
----------------
VendorGuid : {%08X-%04X-%04X-%08X}
StartId    : 0x%04X
State      : 0x%02X
Reserved   : 0x%02X
Attributes : 0x%08X
wtf1       : 0x%016X
wtf2       : 0x%016X
wtf3       : 0x%016X
wtf4       : 0x%08X
NameSize   : 0x%08X
DataSize   : 0x%08X
""" % ( self.guid0, self.guid1, self.guid2, self.guid3[:2].encode('hex').upper(), self.guid3[-6::].encode('hex').upper(), self.StartId, self.State, self.Reserved, self.Attributes, self.wtf1, self.wtf2, self.wtf3, self.wtf4, self.NameSize, self.DataSize )



def getNVstore_VSS( nvram_buf ):
    nvram_start = nvram_buf.find( VARIABLE_STORE_SIGNATURE_VSS )
    if -1 == nvram_start:
        return (-1, 0, None)
    nvram_hdr = VARIABLE_STORE_HEADER_VSS( *struct.unpack_from( VARIABLE_STORE_HEADER_FMT_VSS, nvram_buf[nvram_start:] ) )
    return (nvram_start, nvram_hdr.Size, nvram_hdr)

def _getEFIvariables_VSS( nvram_buf, _fwtype ):
    nvsize = len(nvram_buf)
    if (FWType.EFI_FW_TYPE_VSS == _fwtype):
        hdr_fmt  = HDR_FMT_VSS
    elif (FWType.EFI_FW_TYPE_VSS_NEW == _fwtype):
        hdr_fmt  = HDR_FMT_VSS_NEW
    hdr_size = struct.calcsize( hdr_fmt )
    variables = dict()
    start    = nvram_buf.find( VARIABLE_SIGNATURE_VSS )
    if -1 == start:
        return variables

    while (start + hdr_size) < nvsize:
        if (FWType.EFI_FW_TYPE_VSS == _fwtype):
            efi_var_hdr = EFI_HDR_VSS( *struct.unpack_from( hdr_fmt, nvram_buf[start:] ) )
        elif (FWType.EFI_FW_TYPE_VSS_NEW == _fwtype):
            efi_var_hdr = EFI_HDR_VSS_NEW( *struct.unpack_from( hdr_fmt, nvram_buf[start:] ) )

        if (efi_var_hdr.StartId != 0x55AA): break

        name_size = efi_var_hdr.NameSize
        data_size = efi_var_hdr.DataSize
        efi_var_name = "<not defined>"

        next_var_offset = start + hdr_size + name_size + data_size
        if (next_var_offset > nvsize):
            break
        efi_var_buf  = nvram_buf[ start : next_var_offset ]

        name_offset = hdr_size
        #if not IS_VARIABLE_ATTRIBUTE( efi_var_hdr.Attributes, EFI_VARIABLE_HARDWARE_ERROR_RECORD ):
        #efi_var_name = "".join( efi_var_buf[ NAME_OFFSET_IN_VAR_VSS : NAME_OFFSET_IN_VAR_VSS + name_size ] )
        str_fmt = "%ds" % name_size
        s, = struct.unpack( str_fmt, efi_var_buf[ name_offset : name_offset + name_size ] )
        efi_var_name = unicode(s, "utf-16-le", errors="replace").split(u'\u0000')[0]

        efi_var_data = efi_var_buf[ name_offset + name_size : next_var_offset ]
        guid = guid_str(efi_var_hdr.guid0, efi_var_hdr.guid1, efi_var_hdr.guid2, efi_var_hdr.guid3)
        if efi_var_name not in variables.keys():
            variables[efi_var_name] = []
        #                                off,   buf,         hdr,         data,         guid, attrs
        variables[efi_var_name].append( (start, efi_var_buf, efi_var_hdr, efi_var_data, guid, efi_var_hdr.Attributes) )

        if start >= next_var_offset: break
        start = next_var_offset

    return variables


def getEFIvariables_VSS( nvram_buf ):
    return _getEFIvariables_VSS( nvram_buf, FWType.EFI_FW_TYPE_VSS )

def getEFIvariables_VSS_NEW( nvram_buf ):
    return _getEFIvariables_VSS( nvram_buf, FWType.EFI_FW_TYPE_VSS_NEW )

#######################################################################
#
# EVSA NVRAM (signature = 'EVSA')
#
#
VARIABLE_STORE_SIGNATURE_EVSA = 'EVSA'
ADDITIONAL_NV_STORE_GUID = '00504624-8A59-4EEB-BD0F-6B36E96128E0'

TLV_HEADER = "<BBH"
tlv_h_size = struct.calcsize(TLV_HEADER)

def getNVstore_EVSA( nvram_buf ):
    l = (-1, -1, None)
    FvOffset, FsGuid, FvLength, FvAttributes, FvHeaderLength, FvChecksum, ExtHeaderOffset, FvImage, CalcSum = NextFwVolume(nvram_buf)
    while FvOffset != None:
        if (FsGuid == VARIABLE_STORE_FV_GUID):
            nvram_start = FvImage.find( VARIABLE_STORE_SIGNATURE_EVSA )
            if (nvram_start != -1) and (nvram_start >= tlv_h_size):
                nvram_start = nvram_start - tlv_h_size
                l = (FvOffset + nvram_start, FvLength - nvram_start, None)
                break
        if (FsGuid == ADDITIONAL_NV_STORE_GUID):
            nvram_start = FvImage.find( VARIABLE_STORE_SIGNATURE_EVSA )
            if (nvram_start != -1) and (nvram_start >= tlv_h_size):
                nvram_start = nvram_start - tlv_h_size
                l = (FvOffset + nvram_start, FvLength - nvram_start, None)
        FvOffset, FsGuid, FvLength, Attributes, HeaderLength, Checksum, ExtHeaderOffset, FvImage, CalcSum = NextFwVolume(nvram_buf, FvOffset+FvLength)
    return l

def EFIvar_EVSA(nvram_buf):
    image_size = len(nvram_buf)
    sn = 0
    EVSA_RECORD = "<IIII"
    evsa_rec_size = struct.calcsize(EVSA_RECORD)
    GUID_RECORD = "<HIHH8s"
    guid_rc_size = struct.calcsize(GUID_RECORD)
    fof = 0
    variables = dict()
    while fof < image_size:
        fof = nvram_buf.find("EVSA", fof)
        if fof == -1: break
        if fof < tlv_h_size:
            fof = fof + 1
            continue
        start = fof - tlv_h_size
        Tag0, Tag1, Size = struct.unpack(TLV_HEADER, nvram_buf[start: start + tlv_h_size])
        if Tag0 != 0xEC: # Wrong EVSA block
            fof = fof + 1
            continue
        value = nvram_buf[start + tlv_h_size:start + Size]
        Signature, Unkwn0, Length, Unkwn1 = struct.unpack(EVSA_RECORD, value)
        if start + Length > image_size: # Wrong EVSA record
            fof = fof + 1
            continue
        # NV storage EVSA found
        bof = 0
        guid_map = dict()
        var_list = list()
        value_list = dict()
        while (bof + tlv_h_size) < Length:
            Tag0, Tag1, Size = struct.unpack(TLV_HEADER, nvram_buf[start + bof: start + bof + tlv_h_size])
            value = nvram_buf[start + bof + tlv_h_size:start + bof + Size]
            bof = bof + Size
            if   (Tag0 == 0xED) or (Tag0 == 0xE1):  # guid
                GuidId, guid0, guid1, guid2, guid3 = struct.unpack(GUID_RECORD, value)
                g = guid_str(guid0, guid1, guid2, guid3)
                guid_map[GuidId] = g
            elif (Tag0 == 0xEE) or (Tag0 == 0xE2):  # var name
                VAR_NAME_RECORD = "<H%ds" % (Size - tlv_h_size - 2)
                VarId, Name = struct.unpack(VAR_NAME_RECORD, value)
                Name = unicode(Name, "utf-16-le")[:-1]
                var_list.append((Name, VarId, Tag0, Tag1))
            elif (Tag0 == 0xEF) or (Tag0 == 0xE3) or (Tag0 == 0x83):  # values
                VAR_VALUE_RECORD = "<HHI%ds" % (Size - tlv_h_size - 8)
                GuidId, VarId, Attributes, Data = struct.unpack(VAR_VALUE_RECORD, value)
                value_list[VarId] = (GuidId, Attributes, Data, Tag0, Tag1)
            elif not ((Tag0 == 0xff) and (Tag1 == 0xff) and (Size == 0xffff)):
                pass
        var_count = len(var_list)
        var_list.sort()
        var1 = {}
        for i in var_list:
            name = i[0]
            VarId = i[1]
            #NameTag0 = i[2]
            #NameTag1 = i[3]
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
            variables[name].append((start, None, None, var_value[2], guid, var_value[1]))
        fof = fof + Length
    return variables



#
# Uncomment if you want to parse output buffer returned by NtEnumerateSystemEnvironmentValuesEx
# using 'chipsec_util uefi nvram' command
#
#
# Windows 8 NtEnumerateSystemEnvironmentValuesEx (infcls = 2)
#
#def guid_str(guid0, guid1, guid2, guid3):
#        return ( "%08X-%04X-%04X-%04s-%06s" % (guid0, guid1, guid2, guid3[:2].encode('hex').upper(), guid3[-6::].encode('hex').upper()) )
#
#class EFI_HDR_WIN( namedtuple('EFI_HDR_WIN', 'Size DataOffset DataSize Attributes guid0 guid1 guid2 guid3') ):
#        __slots__ = ()
#        def __str__(self):
#            return """
#Header (Windows)
#----------------
#VendorGuid= {%08X-%04X-%04X-%04s-%06s}
#Size      = 0x%08X
#DataOffset= 0x%08X
#DataSize  = 0x%08X
#Attributes= 0x%08X
#""" % ( self.guid0, self.guid1, self.guid2, self.guid3[:2].encode('hex').upper(), self.guid3[-6::].encode('hex').upper(), self.Size, self.DataOffset, self.DataSize, self.Attributes )
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
           str_fmt = "%ds" % (efi_var_hdr.DataOffset - header_size)
           s, = struct.unpack( str_fmt, buffer[ off + header_size : off + efi_var_hdr.DataOffset ] )
           efi_var_name = unicode(s, "utf-16-le", errors="replace").split(u'\u0000')[0]

           if efi_var_name not in variables.keys():
               variables[efi_var_name] = []
           #                                off, buf,         hdr,         data,         guid,                                                                                 attrs
           variables[efi_var_name].append( (off, efi_var_buf, efi_var_hdr, efi_var_data, guid_str(efi_var_hdr.guid0, efi_var_hdr.guid1, efi_var_hdr.guid2, efi_var_hdr.guid3), efi_var_hdr.Attributes) )

           if 0 == efi_var_hdr.Size: break
           off = next_var_offset

        return variables
#    return ( start, next_var_offset, efi_var_buf, efi_var_hdr, efi_var_name, efi_var_data, guid_str(efi_var_hdr.guid0, efi_var_hdr.guid1, efi_var_hdr.guid2, efi_var_hdr.guid3), efi_var_hdr.Attributes )
"""


#################################################################################################3
# Decoding S3 Resume Boot Script
#################################################################################################3

class S3BootScriptType:
    EFI_BOOT_SCRIPT_TYPE_DEFAULT = 0x00
    EFI_BOOT_SCRIPT_TYPE_AA      = 0xAA


def decode_s3bs_opcode( data ):
    opcode  = None
    size    = None
    width   = None
    unknown = None
    count   = None
    value   = None
    mask    = None

    op = None
    opcode, = struct.unpack( '<B', data[ : 1 ] )
    try:
        if logger().VERBOSE: logger().log( script_opcodes[opcode] )
    except:
        pass
    if S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_WRITE_OPCODE == opcode:
        frmt = '<BBHIQ'
        size = struct.calcsize( frmt )
        opcode, width, address, alignment, count = struct.unpack( frmt, data[ : size ] )
        op = op_io_pci_mem( opcode, size, width, address, unknown, count, data[ size : ], value, mask )
    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE == opcode:
        frmt = '<BBHIQQ'
        size = struct.calcsize( frmt )
        opcode, width, address, alignment, value, mask = struct.unpack( frmt, data[ : size ] )
        op = op_io_pci_mem( opcode, size, width, address, unknown, count, None, value, mask )
    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE == opcode:
        frmt = '<BBHIQQ'
        size = struct.calcsize( frmt )
        opcode, width, unknown, alignment, address, count = struct.unpack( frmt, data[ : size ] )
        op = op_io_pci_mem( opcode, size, width, address, unknown, count, data[ size : ], value, mask )
    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE == opcode:
        frmt = '<BBHIQQQ'
        size = struct.calcsize( frmt )
        opcode, width, unknown, alignment, address, value, mask = struct.unpack( frmt, data[ : size ] )
        op = op_io_pci_mem( opcode, size, width, address, unknown, count, None, value, mask )
    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE == opcode:
        frmt = '<BBHIQQ'
        size = struct.calcsize( frmt )
        opcode, width, unknown, alignment, address, count = struct.unpack( frmt, data[ : size ] )
        op = op_io_pci_mem( opcode, size, width, address, unknown, count, data[ size : ], value, mask )
    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE == opcode:
        frmt = '<BBHIQQQ'
        size = struct.calcsize( frmt )
        opcode, width, unknown, alignment, address, value, mask = struct.unpack( frmt, data[ : size ] )
        op = op_io_pci_mem( opcode, size, width, address, unknown, count, None, value, mask )
    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE == opcode:
        frmt = '<BBQBB'
        size = struct.calcsize( frmt )
        opcode, slave_address, command, operation, peccheck = struct.unpack( frmt, data[ : size ] )
        op = op_smbus_execute( opcode, size, width, address, count, data[ size : ], value, mask )
    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_STALL_OPCODE == opcode:
        frmt = '<BBQ'
        size = struct.calcsize( frmt )
        opcode, dummy, duration = struct.unpack( frmt, data[ : size ] )
        op = op_stall( opcode, size, duration )
    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_DISPATCH_OPCODE == opcode:
        frmt = '<BBHIQ'
        size = struct.calcsize( frmt )
        opcode, dummy1, dummy2, dummy3, entrypoint = struct.unpack( frmt, data[ : size ] )
        op = op_dispatch( opcode, size, entrypoint )
    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_TERMINATE_OPCODE == opcode:
        frmt = '<B'
        size = struct.calcsize( frmt )
        opcode, = struct.unpack( frmt, data[ : size ] )
        op = op_terminate( opcode, size )
    else:
        op = op_unknown( opcode, 1 )
        if logger().VERBOSE: logger().warn( 'Unrecognized opcode %X' % opcode )

    return op

#
# @TODO: encode functions are not fully implemented
#
def encode_s3bs_opcode( op ):
    encoded_opcode = None

    if S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_WRITE_OPCODE == op.opcode:
        encoded_hdr = struct.pack( '<BBHIQ', op.opcode, op.width, op.address, 0x0, op.count )
        if op.values is None: encoded_opcode = encoded_hdr + op.buffer
        else: encoded_opcode = encoded_hdr + struct.pack(  script_width_formats[op.width] * op.count, *op.values )

    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE == op.opcode:
        encoded_opcode = struct.pack( '<BBHIQQ', op.opcode, op.width, op.address, 0x0, op.value, op.mask )

    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE == op.opcode or \
         S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE        == op.opcode:
        encoded_hdr = struct.pack( '<BBHIQQ', op.opcode, op.width, op.unknown, 0x0, op.address, op.count )
        if op.values is None: encoded_opcode = encoded_hdr + op.buffer
        else: encoded_opcode = encoded_hdr + struct.pack(  script_width_formats[op.width] * op.count, *op.values )

    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE == op.opcode:
        frmt = '<BBHIQQQ'

    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE == op.opcode:
        encoded_opcode = struct.pack( '<BBHIQQQ', op.opcode, op.width, op.unknown, 0x0, op.address, op.value, op.mask )

    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE == op.opcode:
        frmt = '<BBQBB'

    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_STALL_OPCODE == op.opcode:
        frmt = '<BBQ'

    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_DISPATCH_OPCODE == op.opcode:
        encoded_opcode = struct.pack( '<BBHIQ', op.opcode, 0x0, 0x0, 0x0, op.entrypoint )

    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_TERMINATE_OPCODE == op.opcode:
        frmt = '<B'

    else:
        if logger().VERBOSE: logger().warn( 'Unrecognized opcode %X' % op.opcode )

    return encoded_opcode


def decode_s3bs_opcode_AA( data ):
    opcode = None
    width  = None
    count  = None
    value  = None
    mask   = None

    op = None

    hdr_frmt = '<BBB'
    header_size = struct.calcsize( hdr_frmt )
    opcode, dummy, size = struct.unpack( hdr_frmt, data[ : header_size ] )
    opcode_data = data[ header_size : ]
    try:
        if logger().VERBOSE: logger().log( script_opcodes[opcode] )
    except:
        pass
    
    if   S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_WRITE_OPCODE                == opcode or \
         S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE        == opcode or \
         S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE               == opcode:
        
        frmt = '<IIQ'
        op_size = struct.calcsize( frmt )
        width, count, address = struct.unpack( frmt, opcode_data[ : op_size ] )
        op = op_io_pci_mem( opcode, size, width, address, count, opcode_data[ op_size : ], value, mask )

    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE         == opcode or \
         S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE == opcode or \
         S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE        == opcode:
        frmt = '<IQ'
        sz = struct.calcsize( frmt )
        width, address = struct.unpack( frmt, opcode_data[ : sz ] )
        frmt = 2*script_width_formats[width]
        op_size = sz + struct.calcsize( frmt )
        value, mask = struct.unpack( frmt, opcode_data[ sz : op_size ] )
        op = op_io_pci_mem( opcode, size, width, address, count, None, value, mask )

    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE == opcode:
        if logger().UTIL_TRACE or logger().VERBOSE: logger().warn( 'Cannot parse opcode %X yet' % opcode )

    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_STALL_OPCODE == opcode:
        frmt = '<Q'
        op_size = struct.calcsize( frmt )
        duration, = struct.unpack( frmt, opcode_data[ : op_size ] )
        op = op_stall( opcode, size, duration )

    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_DISPATCH_OPCODE == opcode:
        frmt = '<Q'
        op_size = struct.calcsize( frmt )
        entrypoint, = struct.unpack( frmt, opcode_data[ : op_size ] )
        op = op_dispatch( opcode, size, entrypoint )

    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_TERMINATE_OPCODE == opcode:
        op = op_terminate( opcode, size )

    else:
        op = op_unknown( opcode, size )
        if logger().VERBOSE: logger().warn( 'Unrecognized opcode %X' % opcode )

    return op

#
# @TODO: encode functions are not fully implemented
#
def encode_s3bs_opcode_AA( op ):
    encoded_opcode = None
    
    if   S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_WRITE_OPCODE                == opcode or \
         S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE        == opcode or \
         S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE               == opcode:
        
        frmt = '<IIQ'
        encoded_hdr = struct.pack( frmt, op.width, op.count, op.address )
        if op.values is None: encoded_opcode = encoded_hdr + op.buffer
        else: encoded_opcode = encoded_hdr + struct.pack(  script_width_formats[op.width] * op.count, *op.values )

    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE         == opcode or \
         S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE == opcode or \
         S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE        == opcode:

        frmt = '<IQ2%c' % script_width_formats[op.width]
        encoded_opcode = struct.pack( frmt, op.width, op.address, op.value, op.mask )

    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE == opcode:
        pass

    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_STALL_OPCODE == opcode:
        frmt = '<Q'

    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_DISPATCH_OPCODE == opcode:
        encoded_opcode = struct.pack( '<Q', op.entrypoint )

    elif S3BootScriptOpcode.EFI_BOOT_SCRIPT_TERMINATE_OPCODE == opcode:
        pass

    return encoded_opcode



def parse_s3bootscript_entry( s3bootscript_type, script, off, log_script=False ):
    entry_index  = None
    entry_length = 0
    opcode       = None
    entry_data   = None

    if S3BootScriptType.EFI_BOOT_SCRIPT_TYPE_AA == s3bootscript_type:
        fhdr = '<BBB'
        hdr_length = struct.calcsize(fhdr)
        opcode, dummy, entry_length = struct.unpack( fhdr, script[ off : off + hdr_length ] )
        if S3BootScriptOpcode.EFI_BOOT_SCRIPT_TERMINATE_OPCODE == opcode:
            entry_length = hdr_length
        entry_data = script[ off : off + entry_length ]

        if entry_length > MAX_S3_BOOTSCRIPT_ENTRY_LENGTH:
            logger().error( '[uefi] Unrecognized S3 boot script format (entry length = 0x%X)' % entry_length )
            return None

        s3script_entry                = S3BOOTSCRIPT_ENTRY( s3bootscript_type, entry_index, off, entry_length, entry_data )
        #s3script_entry.header_length  = hdr_length
        s3script_entry.decoded_opcode = decode_s3bs_opcode_AA( s3script_entry.data )

    else: # S3BootScriptType.EFI_BOOT_SCRIPT_TYPE_DEFAULT

        fhdr       = '<II' 
        hdr_length = struct.calcsize(fhdr)
        f          = fhdr + 'B'
        entry_index, entry_length, opcode = struct.unpack(f, script[ off : off + hdr_length + 1 ])
        if S3BootScriptOpcode.EFI_BOOT_SCRIPT_TERMINATE_OPCODE == opcode:
            entry_length = hdr_length + 1
            entry_index  = -1
        entry_data = script[ off + hdr_length : off + entry_length ]

        if entry_length > MAX_S3_BOOTSCRIPT_ENTRY_LENGTH:
            logger().error( '[uefi] Unrecognized S3 boot script format (entry length = 0x%X)' % entry_length )
            return None

        s3script_entry                = S3BOOTSCRIPT_ENTRY( s3bootscript_type, entry_index, off, entry_length, entry_data )
        s3script_entry.header_length  = hdr_length
        s3script_entry.decoded_opcode = decode_s3bs_opcode( s3script_entry.data )

    if log_script: logger().log( s3script_entry )
    return (opcode,s3script_entry)


def encode_s3bootscript_entry( entry ):
    s3bootscript_type = entry.script_type

    if S3BootScriptType.EFI_BOOT_SCRIPT_TYPE_AA == s3bootscript_type:
        fhdr = '<BBB'
        dummy = 0x0
        entry_hdr_buf = struct.pack( fhdr, entry.decoded_opcode.opcode, dummy, entry.length )
        entry_val_buf = encode_s3bs_opcode_AA( entry.decoded_opcode )

    else: # S3BootScriptType.EFI_BOOT_SCRIPT_TYPE_DEFAULT
        fhdr       = '<II' 
        entry_hdr_buf = struct.pack( fhdr, entry.index, entry.length )
        entry_val_buf = encode_s3bs_opcode( entry.decoded_opcode )

    entry_buf = None
    if entry_val_buf is not None:
        entry_buf = entry_hdr_buf + entry_val_buf
    else:
        logger().warn( 'Could not encode opcode of boot script entry (type 0x%X)' % s3bootscript_type )

    return entry_buf


def id_s3bootscript_type( script, log_script=False ):

    script_header_length = 0

    start_op, = struct.unpack('<B', script[ : 1 ])
    if S3BootScriptOpcode.EFI_BOOT_SCRIPT_TABLE_OPCODE == start_op:
        if logger().VERBOSE: logger().log('S3 Boot Script AA Parser')
        script_type = S3BootScriptType.EFI_BOOT_SCRIPT_TYPE_AA
        if log_script: logger().log( '[uefi] Start opcode 0x%X' % start_op )
        script_header_length = 1 # skip start opcode
        script_header_length += 0x34
    else:
       if logger().VERBOSE: logger().log('S3 Boot Script DEFAULT Parser')
       script_type = S3BootScriptType.EFI_BOOT_SCRIPT_TYPE_DEFAULT

    return (script_type,script_header_length)



#################################################################################################3
# EFI Variable Header Dictionary
#################################################################################################3

#
# Add your EFI variable details to the dictionary
#
# Fields:
# name          func_getefivariables            func_getnvstore
#
EFI_VAR_DICT = {
# UEFI
FWType.EFI_FW_TYPE_UEFI    : {'name' : 'UEFI',    'func_getefivariables' : getEFIvariables_UEFI,    'func_getnvstore' : getNVstore_EFI  },
# Windows 8 NtEnumerateSystemEnvironmentValuesEx (infcls = 2)
#FWType.EFI_FW_TYPE_WIN     : {'name' : 'WIN',     'func_getefivariables' : getEFIvariables_NtEnumerateSystemEnvironmentValuesEx2, 'func_getnvstore' : None },
# NVAR format
FWType.EFI_FW_TYPE_NVAR    : {'name' : 'NVAR',    'func_getefivariables' : getEFIvariables_NVAR,    'func_getnvstore' : getNVstore_NVAR },
# $VSS NVRAM format
FWType.EFI_FW_TYPE_VSS     : {'name' : 'VSS',     'func_getefivariables' : getEFIvariables_VSS,     'func_getnvstore' : getNVstore_VSS },
# $VSS New NVRAM format
FWType.EFI_FW_TYPE_VSS_NEW : {'name' : 'VSS_NEW', 'func_getefivariables' : getEFIvariables_VSS_NEW, 'func_getnvstore' : getNVstore_VSS },
# EVSA
FWType.EFI_FW_TYPE_EVSA    : {'name' : 'EVSA',    'func_getefivariables' : EFIvar_EVSA,             'func_getnvstore' : getNVstore_EVSA },
}
