#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2016, Intel Corporation
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
SPI UEFI Region parsing

usage:
   >>> parse_uefi_region_from_file( filename )
"""

__version__ = '1.0'

import os
import fnmatch
import struct
import sys
import time
import collections
import hashlib
import re
import random
import binascii
#import phex

from chipsec.helper.oshelper import helper
from chipsec.logger import *
from chipsec.file import *

from chipsec.cfg.common import *
from chipsec.hal.uefi_common import *
from chipsec.hal.uefi_platform import *
from chipsec.hal.uefi import identify_EFI_NVRAM

CMD_UEFI_FILE_REMOVE        = 0
CMD_UEFI_FILE_INSERT_BEFORE = 1
CMD_UEFI_FILE_INSERT_AFTER  = 2
CMD_UEFI_FILE_REPLACE       = 3


def decompress_section_data( _uefi, section_dir_path, sec_fs_name, compressed_data, compression_type, remove_files=False ):
    compressed_name = os.path.join(section_dir_path, "%s.gz" % sec_fs_name)
    uncompressed_name = os.path.join(section_dir_path, sec_fs_name)
    write_file(compressed_name, compressed_data)
    uncompressed_image = _uefi.decompress_EFI_binary( compressed_name, uncompressed_name, compression_type )
    if remove_files:
        try:
            os.remove(compressed_name)
            os.remove(uncompressed_name)       
        except: pass
    return uncompressed_image

def compress_image( _uefi, image, compression_type ):
    precomress_file = 'uefi_file.raw.comp'
    compressed_file = 'uefi_file.raw.comp.gz'
    write_file(precomress_file, image)
    compressed_image = _uefi.compress_EFI_binary(precomress_file, compressed_file, compression_type)
    write_file(compressed_file, compressed_image)
    os.remove(precomress_file)
    os.remove(compressed_file)
    return compressed_image


def modify_uefi_region(data, command, guid, uefi_file = ''):
    RgLengthChange = 0
    FvOffset, FsGuid, FvLength, FvAttributes, FvHeaderLength, FvChecksum, ExtHeaderOffset, FvImage, CalcSum = NextFwVolume(data)
    while FvOffset is not None:
        FvLengthChange = 0
        polarity = bit_set(FvAttributes, EFI_FVB2_ERASE_POLARITY)
        if ((FsGuid == EFI_FIRMWARE_FILE_SYSTEM2_GUID) or (FsGuid == EFI_FIRMWARE_FILE_SYSTEM_GUID)):
            cur_offset, next_offset, Name, Type, Attributes, State, Checksum, Size, FileImage, HeaderSize, UD, fCalcSum = NextFwFile(FvImage, FvLength, FvHeaderLength, polarity)
            while next_offset is not None:
                if (Name == guid):
                    uefi_file_size = (len(uefi_file) + 7) & 0xFFFFFFF8
                    CurFileOffset  = FvOffset + cur_offset  + FvLengthChange
                    NxtFileOffset  = FvOffset + next_offset + FvLengthChange
                    if command == CMD_UEFI_FILE_REMOVE:
                        FvLengthChange -= (next_offset - cur_offset)
                        logger().log( "Removing UEFI file with GUID=%s at offset=%08X, size change: %d bytes" % (Name, CurFileOffset, FvLengthChange) )
                        data = data[:CurFileOffset] + data[NxtFileOffset:]
                    elif command == CMD_UEFI_FILE_INSERT_BEFORE:
                        FvLengthChange += uefi_file_size
                        logger().log( "Inserting UEFI file before file with GUID=%s at offset=%08X, size change: %d bytes" % (Name, CurFileOffset, FvLengthChange) )
                        data = data[:CurFileOffset] + uefi_file.ljust(uefi_file_size, '\xFF') + data[CurFileOffset:]
                    elif command == CMD_UEFI_FILE_INSERT_AFTER:
                        FvLengthChange += uefi_file_size
                        logger().log( "Inserting UEFI file after file with GUID=%s at offset=%08X, size change: %d bytes" % (Name, CurFileOffset, FvLengthChange) )
                        data = data[:NxtFileOffset] + uefi_file.ljust(uefi_file_size, '\xFF') + data[NxtFileOffset:]
                    elif command == CMD_UEFI_FILE_REPLACE:
                        FvLengthChange += uefi_file_size - (next_offset - cur_offset)
                        logger().log( "Replacing UEFI file with GUID=%s at offset=%08X, new size: %d, old size: %d, size change: %d bytes" % (Name, CurFileOffset, len(uefi_file), Size, FvLengthChange) )
                        data = data[:CurFileOffset] + uefi_file.ljust(uefi_file_size, '\xFF') + data[NxtFileOffset:]
                    else:
                        raise Exception('Invalid command')

                if next_offset - cur_offset >= 24:
                    FvEndOffset = FvOffset + next_offset + FvLengthChange

                cur_offset, next_offset, Name, Type, Attributes, State, Checksum, Size, FileImage, HeaderSize, UD, fCalcSum = NextFwFile(FvImage, FvLength, next_offset, polarity)

            if FvLengthChange >= 0:
                data = data[:FvEndOffset] + data[FvEndOffset + FvLengthChange:]
            else:
                data = data[:FvEndOffset] + (abs(FvLengthChange) * '\xFF') + data[FvEndOffset:]

            FvLengthChange = 0

            #if FvLengthChange != 0:
            #    logger().log( "Rebuilding Firmware Volume with GUID=%s at offset=%08X" % (FsGuid, FvOffset) )
            #    FvHeader = data[FvOffset: FvOffset + FvHeaderLength]
            #    FvHeader = FvHeader[:0x20] + struct.pack('<Q', FvLength) + FvHeader[0x28:]
            #    NewChecksum = FvChecksum16(FvHeader[:0x32] + '\x00\x00' + FvHeader[0x34:])
            #    FvHeader = FvHeader[:0x32] + struct.pack('<H', NewChecksum) + FvHeader[0x34:]
            #    data = data[:FvOffset] + FvHeader + data[FvOffset + FvHeaderLength:]

        FvOffset, FsGuid, FvLength, FvAttributes, FvHeaderLength, FvChecksum, ExtHeaderOffset, FvImage, CalcSum = NextFwVolume(data, FvOffset + FvLength)
    return data


DEF_INDENT = "    "
class EFI_MODULE(object):
    def __init__(self, Offset, Guid, HeaderSize, Attributes, Image):
        self.Offset     = Offset
        self.Guid       = Guid
        self.HeaderSize = HeaderSize
        self.Attributes = Attributes
        self.Image      = Image

        self.clsname    = "EFI module"
        self.indent     = ''

        self.MD5        = ''
        self.SHA1       = ''
        self.SHA256     = ''

    def __str__(self):
        _ind = self.indent + DEF_INDENT
        return "%sMD5   : %s\n%sSHA1  : %s\n%sSHA256: %s\n" % (_ind,self.MD5,_ind,self.SHA1,_ind,self.SHA256)


class EFI_FV(EFI_MODULE):
    def __init__(self, Offset, Guid, Size, Attributes, HeaderSize, Checksum, ExtHeaderOffset, Image, CalcSum):
        EFI_MODULE.__init__(self, Offset, Guid, HeaderSize, Attributes, Image)
        self.clsname         = "EFI firmware volume"
        self.Size            = Size
        self.Checksum        = Checksum
        self.ExtHeaderOffset = ExtHeaderOffset
        self.CalcSum         = CalcSum

    def __str__(self):
        schecksum = ('%04Xh (%04Xh) *** checksum mismatch ***' % (self.Checksum,self.CalcSum)) if self.CalcSum != self.Checksum else ('%04Xh' % self.Checksum)
        _s = "\n%s%s +%08Xh {%s}: Size %08Xh, Attr %08Xh, HdrSize %04Xh, ExtHdrOffset %08Xh, Checksum %s" % (self.indent,self.clsname,self.Offset,self.Guid,self.Size,self.Attributes,self.HeaderSize,self.ExtHeaderOffset,schecksum)
        _s += ("\n" + super(EFI_FV, self).__str__())
        return _s

class EFI_FILE(EFI_MODULE):
    def __init__(self, Offset, Name, Type, Attributes, State, Checksum, Size, Image, HeaderSize, UD, CalcSum):
        EFI_MODULE.__init__(self, Offset, Name, HeaderSize, Attributes, Image)
        self.clsname     = "EFI binary"
        self.Name        = Name
        self.Type        = Type
        self.State       = State
        self.Size        = Size
        self.Checksum    = Checksum
        self.UD          = UD
        self.CalcSum     = CalcSum

    def __str__(self):
        schecksum = ('%04Xh (%04Xh) *** checksum mismatch ***' % (self.Checksum,self.CalcSum)) if self.CalcSum != self.Checksum else ('%04Xh' % self.Checksum)
        _s = "\n%s%s +%08Xh {%s}\n%sType %02Xh, Attr %08Xh, State %02Xh, Size %06Xh, Checksum %s" % (self.indent,self.clsname,self.Offset,self.Guid,self.indent*2,self.Type,self.Attributes,self.State,self.Size,schecksum)
        _s += ("\n" + super(EFI_FILE, self).__str__())
        return _s

class EFI_SECTION(EFI_MODULE):
    def __init__(self, Offset, Name, Type, Image, HeaderSize):
        EFI_MODULE.__init__(self, Offset, None, HeaderSize, None, Image)
        self.clsname     = "EFI section"
        self.Name        = Name
        self.Type        = Type

        self.ui_string   = ''
        self.DataOffset  = None
    
    def __str__(self):
        _s = "%s%s +%08Xh %-16s: Type %02Xh %s" % (self.indent,self.clsname,self.Offset,self.Name,self.Type,self.ui_string)
        if self.Guid: _s += ", GUID {%s}" % self.Guid
        if self.Attributes: _s += ", Attr %04Xh" % self.Attributes
        if self.DataOffset: _s += ", DataOffset %04Xh" % self.DataOffset
        return _s

def dump_fw_file( fwbin, volume_path ):
    type_s = FILE_TYPE_NAMES[fwbin.Type] if fwbin.Type in FILE_TYPE_NAMES.keys() else ("UNKNOWN_%02X" % fwbin.Type)
    pth = os.path.join( volume_path, "%s.%s-%02X" % (fwbin.Name, type_s, fwbin.Type))
    if os.path.exists( pth ): pth += ("_%08X" % fwbin.Offset)
    write_file( pth, fwbin.Image )
    if fwbin.MD5    != '': write_file( ("%s.md5"    % pth), fwbin.MD5 )
    if fwbin.SHA1   != '': write_file( ("%s.sha1"   % pth), fwbin.SHA1 )
    if fwbin.SHA256 != '': write_file( ("%s.sha256" % pth), fwbin.SHA256 )
    return ("%s.dir" % pth)

def dump_fv( fv, voln, uefi_region_path ):
    fv_pth = os.path.join( uefi_region_path, "%02d_%s" % (voln, fv.Guid) )
    write_file( fv_pth, fv.Image )
    if fv.MD5    != '': write_file( ("%s.md5"    % fv_pth), fv.MD5 )
    if fv.SHA1   != '': write_file( ("%s.sha1"   % fv_pth), fv.SHA1 )
    if fv.SHA256 != '': write_file( ("%s.sha256" % fv_pth), fv.SHA256 )
    volume_path = os.path.join( uefi_region_path, "%02d_%s.dir" % (voln, fv.Guid) )
    if not os.path.exists( volume_path ): os.makedirs( volume_path )
    return volume_path

type2ext = {EFI_SECTION_PE32: 'pe32', EFI_SECTION_TE: 'te', EFI_SECTION_PIC: 'pic', EFI_SECTION_COMPATIBILITY16: 'c16'}
def dump_section( sec, secn, parent_path, efi_file ):
    if sec.Name is not None:
        sec_fs_name = "%02d_%s" % (secn, sec.Name)
        section_path = os.path.join(parent_path, sec_fs_name)
        if sec.Type in (EFI_SECTION_PE32, EFI_SECTION_TE, EFI_SECTION_PIC, EFI_SECTION_COMPATIBILITY16):
            sec_fs_name = "%02d_%s.%s.efi" % (secn, sec.Name, type2ext[sec.Type])
            efi_file = sec_fs_name
            section_path = os.path.join(parent_path, sec_fs_name)
            write_file( section_path, sec.Image[sec.HeaderSize:] )
        else:
            write_file( section_path, sec.Image[sec.HeaderSize:] )
            if sec.Type == EFI_SECTION_USER_INTERFACE:
                ui_string = unicode(sec.Image[sec.HeaderSize:], "utf-16-le")[:-1]
                if ui_string[-4:] != '.efi': ui_string = "%s.efi" % ui_string
                if efi_file is not None:
                    os.rename(os.path.join(parent_path, efi_file), os.path.join(parent_path, ui_string))
                    efi_file = None

    section_dir_path = "%s.dir" % section_path
    return sec_fs_name,section_dir_path,efi_file

def add_hashes( efi ):
    if efi.Image is None: return
    hmd5 = hashlib.md5()
    hmd5.update( efi.Image )
    efi.MD5 = hmd5.hexdigest()
    hsha1 = hashlib.sha1()
    hsha1.update( efi.Image )
    efi.SHA1   = hsha1.hexdigest()
    hsha256 = hashlib.sha256()
    hsha256.update( efi.Image )
    efi.SHA256 = hsha256.hexdigest()

#
# Format of EFI binaries match rules (any field can be empty or missing):
# - Individual rules are OR'ed
# - match criteria within a given rule are AND'ed
#
# Example:
#  {
#    "rule00": { "guid": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" }
#    "rule01": { "name": "module0", "md5": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "sha1": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "sha256": "", "regexp": "" }
#  }
#
# Above search configuration will result in a match if the following EFI module is found:
# - module with guid "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
# OR
# - module with name "module0" AND md5 hash "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" AND sha1 hash "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
#
MATCH_NAME        = 0x1
MATCH_GUID        = (0x1 << 1)
MATCH_REGEXP      = (0x1 << 2)
MATCH_HASH_MD5    = (0x1 << 3)
MATCH_HASH_SHA1   = (0x1 << 4)
MATCH_HASH_SHA256 = (0x1 << 5)

def check_match_criteria( efi, match_criteria ):
    bfound = False
    _log = ''

    for k in match_criteria.keys():
        match_mask   = 0x00000000
        match_result = 0x00000000
        rule = match_criteria[k]
        #
        # Determine which criteria are defined in the current rule
        #
        if ('name'   in rule) and (rule['name']   != ''): match_mask |= MATCH_NAME
        if ('guid'   in rule) and (rule['guid']   != ''): match_mask |= MATCH_GUID
        if ('regexp' in rule) and (rule['regexp'] != ''): match_mask |= MATCH_REGEXP
        if ('md5'    in rule) and (rule['md5']    != ''): match_mask |= MATCH_HASH_MD5
        if ('sha1'   in rule) and (rule['sha1']   != ''): match_mask |= MATCH_HASH_SHA1
        if ('sha256' in rule) and (rule['sha256'] != ''): match_mask |= MATCH_HASH_SHA256

        _s = "[uefi] found matching %s (rule '%s'):" % (efi.clsname,k)
        #
        # Check criteria defined in the current rule against the current EFI module
        #
        if (match_mask & MATCH_NAME) == MATCH_NAME:
            if type(efi) is EFI_SECTION and efi.ui_string == rule['name']: match_result |= MATCH_NAME
        if (match_mask & MATCH_GUID) == MATCH_GUID:
            if ((type(efi) is EFI_FILE) and (efi.Name == rule['guid'])) or (efi.Guid == rule['guid']): match_result |= MATCH_GUID
        if (match_mask & MATCH_REGEXP) == MATCH_REGEXP:
            m = re.compile(rule['regexp']).search( efi.Image )
            if m:
                match_result |= MATCH_REGEXP
                _log = "       + regexp: bytes '%s' at offset %Xh" % (binascii.hexlify(m.group(0)),m.start())
        if (match_mask & MATCH_HASH_MD5) == MATCH_HASH_MD5:
            if efi.MD5 == rule['md5']: match_result |= MATCH_HASH_MD5
        if (match_mask & MATCH_HASH_SHA1) == MATCH_HASH_SHA1:
            if efi.SHA1 == rule['sha1']: match_result |= MATCH_HASH_SHA1
        if (match_mask & MATCH_HASH_SHA256) == MATCH_HASH_SHA256:
            if efi.SHA256 == rule['sha256']: match_result |= MATCH_HASH_SHA256

        brule_match = ((match_result & match_mask) == match_mask)
        bfound = bfound or brule_match
        if brule_match:
            logger().log( _s )
            if (match_result & MATCH_NAME       ) == MATCH_NAME       : logger().log( "       + name  : '%s'" % rule['name'] )
            if (match_result & MATCH_GUID       ) == MATCH_GUID       : logger().log( "       + GUID  : {%s}" % rule['guid'] )
            if (match_result & MATCH_REGEXP     ) == MATCH_REGEXP     : logger().log( _log )
            if (match_result & MATCH_HASH_MD5   ) == MATCH_HASH_MD5   : logger().log( "       + MD5   : %s" % rule['md5'] )
            if (match_result & MATCH_HASH_SHA1  ) == MATCH_HASH_SHA1  : logger().log( "       + SHA1  : %s" % rule['sha1'] )
            if (match_result & MATCH_HASH_SHA256) == MATCH_HASH_SHA256: logger().log( "       + SHA256: %s" % rule['sha256'] )
            logger().log( efi )

    return bfound

def traverse_uefi_section( _uefi, fwtype, data, Size, offset, polarity, parent_offset, printall=True, dumpall=True, parent_path='', match_criteria=None, findall=True ):
    found, secn, efi_file, section_dir_path = False, 0, None, ''
    # caller specified non-empty matching rules so we'll need to look for specific EFI modules as we parse FVs
    bsearch = (match_criteria is not None)

    _off, next_offset, _name, _type, _img, _hdrsz = NextFwFileSection( data, Size, offset, polarity )
    while next_offset is not None:
        sec = EFI_SECTION( _off, _name, _type, _img, _hdrsz )
        sec.indent = DEF_INDENT*2
        # pick random file name in case dumpall=False - we'll need it to decompress the section
        sec_fs_name = "sect%02d_%s" % (secn, ''.join(random.choice(string.ascii_lowercase) for _ in range(4)))
        if sec.Type == EFI_SECTION_USER_INTERFACE:
            sec.ui_string = unicode(sec.Image[sec.HeaderSize:], "utf-16-le")[:-1]

        if printall: logger().log( sec )
        if dumpall: sec_fs_name,section_dir_path,efi_file = dump_section( sec, secn, parent_path, efi_file )
        # only check the match rules if we need to find specific EFI module
        if bsearch and check_match_criteria( sec, match_criteria ):
            if findall: found = True
            else: return True

        if sec.Type in (EFI_SECTION_COMPRESSION, EFI_SECTION_GUID_DEFINED, EFI_SECTION_FIRMWARE_VOLUME_IMAGE, EFI_SECTION_RAW):
            if dumpall: os.makedirs( section_dir_path )
            if sec.Type == EFI_SECTION_COMPRESSION:
                ul, ct = struct.unpack(EFI_COMPRESSION_SECTION, sec.Image[sec.HeaderSize:sec.HeaderSize+EFI_COMPRESSION_SECTION_size])
                d = decompress_section_data( _uefi, section_dir_path, sec_fs_name, sec.Image[sec.HeaderSize+EFI_COMPRESSION_SECTION_size:], ct, True )
                if d:
                    f = traverse_uefi_section( _uefi, fwtype, d, len(d), 0, polarity, 0, printall, dumpall, section_dir_path, match_criteria, findall )
                    if bsearch and f:
                        if findall: found = True
                        else: return True
            elif sec.Type == EFI_SECTION_GUID_DEFINED:
                guid0, guid1, guid2, guid3, sec.DataOffset, sec.Attributes = struct.unpack(EFI_GUID_DEFINED_SECTION, sec.Image[sec.HeaderSize:sec.HeaderSize+EFI_GUID_DEFINED_SECTION_size])
                sec.Guid = guid_str(guid0, guid1, guid2, guid3)
                if sec.Guid == EFI_CRC32_GUIDED_SECTION_EXTRACTION_PROTOCOL_GUID:
                    f = traverse_uefi_section( _uefi, fwtype, sec.Image[sec.DataOffset:], Size - sec.DataOffset, 0, polarity, 0, printall, dumpall, section_dir_path,match_criteria, findall )
                    if bsearch and f:
                        if findall: found = True
                        else: return True
                elif sec.Guid == LZMA_CUSTOM_DECOMPRESS_GUID:
                    d = decompress_section_data( _uefi, section_dir_path, sec_fs_name, sec.Image[sec.DataOffset:], 2, True )
                    if d:
                        f = traverse_uefi_section( _uefi, fwtype, d, len(d), 0, polarity, 0, printall, dumpall, section_dir_path, match_criteria, findall )
                        if bsearch and f:
                            if findall: found = True
                            else: return True
            elif sec.Type in (EFI_SECTION_FIRMWARE_VOLUME_IMAGE, EFI_SECTION_RAW):
                f = traverse_uefi_region( _uefi, sec.Image[sec.HeaderSize:], fwtype, section_dir_path, printall, dumpall, match_criteria, findall )
                if bsearch and f:
                    if findall: found = True
                    else: return True

        _off, next_offset, _name, _type, _img, _hdrsz = NextFwFileSection( data, Size, next_offset, polarity )
        secn += 1
    return found

#
# traverse_uefi_region - searches for a specific EFI binary by its file/UI name, EFI GUID or hash
#
#   Input arguments:
#   _uefi          - instance of chipsec.hal.uefi.UEFI class  
#   data           - an image containing UEFI firmware volumes
#   printall       - a bool flag that tells to print EFI binaries hierarchy
#   dumpall        - a bool flag that tells to dump all EFI binaries onto the file system
#   uefi_path      - root path for EFI hierarchy (used if dumpall==True)
#   match_criteria - criteria to search for sepecific node in EFI hierarchy (Name, GUID, hash, etc.)
#   findall        - a bool flag that tells to find all matching EFI modules in the image (rather than returning upon the first match)
#
def traverse_uefi_region( _uefi, data, fwtype, uefi_path='', printall=True, dumpall=True, match_criteria=None, findall=True ):
    found, voln, fwbin_dir = False, 0, ''
    # caller specified non-empty matching rules so we'll need to look for specific EFI modules as we parse FVs
    bsearch = (match_criteria is not None)

    fv_off, fv_guid, fv_size, fv_attr, fv_hdrsz, fv_csum, fv_hdroff, fv_img, fv_calccsum = NextFwVolume( data )
    while fv_off is not None:
        fv = EFI_FV( fv_off, fv_guid, fv_size, fv_attr, fv_hdrsz, fv_csum, fv_hdroff, fv_img, fv_calccsum )
        add_hashes( fv )

        if printall: logger().log( fv )
        if dumpall: volume_path = dump_fv( fv, voln, uefi_path )
        # only check the match rules if we need to find specific EFI module
        if bsearch and check_match_criteria( fv, match_criteria ):
            if findall: found = True
            else: return True

        polarity = bit_set( fv.Attributes, EFI_FVB2_ERASE_POLARITY )
        #
        # Detect File System firmware volumes
        #
        if fv.Guid == EFI_FIRMWARE_FILE_SYSTEM2_GUID or fv.Guid == EFI_FIRMWARE_FILE_SYSTEM_GUID:
            foff, next_offset, fname, ftype, fattr, fstate, fcsum, fsz, fimg, fhdrsz, fUD, fcalcsum = NextFwFile( fv.Image, fv.Size, fv.HeaderSize, polarity )
            while (next_offset is not None):
                if fname is not None:
                    fwbin = EFI_FILE( foff, fname, ftype, fattr, fstate, fcsum, fsz, fimg, fhdrsz, fUD, fcalcsum )
                    fwbin.indent = DEF_INDENT
                    add_hashes( fwbin )

                    if printall: logger().log( fwbin )
                    if dumpall: fwbin_dir = dump_fw_file( fwbin, volume_path )
                    # only check the match rules if we need to find specific EFI module
                    if bsearch and check_match_criteria( fwbin, match_criteria ):
                        if findall: found = True
                        else: return True

                    if fwbin.Type not in (EFI_FV_FILETYPE_ALL, EFI_FV_FILETYPE_RAW, EFI_FV_FILETYPE_FFS_PAD):
                        if dumpall: os.makedirs( fwbin_dir )
                        f = traverse_uefi_section( _uefi, fwtype, fwbin.Image, fwbin.Size, fwbin.HeaderSize, polarity, fv.Offset + fwbin.Offset, printall, dumpall, fwbin_dir, match_criteria, findall )
                        if bsearch and f:
                            if findall: found = True
                            else: return True
                    elif fwbin.Type == EFI_FV_FILETYPE_RAW:
                        if fwbin.Name == NVAR_NVRAM_FS_FILE and fwbin.UD:
                            if dumpall: _uefi.parse_EFI_variables( os.path.join(file_dir_path, 'DEFAULT_NVRAM'), FvImage, False, FWType.EFI_FW_TYPE_NVAR )

                foff, next_offset, fname, ftype, fattr, fstate, fcsum, fsz, fimg, fhdrsz, fUD, fcalcsum = NextFwFile( fv.Image, fv.Size, next_offset, polarity )
        #
        # Detect NVRAM firmware volumes
        #
        elif fv.Guid in EFI_NVRAM_GUIDS: # == VARIABLE_STORE_FV_GUID:
            if dumpall:
                try:
                    t = identify_EFI_NVRAM( fv.Image ) if fwtype is None else fwtype
                    if t is not None: _uefi.parse_EFI_variables( os.path.join(volume_path, 'NVRAM'), fv.Image, False, t )
                except: logger().error( "[uefi] couldn't parse NVRAM firmware volume {%s}" % fv.Guid )
        #elif fv.Guid == ADDITIONAL_NV_STORE_GUID:
        #    if dumpall: _uefi.parse_EFI_variables( os.path.join(volume_path, 'DEFAULT_NVRAM'), fv.Image, False, FWType.EFI_FW_TYPE_EVSA )

        fv_off, fv_guid, fv_size, fv_attr, fv_hdrsz, fv_csum, fv_hdroff, fv_img, fv_calccsum = NextFwVolume( data, fv.Offset + fv.Size )
        voln += 1

    return found

def parse_uefi_region_from_file( _uefi, filename, fwtype, outpath = None):

    if outpath is None: outpath = os.path.join( helper().getcwd(), filename + ".dir" )
    if not os.path.exists( outpath ): os.makedirs( outpath )
    rom = read_file( filename )
    traverse_uefi_region( _uefi, rom, fwtype, outpath, True, True )


def decode_uefi_region(_uefi, pth, fname, fwtype):

    bios_pth = os.path.join( pth, fname + '.dir' )
    if not os.path.exists( bios_pth ):
        os.makedirs( bios_pth )
    fv_pth = os.path.join( bios_pth, 'FV' )
    if not os.path.exists( fv_pth ):
        os.makedirs( fv_pth )

    # Decoding UEFI Firmware Volumes
    parse_uefi_region_from_file( _uefi, fname, fwtype, fv_pth )

    # Decoding EFI Variables NVRAM
    region_data = read_file( fname )
    if fwtype is None:
        fwtype = identify_EFI_NVRAM( region_data )
        if fwtype is None: return
    elif fwtype not in fw_types:
        if logger().HAL: logger().error( "unrecognized NVRAM type %s" % fwtype )
        return
    nvram_fname = os.path.join( bios_pth, ('nvram_%s' % fwtype) )
    logger().set_log_file( (nvram_fname + '.nvram.lst') )
    _uefi.parse_EFI_variables( nvram_fname, region_data, False, fwtype )
