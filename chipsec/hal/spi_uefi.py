#!/usr/bin/python
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
#
# -------------------------------------------------------------------------------

"""
UEFI firmware image parsing and manipulation functionality

usage:
    >>> parse_uefi_region_from_file(_uefi, filename, fwtype, outpath):
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
import json
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

type2ext = {EFI_SECTION_PE32: 'pe32', EFI_SECTION_TE: 'te', EFI_SECTION_PIC: 'pic', EFI_SECTION_COMPATIBILITY16: 'c16'}

#
# Calculate hashes for all FVs, FW files and sections (PE/COFF or TE executables)
# and write them on the file system
#
WRITE_ALL_HASHES = False

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
        return "%s {%s} %s" % (type(self).__name__,self.Guid,self.ui_string if self.ui_string else '')

    def __str__(self):
        _ind = self.indent + DEF_INDENT
        _s = ''
        if self.MD5   : _s  = "\n%sMD5   : %s" % (_ind,self.MD5)
        if self.SHA1  : _s += "\n%sSHA1  : %s" % (_ind,self.SHA1)
        if self.SHA256: _s += "\n%sSHA256: %s" % (_ind,self.SHA256)
        return _s

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
        schecksum = ('%04Xh (%04Xh) *** checksum mismatch ***' % (self.Checksum,self.CalcSum)) if self.CalcSum != self.Checksum else ('%04Xh' % self.Checksum)
        _s = "\n%s%s +%08Xh {%s}: Size %08Xh, Attr %08Xh, HdrSize %04Xh, ExtHdrOffset %08Xh, Checksum %s" % (self.indent,type(self).__name__,self.Offset,self.Guid,self.Size,self.Attributes,self.HeaderSize,self.ExtHeaderOffset,schecksum)
        _s += super(EFI_FV, self).__str__()
        return _s

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
        schecksum = ('%04Xh (%04Xh) *** checksum mismatch ***' % (self.Checksum,self.CalcSum)) if self.CalcSum != self.Checksum else ('%04Xh' % self.Checksum)
        _s = "\n%s+%08Xh %s\n%sType %02Xh, Attr %08Xh, State %02Xh, Size %06Xh, Checksum %s" % (self.indent,self.Offset,self.name(),self.indent,self.Type,self.Attributes,self.State,self.Size,schecksum)
        _s += (super(EFI_FILE, self).__str__() + '\n')
        return _s

class EFI_SECTION(EFI_MODULE):
    def __init__(self, Offset, Name, Type, Image, HeaderSize):
        super(EFI_SECTION, self).__init__(Offset, None, HeaderSize, None, Image)
        self.Name        = Name
        self.Type        = Type
        self.DataOffset  = None

        # parent GUID used in search, export to JSON/log
        self.parentGuid  = None
    
    def name(self):
        return "%s section of binary {%s} %s" % (self.Name,self.parentGuid,self.ui_string if self.ui_string else '')

    def __str__(self):
        _s = "%s+%08Xh %s: Type %02Xh" % (self.indent,self.Offset,self.name(),self.Type)
        if self.Guid: _s += " GUID {%s}" % self.Guid
        if self.Attributes: _s += " Attr %04Xh" % self.Attributes
        if self.DataOffset: _s += " DataOffset %04Xh" % self.DataOffset
        _s += super(EFI_SECTION, self).__str__()
        return _s


def build_efi_modules_tree( _uefi, fwtype, data, Size, offset, polarity ):
    sections = []
    secn = 0

    _off, next_offset, _name, _type, _img, _hdrsz = NextFwFileSection( data, Size, offset, polarity )
    while next_offset is not None:
        sec = EFI_SECTION( _off, _name, _type, _img, _hdrsz )
        # pick random file name in case dumpall=False - we'll need it to decompress the section
        sec_fs_name = "sect%02d_%s" % (secn, ''.join(random.choice(string.ascii_lowercase) for _ in range(4)))

        if sec.Type in EFI_SECTIONS_EXE:
            # "leaf" executable section: update hashes and check against match criteria
            sec.calc_hashes( sec.HeaderSize )
        elif sec.Type == EFI_SECTION_USER_INTERFACE:
            # "leaf" UI section: update section's UI name
            sec.ui_string = unicode(sec.Image[sec.HeaderSize:], "utf-16-le")[:-1]
        elif sec.Type == EFI_SECTION_GUID_DEFINED:
            guid0, guid1, guid2, guid3, sec.DataOffset, sec.Attributes = struct.unpack(EFI_GUID_DEFINED_SECTION, sec.Image[sec.HeaderSize:sec.HeaderSize+EFI_GUID_DEFINED_SECTION_size])
            sec.Guid = guid_str(guid0, guid1, guid2, guid3)

        # "container" sections: keep parsing
        if sec.Type in (EFI_SECTION_COMPRESSION, EFI_SECTION_GUID_DEFINED, EFI_SECTION_FIRMWARE_VOLUME_IMAGE, EFI_SECTION_RAW):
            if sec.Type == EFI_SECTION_COMPRESSION:
                ul, ct = struct.unpack(EFI_COMPRESSION_SECTION, sec.Image[sec.HeaderSize:sec.HeaderSize+EFI_COMPRESSION_SECTION_size])
                d = decompress_section_data( _uefi, "", sec_fs_name, sec.Image[sec.HeaderSize+EFI_COMPRESSION_SECTION_size:], ct, True )
                if d:
                    sec.children = build_efi_modules_tree( _uefi, fwtype, d, len(d), 0, polarity )
            elif sec.Type == EFI_SECTION_GUID_DEFINED:
                if sec.Guid == EFI_CRC32_GUIDED_SECTION_EXTRACTION_PROTOCOL_GUID:
                    sec.children = build_efi_modules_tree( _uefi, fwtype, sec.Image[sec.DataOffset:], Size - sec.DataOffset, 0, polarity )
                elif sec.Guid == LZMA_CUSTOM_DECOMPRESS_GUID or sec.Guid == TIANO_DECOMPRESSED_GUID:
                    d = decompress_section_data( _uefi, "", sec_fs_name, sec.Image[sec.DataOffset:], 2, True )
                    if d:
                        sec.children = build_efi_modules_tree( _uefi, fwtype, d, len(d), 0, polarity )
                elif sec.Guid == FIRMWARE_VOLUME_GUID:
                    sec.children = build_efi_model( _uefi, sec.Image[sec.HeaderSize:], fwtype )
            elif sec.Type in (EFI_SECTION_FIRMWARE_VOLUME_IMAGE, EFI_SECTION_RAW):
                sec.children = build_efi_model( _uefi, sec.Image[sec.HeaderSize:], fwtype )

        sections.append(sec)
        _off, next_offset, _name, _type, _img, _hdrsz = NextFwFileSection( data, Size, next_offset, polarity )
        secn += 1
    return sections


#
# build_efi_tree - extract EFI modules (FV, files, sections) from EFI image and build an object tree
#
# Input arguments:
#   _uefi          - instance of chipsec.hal.uefi.UEFI class  
#   data           - an image containing UEFI firmware volumes
#   fwtype         - platform specific firmware type used to detect NVRAM format (VSS, EVSA, NVAR...)
#
def build_efi_tree( _uefi, data, fwtype ):
    fvolumes = []
    fv_off, fv_guid, fv_size, fv_attr, fv_hdrsz, fv_csum, fv_hdroff, fv_img, fv_calccsum = NextFwVolume( data )
    while fv_off is not None:
        fv = EFI_FV( fv_off, fv_guid, fv_size, fv_attr, fv_hdrsz, fv_csum, fv_hdroff, fv_img, fv_calccsum )
        fv.calc_hashes()
        polarity = bit_set( fv.Attributes, EFI_FVB2_ERASE_POLARITY )

        # Detect File System firmware volumes
        if fv.Guid in (EFI_PLATFORM_FS_GUIDS + EFI_FS_GUIDS):
            foff, next_offset, fname, ftype, fattr, fstate, fcsum, fsz, fimg, fhdrsz, fUD, fcalcsum = NextFwFile( fv.Image, fv.Size, fv.HeaderSize, polarity )
            while next_offset is not None:
                if fname:
                    fwbin = EFI_FILE( foff, fname, ftype, fattr, fstate, fcsum, fsz, fimg, fhdrsz, fUD, fcalcsum )
                    fwbin.calc_hashes()
                    if fwbin.Type not in (EFI_FV_FILETYPE_ALL, EFI_FV_FILETYPE_RAW, EFI_FV_FILETYPE_FFS_PAD):
                        fwbin.children = build_efi_modules_tree( _uefi, fwtype, fwbin.Image, fwbin.Size, fwbin.HeaderSize, polarity )
                    elif fwbin.Type == EFI_FV_FILETYPE_RAW:
                        if fwbin.Name != NVAR_NVRAM_FS_FILE:
                            fwbin.children = build_efi_tree( _uefi, fwbin.Image, fwtype )
                        else:
                            fwbin.isNVRAM   = True
                            fwbin.NVRAMType = FWType.EFI_FW_TYPE_NVAR

                    fv.children.append(fwbin)
                foff, next_offset, fname, ftype, fattr, fstate, fcsum, fsz, fimg, fhdrsz, fUD, fcalcsum = NextFwFile( fv.Image, fv.Size, next_offset, polarity )

        # Detect NVRAM firmware volumes
        elif fv.Guid in EFI_NVRAM_GUIDS: # == VARIABLE_STORE_FV_GUID:
            fv.isNVRAM = True
            try:
                fv.NVRAMType = identify_EFI_NVRAM( fv.Image ) if fwtype is None else fwtype
            except: logger().warn("couldn't identify NVRAM in FV {%s}" % fv.Guid)

        fvolumes.append(fv)
        fv_off, fv_guid, fv_size, fv_attr, fv_hdrsz, fv_csum, fv_hdroff, fv_img, fv_calccsum = NextFwVolume( data, fv.Offset + fv.Size )

    return fvolumes

#
# update_efi_tree propagates EFI file's GUID down to all sections and
# UI_string from the corresponding section, if found, up to the EFI file at the same time
# File GUID and UI string are then used when searching for EFI files and executable sections
#
def update_efi_tree(modules, parent_guid=None):
    ui_string = None
    for m in modules:
        if type(m) == EFI_FILE:
           parent_guid = m.Guid
        elif type(m) == EFI_SECTION:
           # if it's a section update its parent file's GUID
           m.parentGuid = parent_guid
           if m.Type == EFI_SECTION_USER_INTERFACE:
               # if UI section (leaf), update ui_string in sibling sections including in PE/TE,
               # and propagate it up untill and including parent EFI file
               for m1 in modules: m1.ui_string = m.ui_string
               return m.ui_string
        # update parent file's GUID in all children nodes
        if len(m.children) > 0:
            ui_string = update_efi_tree(m.children, parent_guid)
            # if it's a EFI file then update its ui_string with ui_string extracted from UI section
            if ui_string and (type(m) in (EFI_FILE, EFI_SECTION)):
                m.ui_string = ui_string
                if (type(m) == EFI_FILE):
                    ui_string = None
    return ui_string

def build_efi_model( _uefi, data, fwtype ):
    model = build_efi_tree( _uefi, data, fwtype )
    update_efi_tree(model)
    return model

def FILENAME(mod, parent, modn):
    fname = "%02d_%s" % (modn,mod.Guid)
    if type(mod) == EFI_FILE:
        type_s = FILE_TYPE_NAMES[mod.Type] if mod.Type in FILE_TYPE_NAMES.keys() else ("UNKNOWN_%02X" % mod.Type)
        fname = "%s.%s" % (fname,type_s)
    elif type(mod) == EFI_SECTION:
        fname = "%02d_%s" % (modn,mod.Name)
        if mod.Type in EFI_SECTIONS_EXE:
            if parent.ui_string:
                if (parent.ui_string.endswith(".efi")):
                    fname = parent.ui_string
                else:
                    fname = "%s.efi" % parent.ui_string
            else:                fname = "%s.%s" % (fname,type2ext[mod.Type])
    return fname

def dump_efi_module(mod, parent, modn, path):
    fname = FILENAME(mod, parent, modn)
    mod_path = os.path.join(path, fname)
    write_file(mod_path, mod.Image[mod.HeaderSize:] if type(mod) == EFI_SECTION else mod.Image)
    if type(mod) == EFI_SECTION or WRITE_ALL_HASHES:
        if mod.MD5   : write_file(("%s.md5"    % mod_path), mod.MD5)
        if mod.SHA1  : write_file(("%s.sha1"   % mod_path), mod.SHA1)
        if mod.SHA256: write_file(("%s.sha256" % mod_path), mod.SHA256)
    return mod_path

class EFIModuleType:
  SECTION_EXE = 0
  SECTION     = 1
  FV          = 2
  FILE        = 4

def search_efi_tree(modules, search_callback, match_module_types=EFIModuleType.SECTION_EXE, findall=True):
    matching_modules = []
    for m in modules:
        if search_callback is not None:
            if ((match_module_types & EFIModuleType.SECTION     == EFIModuleType.SECTION)     and type(m) == EFI_SECTION) or \
               ((match_module_types & EFIModuleType.SECTION_EXE == EFIModuleType.SECTION_EXE) and (type(m) == EFI_SECTION and m.Type in EFI_SECTIONS_EXE)) or \
               ((match_module_types & EFIModuleType.FV          == EFIModuleType.FV)          and type(m) == EFI_FV) or \
               ((match_module_types & EFIModuleType.FILE        == EFIModuleType.FILE)        and type(m) == EFI_FILE):
                if search_callback(m):
                    matching_modules.append(m)
                    if not findall: return True
        
        # recurse search if current module node has children nodes
        if len(m.children) > 0:
            matches = search_efi_tree(m.children, search_callback, match_module_types, findall)
            if len(matches) > 0:
                matching_modules.extend(matches)
                if not findall: return True

    return matching_modules

def save_efi_tree(_uefi, modules, parent=None, save_modules=True, path=None, save_log=True, lvl=0):
    mod_dir_path = None
    modules_arr = []
    modn = 0
    for m in modules:
        md = {}
        m.indent = DEF_INDENT*lvl
        if save_log: logger().log(m)

        # extract all non-function non-None members of EFI_MODULE objects
        attrs = [a for a in dir(m) if not callable(getattr(m,a)) and not a.startswith("__") and (getattr(m,a) is not None)]
        for a in attrs: md[a] = getattr(m,a)
        md["class"] = type(m).__name__
        # remove extra attributes
        for f in ["Image","indent"]: del md[f]

        # save EFI module image, make sub-directory for children
        if save_modules:
            mod_path = dump_efi_module(m, parent, modn, path)
            try:
                md["file_path"] = os.path.relpath(mod_path[4:] if mod_path.startswith("\\\\?\\") else mod_path)
            except:
                md["file_path"] = mod_path.split(os.sep)[-1]
            if m.isNVRAM or len(m.children) > 0:
                mod_dir_path = "%s.dir" % mod_path
                if not os.path.exists(mod_dir_path): os.makedirs(mod_dir_path)
                if m.isNVRAM:
                    try:
                        if m.NVRAMType is not None:
                            # @TODO: technically, NVRAM image should be m.Image but
                            # getNVstore_xxx functions expect FV than a FW file within FV
                            # so for EFI_FILE type of module using parent's Image as NVRAM
                            nvram = parent.Image if (type(m) == EFI_FILE and type(parent) == EFI_FV) else m.Image
                            _uefi.parse_EFI_variables( os.path.join(mod_dir_path, 'NVRAM'), nvram, False, m.NVRAMType )
                        else: raise
                    except: logger().warn( "couldn't extract NVRAM in {%s} using type '%s'" % (m.Guid,m.NVRAMType) )
    
        # save children modules
        if len(m.children) > 0:
            md["children"] = save_efi_tree(_uefi, m.children, m, save_modules, mod_dir_path, save_log, lvl+1)
        else:
            del md["children"]

        modules_arr.append(md)
        modn += 1

    return modules_arr


def parse_uefi_region_from_file( _uefi, filename, fwtype, outpath = None):
    # Create an output folder to dump EFI module tree
    if outpath is None: outpath = "%s.dir" % filename
    if not os.path.exists( outpath ): os.makedirs( outpath )

    # Read UEFI image binary to parse
    rom = read_file(filename)

    # Parse UEFI image binary and build a tree hierarchy of EFI modules
    tree = build_efi_model(_uefi, rom, fwtype)

    # Save entire EFI module hierarchy on a file-system and export into JSON
    tree_json = save_efi_tree(_uefi, tree, path=outpath)
    write_file( "%s.UEFI.json" % filename, json.dumps(tree_json, indent=2, separators=(',', ': ')) )


def decode_uefi_region(_uefi, pth, fname, fwtype):

    bios_pth = os.path.join( pth, fname + '.dir' )
    if not os.path.exists( bios_pth ):
        os.makedirs( bios_pth )
    fv_pth = os.path.join( bios_pth, 'FV' )
    if not os.path.exists( fv_pth ):
        os.makedirs( fv_pth )

    # Decoding UEFI Firmware Volumes
    if logger().HAL: logger().log( "[spi_uefi] decoding UEFI firmware volumes..." )
    parse_uefi_region_from_file( _uefi, fname, fwtype, fv_pth )

    # Decoding EFI Variables NVRAM
    if logger().HAL: logger().log( "[spi_uefi] decoding UEFI NVRAM..." )
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
