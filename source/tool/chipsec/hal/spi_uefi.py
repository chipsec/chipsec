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
# chipsec/hal/spi_uefi.py
# =============================
# SPI UEFI Region parsing
# ~~~
# #usage:
#   parse_uefi_region_from_file( filename )
# ~~~
#
__version__ = '1.0'

import os
import fnmatch
import struct
import sys
import time
import collections
#import phex

from chipsec.helper.oshelper import helper
from chipsec.logger import *
from chipsec.file import *

from chipsec.cfg.common import *
from chipsec.hal.uefi_common import *
from chipsec.hal.uefi_platform import *

def save_vol_info( FvOffset, FsGuid, FvLength, FvAttributes, FvHeaderLength, FvChecksum, ExtHeaderOffset, file_path, CalcSum ):
    schecksum = ''
    if (CalcSum != FvChecksum): schecksum = ' *** checksum mismatch ***'
    info = ("Volume offset          : 0x%08X\n" % FvOffset) +\
           ("File system GUID       : %s\n" % FsGuid) + \
           ("Volume length          : 0x%08X (%d)\n" % (FvLength, FvLength)) + \
           ("Attributes             : 0x%08X\n" % FvAttributes) + \
           ("Header length          : 0x%08X\n" % FvHeaderLength) + \
           ("Checksum               : 0x%04X (0x%04X)%s\n" % (FvChecksum, CalcSum, schecksum)) + \
           ("Extended Header Offset : 0x%08X\n" % ExtHeaderOffset)
    logger().log( info )
    #write_file( file_path, info, True )

def save_file_info( cur_offset, Name, Type, Attributes, State, Checksum, Size, file_path, fCalcSum ):
    schecksum = ''
    if (fCalcSum != Checksum): schecksum = ' *** checksum mismatch ***'
    info = ("\tFile offset : 0x%08X\n" % (cur_offset)) + \
           ("\tName        : %s\n" % (Name)) + \
           ("\tType        : 0x%02X\n" % (Type)) + \
           ("\tAttributes  : 0x%08X\n" % (Attributes)) + \
           ("\tState       : 0x%02X\n" % (State)) + \
           ("\tChecksum    : 0x%04X (0x%04X)%s\n" % (Checksum, fCalcSum, schecksum)) + \
           ("\tSize        : 0x%06X (%d)\n" % (Size, Size))
    logger().log( info )
    #write_file( file_path, info, True )

def save_section_info( cur_offset, Name, Type, file_path ):
    info = ("\t\tSection offset : 0x%08X\n" % (cur_offset)) + \
           ("\t\tName           : %s\n" % (Name)) + \
           ("\t\tType           : 0x%02X\n" % (Type))
    logger().log( info )

def parse_uefi_section( _uefi, data, Size, offset, polarity, parent_offset, parent_path, decode_log_path ):
   sec_offset, next_sec_offset, SecName, SecType, SecBody, SecHeaderSize = NextFwFileSection(data, Size, offset, polarity)
   secn = 0
   ui_string = None
   efi_file = None
   while next_sec_offset != None:
      if (SecName != None):
         save_section_info( parent_offset + sec_offset, SecName, SecType, decode_log_path )
         sec_fs_name = "%02d_%s" % (secn, SecName)
         section_path = os.path.join(parent_path, sec_fs_name)
         if (SecType in (EFI_SECTION_PE32, EFI_SECTION_TE, EFI_SECTION_PIC, EFI_SECTION_COMPATIBILITY16)):
            type2ext = {EFI_SECTION_PE32: 'pe32', EFI_SECTION_TE: 'te', EFI_SECTION_PIC: 'pic', EFI_SECTION_COMPATIBILITY16: 'c16'}
            sec_fs_name = "%02d_%s.%s.efi" % (secn, SecName, type2ext[SecType])
            if ui_string != None:
               sec_fs_name = ui_string
               ui_string = None
            efi_file = sec_fs_name
            section_path = os.path.join(parent_path, sec_fs_name)
            write_file( section_path, SecBody[SecHeaderSize:] )
         else:
            write_file( section_path, SecBody[SecHeaderSize:] )
            if (SecType == EFI_SECTION_USER_INTERFACE):
               ui_string = unicode(SecBody[SecHeaderSize:], "utf-16-le")[:-1]
               if (ui_string[-4:] != '.efi'): ui_string = "%s.efi" % ui_string
               #print ui_string
               if efi_file != None:
                  os.rename(os.path.join(parent_path, efi_file), os.path.join(parent_path, ui_string))
                  efi_file = None
         if (SecType in (EFI_SECTION_COMPRESSION, EFI_SECTION_GUID_DEFINED, EFI_SECTION_FIRMWARE_VOLUME_IMAGE)):
            section_dir_path = "%s.dir" % section_path
            os.makedirs( section_dir_path )
            if   (SecType == EFI_SECTION_COMPRESSION):
               UncompressedLength, CompressionType = struct.unpack(EFI_COMPRESSION_SECTION, SecBody[SecHeaderSize:SecHeaderSize+EFI_COMPRESSION_SECTION_size])
               compressed_name = os.path.join(section_dir_path, "%s.gz" % sec_fs_name)
               uncompressed_name = os.path.join(section_dir_path, sec_fs_name)
               write_file(compressed_name, SecBody[SecHeaderSize+EFI_COMPRESSION_SECTION_size:])
               # TODO: decompress section
               decompressed = DecompressSection(compressed_name, uncompressed_name, CompressionType)
               if decompressed:
                  parse_uefi_section(_uefi, decompressed, len(decompressed), 0, polarity, 0, section_dir_path, decode_log_path)
                  pass
            elif (SecType == EFI_SECTION_GUID_DEFINED):
               # TODO: decode section based on its GUID
               # Only CRC32 guided sectioni can be decoded for now
               guid0, guid1, guid2, guid3, DataOffset, Attributes = struct.unpack(EFI_GUID_DEFINED_SECTION, SecBody[SecHeaderSize:SecHeaderSize+EFI_GUID_DEFINED_SECTION_size])
               sguid = guid_str(guid0, guid1, guid2, guid3)
               if (sguid == EFI_CRC32_GUIDED_SECTION_EXTRACTION_PROTOCOL_GUID):
                  parse_uefi_section(_uefi, SecBody[DataOffset:], Size - DataOffset, 0, polarity, 0, section_dir_path, decode_log_path)
               #else:
               #   write_file( os.path.join(section_dir_path, "%s-%04X" % (sguid, Attributes)), SecBody[DataOffset:] )
               pass
            elif (SecType == EFI_SECTION_FIRMWARE_VOLUME_IMAGE):
               parse_uefi_region(_uefi, SecBody[SecHeaderSize:], section_dir_path)
      sec_offset, next_sec_offset, SecName, SecType, SecBody, SecHeaderSize = NextFwFileSection(data, Size, next_sec_offset, polarity)
      secn = secn + 1

def parse_uefi_region( _uefi, data, uefi_region_path ):
    voln = 0
    FvOffset, FsGuid, FvLength, FvAttributes, FvHeaderLength, FvChecksum, ExtHeaderOffset, FvImage, CalcSum = NextFwVolume(data)
    while FvOffset != None:
        decode_log_path = os.path.join(uefi_region_path, "efi_firmware_volumes.log")
        volume_file_path = os.path.join( uefi_region_path, "%02d_%s" % (voln, FsGuid) )
        volume_path = os.path.join( uefi_region_path, "%02d_%s.dir" % (voln, FsGuid) )
        if not os.path.exists( volume_path ):
           os.makedirs( volume_path )
        write_file( volume_file_path, FvImage )
        save_vol_info( FvOffset, FsGuid, FvLength, FvAttributes, FvHeaderLength, FvChecksum, ExtHeaderOffset, decode_log_path, CalcSum )

        polarity = bit_set(FvAttributes, EFI_FVB2_ERASE_POLARITY)
        if (FsGuid == ADDITIONAL_NV_STORE_GUID):
           nvram_fname = os.path.join(volume_path, 'SHADOW_NVRAM')
           _uefi.parse_EFI_variables( nvram_fname, FvImage, False, 'evsa' )
        elif ((FsGuid == EFI_FIRMWARE_FILE_SYSTEM2_GUID) or (FsGuid == EFI_FIRMWARE_FILE_SYSTEM_GUID)):
           cur_offset, next_offset, Name, Type, Attributes, State, Checksum, Size, FileImage, HeaderSize, UD, fCalcSum = NextFwFile(FvImage, FvLength, FvHeaderLength, polarity)
           while next_offset != None:
              #print "File: offset=%08X, next_offset=%08X, UD=%s\n" % (cur_offset, next_offset, UD)
              if (Name != None):
                 file_type_str = "UNKNOWN_%02X" % Type
                 if Type in FILE_TYPE_NAMES.keys():
                    file_type_str = FILE_TYPE_NAMES[Type]
                 file_path = os.path.join( volume_path, "%s.%s-%02X" % (Name, file_type_str, Type))
                 if os.path.exists( file_path ):
                    file_path = file_path + ("_%08X" % cur_offset)
                 write_file( file_path, FileImage )
                 file_dir_path = "%s.dir" % file_path
                 save_file_info( FvOffset + cur_offset, Name, Type, Attributes, State, Checksum, Size, decode_log_path, fCalcSum)
                 if (Type not in (EFI_FV_FILETYPE_ALL, EFI_FV_FILETYPE_RAW, EFI_FV_FILETYPE_FFS_PAD)):
                    os.makedirs( file_dir_path )
                    parse_uefi_section(_uefi, FileImage, Size, HeaderSize, polarity, FvOffset + cur_offset, file_dir_path, decode_log_path)
                 elif (Type == EFI_FV_FILETYPE_RAW):
                    if ((Name == NVAR_NVRAM_FS_FILE) and UD):
                       nvram_fname = os.path.join(file_dir_path, 'SHADOW_NVRAM')
                       _uefi.parse_EFI_variables( nvram_fname, FvImage, False, 'nvar' )
              cur_offset, next_offset, Name, Type, Attributes, State, Checksum, Size, FileImage, HeaderSize, UD, fCalcSum = NextFwFile(FvImage, FvLength, next_offset, polarity)
        FvOffset, FsGuid, FvLength, Attributes, HeaderLength, Checksum, ExtHeaderOffset, FvImage, CalcSum = NextFwVolume(data, FvOffset+FvLength)
        voln = voln + 1

def parse_uefi_region_from_file( _uefi, filename, outpath = None):

    if outpath is None:
       outpath = os.path.join( helper().getcwd(), filename + ".dir" )
    if not os.path.exists( outpath ):
       os.makedirs( outpath )

    #uefi_region_path = os.path.join( os.getcwd(), filename + "_UEFI_region" )
    #if not os.path.exists( uefi_region_path ):
    #    os.makedirs( uefi_region_path )

    rom = read_file( filename )
    parse_uefi_region( _uefi, rom, outpath )

           
def decode_uefi_region(_uefi, pth, fname, fwtype):
    bios_pth = os.path.join( pth, fname + '.dir' )
    if not os.path.exists( bios_pth ):
        os.makedirs( bios_pth )
    fv_pth = os.path.join( bios_pth, 'FV' )
    if not os.path.exists( fv_pth ):
        os.makedirs( fv_pth )
    parse_uefi_region_from_file( _uefi, fname, fv_pth )
    # Decoding EFI Variables NVRAM
    region_data = read_file( fname )
    nvram_fname = os.path.join( bios_pth, ('nvram_%s' % fwtype) )
    logger().set_log_file( (nvram_fname + '.nvram.lst') )
    _uefi.parse_EFI_variables( nvram_fname, region_data, False, fwtype )
