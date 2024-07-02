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

import os
import struct
import random
import json
import string
from uuid import UUID
from typing import Dict, List, Optional, Union, Any, Callable, TYPE_CHECKING
if TYPE_CHECKING:
    from chipsec.hal.uefi_fv import EFI_MODULE
from chipsec.library.logger import logger
from chipsec.library.file import write_file, read_file
from chipsec.hal.uefi_compression import COMPRESSION_TYPE_LZMA, COMPRESSION_TYPE_EFI_STANDARD, COMPRESSION_TYPES_ALGORITHMS, COMPRESSION_TYPE_UNKNOWN, COMPRESSION_TYPE_LZMAF86
from chipsec.hal.uefi_common import bit_set, EFI_GUID_SIZE, EFI_GUID_FMT
from chipsec.hal.uefi_platform import FWType, fw_types, EFI_NVRAM_GUIDS, EFI_PLATFORM_FS_GUIDS, NVAR_NVRAM_FS_FILE
from chipsec.hal.uefi import identify_EFI_NVRAM, parse_EFI_variables
from chipsec.hal.uefi_fv import EFI_SECTION_PE32, EFI_SECTION_TE, EFI_SECTION_PIC, EFI_SECTION_COMPATIBILITY16, EFI_FIRMWARE_FILE_SYSTEM2_GUID
from chipsec.hal.uefi_fv import EFI_FIRMWARE_FILE_SYSTEM_GUID, EFI_SECTIONS_EXE, EFI_SECTION_USER_INTERFACE, EFI_SECTION_GUID_DEFINED
from chipsec.hal.uefi_fv import EFI_GUID_DEFINED_SECTION, EFI_GUID_DEFINED_SECTION_size, NextFwFile, NextFwFileSection, NextFwVolume, GetFvHeader
from chipsec.hal.uefi_fv import EFI_CRC32_GUIDED_SECTION_EXTRACTION_PROTOCOL_GUID, LZMA_CUSTOM_DECOMPRESS_GUID, TIANO_DECOMPRESSED_GUID, LZMAF86_DECOMPRESS_GUID
from chipsec.hal.uefi_fv import EFI_CERT_TYPE_RSA_2048_SHA256_GUID, EFI_CERT_TYPE_RSA_2048_SHA256_GUID_size, EFI_SECTION, EFI_FV, EFI_FILE
from chipsec.hal.uefi_fv import EFI_FIRMWARE_CONTENTS_SIGNED_GUID, WIN_CERT_TYPE_EFI_GUID, WIN_CERTIFICATE_size, WIN_CERTIFICATE
from chipsec.hal.uefi_fv import EFI_SECTION_COMPRESSION, EFI_SECTION_FIRMWARE_VOLUME_IMAGE, EFI_SECTION_RAW, SECTION_NAMES, DEF_INDENT
from chipsec.hal.uefi_fv import FILE_TYPE_NAMES, EFI_FS_GUIDS, EFI_FILE_HEADER_INVALID, EFI_FILE_HEADER_VALID, EFI_FILE_HEADER_CONSTRUCTION
from chipsec.hal.uefi_fv import EFI_COMPRESSION_SECTION_size, EFI_FV_FILETYPE_ALL, EFI_FV_FILETYPE_FFS_PAD, EFI_FVB2_ERASE_POLARITY, EFI_FV_FILETYPE_RAW
from chipsec.hal.uefi_compression import UEFICompression

CMD_UEFI_FILE_REMOVE = 0
CMD_UEFI_FILE_INSERT_BEFORE = 1
CMD_UEFI_FILE_INSERT_AFTER = 2
CMD_UEFI_FILE_REPLACE = 3

type2ext = {EFI_SECTION_PE32: 'pe32', EFI_SECTION_TE: 'te', EFI_SECTION_PIC: 'pic', EFI_SECTION_COMPATIBILITY16: 'c16'}

#
# Calculate hashes for all FVs, FW files and sections (PE/COFF or TE executables)
# and write them on the file system
#
WRITE_ALL_HASHES = False


def decompress_section_data(section_dir_path: str, sec_fs_name: str, compressed_data: bytes, compression_type: int) -> bytes:
    uefi_uc = UEFICompression()
    uncompressed_name = os.path.join(section_dir_path, sec_fs_name)
    logger().log_hal(f'[uefi] Decompressing EFI binary (type = 0x{compression_type:X})\n       {uncompressed_name} ->\n')
    uncompressed_image = uefi_uc.decompress_EFI_binary(compressed_data, compression_type)
    return uncompressed_image


def compress_image(image: bytes, compression_type: int) -> bytes:
    uefi_uc = UEFICompression()
    logger().log_hal(f'[uefi] Compressing EFI binary (type = 0x{compression_type:X})\n')
    compressed_image = uefi_uc.compress_EFI_binary(image, compression_type)
    return compressed_image


def modify_uefi_region(data: bytes, command: int, guid: UUID, uefi_file: bytes = b'') -> bytes:
    FvEndOffset = 0  # Default
    fv = NextFwVolume(data)
    while fv is not None:
        FvLengthChange = 0
        polarity = bit_set(fv.Attributes, EFI_FVB2_ERASE_POLARITY)
        if ((fv.Guid == EFI_FIRMWARE_FILE_SYSTEM2_GUID) or (fv.Guid == EFI_FIRMWARE_FILE_SYSTEM_GUID)):
            fwbin = NextFwFile(fv.Image, fv.Size, fv.HeaderSize, polarity)
            while fwbin is not None:
                next_offset = fwbin.Size + fwbin.Offset
                if (fwbin.Guid == guid):
                    uefi_file_size = (len(uefi_file) + 7) & 0xFFFFFFF8
                    CurFileOffset = fv.Offset + fwbin.Offset + FvLengthChange
                    NxtFileOffset = fv.Offset + next_offset + FvLengthChange
                    if command == CMD_UEFI_FILE_REMOVE:
                        FvLengthChange -= (next_offset - fwbin.Offset)
                        logger().log(f'Removing UEFI file with GUID={fwbin.Guid} at offset={CurFileOffset:08X}, size change: {FvLengthChange:d} bytes')
                        data = data[:CurFileOffset] + data[NxtFileOffset:]
                    elif command == CMD_UEFI_FILE_INSERT_BEFORE:
                        FvLengthChange += uefi_file_size
                        logger().log(f'Inserting UEFI file before file with GUID={fwbin.Guid} at offset={CurFileOffset:08X}, size change: {FvLengthChange:d} bytes')
                        data = data[:CurFileOffset] + uefi_file.ljust(uefi_file_size, b'\xFF') + data[CurFileOffset:]
                    elif command == CMD_UEFI_FILE_INSERT_AFTER:
                        FvLengthChange += uefi_file_size
                        logger().log(f'Inserting UEFI file after file with GUID={fwbin.Guid} at offset={CurFileOffset:08X}, size change: {FvLengthChange:d} bytes')
                        data = data[:NxtFileOffset] + uefi_file.ljust(uefi_file_size, b'\xFF') + data[NxtFileOffset:]
                    elif command == CMD_UEFI_FILE_REPLACE:
                        FvLengthChange += uefi_file_size - (next_offset - fwbin.Offset)
                        logger().log(f'Replacing UEFI file with GUID={fwbin.Guid} at offset={CurFileOffset:08X}, new size: {len(uefi_file):d}, old size: {fwbin.Size:d}, size change: {FvLengthChange:d} bytes')
                        data = data[:CurFileOffset] + uefi_file.ljust(uefi_file_size, b'\xFF') + data[NxtFileOffset:]
                    else:
                        raise Exception('Invalid command')
                if next_offset - fwbin.Offset >= 24:
                    FvEndOffset = fv.Offset + next_offset + FvLengthChange

                fwbin = NextFwFile(fv.Image, fv.Size, next_offset, polarity)
            if FvEndOffset == 0:
                logger().log_hal(f'Using FvEndOffset = 0')
            if FvLengthChange >= 0:
                data = data[:FvEndOffset] + data[FvEndOffset + FvLengthChange:]
            else:
                data = data[:FvEndOffset] + (abs(FvLengthChange) * b'\xFF') + data[FvEndOffset:]

            FvLengthChange = 0

            # if FvLengthChange != 0:
            #    logger().log( "Rebuilding Firmware Volume with GUID={} at offset={:08X}".format(FsGuid, FvOffset) )
            #    FvHeader = data[FvOffset: FvOffset + FvHeaderLength]
            #    FvHeader = FvHeader[:0x20] + struct.pack('<Q', FvLength) + FvHeader[0x28:]
            #    NewChecksum = FvChecksum16(FvHeader[:0x32] + '\x00\x00' + FvHeader[0x34:])
            #    FvHeader = FvHeader[:0x32] + struct.pack('<H', NewChecksum) + FvHeader[0x34:]
            #    data = data[:FvOffset] + FvHeader + data[FvOffset + FvHeaderLength:]

        fv = NextFwVolume(data, fv.Offset, fv.Size)
    return data


def build_efi_modules_tree(fwtype: str, data: bytes, Size: int, offset: int, polarity: bool) -> List[EFI_SECTION]:
    sections: List[EFI_SECTION] = []
    secn = 0

    sec = NextFwFileSection(data, Size, offset, polarity)
    while sec is not None:
        # pick random file name in case dumpall=False - we'll need it to decompress the section
        file_name = ''.join(random.choice(string.ascii_lowercase) for _ in range(4))
        sec_fs_name = f'sect{secn:02d}_{file_name}'

        if sec.Type in EFI_SECTIONS_EXE:
            # "leaf" executable section: update hashes and check against match criteria
            sec.calc_hashes(sec.HeaderSize)
        elif sec.Type == EFI_SECTION_USER_INTERFACE:
            # "leaf" UI section: update section's UI name
            try:
                sec.ui_string = sec.Image[sec.HeaderSize:-2].decode("utf-16")
            except UnicodeDecodeError:
                pass
        elif sec.Type == EFI_SECTION_GUID_DEFINED:
            if len(sec.Image) < sec.HeaderSize + EFI_GUID_DEFINED_SECTION_size:
                logger().log_warning("EFI Section seems to be malformed")
                if len(sec.Image) < sec.HeaderSize + EFI_GUID_SIZE:
                    logger().log_warning("Creating fake GUID of 0000-00-00-0000000")
                    guid0 = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                else:
                    guid0 = struct.unpack(EFI_GUID_FMT, sec.Image[sec.HeaderSize:sec.HeaderSize + EFI_GUID_SIZE])[0]
                    sec.DataOffset = len(sec.Image) - 1
            else:
                guid0, sec.DataOffset, sec.Attributes = struct.unpack(EFI_GUID_DEFINED_SECTION, sec.Image[sec.HeaderSize:sec.HeaderSize + EFI_GUID_DEFINED_SECTION_size])
            if not isinstance(guid0, bytes):
                logger().log_warning("GUID is corrupted")
                logger().log_warning("Creating fake GUID of 0000-00-00-0000000")
                guid0 = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

            sec.Guid = UUID(bytes_le=guid0)

            if sec.Guid == EFI_CRC32_GUIDED_SECTION_EXTRACTION_PROTOCOL_GUID:
                sec.children = build_efi_modules_tree(fwtype, sec.Image[sec.DataOffset:], Size - sec.DataOffset, 0, polarity)
            elif sec.Guid == LZMA_CUSTOM_DECOMPRESS_GUID or sec.Guid == TIANO_DECOMPRESSED_GUID or sec.Guid == LZMAF86_DECOMPRESS_GUID:
                if sec.Guid == LZMA_CUSTOM_DECOMPRESS_GUID:
                    d = decompress_section_data("", sec_fs_name, sec.Image[sec.DataOffset:], COMPRESSION_TYPE_LZMA)
                elif sec.Guid == LZMAF86_DECOMPRESS_GUID:
                    d = decompress_section_data("", sec_fs_name, sec.Image[sec.DataOffset:], COMPRESSION_TYPE_LZMAF86)
                else:
                    d = decompress_section_data("", sec_fs_name, sec.Image[sec.DataOffset:], COMPRESSION_TYPE_EFI_STANDARD)
                if d is None:
                    sec.Comments = "Unable to decompress image"
                    d = decompress_section_data("", sec_fs_name, sec.Image[sec.HeaderSize + EFI_GUID_DEFINED_SECTION_size:], COMPRESSION_TYPE_UNKNOWN)
                if d:
                    sec.children = build_efi_modules_tree(fwtype, d, len(d), 0, polarity)
            elif sec.Guid == EFI_CERT_TYPE_RSA_2048_SHA256_GUID:
                offset = sec.DataOffset + EFI_CERT_TYPE_RSA_2048_SHA256_GUID_size
                sec.Comments = "Certificate Type RSA2048/SHA256"
                if len(sec.Image) > offset:
                    sec.children = build_efi_modules_tree(fwtype, sec.Image[offset:], len(sec.Image[offset:]), 0, polarity)
            elif sec.Guid == EFI_FIRMWARE_CONTENTS_SIGNED_GUID:
                start = sec.HeaderSize + EFI_GUID_DEFINED_SECTION_size
                stop = start + WIN_CERTIFICATE_size
                length, _, cert_type, guid = struct.unpack(WIN_CERTIFICATE, sec.Image[start:stop])
                certGuid = UUID(bytes_le=guid)
                if cert_type == WIN_CERT_TYPE_EFI_GUID:
                    sec.Comments = "Found UEFI Certificate."
                    if certGuid == EFI_CERT_TYPE_RSA_2048_SHA256_GUID:
                        sec.Comments += " Cert of type RSA2048/SHA256!"
                    else:
                        sec.Comments += f" Cert of unknown type! But the guid is: {certGuid}"
                else:
                    sec.Comments = f"Unknown cert type: {cert_type}"
                offset = sec.DataOffset + length
                if len(sec.Image) > offset:
                    sec.children = build_efi_modules_tree(fwtype, sec.Image[offset:], len(sec.Image[offset:]), 0, polarity)
            else:
                sec.children = build_efi_model(sec.Image[sec.HeaderSize:], fwtype)

        elif sec.Type == EFI_SECTION_COMPRESSION:
            for mct in COMPRESSION_TYPES_ALGORITHMS:
                d = decompress_section_data("", sec_fs_name, sec.Image[sec.HeaderSize + EFI_COMPRESSION_SECTION_size:], mct)
                if d:
                    sec.children = build_efi_modules_tree(fwtype, d, len(d), 0, polarity)
                if sec.children:
                    break

        elif sec.Type == EFI_SECTION_FIRMWARE_VOLUME_IMAGE:
            children = build_efi_file_tree(sec.Image[sec.HeaderSize:], fwtype)
            if children is not None:
                sec.children = children

        elif sec.Type == EFI_SECTION_RAW:
            sec.children = build_efi_model(sec.Image[sec.HeaderSize:], fwtype)

        elif sec.Type not in SECTION_NAMES.keys():
            sec.children = build_efi_model(sec.Image[sec.HeaderSize:], fwtype)
            if not sec.children:
                sec.children = build_efi_model(data, fwtype)

        sections.append(sec)
        sec = NextFwFileSection(data, Size, sec.Size + sec.Offset, polarity)
        secn += 1
    return sections


#
# build_efi_file_tree - extract EFI FV file from EFI image and build an object tree
#
# Input arguements:
# fv_image - fv_image containing files
# fwtype - platform specific firmware type used to detect NVRAM format (VSS, EVSA, NVAR...)
def build_efi_file_tree(fv_img: bytes, fwtype: str) -> List[EFI_FILE]:
    fv_size, HeaderSize, Attributes = GetFvHeader(fv_img)
    polarity = bool(Attributes & EFI_FVB2_ERASE_POLARITY)
    fwbin = NextFwFile(fv_img, fv_size, HeaderSize, polarity)
    fv = []
    padding = 0
    while fwbin is not None:
        fw_offset = fwbin.Size + fwbin.Offset
        fwbin.calc_hashes()
        if padding < fwbin.Offset:
            non_UEFI = EFI_SECTION(padding, 'Padding', EFI_FV_FILETYPE_FFS_PAD, fv_img[padding:fw_offset - 1], 0, fwbin.Offset - padding)
            non_UEFI.Comments = 'Attempting to identify modules in Padding Section'
            non_UEFI.children = efi_data_search(fv_img[padding:fwbin.Offset - 1], fwtype, polarity)
            if non_UEFI.children:
                fv.append(non_UEFI)
        padding = fw_offset
        if fwbin.Type not in (EFI_FV_FILETYPE_ALL, EFI_FV_FILETYPE_RAW, EFI_FV_FILETYPE_FFS_PAD):
            fwbin.children = efi_data_search(fwbin.Image[fwbin.HeaderSize:], fwtype, polarity)
            fv.append(fwbin)
        elif fwbin.Type == EFI_FV_FILETYPE_RAW:
            if fwbin.Name != NVAR_NVRAM_FS_FILE:
                fwbin.children = efi_data_search(fwbin.Image, fwtype, polarity)
                fv.append(fwbin)
            else:
                fwbin.isNVRAM = True
                fwbin.NVRAMType = FWType.EFI_FW_TYPE_NVAR
                fv.append(fwbin)
        elif fwbin.Type == EFI_FV_FILETYPE_FFS_PAD:
            non_UEFI = EFI_SECTION(fwbin.Offset, 'Padding', fwbin.Type, fv_img[fw_offset:], 0, fwbin.Size)
            non_UEFI.Comments = 'Attempting to identify modules in Padding Section'
            non_UEFI.children = efi_data_search(fwbin.Image, fwtype, polarity)
            if non_UEFI.children:
                fv.append(non_UEFI)
        elif fwbin.State not in (EFI_FILE_HEADER_CONSTRUCTION, EFI_FILE_HEADER_INVALID, EFI_FILE_HEADER_VALID):
            fwbin.children = efi_data_search(fwbin.Image[fwbin.HeaderSize:], fwtype, polarity)
            fv.append(fwbin)
        fwbin = NextFwFile(fv_img, fv_size, fw_offset, polarity)
        if fwbin is None and fv_size > fw_offset:
            non_UEFI = EFI_SECTION(fw_offset, 'Non-UEFI_data', 0xFF, fv_img[fw_offset:], 0, fv_size - fw_offset)
            non_UEFI.Comments = 'Attempting to identify modules in non_UEFI Data Section'
            non_UEFI.children = efi_data_search(fv_img[fw_offset:], fwtype, polarity)
            if non_UEFI.children:
                fv.append(non_UEFI)
    return fv


#
# build_efi_tree - extract EFI modules (FV, files, sections) from EFI image and build an object tree
#
# Input arguments:
#   data           - an image containing UEFI firmware volumes
#   fwtype         - platform specific firmware type used to detect NVRAM format (VSS, EVSA, NVAR...)
#
def build_efi_tree(data: bytes, fwtype: str) -> List['EFI_MODULE']:
    fvolumes = []
    fv = NextFwVolume(data)
    while fv is not None:
        fv.calc_hashes()

        # Detect File System firmware volumes
        if fv.Guid in EFI_PLATFORM_FS_GUIDS or fv.Guid in EFI_FS_GUIDS:
            fwbin = build_efi_file_tree(fv.Image, fwtype)
            for i in fwbin:
                fv.children.append(i)

        # Detect NVRAM firmware volumes
        elif fv.Guid in EFI_NVRAM_GUIDS:  # == VARIABLE_STORE_FV_GUID:
            fv.isNVRAM = True
            try:
                fv.NVRAMType = identify_EFI_NVRAM(fv.Image) if fwtype is None else fwtype
            except Exception:
                logger().log_warning(f"Couldn't identify NVRAM in FV {{{fv.Guid}}}")
            fwbin = build_efi_file_tree(fv.Image, fwtype)
            for i in fwbin:
                fv.children.append(i)

        fvolumes.append(fv)
        fv = NextFwVolume(data, fv.Offset, fv.Size)

    return fvolumes


#
# Attempt to find efi modules using calls to build_efi_tree, build_efi_file_tree,
# and build_efi_modules_tree in succession.  Return once one of the calls is successful
#
def efi_data_search(data: bytes, fwtype: str, polarity: bool):
    efi_tree = build_efi_tree(data, fwtype)
    if not efi_tree:
        efi_tree = build_efi_file_tree(data, fwtype)
        if not efi_tree:
            efi_tree = build_efi_modules_tree(fwtype, data, len(data), 0, polarity)
    return efi_tree


#
# update_efi_tree propagates EFI file's GUID down to all sections and
# UI_string from the corresponding section, if found, up to the EFI file at the same time
# File GUID and UI string are then used when searching for EFI files and executable sections
#
def update_efi_tree(modules: List['EFI_MODULE'], parent_guid: Optional[UUID] = None) -> str:
    ui_string = ''
    for m in modules:
        if type(m) == EFI_FILE:
            parent_guid = m.Guid
        elif type(m) == EFI_SECTION:
            # if it's a section update its parent file's GUID
            m.parentGuid = parent_guid
            if m.Type == EFI_SECTION_USER_INTERFACE:
                # if UI section (leaf), update ui_string in sibling sections including in PE/TE,
                # and propagate it up until and including parent EFI file
                for m1 in modules:
                    m1.ui_string = m.ui_string
                ui_string = m.ui_string
        # update parent file's GUID in all children nodes
        if len(m.children) > 0:
            ui_string = update_efi_tree(m.children, parent_guid)
            # if it's a EFI file then update its ui_string with ui_string extracted from UI section
            if ui_string and (type(m) in (EFI_FILE, EFI_SECTION)):
                m.ui_string = ui_string
                if (type(m) == EFI_FILE):
                    ui_string = ''
    return ui_string


def build_efi_model(data: bytes, fwtype: str) -> List['EFI_MODULE']:
    model = build_efi_tree(data, fwtype)
    update_efi_tree(model)
    return model


def FILENAME(mod: Union[EFI_FILE, EFI_SECTION], parent: Optional['EFI_MODULE'], modn: int) -> str:
    fname = f'{modn:02d}_{mod.Guid}'
    if type(mod) == EFI_FILE:
        type_s = FILE_TYPE_NAMES[mod.Type] if mod.Type in FILE_TYPE_NAMES.keys() else f'UNKNOWN_{mod.Type:02X}'
        fname = f'{fname}.{type_s}'
    elif type(mod) == EFI_SECTION:
        fname = f'{modn:02d}_{mod.Name}'
        if mod.Type in EFI_SECTIONS_EXE:
            if (parent is not None) and parent.ui_string:
                if (parent.ui_string.endswith(".efi")):
                    fname = parent.ui_string
                else:
                    fname = f'{parent.ui_string}.efi'
            else:
                fname = f'{fname}.{type2ext[mod.Type]}'
    return fname


def dump_efi_module(mod, parent: Optional['EFI_MODULE'], modn: int, path: str) -> str:
    fname = FILENAME(mod, parent, modn)
    mod_path = os.path.join(path, fname)
    write_file(mod_path, mod.Image[mod.HeaderSize:] if type(mod) == EFI_SECTION else mod.Image)
    if type(mod) == EFI_SECTION or WRITE_ALL_HASHES:
        if mod.MD5:
            write_file(f'{mod_path}.md5', mod.MD5)
        if mod.SHA1:
            write_file(f'{mod_path}.sha1', mod.SHA1)
        if mod.SHA256:
            write_file(f'{mod_path}.sha256', mod.SHA256)
    return mod_path


class EFIModuleType:
    SECTION_EXE = 0
    SECTION = 1
    FV = 2
    FILE = 4


def search_efi_tree(modules: List['EFI_MODULE'],
                    search_callback: Optional[Callable],
                    match_module_types: int = EFIModuleType.SECTION_EXE,
                    findall: bool = True
                    ) -> List['EFI_MODULE']:
    matching_modules = []
    for module in modules:
        if search_callback is not None:
            if ((match_module_types & EFIModuleType.SECTION == EFIModuleType.SECTION) and type(module) == EFI_SECTION) or \
               ((match_module_types & EFIModuleType.SECTION_EXE == EFIModuleType.SECTION_EXE) and (type(module) == EFI_SECTION and module.Type in EFI_SECTIONS_EXE)) or \
               ((match_module_types & EFIModuleType.FV == EFIModuleType.FV) and type(module) == EFI_FV) or \
               ((match_module_types & EFIModuleType.FILE == EFIModuleType.FILE) and type(module) == EFI_FILE):
                if search_callback(module):
                    matching_modules.append(module)
                    if not findall:
                        return [module]

        # recurse search if current module node has children nodes
        if len(module.children) > 0:
            matches = search_efi_tree(module.children, search_callback, match_module_types, findall)
            if len(matches) > 0:
                matching_modules.extend(matches)
                if not findall:
                    return [module]

    return matching_modules


def save_efi_tree(modules: List['EFI_MODULE'],
                  parent: Optional['EFI_MODULE'] = None,
                  save_modules: bool = True,
                  path: str = '',
                  save_log: bool = True,
                  lvl: int = 0
                  ) -> List[Dict[str, Any]]:
    mod_dir_path = ''
    modules_arr = []
    modn = 0
    for m in modules:
        md: Dict[str, Any] = {}
        m.indent = DEF_INDENT * lvl
        if save_log:
            logger().log(str(m))

        # extract all non-function non-None members of EFI_MODULE objects
        attrs = [a for a in dir(m) if not callable(getattr(m, a)) and not a.startswith("__") and (getattr(m, a) is not None)]
        for a in attrs:
            md[a] = getattr(m, a)
        md["class"] = type(m).__name__
        # remove extra attributes
        for f in ["Image", "indent"]:
            del md[f]

        # save EFI module image, make sub-directory for children
        if save_modules:
            mod_path = dump_efi_module(m, parent, modn, path)
            try:
                md["file_path"] = os.path.relpath(mod_path[4:] if mod_path.startswith("\\\\?\\") else mod_path)
            except Exception:
                md["file_path"] = mod_path.split(os.sep)[-1]
            if m.isNVRAM or len(m.children) > 0:
                mod_dir_path = f'{mod_path}.dir'
                if not os.path.exists(mod_dir_path):
                    os.makedirs(mod_dir_path)
                if m.isNVRAM:
                    try:
                        if m.NVRAMType and (parent is not None):
                            # @TODO: technically, NVRAM image should be m.Image but
                            # getNVstore_xxx functions expect FV than a FW file within FV
                            # so for EFI_FILE type of module using parent's Image as NVRAM
                            nvram = parent.Image if (type(m) == EFI_FILE and type(parent) == EFI_FV) else m.Image
                            file_path = os.path.join(mod_dir_path, 'NVRAM')
                            parse_EFI_variables(file_path, nvram, False, m.NVRAMType)
                        else:
                            raise Exception("NVRAM type cannot be None")
                    except Exception:
                        logger().log_warning(f"Couldn't extract NVRAM in {{{m.Guid}}} using type '{m.NVRAMType}'")

        # save children modules
        if len(m.children) > 0:
            md["children"] = save_efi_tree(m.children, m, save_modules, mod_dir_path, save_log, lvl + 1)
        else:
            del md["children"]

        modules_arr.append(md)
        modn += 1

    return modules_arr


class UUIDEncoder(json.JSONEncoder):
    def default(self, obj: Any):
        if isinstance(obj, UUID):
            return str(obj).upper()
        return json.JSONEncoder.default(self, obj)


def parse_uefi_region_from_file(filename: str, fwtype: str, outpath: Optional[str] = None, filetype: List[int] = []) -> None:
    # Create an output folder to dump EFI module tree
    if outpath is None:
        outpath = f'{filename}.dir'
    if not os.path.exists(outpath):
        os.makedirs(outpath)

    # Read UEFI image binary to parse
    rom = read_file(filename)

    # Parse UEFI image binary and build a tree hierarchy of EFI modules
    tree = build_efi_model(rom, fwtype)

    # Save entire EFI module hierarchy on a file-system and export into JSON
    if filetype:
        tree_json = save_efi_tree_filetype(tree, path=outpath, filetype=filetype)
    else:
        tree_json = save_efi_tree(tree, path=outpath)
    write_file(f'{filename}.UEFI.json', json.dumps(tree_json, indent=2, separators=(',', ': '), cls=UUIDEncoder))


def decode_uefi_region(pth: str, fname: str, fwtype: str, filetype: List[int] = []) -> None:

    bios_pth = os.path.join(pth, f'{fname}.dir')
    if not os.path.exists(bios_pth):
        os.makedirs(bios_pth)
    fv_pth = os.path.join(bios_pth, 'FV')
    if not os.path.exists(fv_pth):
        os.makedirs(fv_pth)

    # Decoding UEFI Firmware Volumes
    logger().log_hal("[spi_uefi] Decoding UEFI firmware volumes...")
    parse_uefi_region_from_file(fname, fwtype, fv_pth, filetype)
    # If a specific filetype is wanted, there is no need to check for EFI Variables
    if filetype:
        return

    # Decoding EFI Variables NVRAM
    logger().log_hal("[spi_uefi] Decoding UEFI NVRAM...")
    region_data = read_file(fname)
    if fwtype is None:
        fwtype = identify_EFI_NVRAM(region_data)
        if fwtype is None:
            return
    elif fwtype not in fw_types:
        if logger().HAL:
            logger().log_error(f'Unrecognized NVRAM type {fwtype}')
        return
    nvram_fname = os.path.join(bios_pth, (f'nvram_{fwtype}'))
    logger().set_log_file(f'{nvram_fname}.nvram.lst', False)
    parse_EFI_variables(nvram_fname, region_data, False, fwtype)


def save_efi_tree_filetype(modules: List['EFI_MODULE'],
                           parent: Optional['EFI_MODULE'] = None,
                           path: str = '',
                           lvl: int = 0,
                           filetype: List[int] = [],
                           save: bool = True
                           ) -> List[Dict[str, Any]]:
    mod_dir_path = path
    modules_arr = []
    modn = 0
    for m in modules:
        md: Dict[str, Any] = {}
        m.indent = DEF_INDENT * lvl
        if (isinstance(m, EFI_FILE) and m.Type in filetype) and save:
            logger().log(str(m))

        # extract all non-function non-None members of EFI_MODULE objects
        attrs = [a for a in dir(m) if not callable(getattr(m, a)) and not a.startswith("__") and (getattr(m, a) is not None)]
        for a in attrs:
            md[a] = getattr(m, a)
        md["class"] = type(m).__name__
        # remove extra attributes
        for f in ["Image", "indent"]:
            del md[f]

        # save EFI module image, make sub-directory for children
        if (isinstance(m, EFI_FILE) and m.Type in filetype) or save:
            mod_path = dump_efi_module(m, parent, modn, path)
            try:
                md["file_path"] = os.path.relpath(mod_path[4:] if mod_path.startswith("\\\\?\\") else mod_path)
            except Exception:
                md["file_path"] = mod_path.split(os.sep)[-1]
            if m.isNVRAM or len(m.children) > 0:
                mod_dir_path = f'{mod_path}.dir'
                if not os.path.exists(mod_dir_path):
                    os.makedirs(mod_dir_path)
        # save children modules
        if len(m.children) > 0:
            md["children"] = save_efi_tree_filetype(m.children, m, mod_dir_path, lvl + 1, filetype, save)
        else:
            del md["children"]

        modules_arr.append(md)
        modn += 1

    return modules_arr
