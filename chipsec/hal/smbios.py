#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2019, Intel Corporation
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
import struct
import uuid
from collections import namedtuple

from chipsec.defines import BOUNDARY_1MB, BOUNDARY_4GB, bytestostring
from chipsec.hal import hal_base, uefi
from chipsec.logger import logger

SCAN_LOW_LIMIT = 0xF0000
SCAN_SIZE = 0x10000

SMBIOS_2_x_SIG = b"_SM_"
SMBIOS_2_x_ENTRY_SIZE = 0x1F
SMBIOS_2_x_ENTRY_SIZE_OLD = 0x1E
SMBIOS_2_x_MAJOR_VER = 0x02
SMBIOS_2_x_INT_SIG = b"_DMI_"
SMBIOS_2_x_GUID = "EB9D2D31-2D88-11D3-9A16-0090273FC14D"
SMBIOS_2_x_ENTRY_POINT_FMT = "=4sBBBBHB5B5sBHIHB"
SMBIOS_2_x_ENTRY_POINT_SIZE = struct.calcsize(SMBIOS_2_x_ENTRY_POINT_FMT)
SMBIOS_2_x_FORMAT_STRING = """
SMBIOS 2.x Entry Point Structure:
  Anchor String             : {}
  Checksum                  : 0x{:02X}
  Entry Point Length        : 0x{:02X}
  Entry Point Version       : {:d}.{:d}
  Max Structure Size        : 0x{:04X}
  Entry Point Revision      : 0x{:02X}
  Formatted Area            : 0x{:02X}, 0x{:02X}, 0x{:02X}, 0x{:02X}, 0x{:02X}
  Intermediate Anchor String: {}
  Intermediate Checksum     : 0x{:02X}
  Structure Table Length    : 0x{:04X}
  Structure Talbe Address   : 0x{:08X}
  SMBIOS Structure Count    : 0x{:04X}
  SMBIOS BCD Revision       : 0x{:02X}
"""
class SMBIOS_2_x_ENTRY_POINT(namedtuple('SMBIOS_2_x_ENTRY_POINT', 'Anchor EntryCs EntryLen MajorVer MinorVer MaxSize EntryRev \
    FormatArea0 FormatArea1 FormatArea2 FormatArea3 FormatArea4 IntAnchor IntCs TableLen TableAddr NumStructures BcdRev')):
    __slots__ = ()
    def __str__(self):
        return SMBIOS_2_x_FORMAT_STRING.format(bytestostring(self.Anchor), self.EntryCs, self.EntryLen, self.MajorVer, \
                                            self.MinorVer, self.MaxSize, self.EntryRev, self.FormatArea0, self.FormatArea1, \
                                            self.FormatArea2, self.FormatArea3, self.FormatArea4, bytestostring(self.IntAnchor), \
                                            self.IntCs, self.TableLen, self.TableAddr, self.NumStructures, self.BcdRev)


SMBIOS_3_x_SIG = b"_SM3_"
SMBIOS_3_x_ENTRY_SIZE = 0x18
SMBIOS_3_x_MAJOR_VER = 0x03
SMBIOS_3_x_GUID = "F2FD1544-9794-4A2C-992E-E5BBCF20E394"
SMBIOS_3_x_ENTRY_POINT_FMT = "=5sBBBBBBBIQ"
SMBIOS_3_x_ENTRY_POINT_SIZE = struct.calcsize(SMBIOS_3_x_ENTRY_POINT_FMT)
SMBIOS_3_x_FORMAT_STRING = """
SMBIOS 3.x Entry Point Structure:
  Anchor String             : {}
  Checksum                  : 0x{:02X}
  Entry Point Length        : 0x{:02X}
  Entry Ponnt Version       : {:d}.{:d}
  SMBIOS Docrev             : 0x{:02X}
  Entry Point Revision      : 0x{:02X}
  Reserved                  : 0x{:02X}
  Max Structure Size        : 0x{:08X}
  Structure Table Address   : 0x{:016X}
"""
class SMBIOS_3_x_ENTRY_POINT(namedtuple('SMBIOS_3_x_ENTRY_POINT', 'Anchor EntryCs EntryLen MajorVer MinorVer Docrev EntryRev \
    Reserved MaxSize TableAddr')):
    __slots__ = ()
    def __str__(self):
        return SMBIOS_3_x_FORMAT_STRING.format(bytestostring(self.Anchor), self.EntryCs, self.EntryLen, self.MajorVer, \
                                            self.MinorVer, self.Docrev, self.EntryRev, self.Reserved, self.MaxSize, \
                                            self.TableAddr)


SMBIOS_STRUCT_HEADER_FMT = "=BBH"
SMBIOS_STRUCT_HEADER_SIZE = struct.calcsize(SMBIOS_STRUCT_HEADER_FMT)
SMBIOS_STRUCT_HEADER_FORMAT_STRING = """
SMBIOS Stuct Header:
  Type                      : 0x{0:02X} ({0:d})
  Length                    : 0x{1:02X}
  Handle                    : 0x{2:04X}
"""
class SMBIOS_STRUCT_HEADER(namedtuple('SMBIOS_STRUCT_HEADER', 'Type Length Handle')):
    __slots__ = ()
    def __str__(self):
        return SMBIOS_STRUCT_HEADER_FORMAT_STRING.format(self.Type, self.Length, self.Handle)

SMBIOS_STRUCT_TERM_FMT = "=H"
SMBIOS_STRUCT_TERM_SIZE = struct.calcsize(SMBIOS_STRUCT_TERM_FMT)
SMBIOS_STRUCT_TERM_VAL = 0x0000


SMBIOS_BIOS_INFO_ENTRY_ID = 0
SMBIOS_BIOS_INFO_2_0_ENTRY_FMT = '=BBHBBHBBQ'
SMBIOS_BIOS_INFO_2_0_ENTRY_SIZE = struct.calcsize(SMBIOS_BIOS_INFO_2_0_ENTRY_FMT)
SMBIOS_BIOS_INFO_2_0_FORMAT_STRING = """
SMBIOS BIOS Information:
  Type                      : 0x{:02X} ({:d})
  Length                    : 0x{:02X}
  Handle                    : 0x{:04X}
  Vendor                    : {:s}
  BIOS Version              : {:s}
  BIOS Starting Segment     : 0x{:04X}
  BIOS Release Date         : {:s}
  BIOS ROM Size             : 0x{:02X}
  BIOS Characteristics      : 0x{:016X}
"""
SMBIOS_BIOS_INFO_2_0_FORMAT_STRING_FAILED = """
SMBIOS BIOS Information structure decode failed
"""
class SMBIOS_BIOS_INFO_2_0(namedtuple('SMBIOS_BIOS_ENTRY_2_0', 'type length handle vendor_str version_str segment release_str \
    rom_sz bios_char strings')):
    __slots__ = ()
    def __str__(self):
        str_count = len(self.strings)
        ven_str = ''
        ver_str = ''
        rel_str = ''
        if self.vendor_str != 0 and self.vendor_str <= str_count:
            ven_str = self.strings[self.vendor_str - 1]
        if self.version_str != 0 and self.version_str <= str_count:
            ver_str = self.strings[self.version_str - 1]
        if self.release_str != 0 and self.release_str <= str_count:
            rel_str = self.strings[self.release_str - 1]
        return SMBIOS_BIOS_INFO_2_0_FORMAT_STRING.format(self.type, self.type, self.length, self.handle, ven_str, \
            ver_str, self.segment, rel_str, self.rom_sz, self.bios_char)


struct_decode_tree = {
    SMBIOS_BIOS_INFO_ENTRY_ID: {'class':SMBIOS_BIOS_INFO_2_0, 'format':SMBIOS_BIOS_INFO_2_0_ENTRY_FMT}
}

class SMBIOS(hal_base.HALBase):
    def __init__(self, cs):
        super(SMBIOS, self).__init__(cs)
        self.uefi = uefi.UEFI(cs)
        self.smbios_2_guid_found = False
        self.smbios_2_pa = None
        self.smbios_2_ep = None
        self.smbios_2_data = None
        self.smbios_3_guid_found = False
        self.smbios_3_pa = None
        self.smbios_3_ep = None
        self.smbios_3_data = None

    def __get_raw_struct(self, table, start_offset):
        """
        Returns a tuple including the raw data and the offset to the next entry.  This allows the function
        to be called multiple times to process all the entries in a table.

        Return Value:
        (raw_data, next_offset)

        Error/End:
        (None, None)
        """
        # Check for end of table and remaining size to parse
        if table is None:
            if logger().HAL: logger().log('- Invalid table')
            return (None, None)
        table_len = len(table)
        if logger().HAL: logger().log('Start Offset: 0x{:04X}, Table Size: 0x{:04X}'.format(start_offset, table_len))
        if start_offset >= table_len:
            if logger().HAL: logger().log('- Bad table length (table_len): 0x{:04X}'.format(table_len))
            return (None, None)
        size_left = len(table[start_offset:])
        if size_left < SMBIOS_STRUCT_HEADER_SIZE:
            if logger().HAL: logger().log('- Table too small (size_left): 0x{:04X}'.format(size_left))
            return (None, None)

        # Read the header to determine structure fixed size
        try:
            header = SMBIOS_STRUCT_HEADER(*struct.unpack_from(SMBIOS_STRUCT_HEADER_FMT, \
                table[start_offset:start_offset + SMBIOS_STRUCT_HEADER_SIZE]))
        except:
            if logger().HAL: logger().log('- Unable to unpack data')
            return (None, None)
        str_offset = start_offset + header.Length
        if str_offset + SMBIOS_STRUCT_TERM_SIZE >= table_len:
            if logger().HAL: logger().log('- Not enough space for termination (str_offset): 0x{:04X}'.format(str_offset))
            return (None, None)

        # Process any remaing content (strings)
        if logger().HAL: logger().log('String start offset: 0x{:04X}'.format(str_offset))
        tmp_offset = str_offset
        while (tmp_offset + SMBIOS_STRUCT_TERM_SIZE < table_len):
            (value, ) = struct.unpack_from(SMBIOS_STRUCT_TERM_FMT, table[tmp_offset:tmp_offset + SMBIOS_STRUCT_TERM_SIZE])
            if value == SMBIOS_STRUCT_TERM_VAL:
                if logger().HAL: logger().log('+ Found structure termination')
                break
            tmp_offset += 1
        if tmp_offset >= table_len:
            if logger().HAL: logger().log('- End of table reached')
            return (None, None)
        tmp_offset += SMBIOS_STRUCT_TERM_SIZE

        if logger().HAL: logger().log('Structure Size: 0x{:04X}'.format(tmp_offset - start_offset))
        return (table[start_offset:tmp_offset], tmp_offset)

    def __validate_ep_2_values(self, pa):
        # Force a second read of memory so we don't have to worry about it falling outside the
        # original buffer.
        try:
            if logger().HAL: logger().log('Validating 32bit SMBIOS header @ 0x{:08X}'.format(pa))
            mem_buffer = self.cs.mem.read_physical_mem(pa, SMBIOS_2_x_ENTRY_POINT_SIZE)
            ep_data = SMBIOS_2_x_ENTRY_POINT(*struct.unpack_from(SMBIOS_2_x_ENTRY_POINT_FMT, mem_buffer))
        except:
            if logger().HAL: logger().log('- Memory read failed')
            return None
        if ep_data.Anchor != SMBIOS_2_x_SIG:
            if logger().HAL: logger().log('- Invalid signature')
            return None
        if not (ep_data.EntryLen == SMBIOS_2_x_ENTRY_SIZE or ep_data.EntryLen == SMBIOS_2_x_ENTRY_SIZE_OLD):
            if logger().HAL: logger().log('- Invalid structure size')
            return None
        if ep_data.IntAnchor != SMBIOS_2_x_INT_SIG:
            if logger().HAL: logger().log('- Invalid intermediate signature')
            return None
        if ep_data.TableAddr == 0 or ep_data.TableLen == 0:
            if logger().HAL: logger().log('- Invalid table address or length')
            return None
        return ep_data

    def __validate_ep_3_values(self, pa):
        # Force a second read of memory so we don't have to worry about it falling outside the
        # original buffer.
        try:
            if logger().HAL: logger().log('Validating 64bit SMBIOS header @ 0x{:08X}'.format(pa))
            mem_buffer = self.cs.mem.read_physical_mem(pa, SMBIOS_3_x_ENTRY_POINT_SIZE)
            ep_data = SMBIOS_3_x_ENTRY_POINT(*struct.unpack_from(SMBIOS_3_x_ENTRY_POINT_FMT, mem_buffer))
        except:
            if logger().HAL: logger().log('- Memory read failed')
            return None
        if ep_data.Anchor != SMBIOS_3_x_SIG:
            if logger().HAL: logger().log('- Invalid signature')
            return None
        if not (ep_data.EntryLen == SMBIOS_3_x_ENTRY_SIZE):
            if logger().HAL: logger().log('- Invalid structure size')
            return None
        if ep_data.MaxSize == 0 or ep_data.TableAddr == 0:
            if logger().HAL: logger().log('- Invalid table address or maximum size')
            return None
        return ep_data

    def find_smbios_table(self):
        # Handle the case were we already found the tables
        if self.smbios_2_ep is not None or self.smbios_3_ep is not None:
            return True

        # Initialize search parameters
        entries_to_find = entries_found = 0

        # Fist get the configuration table using the UEFI HAL.  You may not be able to use the addresses
        # in the table because in some cases they have been converted to a VA and are not mapped.
        if logger().HAL: logger().log('Chedking UEFI Configuration Table for SMBIOS entry')
        (ect_found, ect_pa, ect, ect_buf) = self.uefi.find_EFI_Configuration_Table()
        if ect_found:
            if logger().HAL: logger().log(ect)
            if SMBIOS_2_x_GUID in ect.VendorTables:
                if logger().HAL: logger().log('+ Found 32bit SMBIOS entry')
                if logger().HAL: logger().log('+ Potential 2.x table address: 0x{:016X}'.format(ect.VendorTables[SMBIOS_2_x_GUID]))
                self.smbios_2_guid_found = True
                entries_to_find += 1
            if SMBIOS_3_x_GUID in ect.VendorTables:
                if logger().HAL: logger().log('+ Found 64bit SMBIOS entry')
                if logger().HAL: logger().log('+ Potential 3.x table address: 0x{:016X}'.format(ect.VendorTables[SMBIOS_3_x_GUID]))
                self.smbios_3_guid_found = True
                entries_to_find += 1

        # Determine regions to scan
        if self.smbios_2_guid_found or self.smbios_3_guid_found:
            (smm_base, smm_limit, smm_size) = self.cs.cpu.get_SMRAM()
            pa = smm_base - SCAN_SIZE
        else:
            entries_to_find = 2
            pa = BOUNDARY_1MB - SCAN_SIZE

        # Scan memory for the signature
        if logger().HAL: logger().log('Scanning memory for {:d} signature(s)'.format(entries_to_find))
        while (pa >= SCAN_LOW_LIMIT):
            mem_buffer = self.cs.mem.read_physical_mem(pa, SCAN_SIZE)
            sig_pa = mem_buffer.find(SMBIOS_2_x_SIG) + pa
            if sig_pa >= pa and self.smbios_2_pa is None:
                if logger().HAL: logger().log('+ Found SMBIOS 2.x signature @ 0x{:08X}'.format(sig_pa))
                self.smbios_2_ep = self.__validate_ep_2_values(sig_pa)
                if self.smbios_2_ep is not None:
                    if logger().HAL: logger().log('+ Verified SMBIOS 2.x Entry Point structure')
                    self.smbios_2_pa = sig_pa
                    entries_found += 1
            sig_pa = mem_buffer.find(SMBIOS_3_x_SIG) + pa
            if sig_pa >= pa and self.smbios_3_pa is None:
                if logger().HAL: logger().log('+ Found SMBIOS 3.x signature @ 0x{:08X}'.format(sig_pa))
                self.smbios_3_ep = self.__validate_ep_3_values(sig_pa)
                if self.smbios_3_ep is not None:
                    if logger().HAL: logger().log('+ Verified SMBIOS 3.x Entry Point structure')
                    self.smbios_3_pa = sig_pa
                    entries_found += 1
            if entries_found >= entries_to_find:
                break
            pa -= SCAN_SIZE

        # Check to see if we thing we found the structure
        if self.smbios_2_pa is None and self.smbios_3_pa is None:
            if logger().HAL: logger().log('- Unable to find SMBIOS tables')
            return False

        # Read the raw data regions
        if logger().HAL: logger().log('Reading SMBIOS data tables:')
        if self.smbios_2_ep is not None and self.smbios_2_ep.TableAddr != 0 and self.smbios_2_ep.TableLen != 0:
            self.smbios_2_data = self.cs.mem.read_physical_mem(self.smbios_2_ep.TableAddr, self.smbios_2_ep.TableLen)
            if self.smbios_2_data is None and logger().HAL:
                logger().log('- Failed to read 32bit SMBIOS data')
        if self.smbios_3_ep is not None and self.smbios_3_ep.TableAddr != 0 and self.smbios_3_ep.MaxSize != 0:
            self.smbios_3_data = self.cs.mem.read_physical_mem(self.smbios_3_ep.TableAddr, self.smbios_3_ep.MaxSize)
            if self.smbios_3_data is None and logger().HAL:
                logger().log('- Failed to read 64bit SMBIOS data')

        return True

    def get_raw_structs(self, struct_type=None, force_32bit=False):
        """
        Returns a list of raw data blobs for each SMBIOS structure.  The default is to process the 64bit
        entries if available unless specifically specified.

        Error:
        None
        """
        ret_val = []

        if self.smbios_3_data is not None and not force_32bit:
            if logger().HAL: logger().log('Using 64bit SMBIOS table')
            table = self.smbios_3_data
        elif self.smbios_3_data is not None:
            if logger().HAL: logger().log('Using 32bit SMBIOS table')
            table = self.smbios_2_data
        else:
            if logger().HAL: logger().log('- No SMBIOS data available')
            return None

        if logger().HAL: logger().log('Getting SMBIOS structures...')
        raw_data, next_offset = self.__get_raw_struct(table, 0)
        while next_offset is not None:
            if struct_type is None:
                ret_val.append(raw_data)
            else:
                header = SMBIOS_STRUCT_HEADER(*struct.unpack_from(SMBIOS_STRUCT_HEADER_FMT, raw_data[:SMBIOS_STRUCT_HEADER_SIZE]))
                if header is not None and header.Type == struct_type:
                    ret_val.append(raw_data)
            raw_data, next_offset = self.__get_raw_struct(table, next_offset)

        return ret_val

    def get_header(self, raw_data):
        if logger().HAL: logger().log('Getting generic SMBIOS header information')
        if raw_data is None:
            if logger().HAL: logger().log('- Raw data pointer is None')
            return None
        if len(raw_data) < SMBIOS_STRUCT_HEADER_SIZE:
            if logger().HAL: logger().log('- Raw data too small for header information')
            return None

        try:
            header = SMBIOS_STRUCT_HEADER(*struct.unpack_from(SMBIOS_STRUCT_HEADER_FMT, raw_data[:SMBIOS_STRUCT_HEADER_SIZE]))
        except:
            if logger().HAL: logger().log('- Failed to extract information from raw data')
            return None

        return header

    def get_string_list(self, raw_data):
        ret_val = []

        if logger().HAL: logger().log('Getting strings from structure')
        raw_data_size = len(raw_data)
        header = self.get_header(raw_data)
        if header is None:
            return None
        if header.Length + SMBIOS_STRUCT_TERM_SIZE > raw_data_size:
            if logger().HAL: logger().log('- Data buffer too small for structure')
            return None
        if header.Length + SMBIOS_STRUCT_TERM_SIZE == raw_data_size:
            if logger().HAL: logger().log('+ No strings in this structure')
            return ret_val

        index = 0
        tmp_offset = header.Length
        while tmp_offset + index + 1 < raw_data_size:
            (value, ) = struct.unpack_from('=B', raw_data[tmp_offset+index:])
            if value == 0:
                if logger().HAL: logger().log('+ Unpacking string of size {:d}'.format(index))
                (string, ) = struct.unpack_from('={:d}s'.format(index), raw_data[tmp_offset:])
                string = bytestostring(string)
                if logger().HAL: logger().log('+ Found: {:s}'.format(string))
                ret_val.append(string)
                tmp_offset += index + 1
                index = 0
                continue
            index += 1

        if logger().HAL: logger().log('+ Found {:d} strings'.format(len(ret_val)))
        return ret_val

    def get_decoded_structs(self, struct_type=None, force_32bit=False):
        ret_val = []

        # Determine if the structure exists in the table
        if logger().HAL: logger().log('Getting decoded SMBIOS structures')
        structs = self.get_raw_structs(struct_type, force_32bit)
        if structs is None:
            return None

        # Process all the entries
        for data in structs:
            # Get the structures header information so we can determine the correct decode method
            header = self.get_header(data)
            if header is None:
                if logger().HAL: logger().log('- Could not decode header')
                continue
            if header.Type not in struct_decode_tree:
                if logger().HAL: logger().log('- Structure {:d} not in decode list'.format(header.Type))
                continue

            # Unpack the structure and then get the strings
            tmp_decode = struct_decode_tree[header.Type]
            try:
                decode_data = struct.unpack_from(tmp_decode['format'], data)
            except:
                if logger().HAL: logger().log('- Could not decode structure')
                continue
            if decode_data is None:
                if logger().HAL: logger().log('- No structure data was decoded')
                continue
            strings = self.get_string_list(data)
            if strings is not None:
                decode_data = decode_data + (strings, )

            # Create the actual object
            try:
                decode_object = tmp_decode['class'](*decode_data)
            except:
                if logger().HAL: logger().log('- Failed to create structure')
                continue
            ret_val.append(decode_object)

        return ret_val
