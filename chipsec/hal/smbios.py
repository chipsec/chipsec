# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2019-2021, Intel Corporation
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
HAL component providing access to and decoding of SMBIOS structures
"""

import struct
from collections import namedtuple
from typing import Dict, List, Optional, Tuple, Any, Union, Type
from chipsec.library.defines import BOUNDARY_1MB, bytestostring
from chipsec.hal import hal_base, uefi
from chipsec.library.logger import logger

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


class SMBIOS_2_x_ENTRY_POINT(namedtuple('SMBIOS_2_x_ENTRY_POINT', 'Anchor EntryCs EntryLen MajorVer MinorVer MaxSize EntryRev \
        FormatArea0 FormatArea1 FormatArea2 FormatArea3 FormatArea4 IntAnchor IntCs TableLen TableAddr NumStructures BcdRev')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
SMBIOS 2.x Entry Point Structure:
  Anchor String             : {bytestostring(self.Anchor)}
  Checksum                  : 0x{self.EntryCs:02X}
  Entry Point Length        : 0x{self.EntryLen:02X}
  Entry Point Version       : {self.MajorVer:d}.{self.MinorVer:d}
  Max Structure Size        : 0x{self.MaxSize:04X}
  Entry Point Revision      : 0x{self.EntryRev:02X}
  Formatted Area            : 0x{self.FormatArea0:02X}, 0x{self.FormatArea1:02X}, 0x{self.FormatArea2:02X}, 0x{self.FormatArea3:02X}, 0x{self.FormatArea4:02X}
  Intermediate Anchor String: {bytestostring(self.IntAnchor)}
  Intermediate Checksum     : 0x{self.IntCs:02X}
  Structure Table Length    : 0x{self.TableLen:04X}
  Structure Table Address   : 0x{self.TableAddr:08X}
  SMBIOS Structure Count    : 0x{self.NumStructures:04X}
  SMBIOS BCD Revision       : 0x{self.BcdRev:02X}
"""


SMBIOS_3_x_SIG = b"_SM3_"
SMBIOS_3_x_ENTRY_SIZE = 0x18
SMBIOS_3_x_MAJOR_VER = 0x03
SMBIOS_3_x_GUID = "F2FD1544-9794-4A2C-992E-E5BBCF20E394"
SMBIOS_3_x_ENTRY_POINT_FMT = "=5sBBBBBBBIQ"
SMBIOS_3_x_ENTRY_POINT_SIZE = struct.calcsize(SMBIOS_3_x_ENTRY_POINT_FMT)


class SMBIOS_3_x_ENTRY_POINT(namedtuple('SMBIOS_3_x_ENTRY_POINT', 'Anchor EntryCs EntryLen MajorVer MinorVer Docrev EntryRev \
        Reserved MaxSize TableAddr')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
SMBIOS 3.x Entry Point Structure:
  Anchor String             : {bytestostring(self.Anchor)}
  Checksum                  : 0x{self.EntryCs:02X}
  Entry Point Length        : 0x{self.EntryLen:02X}
  Entry Ponnt Version       : {self.MajorVer:d}.{self.MinorVer:d}
  SMBIOS Docrev             : 0x{self.Docrev:02X}
  Entry Point Revision      : 0x{self.EntryRev:02X}
  Reserved                  : 0x{self.Reserved:02X}
  Max Structure Size        : 0x{self.MaxSize:08X}
  Structure Table Address   : 0x{self.TableAddr:016X}
"""


SMBIOS_STRUCT_HEADER_FMT = "=BBH"
SMBIOS_STRUCT_HEADER_SIZE = struct.calcsize(SMBIOS_STRUCT_HEADER_FMT)


class SMBIOS_STRUCT_HEADER(namedtuple('SMBIOS_STRUCT_HEADER', 'Type Length Handle')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
SMBIOS Struct Header:
  Type                      : 0x{self.Type:02X} ({self.Type:d})
  Length                    : 0x{self.Length:02X}
  Handle                    : 0x{self.Handle:04X}
"""


SMBIOS_STRUCT_TERM_FMT = "=H"
SMBIOS_STRUCT_TERM_SIZE = struct.calcsize(SMBIOS_STRUCT_TERM_FMT)
SMBIOS_STRUCT_TERM_VAL = 0x0000


SMBIOS_BIOS_INFO_ENTRY_ID = 0
SMBIOS_BIOS_INFO_2_0_ENTRY_FMT = '=BBHBBHBBQ'
SMBIOS_BIOS_INFO_2_0_ENTRY_SIZE = struct.calcsize(SMBIOS_BIOS_INFO_2_0_ENTRY_FMT)
SMBIOS_BIOS_INFO_2_0_FORMAT_STRING_FAILED = """
SMBIOS BIOS Information structure decode failed
"""


class SMBIOS_BIOS_INFO_2_0(namedtuple('SMBIOS_BIOS_INFO_2_0_ENTRY', 'type length handle vendor_str version_str segment \
        release_str rom_sz bios_char strings')):
    __slots__ = ()

    def __str__(self) -> str:
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
        return f"""
SMBIOS BIOS Information:
  Type                      : 0x{self.type:02X} ({self.type:d})
  Length                    : 0x{self.length:02X}
  Handle                    : 0x{self.handle:04X}
  Vendor                    : {ven_str:s}
  BIOS Version              : {ver_str:s}
  BIOS Starting Segment     : 0x{self.segment:04X}
  BIOS Release Date         : {rel_str:s}
  BIOS ROM Size             : 0x{self.rom_sz:02X}
  BIOS Characteristics      : 0x{self.bios_char:016X}
"""


SMBIOS_SYSTEM_INFO_ENTRY_ID = 1
SMBIOS_SYSTEM_INFO_2_0_ENTRY_FMT = '=BBHBBBB'
SMBIOS_SYSTEM_INFO_2_0_ENTRY_SIZE = struct.calcsize(SMBIOS_SYSTEM_INFO_2_0_ENTRY_FMT)
SMBIOS_SYSTEM_INFO_2_0_FORMAT_STRING_FAILED = """
SMBIOS System Information structure decode failed
"""


class SMBIOS_SYSTEM_INFO_2_0(namedtuple('SMBIOS_SYSTEM_INFO_2_0_ENTRY', 'type length handle manufacturer_str product_str \
        version_str serial_str strings')):
    __slots__ = ()

    def __str__(self) -> str:
        str_count = len(self.strings)
        man_str = ''
        pro_str = ''
        ver_str = ''
        ser_str = ''
        if self.manufacturer_str != 0 and self.manufacturer_str <= str_count:
            man_str = self.strings[self.manufacturer_str - 1]
        if self.product_str != 0 and self.product_str <= str_count:
            pro_str = self.strings[self.product_str - 1]
        if self.version_str != 0 and self.version_str <= str_count:
            ver_str = self.strings[self.version_str - 1]
        if self.serial_str != 0 and self.serial_str <= str_count:
            ser_str = self.strings[self.serial_str - 1]
        return f"""
SMBIOS System Information:
  Type                      : 0x{self.type:02X} ({self.type:d})
  Length                    : 0x{self.length:02X}
  Handle                    : 0x{self.handle:04X}
  Manufacturer              : {man_str:s}
  Product Name              : {pro_str:s}
  Version                   : {ver_str:s}
  Serial Number             : {ser_str:s}
"""


SmbiosInfo = Union[SMBIOS_BIOS_INFO_2_0, SMBIOS_SYSTEM_INFO_2_0]
StructDecode = Dict[str, Any]  # TODO: Replace Any when TypeDict (PEP 589) supported

struct_decode_tree: Dict[int, StructDecode] = {
    SMBIOS_BIOS_INFO_ENTRY_ID: {'class': SMBIOS_BIOS_INFO_2_0, 'format': SMBIOS_BIOS_INFO_2_0_ENTRY_FMT},
    SMBIOS_SYSTEM_INFO_ENTRY_ID: {'class': SMBIOS_SYSTEM_INFO_2_0, 'format': SMBIOS_SYSTEM_INFO_2_0_ENTRY_FMT}
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

    def __get_raw_struct(self, table: bytes, start_offset: int) -> Tuple[Optional[bytes], Optional[int]]:
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
            logger().log_hal('- Invalid table')
            return (None, None)
        table_len = len(table)
        logger().log_hal(f'Start Offset: 0x{start_offset:04X}, Table Size: 0x{table_len:04X}')
        if start_offset >= table_len:
            logger().log_hal(f'- Bad table length (table_len): 0x{table_len:04X}')
            return (None, None)
        size_left = len(table[start_offset:])
        if size_left < SMBIOS_STRUCT_HEADER_SIZE:
            logger().log_hal(f'- Table too small (size_left): 0x{size_left:04X}')
            return (None, None)

        # Read the header to determine structure fixed size
        try:
            header = SMBIOS_STRUCT_HEADER(*struct.unpack_from(SMBIOS_STRUCT_HEADER_FMT,
                                                              table[start_offset:start_offset + SMBIOS_STRUCT_HEADER_SIZE]))
        except:
            logger().log_hal('- Unable to unpack data')
            return (None, None)
        str_offset = start_offset + header.Length
        if str_offset + SMBIOS_STRUCT_TERM_SIZE >= table_len:
            logger().log_hal(f'- Not enough space for termination (str_offset): 0x{str_offset:04X}')
            return (None, None)

        # Process any remaining content (strings)
        logger().log_hal(f'String start offset: 0x{str_offset:04X}')
        tmp_offset = str_offset
        while (tmp_offset + SMBIOS_STRUCT_TERM_SIZE < table_len):
            (value, ) = struct.unpack_from(SMBIOS_STRUCT_TERM_FMT, table[tmp_offset:tmp_offset + SMBIOS_STRUCT_TERM_SIZE])
            if value == SMBIOS_STRUCT_TERM_VAL:
                logger().log_hal('+ Found structure termination')
                break
            tmp_offset += 1
        if tmp_offset >= table_len:
            logger().log_hal('- End of table reached')
            return (None, None)
        tmp_offset += SMBIOS_STRUCT_TERM_SIZE

        logger().log_hal(f'Structure Size: 0x{tmp_offset - start_offset:04X}')
        return (table[start_offset:tmp_offset], tmp_offset)

    def __validate_ep_2_values(self, pa: int) -> Optional[SMBIOS_2_x_ENTRY_POINT]:
        # Force a second read of memory so we don't have to worry about it falling outside the
        # original buffer.
        try:
            logger().log_hal(f'Validating 32bit SMBIOS header @ 0x{pa:08X}')
            mem_buffer = self.cs.mem.read_physical_mem(pa, SMBIOS_2_x_ENTRY_POINT_SIZE)
            ep_data = SMBIOS_2_x_ENTRY_POINT(*struct.unpack_from(SMBIOS_2_x_ENTRY_POINT_FMT, mem_buffer))
        except:
            logger().log_hal('- Memory read failed')
            return None
        if ep_data.Anchor != SMBIOS_2_x_SIG:
            logger().log_hal('- Invalid signature')
            return None
        if not (ep_data.EntryLen == SMBIOS_2_x_ENTRY_SIZE or ep_data.EntryLen == SMBIOS_2_x_ENTRY_SIZE_OLD):
            logger().log_hal('- Invalid structure size')
            return None
        if ep_data.IntAnchor != SMBIOS_2_x_INT_SIG:
            logger().log_hal('- Invalid intermediate signature')
            return None
        if (ep_data.TableAddr == 0) or (ep_data.TableLen == 0):
            logger().log_hal('- Invalid table address or length')
            return None
        return ep_data

    def __validate_ep_3_values(self, pa: int) -> Optional[SMBIOS_3_x_ENTRY_POINT]:
        # Force a second read of memory so we don't have to worry about it falling outside the
        # original buffer.
        try:
            logger().log_hal(f'Validating 64bit SMBIOS header @ 0x{pa:08X}')
            mem_buffer = self.cs.mem.read_physical_mem(pa, SMBIOS_3_x_ENTRY_POINT_SIZE)
            ep_data = SMBIOS_3_x_ENTRY_POINT(*struct.unpack_from(SMBIOS_3_x_ENTRY_POINT_FMT, mem_buffer))
        except:
            logger().log_hal('- Memory read failed')
            return None
        if ep_data.Anchor != SMBIOS_3_x_SIG:
            logger().log_hal('- Invalid signature')
            return None
        if not (ep_data.EntryLen == SMBIOS_3_x_ENTRY_SIZE):
            logger().log_hal('- Invalid structure size')
            return None
        if ep_data.MaxSize == 0 or ep_data.TableAddr == 0:
            logger().log_hal('- Invalid table address or maximum size')
            return None
        return ep_data

    def find_smbios_table(self) -> bool:
        # Handle the case were we already found the tables
        if self.smbios_2_ep is not None or self.smbios_3_ep is not None:
            return True

        # Initialize search parameters
        entries_to_find = entries_found = 0

        # Fist get the configuration table using the UEFI HAL.  You may not be able to use the addresses
        # in the table because in some cases they have been converted to a VA and are not mapped.
        logger().log_hal('Checking UEFI Configuration Table for SMBIOS entry')
        (ect_found, _, ect, _) = self.uefi.find_EFI_Configuration_Table()
        if ect_found and (ect is not None):
            logger().log_hal(str(ect))
            if SMBIOS_2_x_GUID in ect.VendorTables:
                logger().log_hal('+ Found 32bit SMBIOS entry')
                logger().log_hal(f'+ Potential 2.x table address: 0x{ect.VendorTables[SMBIOS_2_x_GUID]:016X}')
                self.smbios_2_guid_found = True
                entries_to_find += 1
            if SMBIOS_3_x_GUID in ect.VendorTables:
                logger().log_hal('+ Found 64bit SMBIOS entry')
                logger().log_hal(f'+ Potential 3.x table address: 0x{ect.VendorTables[SMBIOS_3_x_GUID]:016X}')
                self.smbios_3_guid_found = True
                entries_to_find += 1

        # Determine regions to scan
        if self.smbios_2_guid_found or self.smbios_3_guid_found:
            (smm_base, _, _) = self.cs.cpu.get_SMRAM()
            pa = smm_base - SCAN_SIZE
        else:
            entries_to_find = 2
            pa = BOUNDARY_1MB - SCAN_SIZE

        # Scan memory for the signature
        logger().log_hal(f'Scanning memory for {entries_to_find:d} signature(s)')
        while (pa >= SCAN_LOW_LIMIT):
            mem_buffer = self.cs.mem.read_physical_mem(pa, SCAN_SIZE)
            sig_pa = mem_buffer.find(SMBIOS_2_x_SIG) + pa
            if sig_pa >= pa and self.smbios_2_pa is None:
                logger().log_hal(f'+ Found SMBIOS 2.x signature @ 0x{sig_pa:08X}')
                self.smbios_2_ep = self.__validate_ep_2_values(sig_pa)
                if self.smbios_2_ep is not None:
                    logger().log_hal('+ Verified SMBIOS 2.x Entry Point structure')
                    self.smbios_2_pa = sig_pa
                    entries_found += 1
            sig_pa = mem_buffer.find(SMBIOS_3_x_SIG) + pa
            if sig_pa >= pa and self.smbios_3_pa is None:
                logger().log_hal(f'+ Found SMBIOS 3.x signature @ 0x{sig_pa:08X}')
                self.smbios_3_ep = self.__validate_ep_3_values(sig_pa)
                if self.smbios_3_ep is not None:
                    logger().log_hal('+ Verified SMBIOS 3.x Entry Point structure')
                    self.smbios_3_pa = sig_pa
                    entries_found += 1
            if entries_found >= entries_to_find:
                break
            pa -= SCAN_SIZE

        # Check to see if we thing we found the structure
        if self.smbios_2_pa is None and self.smbios_3_pa is None:
            logger().log_hal('- Unable to find SMBIOS tables')
            return False

        # Read the raw data regions
        logger().log_hal('Reading SMBIOS data tables:')
        if self.smbios_2_ep is not None and self.smbios_2_ep.TableAddr != 0 and self.smbios_2_ep.TableLen != 0:
            self.smbios_2_data = self.cs.mem.read_physical_mem(self.smbios_2_ep.TableAddr, self.smbios_2_ep.TableLen)
            if self.smbios_2_data is None:
                logger().log_hal('- Failed to read 32bit SMBIOS data')
        if self.smbios_3_ep is not None and self.smbios_3_ep.TableAddr != 0 and self.smbios_3_ep.MaxSize != 0:
            self.smbios_3_data = self.cs.mem.read_physical_mem(self.smbios_3_ep.TableAddr, self.smbios_3_ep.MaxSize)
            if self.smbios_3_data is None:
                logger().log_hal('- Failed to read 64bit SMBIOS data')

        return True

    def get_raw_structs(self, struct_type: Optional[int], force_32bit: bool):
        """
        Returns a list of raw data blobs for each SMBIOS structure.  The default is to process the 64bit
        entries if available unless specifically specified.

        Error:
        None
        """
        ret_val = []

        if self.smbios_3_data is not None and not force_32bit:
            logger().log_hal('Using 64bit SMBIOS table')
            table = self.smbios_3_data
        elif self.smbios_2_data is not None:
            logger().log_hal('Using 32bit SMBIOS table')
            table = self.smbios_2_data
        else:
            logger().log_hal('- No SMBIOS data available')
            return None

        logger().log_hal('Getting SMBIOS structures...')
        raw_data, next_offset = self.__get_raw_struct(table, 0)
        while (next_offset is not None) and (raw_data is not None):
            if struct_type is None:
                ret_val.append(raw_data)
            else:
                header = SMBIOS_STRUCT_HEADER(*struct.unpack_from(SMBIOS_STRUCT_HEADER_FMT, raw_data[:SMBIOS_STRUCT_HEADER_SIZE]))
                if header is not None and header.Type == struct_type:
                    ret_val.append(raw_data)
            raw_data, next_offset = self.__get_raw_struct(table, next_offset)

        return ret_val

    def get_header(self, raw_data: bytes) -> Optional[SMBIOS_STRUCT_HEADER]:
        logger().log_hal('Getting generic SMBIOS header information')
        if raw_data is None:
            logger().log_hal('- Raw data pointer is None')
            return None
        if len(raw_data) < SMBIOS_STRUCT_HEADER_SIZE:
            logger().log_hal('- Raw data too small for header information')
            return None

        try:
            header = SMBIOS_STRUCT_HEADER(*struct.unpack_from(SMBIOS_STRUCT_HEADER_FMT, raw_data[:SMBIOS_STRUCT_HEADER_SIZE]))
        except:
            logger().log_hal('- Failed to extract information from raw data')
            return None

        return header

    def get_string_list(self, raw_data: bytes) -> Optional[List[str]]:
        ret_val = []

        logger().log_hal('Getting strings from structure')
        raw_data_size = len(raw_data)
        header = self.get_header(raw_data)
        if header is None:
            return None
        if header.Length + SMBIOS_STRUCT_TERM_SIZE > raw_data_size:
            logger().log_hal('- Data buffer too small for structure')
            return None
        if header.Length + SMBIOS_STRUCT_TERM_SIZE == raw_data_size:
            logger().log_hal('+ No strings in this structure')
            return ret_val

        index = 0
        tmp_offset = header.Length
        while tmp_offset + index + 1 < raw_data_size:
            (value, ) = struct.unpack_from('=B', raw_data[tmp_offset + index:])
            if value == 0:
                logger().log_hal(f'+ Unpacking string of size {index:d}')
                (string, ) = struct.unpack_from(f'={index:d}s', raw_data[tmp_offset:])
                string = bytestostring(string)
                logger().log_hal(f'+ Found: {string:s}')
                ret_val.append(string)
                tmp_offset += index + 1
                index = 0
                continue
            index += 1

        logger().log_hal(f'+ Found {len(ret_val):d} strings')
        return ret_val

    def get_decoded_structs(self, struct_type: Optional[int] = None, force_32bit: bool = False) -> Optional[List[Type[SmbiosInfo]]]:
        ret_val = []

        # Determine if the structure exists in the table
        logger().log_hal('Getting decoded SMBIOS structures')
        structs = self.get_raw_structs(struct_type, force_32bit)
        if structs is None:
            return None

        # Process all the entries
        for data in structs:
            # Get the structures header information so we can determine the correct decode method
            header = self.get_header(data)
            if header is None:
                logger().log_hal('- Could not decode header')
                continue
            if header.Type not in struct_decode_tree:
                logger().log_hal(f'- Structure {header.Type:d} not in decode list')
                continue

            # Unpack the structure and then get the strings
            tmp_decode = struct_decode_tree[header.Type]
            try:
                decode_data = struct.unpack_from(tmp_decode['format'], data)
            except:
                logger().log_hal('- Could not decode structure')
                continue
            if decode_data is None:
                logger().log_hal('- No structure data was decoded')
                continue
            strings = self.get_string_list(data)
            if strings is not None:
                decode_data = decode_data + (strings, )

            # Create the actual object
            try:
                decode_object = tmp_decode['class'](*decode_data)
            except:
                logger().log_hal('- Failed to create structure')
                continue
            ret_val.append(decode_object)

        return ret_val
