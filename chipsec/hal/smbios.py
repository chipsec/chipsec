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

SMBIOS_2_x_SIG = "_SM_"
SMBIOS_2_x_ENTRY_SIZE = 0x1F
SMBIOS_2_x_ENTRY_SIZE_OLD = 0x1E
SMBIOS_2_x_MAJOR_VER = 0x02
SMBIOS_2_x_INT_SIG = "_DMI_"
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
        return SMBIOS_2_x_FORMAT_STRING.format(self.Anchor, self.EntryCs, self.EntryLen, self.MajorVer, self.MinorVer, \
                                            self.MaxSize, self.EntryRev, self.FormatArea0, self.FormatArea1, self.FormatArea2, \
                                            self.FormatArea3, self.FormatArea4, self.IntAnchor, self.IntCs, self.TableLen, \
                                            self.TableAddr, self.NumStructures, self.BcdRev)

SMBIOS_3_x_SIG = "_SM3_"
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
        return SMBIOS_3_x_FORMAT_STRING.format(self.Anchor, self.EntryCs, self.EntryLen, self.MajorVer, self.MinorVer, \
                                            self.Docrev, self.EntryRev, self.Reserved, self.MaxSize, self.TableAddr)

class SMBIOS(hal_base.HALBase):
    def __init__(self, cs):
        super(SMBIOS, self).__init__(cs)
        self.uefi = uefi.UEFI(cs)
        self.smbios_2_guid_found = False
        self.smbios_2_pa = None
        self.smbios_2_ep = None
        self.smbios_3_guid_found = False
        self.smbios_3_pa = None
        self.smbios_3_ep = None

    def validate_ep_2_values(self, pa):
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
        if not ep_data.IntAnchor.startswith(SMBIOS_2_x_INT_SIG):
            if logger().HAL: logger().log('- Invalid intermediate signature')
            return None
        if ep_data.TableAddr == 0 or ep_data.TableLen == 0:
            if logger().HAL: logger().log('- Invalid table address or length')
            return None
        return ep_data

    def validate_ep_3_values(self, pa):
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
            sig_pa = bytestostring(mem_buffer).find(SMBIOS_2_x_SIG) + pa
            if sig_pa >= pa and self.smbios_2_pa is None:
                if logger().HAL: logger().log('+ Found SMBIOS 2.x signature @ 0x{:08X}'.format(sig_pa))
                self.smbios_2_ep = self.validate_ep_2_values(sig_pa)
                if self.smbios_2_ep is not None:
                    if logger().HAL: logger().log('+ Verified SMBIOS 2.x Entry Point structure')
                    self.smbios_2_pa = sig_pa
                    entries_found += 1
            sig_pa = bytestostring(mem_buffer).find(SMBIOS_3_x_SIG) + pa
            if sig_pa >= pa and self.smbios_3_pa is None:
                if logger().HAL: logger().log('+ Found SMBIOS 3.x signature @ 0x{:08X}'.format(sig_pa))
                self.smbios_3_ep = self.validate_ep_3_values(sig_pa)
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

        return True