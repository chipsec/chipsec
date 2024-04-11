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

"""
HAL component providing access to and decoding of ACPI tables
"""

__version__ = '0.1'

import struct
from typing import Dict, List, Tuple, Optional, Callable, Union, TYPE_CHECKING
from collections import defaultdict
from collections import namedtuple

from chipsec.library.defines import bytestostring
from chipsec.library.exceptions import UnimplementedAPIError
from chipsec.library.file import read_file
from chipsec.hal import acpi_tables
from chipsec.hal.hal_base import HALBase
from chipsec.hal.uefi import UEFI
from chipsec.library.logger import logger, print_buffer_bytes
from chipsec.hal.acpi_tables import ACPI_TABLE

if TYPE_CHECKING:
    from ctypes import Array

# ACPI Table Header Format
ACPI_TABLE_HEADER_FORMAT = '=4sIBB6s8sI4sI'
ACPI_TABLE_HEADER_SIZE = struct.calcsize(ACPI_TABLE_HEADER_FORMAT)  # 36
assert 36 == ACPI_TABLE_HEADER_SIZE


class ACPI_TABLE_HEADER(namedtuple('ACPI_TABLE_HEADER', 'Signature Length Revision Checksum OEMID OEMTableID OEMRevision CreatorID CreatorRevision')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""  Table Header
------------------------------------------------------------------
  Signature        : {self.Signature}
  Length           : 0x{self.Length:08X}
  Revision         : 0x{self.Revision:02X}
  Checksum         : 0x{self.Checksum:02X}
  OEM ID           : {self.OEMID}
  OEM Table ID     : {self.OEMTableID}
  OEM Revision     : 0x{self.OEMRevision:08X}
  Creator ID       : {self.CreatorID}
  Creator Revision : 0x{self.CreatorRevision:08X}
"""


ACPI_TABLE_SIG_SIZE = 0x4

ACPI_TABLE_SIG_ROOT = 'ROOT'
ACPI_TABLE_SIG_RSDP = 'RSDP'
ACPI_TABLE_SIG_RSDT = 'RSDT'
ACPI_TABLE_SIG_XSDT = 'XSDT'
ACPI_TABLE_SIG_FACP = 'FACP'
ACPI_TABLE_SIG_FACS = 'FACS'
ACPI_TABLE_SIG_DSDT = 'DSDT'
ACPI_TABLE_SIG_SSDT = 'SSDT'
ACPI_TABLE_SIG_PSDT = 'PSDT'
ACPI_TABLE_SIG_APIC = 'APIC'
ACPI_TABLE_SIG_SBST = 'SBST'
ACPI_TABLE_SIG_ECDT = 'ECDT'
ACPI_TABLE_SIG_SRAT = 'SRAT'
ACPI_TABLE_SIG_SLIC = 'SLIC'
ACPI_TABLE_SIG_SLIT = 'SLIT'
ACPI_TABLE_SIG_BOOT = 'BOOT'
ACPI_TABLE_SIG_CPEP = 'CPEP'
ACPI_TABLE_SIG_DBGP = 'DBGP'
ACPI_TABLE_SIG_ETDT = 'ETDT'
ACPI_TABLE_SIG_HPET = 'HPET'
ACPI_TABLE_SIG_MCFG = 'MCFG'
ACPI_TABLE_SIG_SPCR = 'SPCR'
ACPI_TABLE_SIG_SPMI = 'SPMI'
ACPI_TABLE_SIG_TCPA = 'TCPA'
ACPI_TABLE_SIG_WDAT = 'WDAT'
ACPI_TABLE_SIG_WDRT = 'WDRT'
ACPI_TABLE_SIG_WSPT = 'WSPT'
ACPI_TABLE_SIG_WDDT = 'WDDT'
ACPI_TABLE_SIG_ASF = 'ASF!'
ACPI_TABLE_SIG_MSEG = 'MSEG'
ACPI_TABLE_SIG_DMAR = 'DMAR'
ACPI_TABLE_SIG_UEFI = 'UEFI'
ACPI_TABLE_SIG_FPDT = 'FPDT'
ACPI_TABLE_SIG_PCCT = 'PCCT'
ACPI_TABLE_SIG_MSDM = 'MSDM'
ACPI_TABLE_SIG_BATB = 'BATB'
ACPI_TABLE_SIG_BGRT = 'BGRT'
ACPI_TABLE_SIG_LPIT = 'LPIT'
ACPI_TABLE_SIG_ASPT = 'ASPT'
ACPI_TABLE_SIG_FIDT = 'FIDT'
ACPI_TABLE_SIG_HEST = 'HEST'
ACPI_TABLE_SIG_BERT = 'BERT'
ACPI_TABLE_SIG_ERST = 'ERST'
ACPI_TABLE_SIG_EINJ = 'EINJ'
ACPI_TABLE_SIG_TPM2 = 'TPM2'
ACPI_TABLE_SIG_WSMT = 'WSMT'
ACPI_TABLE_SIG_DBG2 = 'DBG2'
ACPI_TABLE_SIG_NHLT = 'NHLT'
ACPI_TABLE_SIG_MSCT = 'MSCT'
ACPI_TABLE_SIG_RASF = 'RASF'
ACPI_TABLE_SIG_OEM1 = 'OEM1'
ACPI_TABLE_SIG_OEM2 = 'OEM2'
ACPI_TABLE_SIG_OEM3 = 'OEM3'
ACPI_TABLE_SIG_OEM4 = 'OEM4'
ACPI_TABLE_SIG_NFIT = 'NFIT'

ACPI_TABLES: Dict[str, Callable] = {
    ACPI_TABLE_SIG_ROOT: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_RSDT: acpi_tables.RSDT,
    ACPI_TABLE_SIG_XSDT: acpi_tables.XSDT,
    ACPI_TABLE_SIG_FACP: acpi_tables.FADT,
    ACPI_TABLE_SIG_FACS: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_DSDT: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_SSDT: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_PSDT: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_APIC: acpi_tables.APIC,
    ACPI_TABLE_SIG_SBST: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_ECDT: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_SRAT: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_SLIC: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_SLIT: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_BOOT: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_CPEP: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_DBGP: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_ETDT: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_HPET: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_MCFG: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_SPCR: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_TCPA: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_WDAT: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_WDRT: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_WSPT: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_WDDT: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_ASF: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_MSEG: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_DMAR: acpi_tables.DMAR,
    ACPI_TABLE_SIG_UEFI: acpi_tables.UEFI_TABLE,
    ACPI_TABLE_SIG_FPDT: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_PCCT: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_MSDM: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_BATB: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_BGRT: acpi_tables.BGRT,
    ACPI_TABLE_SIG_LPIT: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_ASPT: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_FIDT: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_HEST: acpi_tables.HEST,
    ACPI_TABLE_SIG_BERT: acpi_tables.BERT,
    ACPI_TABLE_SIG_ERST: acpi_tables.ERST,
    ACPI_TABLE_SIG_EINJ: acpi_tables.EINJ,
    ACPI_TABLE_SIG_TPM2: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_WSMT: acpi_tables.WSMT,
    ACPI_TABLE_SIG_DBG2: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_NHLT: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_MSCT: acpi_tables.MSCT,
    ACPI_TABLE_SIG_RASF: acpi_tables.RASF,
    ACPI_TABLE_SIG_SPMI: acpi_tables.SPMI,
    ACPI_TABLE_SIG_OEM1: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_OEM2: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_OEM3: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_OEM4: acpi_tables.ACPI_TABLE,
    ACPI_TABLE_SIG_NFIT: acpi_tables.NFIT
}

########################################################################################################
#
# RSDP
#
########################################################################################################

RSDP_GUID_ACPI2_0 = '8868E871-E4F1-11D3-BC22-0080C73C8881'
RSDP_GUID_ACPI1_0 = 'EB9D2D31-2D88-11D3-9A16-0090273FC14D'
ACPI_RSDP_SIG = 'RSD PTR '

########################################################################################################
#
# ACPI HAL Component
#
########################################################################################################


class ACPI(HALBase):
    def __init__(self, cs):
        super(ACPI, self).__init__(cs)
        self.uefi = UEFI(self.cs)
        self.tableList: Dict[str, List[int]] = defaultdict(list)
        self.get_ACPI_table_list()

    def read_RSDP(self, rsdp_pa: int) -> acpi_tables.RSDP:
        rsdp_buf = self.cs.mem.read_physical_mem(rsdp_pa, acpi_tables.ACPI_RSDP_SIZE)
        rsdp = acpi_tables.RSDP()
        rsdp.parse(rsdp_buf)
        if rsdp.Revision >= 0x2:
            rsdp_buf = self.cs.mem.read_physical_mem(rsdp_pa, acpi_tables.ACPI_RSDP_EXT_SIZE)
            rsdp = acpi_tables.RSDP()
            rsdp.parse(rsdp_buf)
        return rsdp

    #
    # Check RSDP in Extended BIOS Data Area
    #
    def _find_RSDP_in_EBDA(self) -> Tuple[Optional[acpi_tables.RSDP], Optional[int]]:
        rsdp_pa = None
        rsdp = None
        logger().log_hal('[acpi] searching RSDP in EBDA...')
        ebda_ptr_addr = 0x40E
        ebda_addr = struct.unpack('<H', self.cs.mem.read_physical_mem(ebda_ptr_addr, 2))[0] << 4
        if ebda_addr > 0x400 and ebda_addr < 0xA0000:
            membuf = self.cs.mem.read_physical_mem(ebda_addr, 0xA0000 - ebda_addr)
            pos = bytestostring(membuf).find(ACPI_RSDP_SIG)
            if -1 != pos:
                rsdp_pa = ebda_addr + pos
                rsdp = self.read_RSDP(rsdp_pa)
                if rsdp.is_RSDP_valid():
                    logger().log_hal(f'[acpi] found RSDP in EBDA at: 0x{rsdp_pa:016X}')
                else:
                    rsdp_pa = None
        return rsdp, rsdp_pa

    #
    # Search RSDP in legacy BIOS E/F segments (0xE0000 - 0xFFFFF)
    #
    def _find_RSDP_in_legacy_BIOS_segments(self) -> Tuple[Optional[acpi_tables.RSDP], Optional[int]]:
        rsdp_pa = None
        rsdp = None
        membuf = self.cs.mem.read_physical_mem(0xE0000, 0x20000)
        membuf = bytestostring(membuf)
        pos = bytestostring(membuf).find(ACPI_RSDP_SIG)
        if -1 != pos:
            rsdp_pa = 0xE0000 + pos
            rsdp = self.read_RSDP(rsdp_pa)
            if rsdp.is_RSDP_valid():
                logger().log_hal(f'[acpi] Found RSDP in BIOS E/F segments: 0x{rsdp_pa:016X}')
            else:
                rsdp_pa = None
        return rsdp, rsdp_pa

    #
    # Search for RSDP in the EFI memory (EFI Configuration Table)
    #
    def _find_RSDP_in_EFI_config_table(self) -> Tuple[Optional[acpi_tables.RSDP], Optional[int]]:
        rsdp_pa = None
        rsdp = None
        logger().log_hal('[acpi] Searching RSDP pointers in EFI Configuration Table...')
        (isFound, _, ect, _) = self.uefi.find_EFI_Configuration_Table()
        if isFound and (ect is not None):
            if RSDP_GUID_ACPI2_0 in ect.VendorTables:
                rsdp_pa = ect.VendorTables[RSDP_GUID_ACPI2_0]
                logger().log_hal(f'[acpi] ACPI 2.0+ RSDP {{{RSDP_GUID_ACPI2_0}}} in EFI Config Table: 0x{rsdp_pa:016X}')
            elif RSDP_GUID_ACPI1_0 in ect.VendorTables:
                rsdp_pa = ect.VendorTables[RSDP_GUID_ACPI1_0]
                logger().log_hal('[acpi] ACPI 1.0 RSDP {{{RSDP_GUID_ACPI1_0}}} in EFI Config Table: 0x{rsdp_pa:016X}')

        if rsdp_pa:
            rsdp = self.read_RSDP(rsdp_pa)
            if rsdp.is_RSDP_valid():
                logger().log_hal(f'[acpi] Found RSDP in EFI Config Table: 0x{rsdp_pa:016X}')
            else:
                rsdp_pa = None
        return rsdp, rsdp_pa

    #
    # Search for RSDP in all EFI memory
    #
    def _find_RSDP_in_EFI(self) -> Tuple[Optional[acpi_tables.RSDP], Optional[int]]:
        rsdp_pa = None
        rsdp = None
        logger().log_hal("[acpi] Searching all EFI memory for RSDP (this may take a minute).")
        CHUNK_SZ = 1024 * 1024  # 1MB
        (smram_base, _, _) = self.cs.cpu.get_SMRAM()
        pa = smram_base - CHUNK_SZ
        while pa > CHUNK_SZ:
            membuf = self.cs.mem.read_physical_mem(pa, CHUNK_SZ)
            pos = bytestostring(membuf).find(ACPI_RSDP_SIG)
            if -1 != pos:
                rsdp_pa = pa + pos
                logger().log_hal(f"[acpi] Found '{ACPI_RSDP_SIG}' signature at 0x{rsdp_pa:16X}. Checking if valid RSDP.")
                rsdp = self.read_RSDP(rsdp_pa)
                if rsdp.is_RSDP_valid():
                    logger().log_hal(f'[acpi] Found RSDP in EFI memory: 0x{rsdp_pa:016X}')
                    break
            pa -= CHUNK_SZ
        return rsdp, rsdp_pa

    #
    # Searches for Root System Description Pointer (RSDP) in various locations for legacy/EFI systems
    #
    def find_RSDP(self) -> Tuple[Optional[int], Optional[acpi_tables.RSDP]]:
        rsdp, rsdp_pa = self._find_RSDP_in_EBDA()

        if rsdp_pa is None:
            rsdp, rsdp_pa = self._find_RSDP_in_legacy_BIOS_segments()

        if rsdp_pa is None:
            rsdp, rsdp_pa = self._find_RSDP_in_EFI_config_table()

        if rsdp_pa is None:
            rsdp, rsdp_pa = self._find_RSDP_in_EFI()

        if rsdp is not None:
            logger().log_hal(str(rsdp))

        return (rsdp_pa, rsdp)

    RsdtXsdt = Union[acpi_tables.RSDT, acpi_tables.XSDT]
    #
    # Retrieves System Description Table (RSDT or XSDT) either from RSDP or using OS API
    #
    def get_SDT(self, search_rsdp: bool = True) -> Tuple[bool, Optional[int], Optional[RsdtXsdt], Optional[ACPI_TABLE_HEADER]]:
        is_xsdt = False
        sdt_pa = None
        sdt_header = None
        sdt_buf = b''
        if search_rsdp:
            (_, rsdp) = self.find_RSDP()
            if rsdp is not None:
                if 0x0 == rsdp.Revision:
                    sdt_pa = rsdp.RsdtAddress
                    is_xsdt = False
                elif 0x2 == rsdp.Revision:
                    sdt_pa = rsdp.XsdtAddress
                    is_xsdt = True
                else:
                    return (False, None, None, None)
                found_str = 'XSDT' if is_xsdt else 'RSDT'
                logger().log_hal(f'[acpi] Found {found_str} at PA: 0x{sdt_pa:016X}')
                sdt_header_buf = self.cs.mem.read_physical_mem(sdt_pa, ACPI_TABLE_HEADER_SIZE)
                sdt_header = self._parse_table_header(sdt_header_buf)
                sdt_buf = self.cs.mem.read_physical_mem(sdt_pa, sdt_header.Length)
        else:
            sdt_pa = None
            if logger().HAL:
                logger().log("[acpi] Reading RSDT/XSDT using OS API...")
            (sdt_buf, is_xsdt) = self.get_ACPI_SDT()
            sdt_header = self._parse_table_header(sdt_buf[:ACPI_TABLE_HEADER_SIZE])

        sdt_contents = sdt_buf[ACPI_TABLE_HEADER_SIZE:]
        sdt = ACPI_TABLES[ACPI_TABLE_SIG_XSDT if is_xsdt else ACPI_TABLE_SIG_RSDT]()
        sdt.parse(sdt_contents)
        return (is_xsdt, sdt_pa, sdt, sdt_header)



    def get_ACPI_SDT(self) -> Tuple[Optional['Array'], bool]:
        sdt = self.cs.helper.get_acpi_table('XSDT')  # FirmwareTableID_XSDT
        xsdt = sdt is not None
        if not xsdt:
            sdt = self.get_acpi_table('RSDT')  # FirmwareTableID_RSDT
        return sdt, xsdt

    #
    # Populates a list of ACPI tables available on the system
    #
    def get_ACPI_table_list(self) -> Dict[str, List[int]]:
        try:
            # 1. If didn't work, try using get_ACPI_table if a helper implemented
            #    reading ACPI tables via native API which some OS may provide
            # raise UnimplementedAPIError("asdf")
            logger().log_hal("[acpi] Trying to enumerate ACPI tables using get_ACPI_table...")
            for table_name in self.cs.helper.enum_ACPI_tables():
                self.tableList[table_name.decode("utf-8")].append(0)
        except UnimplementedAPIError:
            # 2. Try to extract ACPI table(s) from physical memory
            #    read_physical_mem can be implemented using both
            #    CHIPSEC kernel module and OS native API
            logger().log_hal("[acpi] Trying to enumerate ACPI tables from physical memory...")
            # find RSDT/XSDT table
            (is_xsdt, sdt_pa, sdt, sdt_header) = self.get_SDT()

            # cache RSDT/XSDT in the list of ACPI tables
            if (sdt_pa is not None) and (sdt_header is not None):
                self.tableList[bytestostring(sdt_header.Signature)].append(sdt_pa)
            if sdt is not None:
                self.get_table_list_from_SDT(sdt, is_xsdt)
            self.get_DSDT_from_FADT()

        return self.tableList

    #
    # Gets table list from entries in RSDT/XSDT
    #
    def get_table_list_from_SDT(self, sdt: RsdtXsdt, is_xsdt: bool) -> None:
        logger().log_hal(f'[acpi] Getting table list from entries in {"XSDT" if is_xsdt else "RSDT"}')
        for a in sdt.Entries:
            _sig = self.cs.mem.read_physical_mem(a, ACPI_TABLE_SIG_SIZE)
            _sig = bytestostring(_sig)
            if _sig not in ACPI_TABLES.keys():
                if logger().HAL:
                    logger().log_warning(f'Unknown ACPI table signature: {_sig}')
            self.tableList[_sig].append(a)

    #
    # Gets DSDT from FADT
    #
    def get_DSDT_from_FADT(self) -> None:
        logger().log_hal('[acpi] Getting DSDT from FADT')

        if ACPI_TABLE_SIG_FACP in self.tableList:
            (_, parsed_fadt_content, _, _) = self.get_parse_ACPI_table('FACP')[0]
        else:
            if logger().HAL:
                found_table = 'XSDT' if ACPI_TABLE_SIG_XSDT in self.tableList else 'RSDT'
                logger().log_warning(f'Cannot find FADT in {found_table}')
            return

        dsdt_address_to_use = parsed_fadt_content.get_DSDT_address_to_use()

        if dsdt_address_to_use is None:
            dsdt_address = parsed_fadt_content.dsdt
            x_dsdt_address = parsed_fadt_content.x_dsdt
            if logger().HAL:
                logger().log_error('Unable to determine the correct DSDT address')
            if logger().HAL:
                logger().log_error(f'  DSDT   address = 0x{dsdt_address:08X}')
            if logger().HAL:
                address_str = f'{x_dsdt_address:16X}' if x_dsdt_address is not None else 'Not found'
                logger().log_error(f'  X_DSDT address = 0x{address_str}')
            return

        self.tableList[ACPI_TABLE_SIG_DSDT].append(dsdt_address_to_use)

    #
    # Checks is ACPI table with <name> is available on the system
    #
    def is_ACPI_table_present(self, name: str) -> bool:
        return (name in self.tableList)

    #
    # Prints a list of ACPI tables available on the system
    #
    def print_ACPI_table_list(self) -> None:
        if len(self.tableList) == 0:
            logger().log_error("Couldn't get a list of ACPI tables")
        else:
            logger().log_hal('[acpi] Found the following ACPI tables:')
            for tableName in sorted(self.tableList.keys()):
                table_values_str = ', '.join([f'0x{addr:016X}' for addr in self.tableList[tableName]])
                logger().log(f' - {tableName}: {table_values_str}')

    #
    # Retrieves contents of ACPI table from memory or from file
    #
    def get_parse_ACPI_table(self, name: str, isfile: bool = False) -> List['ParseTable']:
        acpi_tables = self.get_ACPI_table(name, isfile)
        return [self._parse_table(name, table_header_blob, table_blob) for (table_header_blob, table_blob) in acpi_tables if table_header_blob is not None]

    def get_ACPI_table(self, name: str, isfile: bool = False) -> List[Tuple[bytes, bytes]]:
        acpi_tables_data: List[bytes] = []
        if isfile:
            acpi_tables_data.append(read_file(name))
        else:
            try:
                # 1. Try to extract ACPI table(s) using get_ACPI_table if a helper implemented
                #    reading ACPI tables via native API which some OS may provide
                logger().log_hal("[acpi] trying to extract ACPI table using get_ACPI_table...")
                t_data = self.cs.helper.get_ACPI_table(name)
                acpi_tables_data.append(t_data)
            except UnimplementedAPIError:
                # 2. If didn't work, try scrubbing physical memory
                #    read_physical_mem can be implemented using both
                #    CHIPSEC kernel module and OS native API
                logger().log_hal('[acpi] trying to extract ACPI table from physical memory...')
                for table_address in self.tableList[name]:
                    t_size = self.cs.mem.read_physical_mem_dword(table_address + 4)
                    t_data = self.cs.mem.read_physical_mem(table_address, t_size)
                    acpi_tables_data.append(t_data)

        acpi_tables = []
        for data in acpi_tables_data:
            acpi_tables.append((data[: ACPI_TABLE_HEADER_SIZE], data[ACPI_TABLE_HEADER_SIZE:]))

        return acpi_tables

    #
    # Dumps contents of ACPI table
    #
    def dump_ACPI_table(self, name: str, isfile: bool = False) -> None:
        acpi_tables = self.get_parse_ACPI_table(name, isfile)
        for acpi_table in acpi_tables:
            (table_header, table, table_header_blob, table_blob) = acpi_table
            logger().log("==================================================================")
            logger().log(f'ACPI Table: {name}')
            logger().log("==================================================================")
            # print table header
            logger().log(str(table_header))
            print_buffer_bytes(table_header_blob)
            # print table contents
            logger().log('')
            logger().log(str(table))
            print_buffer_bytes(table_blob)
            logger().log('')

    # --------------------------------------------------------------------
    # Internal ACPI table parsing functions
    # --------------------------------------------------------------------

    ParseTable = Tuple[ACPI_TABLE_HEADER, Optional[ACPI_TABLE], bytes, bytes]

    def _parse_table(self, name: str, table_header_blob: bytes, table_blob: bytes) -> ParseTable:
        table_header = self._parse_table_header(table_header_blob)
        table = self._parse_table_contents(name, table_blob, table_header_blob)
        return (table_header, table, table_header_blob, table_blob)

    def _parse_table_header(self, header: bytes) -> ACPI_TABLE_HEADER:
        acpi_table_hdr = ACPI_TABLE_HEADER(*struct.unpack_from(ACPI_TABLE_HEADER_FORMAT, header))
        logger().log_hal(str(acpi_table_hdr))
        return acpi_table_hdr

    def _parse_table_contents(self, signature: str, contents: bytes, header: bytes) -> Optional[ACPI_TABLE]:
        table = None
        if ACPI_TABLES.__contains__(signature):
            logger().log_hal(f'{signature}')
            if 'BERT' in signature:
                BootRegionLen = struct.unpack('<L', contents[0:4])[0]
                BootRegionAddr = struct.unpack('<Q', contents[4:12])[0]
                bootRegion = self.cs.mem.read_physical_mem(BootRegionAddr, BootRegionLen)
                table = (ACPI_TABLES[signature])(bootRegion)
            elif 'NFIT' in signature:
                table = (ACPI_TABLES[signature])(header)
            else:
                table = (ACPI_TABLES[signature])()
            table.parse(contents)
        return table
