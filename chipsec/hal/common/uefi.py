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
Main UEFI component using platform specific and common UEFI functionality
"""

import struct
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING
if TYPE_CHECKING:
    from chipsec.library.uefi.sleep_states import S3BOOTSCRIPT_ENTRY
    from chipsec.library.uefi.common import EFI_SYSTEM_TABLE
    from chipsec.library.types import EfiVariableType
from chipsec.hal import hal_base
from chipsec.hal.intel.spi import SPI, BIOS
from chipsec.library.uefi.common import EFI_VENDOR_TABLE, EFI_VENDOR_TABLE_SIZE, EFI_VENDOR_TABLE_FORMAT, EFI_TABLE_HEADER_SIZE, EFI_TABLE_HEADER, EFI_TABLES, MAX_EFI_TABLE_SIZE
from chipsec.library.uefi.common import EFI_REVISIONS
from chipsec.library.uefi.common import EFI_TABLE_HEADER_FMT, EFI_SYSTEM_TABLE_SIGNATURE, EFI_RUNTIME_SERVICES_SIGNATURE, EFI_BOOT_SERVICES_SIGNATURE
from chipsec.library.uefi.common import EFI_DXE_SERVICES_TABLE_SIGNATURE, EFI_CONFIGURATION_TABLE
from chipsec.library.uefi.sleep_states import ACPI_VARIABLE_SET_STRUCT_SIZE, S3_BOOTSCRIPT_VARIABLES, parse_script
from chipsec.library.logger import logger, print_buffer_bytes
from chipsec.library.file import write_file, read_file
from chipsec.library.defines import bytestostring
from chipsec.helper.oshelper import OsHelperError
from chipsec.library.uefi.platform import FWType, fw_types
from chipsec.library.uefi.varstore import find_EFI_variable_store, EFI_VAR_DICT
from chipsec.library.uefi.variables import print_sorted_EFI_variables, get_attr_string


########################################################################################################
#
# UEFI HAL Component
#
########################################################################################################


class UEFI(hal_base.HALBase):
    def __init__(self, cs):
        super(UEFI, self).__init__(cs)
        self.helper = cs.helper
        self._FWType = FWType.EFI_FW_TYPE_UEFI

    ######################################################################
    # FWType defines platform/BIOS dependent formats like
    # format of EFI NVRAM, format of FV, etc.
    #
    # FWType chooses an element from the EFI_VAR_DICT Dictionary
    #
    # Default current platform type is EFI_FW_TYPE_UEFI
    ######################################################################

    def set_FWType(self, efi_nvram_format: str) -> None:
        if efi_nvram_format in fw_types:
            self._FWType = efi_nvram_format

    ######################################################################
    # EFI NVRAM Parsing Functions
    ######################################################################

    def init_spi_hal(self) -> None:
        if not hasattr(self, 'spi'):
            self.spi = SPI(self.cs)

    def dump_EFI_variables_from_SPI(self) -> bytes:
        self.init_spi_hal()
        (_, limit, _) = self.spi.get_SPI_region(BIOS)
        spi_size = limit + 1
        self.logger.log_hal(f'[uefi] Reading from SPI: 0x0-0x{spi_size:X}')
        return self.read_EFI_variables_from_SPI(0, spi_size)

    def read_EFI_variables_from_rom(self, rom: bytes) -> bytes:
        self.logger.log_hal('[uefi] Looking for variables in SPI dump')
        efi_var_store = find_EFI_variable_store(rom, 'nvar')
        if efi_var_store:
            efi_vars = EFI_VAR_DICT['nvar']['func_getefivariables'](efi_var_store)
            return efi_vars
        return efi_var_store

    def read_EFI_variables_from_SPI(self, BIOS_region_base: int, BIOS_region_size: int) -> bytes:
        self.init_spi_hal()
        rom = self.spi.read_spi(BIOS_region_base, BIOS_region_size)
        return self.read_EFI_variables_from_rom(rom)

    def read_EFI_variables_from_file(self, filename: str) -> bytes:
        rom = read_file(filename)
        return self.read_EFI_variables_from_rom(rom)

    # @TODO: Do not use, will be removed

    def read_EFI_variables(self, efi_var_store: Optional[bytes], authvars: bool) -> Dict[str, List['EfiVariableType']]:
        if efi_var_store is None:
            logger().log_error('efi_var_store is None')
            return {}
        variables: Dict[str, List[EfiVariableType]] = EFI_VAR_DICT[self._FWType]['func_getefivariables'](efi_var_store)
        if logger().UTIL_TRACE:
            print_sorted_EFI_variables(variables)
        return variables

    ######################################################################
    # S3 Resume Boot-Script Parsing Functions
    ######################################################################

    #
    # Finds physical address of the S3 resume boot script from UEFI variables
    # Returns:
    #   found               - status is the script is found
    #   AcpiBootScriptTable - physical address of the S3 resume boot script, 0 if (not found)
    #
    def find_s3_bootscript(self) -> Tuple[bool, List[int]]:
        found = False
        BootScript_addresses = []

        efivars = self.list_EFI_variables()
        if efivars is None:
            logger().log_error('Could not enumerate UEFI variables at runtime')
            return (found, BootScript_addresses)
        logger().log_hal(f'[uefi] Searching for EFI variable(s): {str(S3_BOOTSCRIPT_VARIABLES)}')

        for efivar_name in efivars:
            (off, buf, hdr, data, guid, attrs) = efivars[efivar_name][0]
            if efivar_name in S3_BOOTSCRIPT_VARIABLES:
                logger().log_hal(f'[uefi] Found: {efivar_name} {{{guid}}} {get_attr_string(attrs)} variable')
                logger().log_hal(f'[uefi] {efivar_name} variable data:')
                if logger().HAL:
                    print_buffer_bytes(data)

                varsz = len(data)
                if 4 == varsz:
                    AcpiGlobalAddr_fmt = '<L'
                elif 8 == varsz:
                    AcpiGlobalAddr_fmt = '<Q'
                else:
                    logger().log_error(f"Unrecognized format of '{efivar_name}' UEFI variable (data size = 0x{varsz:X})")
                    break
                AcpiGlobalAddr = struct.unpack_from(AcpiGlobalAddr_fmt, data)[0]
                if 0 == AcpiGlobalAddr:
                    logger().log_error(f'Pointer to ACPI Global Data structure in {efivar_name} variable is 0')
                    break
                logger().log_hal(f"[uefi] Pointer to ACPI Global Data structure: 0x{AcpiGlobalAddr:016X}")
                logger().log_hal('[uefi] Decoding ACPI Global Data structure...')
                AcpiVariableSet = self.helper.read_phys_mem(AcpiGlobalAddr, ACPI_VARIABLE_SET_STRUCT_SIZE)
                logger().log_hal('[uefi] AcpiVariableSet structure:')
                if logger().HAL:
                    print_buffer_bytes(AcpiVariableSet)
                AcpiVariableSet_fmt = '<6Q'
                # if len(AcpiVariableSet) < struct.calcsize(AcpiVariableSet_fmt):
                #    logger().log_error( 'Unrecognized format of AcpiVariableSet structure' )
                #    return (False,0)
                _, _, _, AcpiBootScriptTable, _, _ = struct.unpack_from(AcpiVariableSet_fmt, AcpiVariableSet)
                logger().log_hal(f'[uefi] ACPI Boot-Script table base = 0x{AcpiBootScriptTable:016X}')
                found = True
                BootScript_addresses.append(AcpiBootScriptTable)
                # break
        return (found, BootScript_addresses)

    #
    # Upper level function to find and parse S3 resume boot script
    # Returns:
    #   bootscript_pa  - physical address of the S3 resume boot script
    #   script_entries - a list of parse S3 resume boot script operations
    #
    def get_s3_bootscript(self, log_script: bool = False) -> Tuple[List[int], Optional[Dict[int, List['S3BOOTSCRIPT_ENTRY']]]]:
        parsed_scripts = {}
        script_entries = []
        #
        # Find the S3 Resume Boot-Script from UEFI variables
        #
        found, bootscript_PAs = self.find_s3_bootscript()
        if not found:
            return (bootscript_PAs, None)
        logger().log_hal(f'[uefi] Found {len(bootscript_PAs):d} S3 resume boot-scripts')

        for bootscript_pa in bootscript_PAs:
            if (bootscript_pa == 0):
                continue
            logger().log_hal(f'[uefi] S3 resume boot-script at 0x{bootscript_pa:016X}')
            #
            # Decode the S3 Resume Boot-Script into a sequence of operations/opcodes
            #
            # @TODO: should be dumping memory contents in a loop until end opcode is found or id'ing actual size
            script_buffer = self.helper.read_phys_mem(bootscript_pa, 0x200000)
            logger().log_hal('[uefi] Decoding S3 Resume Boot-Script...')
            script_entries = parse_script(script_buffer, log_script)
            parsed_scripts[bootscript_pa] = script_entries
        return (bootscript_PAs, parsed_scripts)

    ######################################################################
    # Runtime Variable API Functions
    ######################################################################

    def list_EFI_variables(self) -> Optional[Dict[str, List[Tuple[int, bytes, int, bytes, str, int]]]]:
        varlist = self.helper.list_EFI_variables()
        return varlist

    def list_EFI_variables_spi(self, filename: str = None) -> Optional[Dict[str, List[Tuple[int, bytes, int, bytes, str, int]]]]:
        if filename:
            varlist = self.read_EFI_variables_from_file(filename)
        else:
            varlist = self.dump_EFI_variables_from_SPI()
        return varlist

    def get_EFI_variable(self, name: str, guid: str, filename: Optional[str] = None) -> Optional[bytes]:
        var = self.helper.get_EFI_variable(name, guid)
        if var:
            if filename:
                write_file(filename, var)
            if logger().UTIL_TRACE or logger().HAL:
                logger().log(f'[uefi] EFI variable {guid}:{name} :')
                print_buffer_bytes(var)
        return var

    def set_EFI_variable(self, name: str, guid: str, var: bytes, datasize: Optional[int] = None, attrs: Optional[int] = None) -> Optional[int]:
        atts_str = '' if attrs is None else f'(attributes = {attrs})'
        logger().log_hal(f'[uefi] Writing EFI variable {guid}:{name} {atts_str}')
        return self.helper.set_EFI_variable(name, guid, var, datasize, attrs)

    def set_EFI_variable_from_file(self, name: str, guid: str, filename: str, datasize: Optional[int] = None, attrs: Optional[int] = None) -> Optional[int]:
        if filename is None:
            logger().log_error('File with EFI variable is not specified')
            return False
        var = read_file(filename)
        return self.set_EFI_variable(name, guid, var, datasize, attrs)

    def delete_EFI_variable(self, name: str, guid: str) -> Optional[int]:
        logger().log_hal(f'[uefi] Deleting EFI variable {guid}:{name}')
        return self.helper.delete_EFI_variable(name, guid)

    ######################################################################
    # UEFI System Tables
    ######################################################################

    EfiTable = Tuple[bool, int, Optional[EFI_TABLE_HEADER], Optional['EFI_SYSTEM_TABLE'], bytes]

    def find_EFI_Table(self, table_sig: str) -> EfiTable:
        (smram_base, _, _) = self.cs.hals.CPU.get_SMRAM()
        CHUNK_SZ = 1024 * 1024  # 1MB
        logger().log_hal(f"[uefi] Searching memory for EFI table with signature '{table_sig}'...")
        table_pa = 0
        table_header = None
        table = None
        table_buf = b''
        pa = smram_base - CHUNK_SZ
        isFound = False

        (tseg_base, tseg_limit, _) = self.cs.hals.CPU.get_TSEG()

        while pa > CHUNK_SZ:
            if (pa <= tseg_limit) and (pa >= tseg_base):
                logger().log_hal(f'[uefi] Skipping memory read at pa: {pa:016X}')
                pa -= CHUNK_SZ
                continue
            logger().log_hal(f'[uefi] Reading 0x{pa:016X}...')
            try:
                membuf = self.cs.hals.Memory.read_physical_mem(pa, CHUNK_SZ)
            except OsHelperError as err:
                logger().log_hal(f'[uefi] Unable to read memory at pa: {pa:016X} Error: {err}')
                pa -= CHUNK_SZ
                continue
            pos = bytestostring(membuf).find(table_sig)
            if -1 != pos:
                table_pa = pa + pos
                logger().log_hal(f"[uefi] Round signature '{table_sig}' at 0x{table_pa:016X}...")
                if pos < (CHUNK_SZ - EFI_TABLE_HEADER_SIZE):
                    hdr = membuf[pos: pos + EFI_TABLE_HEADER_SIZE]
                else:
                    hdr = self.cs.hals.Memory.read_physical_mem(table_pa, EFI_TABLE_HEADER_SIZE)
                table_header = EFI_TABLE_HEADER(*struct.unpack_from(EFI_TABLE_HEADER_FMT, hdr))
                # do some sanity checks on the header
                is_reserved = table_header.Reserved != 0
                is_bad_crc = table_header.CRC32 == 0
                is_not_table_rev = table_header.Revision not in EFI_REVISIONS
                is_not_correct_size = table_header.HeaderSize > MAX_EFI_TABLE_SIZE
                if is_reserved or is_bad_crc or is_not_table_rev or is_not_correct_size:
                    logger().log_hal(f"[uefi] Found '{table_sig}' at 0x{table_pa:016X} but doesn't look like an actual table. Keep searching...")
                    logger().log_hal(str(table_header))
                else:
                    isFound = True
                    logger().log_hal(f"[uefi] Found EFI table at 0x{table_pa:016X} with signature '{table_sig}'...")
                    table_size = struct.calcsize(EFI_TABLES[table_sig]['fmt'])
                    if pos < (CHUNK_SZ - EFI_TABLE_HEADER_SIZE - table_size):
                        table_buf = membuf[pos: pos + EFI_TABLE_HEADER_SIZE + table_size]
                    else:
                        table_buf = self.cs.hals.Memory.read_physical_mem(table_pa, EFI_TABLE_HEADER_SIZE + table_size)
                    table = EFI_TABLES[table_sig]['struct'](*struct.unpack_from(EFI_TABLES[table_sig]['fmt'], table_buf[EFI_TABLE_HEADER_SIZE:]))
                    if logger().HAL:
                        print_buffer_bytes(table_buf)
                    logger().log_hal(f'[uefi] {EFI_TABLES[table_sig]["name"]}:')
                    logger().log_hal(str(table_header))
                    logger().log_hal(str(table))
                    break
            pa -= CHUNK_SZ
        if not isFound:
            logger().log_hal(f"[uefi] Could not find EFI table with signature '{table_sig}'")
        return (isFound, table_pa, table_header, table, table_buf)

    def find_EFI_System_Table(self) -> EfiTable:
        return self.find_EFI_Table(EFI_SYSTEM_TABLE_SIGNATURE)

    def find_EFI_RuntimeServices_Table(self) -> EfiTable:
        return self.find_EFI_Table(EFI_RUNTIME_SERVICES_SIGNATURE)

    def find_EFI_BootServices_Table(self) -> EfiTable:
        return self.find_EFI_Table(EFI_BOOT_SERVICES_SIGNATURE)

    def find_EFI_DXEServices_Table(self) -> EfiTable:
        return self.find_EFI_Table(EFI_DXE_SERVICES_TABLE_SIGNATURE)
    # def find_EFI_PEI_Table( self ):
    #    return self.find_EFI_Table( EFI_FRAMEWORK_PEI_SERVICES_TABLE_SIGNATURE )
    # def find_EFI_SMM_System_Table( self ):
    #    return self.find_EFI_Table( EFI_SMM_SYSTEM_TABLE_SIGNATURE )

    def find_EFI_Configuration_Table(self) -> Tuple[bool, int, Optional[EFI_CONFIGURATION_TABLE], bytes]:
        ect_pa = 0
        ect = None
        ect_buf = b''
        (isFound, _, _, est, _) = self.find_EFI_System_Table()
        if isFound and est is not None:
            if 0 != est.BootServices:
                logger().log_hal('[uefi] UEFI appears to be in Boot mode')
                ect_pa = est.ConfigurationTable
            else:
                logger().log_hal('[uefi] UEFI appears to be in Runtime mode')
                ect_pa = self.cs.hals.Memory.va2pa(est.ConfigurationTable)
                if not ect_pa:
                    # Most likely the VA in the System Table is not mapped so find the RST by signature and
                    # then compute the address of the configuration table.  This assumes the VA mapping keeps
                    # the pages in the same relative location as in physical memory.
                    (rst_found, rst_pa, rst_header, rst, rst_buf) = self.find_EFI_RuntimeServices_Table()
                    if rst_found:
                        if logger().HAL:
                            logger().log_warning('Attempting to derive configuration table address')
                        ect_pa = rst_pa + (est.ConfigurationTable - est.RuntimeServices)
                    else:
                        if logger().HAL:
                            logger().log_warning("Can't find UEFI ConfigurationTable")
                        return (False, ect_pa, ect, ect_buf)
        if est is not None:
            logger().log_hal(f'[uefi] EFI Configuration Table ({est.NumberOfTableEntries:d} entries): VA = 0x{est.ConfigurationTable:016X}, PA = 0x{ect_pa:016X}')
        else:
            logger().log_hal('[uefi] EFI Configuration Table (No entries found)')

        found = ect_pa is not None
        if found and (est is not None):
            ect_buf = self.cs.hals.Memory.read_physical_mem(ect_pa, EFI_VENDOR_TABLE_SIZE * est.NumberOfTableEntries)
            ect = EFI_CONFIGURATION_TABLE()
            for i in range(est.NumberOfTableEntries):
                vt = EFI_VENDOR_TABLE(*struct.unpack_from(EFI_VENDOR_TABLE_FORMAT, ect_buf[i * EFI_VENDOR_TABLE_SIZE:]))
                ect.VendorTables[vt.VendorGuid()] = vt.VendorTable
        return (found, ect_pa, ect, ect_buf)

    def dump_EFI_tables(self) -> None:
        (found, pa, hdr, table, table_buf) = self.find_EFI_System_Table()
        if found:
            logger().log('[uefi] EFI System Table:')
            if table_buf is not None:
                print_buffer_bytes(table_buf)
            logger().log(str(hdr))
            logger().log(str(table))
        (found, _, ect, ect_buf) = self.find_EFI_Configuration_Table()
        if found:
            logger().log('\n[uefi] EFI Configuration Table:')
            if ect_buf is not None:
                print_buffer_bytes(ect_buf)
            logger().log(str(ect))
        (found, pa, hdr, table, table_buf) = self.find_EFI_RuntimeServices_Table()
        if found:
            logger().log('\n[uefi] EFI Runtime Services Table:')
            if table_buf is not None:
                print_buffer_bytes(table_buf)
            logger().log(str(hdr))
            logger().log(str(table))
        (found, pa, hdr, table, table_buf) = self.find_EFI_BootServices_Table()
        if found:
            logger().log('\n[uefi] EFI Boot Services Table:')
            if table_buf is not None:
                print_buffer_bytes(table_buf)
            logger().log(str(hdr))
            logger().log(str(table))
        (found, pa, hdr, table, table_buf) = self.find_EFI_DXEServices_Table()
        if found:
            logger().log('\n[uefi] EFI DXE Services Table:')
            if table_buf is not None:
                print_buffer_bytes(table_buf)
            logger().log(str(hdr))
            logger().log(str(table))


haldata = {"arch": ['FFFF'], 'name': ['UEFI']}
