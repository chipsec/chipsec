#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2015, Intel Corporation
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

"""
HAL component providing access to and decoding of ACPI tables
"""

__version__ = '0.1'

import struct
import sys

from collections import namedtuple

from chipsec.logger import *
from chipsec.file import *

import chipsec.hal.acpi_tables
import chipsec.hal.uefi

class AcpiRuntimeError (RuntimeError):
    pass

# ACPI Table Header Format
ACPI_TABLE_HEADER_FORMAT = '=4sIBB6s8sI4sI'
ACPI_TABLE_HEADER_SIZE   = struct.calcsize(ACPI_TABLE_HEADER_FORMAT) # 36
assert( 36 == ACPI_TABLE_HEADER_SIZE )

class ACPI_TABLE_HEADER( namedtuple('ACPI_TABLE_HEADER', 'Signature Length Revision Checksum OEMID OEMTableID OEMRevision CreatorID CreatorRevision') ):
    __slots__ = ()
    def __str__(self):
        return """  Table Header
------------------------------------------------------------------
  Signature        : %s
  Length           : 0x%08X
  Revision         : 0x%02X
  Checksum         : 0x%02X
  OEM ID           : %s
  OEM Table ID     : %s
  OEM Revision     : 0x%08X
  Creator ID       : %s
  Creator Revision : 0x%08X
""" % ( self.Signature, self.Length, self.Revision, self.Checksum, self.OEMID, self.OEMTableID, self.OEMRevision, self.CreatorID, self.CreatorRevision )


class ACPI_TABLE_NULL( namedtuple('ACPI_TABLE_NULL', 'null') ):
    __slots__ = ()
    def __str__(self):
        return """------------------------------------------------------------------
  Table Contents: Template
------------------------------------------------------------------
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
ACPI_TABLE_SIG_ASF  = 'ASF!'
ACPI_TABLE_SIG_MSEG = 'MSEG'
ACPI_TABLE_SIG_DMAR = 'DMAR'
ACPI_TABLE_SIG_UEFI = 'UEFI'
ACPI_TABLE_SIG_FPDT = 'FPDT'
ACPI_TABLE_SIG_PCCT = 'PCCT'
ACPI_TABLE_SIG_MSDM = 'MSDM'
ACPI_TABLE_SIG_BATB = 'BATB'
ACPI_TABLE_SIG_BGRT = 'BGRT'

ACPI_TABLES = {
  ACPI_TABLE_SIG_ROOT: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_RSDP: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_RSDT: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_XSDT: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_FACP: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_FACS: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_DSDT: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_SSDT: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_PSDT: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_APIC: chipsec.hal.acpi_tables.ACPI_TABLE_APIC,
  ACPI_TABLE_SIG_SBST: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_ECDT: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_SRAT: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_SLIC: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_SLIT: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_BOOT: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_CPEP: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_DBGP: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_ETDT: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_HPET: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_MCFG: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_SPCR: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_SPMI: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_TCPA: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_WDAT: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_WDRT: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_WSPT: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_WDDT: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_ASF : ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_MSEG: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_DMAR: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_UEFI: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_FPDT: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_PCCT: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_MSDM: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_BATB: ACPI_TABLE_NULL,
  ACPI_TABLE_SIG_BGRT: ACPI_TABLE_NULL
}

RSDP_GUID_ACPI2_0 = '8868E871-E4F1-11D3-BC22-0080C73C8881'
RSDP_GUID_ACPI1_0 = 'EB9D2D31-2D88-11D3-9A16-0090273FC14D'


ACPI_RSDP_SIG = 'RSD PTR '
# RSDP Format
ACPI_RSDP_FORMAT = '=8sB6sBIIQB3s'
ACPI_RSDP_SIZE   = struct.calcsize(ACPI_RSDP_FORMAT)
assert( 36 == ACPI_RSDP_SIZE )

class ACPI_RSDP( namedtuple('ACPI_RSDP', 'Signature Checksum OEMID Revision RsdtAddress Length XsdtAddress ExtChecksum Reserved') ):
    __slots__ = ()
    def __str__(self):
        return """==================================================================
  Root System Description Pointer (RSDP)
==================================================================
  Signature        : %s
  Checksum         : 0x%02X
  OEM ID           : %s
  Revision         : 0x%02X
  RSDT Address     : 0x%08X
  Length           : 0x%08X
  XSDT Address     : 0x%016X
  Extended Checksum: 0x%02X
  Reserved         : %s
""" % ( self.Signature, self.Checksum, self.OEMID, self.Revision, self.RsdtAddress, self.Length, self.XsdtAddress, self.ExtChecksum, chipsec.hal.acpi_tables.HEX_STRING(self.Reserved) )


class ACPI_SDT():
    def __init__( self, is_xsdt, acpi_entries ):
        self.is_xsdt = is_xsdt
        self.Entries = acpi_entries
    def __str__(self):
        _str = '------------------------------------------------------------------\n'
        _str += '  Extended System Description Table (XSDT)\n' if self.is_xsdt else '  Root System Description Table (RSDT)\n'
        _str += '------------------------------------------------------------------\n'
        _str += ( 'ACPI Table Entries:\n%s' % (''.join( ['0x%016X\n' % addr for addr in self.Entries])) )
        return _str


# some sanity checking on RSDP
def is_RSDP_valid( rsdp ):
    return (0 != rsdp.Checksum and (0x0 == rsdp.Revision or 0x2 == rsdp.Revision) )


########################################################################################################
#
# ACPI HAL Component
#
########################################################################################################

class ACPI:
    def __init__( self, cs ):
        self.cs     = cs
        self.uefi   = chipsec.hal.uefi.UEFI( self.cs )
        self.tableList = {}
        self.get_ACPI_table_list()
 
    #
    # Searches for Root System Description Pointer (RSDP) in various locations for legacy/EFI systems
    #
    def find_RSDP( self ):
        rsdp_pa  = None
        rsdp     = None
        rsdp_buf = None
        #
        # Check RSDP in Extended BIOS Data Area first
        #
        if logger().HAL: logger().log( "[acpi] searching RSDP in EBDA address 0x4E0.." )
        rsdptr_ebda = 0x40E
        sig = self.cs.mem.read_physical_mem( rsdptr_ebda, 8 )
        if ACPI_RSDP_SIG == sig:
            rsdp_pa  = rsdptr_ebda
            rsdp_buf = self.cs.mem.read_physical_mem( rsdp_pa, ACPI_RSDP_SIZE )
            rsdp     = ACPI_RSDP( *struct.unpack_from( ACPI_RSDP_FORMAT, rsdp_buf ) )
            if is_RSDP_valid( rsdp ): logger().log( "[acpi] found RSDP in EBDA at: 0x%016X" % rsdp_pa )
            else: rsdp_pa = None
        else:
            #
            # Search RSDP in the first 1kB of physical memory (legacy DoS area)
            #
            if logger().HAL: logger().log( "[acpi] searching RSDP in the first 1kB.." )
            membuf = self.cs.mem.read_physical_mem( 0x0, 0x400 )
            pos = membuf.find( ACPI_RSDP_SIG )
            if -1 != pos:
                rsdp_pa  = pos
                rsdp_buf = self.cs.mem.read_physical_mem( rsdp_pa, ACPI_RSDP_SIZE )
                rsdp     = ACPI_RSDP( *struct.unpack_from( ACPI_RSDP_FORMAT, rsdp_buf ) )
                if is_RSDP_valid( rsdp ): logger().log( "[acpi] found RSDP in the first 1kB: 0x%016X" % rsdp_pa )
                else: rsdp_pa = None
            else:
                #
                # Search RSDP in legacy BIOS E/F segments (0xE0000 - 0xFFFFF)
                #
                membuf = self.cs.mem.read_physical_mem( 0xE0000, 0x20000 )
                pos = membuf.find( ACPI_RSDP_SIG )
                if -1 != pos:
                    rsdp_pa  = pos
                    rsdp_buf = self.cs.mem.read_physical_mem( rsdp_pa, ACPI_RSDP_SIZE )
                    rsdp     = ACPI_RSDP( *struct.unpack_from( ACPI_RSDP_FORMAT, rsdp_buf ) )
                    if is_RSDP_valid( rsdp ): logger().log( "[acpi] found RSDP in BIOS E/F segments: 0x%016X" % rsdp_pa )
                    else: rsdp_pa = None
                else:
                    #
                    # Search for RSDP in the EFI memory (EFI Configuration Table)
                    #
                    if logger().HAL: logger().log( '[acpi] searching RSDP pointers in EFI Configuration Table..' )
                    (isFound,ect_pa,ect,ect_buf) = self.uefi.find_EFI_Configuration_Table()
                    if isFound:
                        if RSDP_GUID_ACPI2_0 in ect.VendorTables: 
                            rsdp_pa = ect.VendorTables[ RSDP_GUID_ACPI2_0 ]
                            logger().log( '[acpi] ACPI 2.0+ RSDP {%s} in EFI Config Table: 0x%016X' % (RSDP_GUID_ACPI2_0,rsdp_pa) )
                        elif RSDP_GUID_ACPI1_0 in ect.VendorTables: 
                            rsdp_pa = ect.VendorTables[ RSDP_GUID_ACPI1_0 ]
                            logger().log( '[acpi] ACPI 1.0 RSDP {%s} in EFI Config Table: 0x%016X' % (RSDP_GUID_ACPI1_0,rsdp_pa) )

                        rsdp_buf = self.cs.mem.read_physical_mem( rsdp_pa, ACPI_RSDP_SIZE )
                        rsdp     = ACPI_RSDP( *struct.unpack_from( ACPI_RSDP_FORMAT, rsdp_buf ) )
                        if is_RSDP_valid( rsdp ): logger().log( "[acpi] found RSDP in EFI Config Table: 0x%016X" % rsdp_pa )
                        else: rsdp_pa = None

        if rsdp_pa is not None and rsdp is not None:
            logger().log( rsdp ) 
            return (rsdp_pa,rsdp)

        if logger().HAL: logger().log( "[acpi] searching all EFI memory for RSDP (this may take a minute).." )
        CHUNK_SZ = 1024*1024 # 1MB
        pa = self.uefi.get_SMRAM_base() - CHUNK_SZ
        while pa > CHUNK_SZ:
            membuf = self.cs.mem.read_physical_mem( pa, CHUNK_SZ )
            pos = membuf.find( ACPI_RSDP_SIG )
            if -1 != pos:
                rsdp_pa  = pa + pos
                if logger().VERBOSE: logger().log( "[acpi] found '%s' signature at 0x%016X. Checking if valid RSDP.." % (ACPI_RSDP_SIG,rsdp_pa) )
                rsdp_buf = self.cs.mem.read_physical_mem( rsdp_pa, ACPI_RSDP_SIZE )
                rsdp     = ACPI_RSDP( *struct.unpack_from( ACPI_RSDP_FORMAT, rsdp_buf ) )
                if is_RSDP_valid( rsdp ):
                    logger().log( "[acpi] found RSDP in EFI memory: 0x%016X" % rsdp_pa )
                    break
            pa -= CHUNK_SZ

        if rsdp_pa is not None: logger().log( rsdp ) 
        return (rsdp_pa,rsdp)        


    def _parse_RSDT( self, sdt_content ):
        num_of_tables = len(sdt_content) / 4
        acpi_entries = struct.unpack( ('=%dI' % num_of_tables), sdt_content )
        return ACPI_SDT(False, acpi_entries)

    def _parse_XSDT( self, sdt_content ):
        num_of_tables = len(sdt_content) / 8
        acpi_entries = struct.unpack( ('=%dQ' % num_of_tables), sdt_content )
        return ACPI_SDT(True, acpi_entries)


    #
    # Retrieves System Description Table (RSDT or XSDT) either from RSDP or using OS API
    #
    def get_SDT( self, search_rsdp=True ):
        if search_rsdp:
            (rsdp_pa,rsdp) = self.find_RSDP()
            if 0x0 == rsdp.Revision:
                sdt_pa = rsdp.RsdtAddress
                is_xsdt = False
            elif 0x2 == rsdp.Revision:
                sdt_pa = rsdp.XsdtAddress
                is_xsdt = True
            else:
                return (False,None,None,None)
            logger().log( "[acpi] found %s at PA: 0x%016X" % ('XSDT' if is_xsdt else 'SSDT', sdt_pa) )
            sdt_header_buf = self.cs.mem.read_physical_mem( sdt_pa, ACPI_TABLE_HEADER_SIZE )
            sdt_header     = self._parse_table_header( sdt_header_buf )
            sdt_buf        = self.cs.mem.read_physical_mem( sdt_pa, sdt_header.Length )
        else:
            logger().log( "[acpi] reading RSDT/XSDT using OS API.." )
            (sdt_buf, is_xsdt) = self.cs.helper.get_ACPI_SDT()
            sdt_header = self._parse_table_header( sdt_buf[ :ACPI_TABLE_HEADER_SIZE] )

        sdt_contents = sdt_buf[ ACPI_TABLE_HEADER_SIZE : ]
        if is_xsdt: sdt = self._parse_XSDT( sdt_contents )
        else:       sdt = self._parse_RSDT( sdt_contents ) 
        return (is_xsdt,sdt_pa,sdt,sdt_header)


    #
    # Populates a list of ACPI tables available on the system
    #
    def get_ACPI_table_list( self ):
        addresses = []
        # find RSDT/XSDT table
        (is_xsdt,sdt_pa,sdt,sdt_header) = self.get_SDT()

        # cache RSDT/XSDT in the list of ACPI tables
        if sdt_pa is not None: self.tableList[ sdt_header.Signature ] = sdt_pa

        # cache other ACPI tables in the list
        for a in sdt.Entries:
            _sig = self.cs.mem.read_physical_mem( a, ACPI_TABLE_SIG_SIZE )
            if _sig not in ACPI_TABLES.keys():
                logger().warn( 'Unknown ACPI table signature: %s' % _sig )
            self.tableList[ _sig ] = a

        return self.tableList

    #
    # Checks is ACPI table with <name> is available on the system
    #
    def is_ACPI_table_present( self, name ):
        return (name in self.tableList)

    #
    # Prints a list of ACPI tables available on the system
    #
    def print_ACPI_table_list(self):
        if len( self.tableList ) == 0:
            logger().error("Couldn't get list of ACPI tables")
        else:
            if logger().HAL: logger().log( "[acpi] Found the following ACPI tables:" )
            for tableName in self.tableList.keys():
                logger().log( " - %s: 0x%016X" % (tableName,self.tableList[tableName]) )

    #
    # Retrieves contents of ACPI table from memory or from file
    #
    def get_ACPI_table( self, name, isfile = False ):
        t_data = None
        if isfile == True:
            t_data = chipsec.file.read_file( name )
        else:
            t_size = self.cs.mem.read_physical_mem_dword( self.tableList[name] + 4 )
            t_data = self.cs.mem.read_physical_mem( self.tableList[name], t_size )

        if t_data is not None:
            return self._parse_table( name, t_data )
    #
    # Retrieves the content of the APIC signature in the acpi structures.
    #
    def get_table_content_APIC(self):
        name='APIC'
        t_size = self.cs.mem.read_physical_mem_dword( self.tableList[name] + 4 )
        t_data = self.cs.mem.read_physical_mem( self.tableList[name], t_size )
        return t_data[ ACPI_TABLE_HEADER_SIZE : ]

    #
    # Dumps contents of ACPI table
    #
    def dump_ACPI_table( self, name, isfile = False ):
        (table_header,table,table_header_blob,table_blob) = self.get_ACPI_table( name, isfile )
        logger().log( "==================================================================" )
        logger().log( "ACPI Table: %s" % name )
        logger().log( "==================================================================" )
        # print table header
        logger().log( table_header )
        print_buffer( table_header_blob )
        # print table contents
        logger().log( '' )
        logger().log( table )
        print_buffer( table_blob )
        logger().log( '' )

    # --------------------------------------------------------------------
    # Internal ACPI table parsing functions
    # --------------------------------------------------------------------

    def _parse_table( self, name, t_data ):
        table_header_blob  = t_data[ : ACPI_TABLE_HEADER_SIZE ]
        table_blob         = t_data[ ACPI_TABLE_HEADER_SIZE : ]
        table_header       = self._parse_table_header( table_header_blob )
        table              = self._parse_table_contents( name, table_blob )
        return (table_header,table,table_header_blob,table_blob)


    def _parse_table_header( self, header ):
        acpi_table_hdr = ACPI_TABLE_HEADER( *struct.unpack_from( ACPI_TABLE_HEADER_FORMAT, header ) )
        if logger().VERBOSE: logger().log( acpi_table_hdr ) 
        return acpi_table_hdr


    def _parse_table_contents( self, signature, contents ):
        table = None
        if   ACPI_TABLE_SIG_RSDT == signature: table = self._parse_RSDT( contents )
        elif ACPI_TABLE_SIG_XSDT == signature: table = self._parse_XSDT( contents )
        elif ACPI_TABLE_SIG_APIC == signature: table = chipsec.hal.acpi_tables._parse_ACPI_table_APIC( contents )
        elif ACPI_TABLE_SIG_DMAR == signature: table = chipsec.hal.acpi_tables._parse_ACPI_table_DMAR( contents )
        return table
        