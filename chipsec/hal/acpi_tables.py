#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2018, Intel Corporation
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
# Authors:
#  Sarah Van Sickle, INTEL DCG RED team
#




# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
# (c) 2010-2012 Intel Corporation
#
# -------------------------------------------------------------------------------

"""
HAL component decoding various ACPI tables
"""

__version__ = '0.1'

import struct
from collections import namedtuple

from chipsec.logger import *

class ACPI_TABLE():
    def parse( self, table_content ):
        return
    def __str__( self ):
        return """------------------------------------------------------------------
  Table Content
------------------------------------------------------------------
"""

########################################################################################################
#
# DMAR Table
#
########################################################################################################

ACPI_TABLE_FORMAT_DMAR = '=BB10s'
ACPI_TABLE_SIZE_DMAR   = struct.calcsize(ACPI_TABLE_FORMAT_DMAR)
#class ACPI_TABLE_DMAR( namedtuple('ACPI_TABLE_DMAR', 'HostAddrWidth Flags Reserved dmar_structures') ):
class DMAR (ACPI_TABLE):
    def __init__(self):
        self.dmar_structures=[]
        self.DMAR_TABLE_FORMAT={
          'DeviceScope_FORMAT': '=BBHBB',
          'DRHD_FORMAT'       : '=HHBBHQ',
          'RMRR_FORMAT'       : '=HHHHQQ',
          'ATSR_FORMAT'       : '=HHBBH',
          'RHSA_FORMAT'       : '=HHIQI',
          'ANDD_FORMAT'       : 'HH3sB'
        }

    def parse(self , table_content):
        off = ACPI_TABLE_SIZE_DMAR
        struct_fmt = '=HH'
        while off < len(table_content) - 1:
            (_type,length) = struct.unpack( struct_fmt, table_content[ off : off + struct.calcsize(struct_fmt) ] )
            if 0 == length: break
            self.dmar_structures.append( self._get_structure_DMAR( _type, table_content[ off : off + length ] ) )
            off += length
        (self.HostAddrWidth, self.Flags, self.Reserved) = struct.unpack_from( ACPI_TABLE_FORMAT_DMAR, table_content ) 
        return

    def __str__(self):
        _str = """------------------------------------------------------------------
  DMAR Table Contents
------------------------------------------------------------------
  Host Address Width  : %d
  Flags               : 0x%02X
  Reserved            : %s
""" % ( self.HostAddrWidth, self.Flags, ''.join('%02x ' % ord(c) for c in self.Reserved) )
        _str += "\n  Remapping Structures:\n"
        for st in self.dmar_structures: _str += str(st)
        return _str
    
    def _get_structure_DMAR(self, _type, DataStructure ):
        if   0x00 == _type: return self._get_DMAR_structure_DRHD( DataStructure )
        elif 0x01 == _type: return self._get_DMAR_structure_RMRR( DataStructure )
        elif 0x02 == _type: return self._get_DMAR_structure_ATSR( DataStructure )
        elif 0x03 == _type: return self._get_DMAR_structure_RHSA( DataStructure )
        elif 0x04 == _type: return self._get_DMAR_structure_ANDD( DataStructure )
        else:               return ("\n  Unknown DMAR structure 0x%02X\n" % _type)

    def _get_DMAR_structure_DRHD(self, structure ):  
        device_scope = []
        fmt          = '=BB'
        step         = struct.calcsize(fmt)
        off          = struct.calcsize(self.DMAR_TABLE_FORMAT["DRHD_FORMAT"])
        while off < len(structure) - 1:
            (_type,length) = struct.unpack( fmt, structure[off:off+step] )
            if 0 == length: break
            path_sz = length - struct.calcsize(self.DMAR_TABLE_FORMAT["DeviceScope_FORMAT"])
            f = self.DMAR_TABLE_FORMAT["DeviceScope_FORMAT"] + ('%ds' % path_sz)
            device_scope.append( ACPI_TABLE_DMAR_DeviceScope( *struct.unpack_from(f,structure[off:off+length]) ) )
            off += length
        return ACPI_TABLE_DMAR_DRHD( *struct.unpack_from( self.DMAR_TABLE_FORMAT["DRHD_FORMAT"], structure ), DeviceScope=device_scope )

    def _get_DMAR_structure_RMRR(self, structure ):  
        device_scope = []
        fmt          = '=HH'
        step         = struct.calcsize(fmt)
        off          = struct.calcsize(self.DMAR_TABLE_FORMAT["RMRR_FORMAT"])
        while off < len(structure) - 1:
            (_type,length) = struct.unpack( fmt, structure[off:off+step] )
            if 0 == length: break
            path_sz = length - struct.calcsize(self.DMAR_TABLE_FORMAT["DeviceScope_FORMAT"])
            f = self.DMAR_TABLE_FORMAT["DeviceScope_FORMAT"] + ('%ds' % path_sz)
            device_scope.append( ACPI_TABLE_DMAR_DeviceScope( *struct.unpack_from(f,structure[off:off+length]) ) )
            off += length
        return ACPI_TABLE_DMAR_RMRR( *struct.unpack_from(self.DMAR_TABLE_FORMAT["RMRR_FORMAT"], structure ), DeviceScope=device_scope )

    def _get_DMAR_structure_ATSR(self, structure ):  
        device_scope = []
        fmt          = '=HH'
        step         = struct.calcsize(fmt)
        off          = struct.calcsize(self.DMAR_TABLE_FORMAT["ATSR_FORMAT"])
        while off < len(structure) - 1:
            (_type,length) = struct.unpack( fmt, structure[off:off+step] )
            if 0 == length: break
            path_sz = length - struct.calcsize(self.DMAR_TABLE_FORMAT["DeviceScope_FORMAT"])
            f = self.DMAR_TABLE_FORMAT["DeviceScope_FORMAT"] + ('%ds' % path_sz)
            device_scope.append( ACPI_TABLE_DMAR_DeviceScope( *struct.unpack_from(f,structure[off:off+length]) ) )
            off += length
        return ACPI_TABLE_DMAR_ATSR( *struct.unpack_from( self.DMAR_TABLE_FORMAT["ATSR_FORMAT"], structure ), DeviceScope=device_scope )
    
    def _get_DMAR_structure_RHSA(self, structure ):  
        return ACPI_TABLE_DMAR_RHSA( *struct.unpack_from( self.DMAR_TABLE_FORMAT["RHSA_FORMAT"], structure ) )
    
    def _get_DMAR_structure_ANDD(self, structure ):  
        sz = struct.calcsize('=H')
        length = struct.unpack( '=H', structure[sz:sz+sz] )[0]
        f = self.DMAR_TABLE_FORMAT["ANDD_FORMAT"] + ('%ds' % (length - struct.calcsize(self.DMAR_TABLE_FORMAT["ANDD_FORMAT"])))
        return ACPI_TABLE_DMAR_ANDD( *struct.unpack_from( f, structure ) )

#
# DMAR Device Scope
#

DMAR_DS_TYPE_PCI_ENDPOINT     = 0x1
DMAR_DS_TYPE_PCIPCI_BRIDGE    = 0x2
DMAR_DS_TYPE_IOAPIC           = 0x3
DMAR_DS_TYPE_MSI_CAPABLE_HPET = 0x4
DMAR_DS_TYPE_ACPI_NAMESPACE   = 0x5
DMAR_DS_TYPE ={
  DMAR_DS_TYPE_PCI_ENDPOINT     : 'PCI Endpoint Device',
  DMAR_DS_TYPE_PCIPCI_BRIDGE    : 'PCI-PCI Bridge',
  DMAR_DS_TYPE_IOAPIC           : 'I/O APIC Device',
  DMAR_DS_TYPE_MSI_CAPABLE_HPET : 'MSI Capable HPET',
  DMAR_DS_TYPE_ACPI_NAMESPACE   : 'ACPI Namaspace Device'
}

class ACPI_TABLE_DMAR_DeviceScope( namedtuple('ACPI_TABLE_DMAR_DeviceScope', 'Type Length Reserved EnumerationID StartBusNum Path') ):
    __slots__ = ()
    def __str__(self):
        return """      %s (%02X): Len: 0x%02X, Rsvd: 0x%04X, Enum ID: 0x%02X, Start Bus#: 0x%02X, Path: %s
""" % ( DMAR_DS_TYPE[self.Type], self.Type, self.Length, self.Reserved, self.EnumerationID, self.StartBusNum, ''.join('%02x ' % ord(c) for c in self.Path) )

#
# DMAR DMA Remapping Hardware Unit Definition (DRHD) Structure
#
class ACPI_TABLE_DMAR_DRHD( namedtuple('ACPI_TABLE_DMAR_DRHD', 'Type Length Flags Reserved SegmentNumber RegisterBaseAddr DeviceScope') ):
    __slots__ = ()
    def __str__(self):
        _str = """
  DMA Remapping Hardware Unit Definition (0x%04X):
    Length                : 0x%04X
    Flags                 : 0x%02X
    Reserved              : 0x%02X
    Segment Number        : 0x%04X
    Register Base Address : 0x%016X
""" % ( self.Type, self.Length, self.Flags, self.Reserved, self.SegmentNumber, self.RegisterBaseAddr )
        _str += '    Device Scope          :\n'
        for ds in self.DeviceScope: _str += str(ds)
        return _str

#
# DMAR Reserved Memory Range Reporting (RMRR) Structure
#
class ACPI_TABLE_DMAR_RMRR( namedtuple('ACPI_TABLE_DMAR_RMRR', 'Type Length Reserved SegmentNumber RMRBaseAddr RMRLimitAddr DeviceScope') ):
    __slots__ = ()
    def __str__(self):
        _str = """
  Reserved Memory Range (0x%04X):
    Length                : 0x%04X
    Reserved              : 0x%04X
    Segment Number        : 0x%04X
    Reserved Memory Base  : 0x%016X
    Reserved Memory Limit : 0x%016X
""" % ( self.Type, self.Length, self.Reserved, self.SegmentNumber, self.RMRBaseAddr, self.RMRLimitAddr )
        _str += '    Device Scope          :\n'
        for ds in self.DeviceScope: _str += str(ds)
        return _str
#
# DMAR Root Port ATS Capability Reporting (ATSR) Structure
#

class ACPI_TABLE_DMAR_ATSR( namedtuple('ACPI_TABLE_DMAR_ATSR', 'Type Length Flags Reserved SegmentNumber DeviceScope') ):
    __slots__ = ()
    def __str__(self):
        _str = """
  Root Port ATS Capability (0x%04X):
    Length                : 0x%04X
    Flags                 : 0x%02X
    Reserved (0)          : 0x%02X
    Segment Number        : 0x%04X
""" % ( self.Type, self.Length, self.Flags, self.Reserved, self.SegmentNumber )
        _str += '    Device Scope          :\n'
        for ds in self.DeviceScope: _str += str(ds)
        return _str

#
# DMAR Remapping Hardware Status Affinity (RHSA) Structure
#
class ACPI_TABLE_DMAR_RHSA( namedtuple('ACPI_TABLE_DMAR_RHSA', 'Type Length Reserved RegisterBaseAddr ProximityDomain') ):
    __slots__ = ()
    def __str__(self):
        return """
  Remapping Hardware Status Affinity (0x%04X):
    Length                : 0x%04X
    Reserved (0)          : 0x%08X
    Register Base Address : 0x%016X
    Proximity Domain      : 0x%08X
""" % ( self.Type, self.Length, self.Reserved, self.RegisterBaseAddr, self.ProximityDomain )
#
# DMAR ACPI Name-space Device Declaration (ANDD) Structure
#
ACPI_TABLE_DMAR_ANDD_FORMAT = '=HH3sB'
ACPI_TABLE_DMAR_ANDD_SIZE   = struct.calcsize(ACPI_TABLE_DMAR_ANDD_FORMAT)
assert(8 == ACPI_TABLE_DMAR_ANDD_SIZE)
class ACPI_TABLE_DMAR_ANDD( namedtuple('ACPI_TABLE_DMAR_ANDD', 'Type Length Reserved ACPIDevNum ACPIObjectName') ):
    __slots__ = ()
    def __str__(self):
        return """
  Remapping Hardware Status Affinity (0x%04X):
    Length                : 0x%04X
    Reserved (0)          : %s
    ACPI Device Number    : 0x%02X
    ACPI Object Name      : %s
""" % ( self.Type, self.Length, ''.join('%02x ' % ord(c) for c in self.Reserved), self.ACPIDevNum, self.ACPIObjectName )

########################################################################################################
#
# APIC Table
#
########################################################################################################

ACPI_TABLE_FORMAT_APIC = '=II'
ACPI_TABLE_SIZE_APIC   = struct.calcsize(ACPI_TABLE_FORMAT_APIC)
#class ACPI_TABLE_APIC( namedtuple('ACPI_TABLE_APIC', 'LAPICBase Flags apic_structures') ):
class APIC (ACPI_TABLE):
    def __init__(self):
        self.apic_structs = []
        self.ACPI_TABLE_FORMAT={}
        
        # APIC Table Structures
        self.APIC_TABLE_FORMAT={
          "PROCESSOR_LAPIC"            : '<BBBBI',
          "IOAPIC"                     : '<BBBBII',
          "INTERRUPT_SOURSE_OVERRIDE"  : '<BBBBIH', 
          "NMI_SOURCE"                 : '<BBHI',
          "LAPIC_NMI"                  : '<BBBHB',
          "LAPIC_ADDRESS_OVERRIDE"     : '<BBHQ',
          "IOSAPIC"                    : '<BBBBIQ',
          "PROCESSOR_LSAPIC"           : '<BBBBBHII',
          "PLATFORM_INTERRUPT_SOURCES" : '<BBHBBBII',
          "PROCESSOR_Lx2APIC"          : '<BBHIII',
          "Lx2APIC_NMI"                : '<BBHIB3s',
          "GICC_CPU"                   : '<BBHIIIIIQQQQIQQ',
          "GIC_DISTRIBUTOR"            : '<BBHIQII',
          "GIC_MSI"                    : '<BBHIQIHH',
          "GIC_REDISTRIBUTOR"          : '<BBHQI'
        }
    
    def parse(self , table_content):
        (self.LAPICBase,self.Flags) = struct.unpack( '=II', table_content[ 0 : 8 ] )
        cont = 8
        while cont < len(table_content) - 1:
            (value,length) = struct.unpack( '=BB', table_content[ cont : cont + 2 ] )
            if 0 == length: break
            self.apic_structs.append( self.get_structure_APIC( value, table_content[ cont : cont + length ] ) )
            cont += length
        return

    def __str__(self):
        apic_str = """------------------------------------------------------------------
  APIC Table Contents
------------------------------------------------------------------
  Local APIC Base  : 0x%016X
  Flags            : 0x%08X
""" % ( self.LAPICBase, self.Flags )
        apic_str += "\n  Interrupt Controller Structures:\n"
        for st in self.apic_structs: apic_str += str(st)
        return apic_str
    
    def get_structure_APIC(self, value, DataStructure ):
        if   0x00 == value: return ACPI_TABLE_APIC_PROCESSOR_LAPIC( *struct.unpack_from( self.APIC_TABLE_FORMAT["PROCESSOR_LAPIC"], DataStructure ))
        elif 0x01 == value: return ACPI_TABLE_APIC_IOAPIC( *struct.unpack_from( self.APIC_TABLE_FORMAT["IOAPIC"], DataStructure ))
        elif 0x02 == value: return ACPI_TABLE_APIC_INTERRUPT_SOURSE_OVERRIDE( *struct.unpack_from( self.APIC_TABLE_FORMAT["INTERRUPT_SOURSE_OVERRIDE"], DataStructure ))
        elif 0x03 == value: return ACPI_TABLE_APIC_NMI_SOURCE( *struct.unpack_from( self.APIC_TABLE_FORMAT["NMI_SOURCE"], DataStructure ))
        elif 0x04 == value: return ACPI_TABLE_APIC_LAPIC_NMI( *struct.unpack_from( self.APIC_TABLE_FORMAT["LAPIC_NMI"], DataStructure ))
        elif 0x05 == value: return ACPI_TABLE_APIC_LAPIC_ADDRESS_OVERRIDE( *struct.unpack_from( self.APIC_TABLE_FORMAT["LAPIC_ADDRESS_OVERRIDE"], DataStructure ))
        elif 0x06 == value: return ACPI_TABLE_APIC_IOSAPIC( *struct.unpack_from( self.APIC_TABLE_FORMAT["IOSAPIC"], DataStructure ))
        elif 0x07 == value: return ACPI_TABLE_APIC_PROCESSOR_LSAPIC( *struct.unpack_from( "%s%ss"%( self.APIC_TABLE_FORMAT["PROCESSOR_LSAPIC"],str(len(DataStructure)-16)), DataStructure ))
        elif 0x08 == value: return ACPI_TABLE_APIC_PLATFORM_INTERRUPT_SOURCES( *struct.unpack_from( self.APIC_TABLE_FORMAT["PLATFORM_INTERRUPT_SOURCES"], DataStructure ))
        elif 0x09 == value: return ACPI_TABLE_APIC_PROCESSOR_Lx2APIC( *struct.unpack_from( self.APIC_TABLE_FORMAT["PROCESSOR_Lx2APIC"], DataStructure ))
        elif 0x0A == value: return ACPI_TABLE_APIC_Lx2APIC_NMI( *struct.unpack_from( self.APIC_TABLE_FORMAT["Lx2APIC_NMI"], DataStructure ))
        elif 0x0B == value: return ACPI_TABLE_APIC_GICC_CPU( *struct.unpack_from( self.APIC_TABLE_FORMAT["GICC_CPU"], DataStructure ))
        elif 0x0C == value: return ACPI_TABLE_APIC_GIC_DISTRIBUTOR( *struct.unpack_from( self.APIC_TABLE_FORMAT["GIC_DISTRIBUTOR"], DataStructure ))
        elif 0x0D == value: return ACPI_TABLE_APIC_GIC_MSI( *struct.unpack_from( self.APIC_TABLE_FORMAT["GIC_MSI"], DataStructure ))
        elif 0x0E == value: return ACPI_TABLE_APIC_GIC_REDISTRIBUTOR( *struct.unpack_from( self.APIC_TABLE_FORMAT["GIC_REDISTRIBUTOR"], DataStructure ))
        else:
            DataStructure = ''.join(x.encode('hex') for x in DataStructure)
            return """
Reserved ....................................%s"
     %s"
""" % (value, DataStructure)

class ACPI_TABLE_APIC_PROCESSOR_LAPIC(namedtuple('ACPI_TABLE_APIC_PROCESSOR_LAPIC', 'Type Length ACPIProcID APICID Flags')):
    __slots__ = ()
    def __str__(self):
        return """
  Processor Local APIC (0x00)
    Type         : 0x%02X
    Length       : 0x%02X
    ACPI Proc ID : 0x%02X
    APIC ID      : 0x%02X
    Flags        : 0x%02X
"""%( self.Type, self.Length, self.ACPIProcID, self.APICID, self.Flags )

class ACPI_TABLE_APIC_IOAPIC(namedtuple('ACPI_TABLE_APIC_IOAPIC', 'Type Length IOAPICID Reserved IOAPICAddr GlobalSysIntBase')):
    __slots__ = ()
    def __str__(self):
        return """
  I/O APIC (0x01)
    Type                : 0x%02X
    Length              : 0x%02X
    Reserved            : 0x%02X 
    I/O APIC ID         : 0x%02X
    I/O APIC Base       : 0x%02X
    Global Sys Int Base : 0x%02X
"""%( self.Type, self.Length, self.IOAPICID, self.Reserved, self.IOAPICAddr, self.GlobalSysIntBase )
     
class ACPI_TABLE_APIC_INTERRUPT_SOURSE_OVERRIDE(namedtuple('ACPI_TABLE_APIC_INTERRUPT_SOURSE_OVERRIDE', 'Type Length Bus Source GlobalSysIntBase Flags')):
    __slots__ = ()
    def __str__(self):
        return """
  Interrupt Source Override (0x02)
    Type                : 0x%02X
    Length              : 0x%02X
    Bus                 : 0x%02X
    Source              : 0x%02X
    Global Sys Int Base : 0x%02X
    Flags               : 0x%02X
"""%( self.Type, self.Length, self.Bus, self.Source, self.GlobalSysIntBase, self.Flags )

class ACPI_TABLE_APIC_NMI_SOURCE(namedtuple('ACPI_TABLE_APIC_NMI_SOURCE', 'Type Length Flags GlobalSysIntBase')):
    __slots__ = ()
    def __str__(self):
        return """
  Non-maskable Interrupt (NMI) Source (0x03)
    Type                : 0x%02X
    Length              : 0x%02X
    Flags               : 0x%02X
    Global Sys Int Base : 0x%02X
"""%( self.Type, self.Length, self.Flags, self.GlobalSysIntBase )

class ACPI_TABLE_APIC_LAPIC_NMI(namedtuple('ACPI_TABLE_APIC_LAPIC_NMI', 'Type Length ACPIProcessorID Flags LocalAPICLINT')):
    __slots__ = ()
    def __str__(self):
        return """
  Local APIC NMI (0x04)
    Type              : 0x%02X
    Length            : 0x%02X
    ACPI Processor ID : 0x%02X
    Flags             : 0x%02X
    Local APIC LINT   : 0x%02X
"""%( self.Type, self.Length, self.ACPIProcessorID, self.Flags, self.LocalAPICLINT )

class ACPI_TABLE_APIC_LAPIC_ADDRESS_OVERRIDE(namedtuple('ACPI_TABLE_APIC_LAPIC_ADDRESS_OVERRIDE', 'Type Length Reserved LocalAPICAddress')):
    __slots__ = ()
    def __str__(self):
        return """
  Local APIC Address Override (0x05)
    Type               : 0x%02X
    Length             : 0x%02X
    Reserved           : 0x%02X
    Local APIC Address : 0x%02X
"""%( self.Type, self.Length, self.Reserved, self.LocalAPICAddress )

class ACPI_TABLE_APIC_IOSAPIC(namedtuple('ACPI_TABLE_APIC_IOSAPIC', 'Type Length IOAPICID Reserved GlobalSysIntBase IOSAPICAddress')):
    __slots__ = ()
    def __str__(self):
        return """
  I/O SAPIC (0x06)
    Type                : 0x%02X
    Length              : 0x%02X
    IO APIC ID          : 0x%02X
    Reserved            : 0x%02X
    Global Sys Int Base : 0x%02X
    IO SAPIC Address    : 0x%02X
"""%( self.Type, self.Length, self.IOAPICID, self.Reserved, self.GlobalSysIntBase, self.IOSAPICAddress )

class ACPI_TABLE_APIC_PROCESSOR_LSAPIC(namedtuple('ACPI_TABLE_APIC_PROCESSOR_LSAPIC', 'Type Length ACPIProcID LocalSAPICID LocalSAPICEID Reserved Flags ACPIProcUIDValue ACPIProcUIDString'), ):
    __slots__ = ()
    def __str__(self):
        return """
  Local SAPIC (0x07)    
    Type                 : 0x%02X
    Length               : 0x%02X
    ACPI Proc ID         : 0x%02X
    Local SAPIC ID       : 0x%02X
    Local SAPIC EID      : 0x%02X
    Reserved             : 0x%02X
    Flags                : 0x%02X
    ACPI Proc UID Value  : 0x%02X
    ACPI Proc UID String : 0x%02X
"""%( self.Type, self.Length, self.ACPIProcID, self.LocalSAPICID, self.LocalSAPICEID, self.Reserved, self.Flags, self.ACPIProcUIDValue, self.ACPIProcUIDString )

class ACPI_TABLE_APIC_PLATFORM_INTERRUPT_SOURCES(namedtuple('ACPI_TABLE_APIC_PLATFORM_INTERRUPT_SOURCES', 'Type Length Flags InterruptType ProcID ProcEID IOSAPICVector GlobalSystemInterrupt PlatIntSourceFlags')):
    __slots__ = ()
    def __str__(self):
        return """
  Platform Interrupt Sources (0x08)
    Type                    : 0x%02X
    Length                  : 0x%02X
    Flags                   : 0x%02X
    Interrupt Type          : 0x%02X
    Proc ID                 : 0x%02X
    Proc EID                : 0x%02X
    I/O SAPIC Vector        : 0x%02X
    Global System Interrupt : 0x%02X
    Plat Int Source Flags   : 0x%02X
"""%( self.Type, self.Length, self.Flags, self.InterruptType, self.ProcID, self.ProcEID, self.IOSAPICVector, self.GlobalSystemInterrupt, self.PlatIntSourceFlags )

class ACPI_TABLE_APIC_PROCESSOR_Lx2APIC(namedtuple('ACPI_TABLE_APIC_PROCESSOR_Lx2APIC', 'Type Length Reserved x2APICID Flags ACPIProcUID')):
    __slots__ = ()
    def __str__(self):
        return """
  Processor Local x2APIC (0x09)
    Type          : 0x%02X
    Length        : 0x%02X
    Reserved      : 0x%02X
    x2APIC ID     : 0x%02X
    Flags         : 0x%02X
    ACPI Proc UID : 0x%02X
"""%( self.Type, self.Length, self.Reserved, self.x2APICID, self.Flags, self.ACPIProcUID )

class ACPI_TABLE_APIC_Lx2APIC_NMI(namedtuple('ACPI_TABLE_APIC_Lx2APIC_NMI', 'Type Length Flags ACPIProcUID Localx2APICLINT Reserved')):
    __slots__ = ()
    def __str__(self):
        return """
  Local x2APIC NMI (0x0A)
    Type              : 0x%02X
    Length            : 0x%02X
    Flags             : 0x%02X
    ACPI Proc UID     : 0x%02X
    Local x2APIC LINT : 0x%02X
    Reserved          : 0x%02X
"""%( self.Type, self.Length, self.Flags, self.ACPIProcUID, self.Localx2APICLINT, self.Reserved )

class ACPI_TABLE_APIC_GICC_CPU(namedtuple('ACPI_TABLE_APIC_GICC_CPU', 'Type Length Reserved CPUIntNumber ACPIProcUID Flags ParkingProtocolVersion PerformanceInterruptGSIV ParkedAddress PhysicalAddress GICV GICH VGICMaintenanceINterrupt GICRBaseAddress MPIDR')):
    __slots__ = ()
    def __str__(self):
        return """
  GICC CPU Interface Structure (0x0B)
    Type                       : 0x%02X
    Length                     : 0x%02X
    Reserved                   : 0x%02X
    CPU Int Number             : 0x%02X
    ACPI Proc UID              : 0x%02X
    Flags                      : 0x%02X
    Parking Protocol Version   : 0x%02X
    Performance Interrupt GSIV : 0x%02X
    Parked Address             : 0x%02X
    Physical Address           : 0x%02X
    GICV                       : 0x%02X
    GICH                       : 0x%02X
    VGIC Maintenance INterrupt : 0x%02X
    GICR Base Address          : 0x%02X
    MPIDR                      : 0x%02X
"""%( self.Type, self.Length, self.Reserved, self.CPUIntNumber, self.ACPIProcUID, self.Flags, self.ParkingProtocolVersion, self.PerformanceInterruptGSIV, self.ParkedAddress, self.PhysicalAddress, self.GICV, self.GICH, self.VGICMaintenanceINterrupt, self.GICRBaseAddress, self.MPIDR )

class ACPI_TABLE_APIC_GIC_DISTRIBUTOR(namedtuple('ACPI_TABLE_APIC_GIC_DISTRIBUTOR', 'Type Length Reserved GICID PhysicalBaseAddress SystemVectorBase Reserved2 ')):
    __slots__ = ()
    def __str__(self):
        return """
  GICD GIC Distributor Structure (0x0C)
    Type                  : 0x%02X
    Length                : 0x%02X
    Reserved              : 0x%02X
    GICID                 : 0x%02X
    Physical Base Address : 0x%02X
    System Vector Base    : 0x%02X
    Reserved              : 0x%02X
"""%( self.Type, self.Length, self.Reserved, self.GICID, self.PhysicalBaseAddress, self.SystemVectorBase, self.Reserved2 )

class ACPI_TABLE_APIC_GIC_MSI(namedtuple('ACPI_TABLE_APIC_GIC_MSI', 'Type Length Reserved GICMSIFrameID PhysicalBaseAddress Flags SPICount SPIBase')):
    __slots__ = ()
    def __str__(self):
        return """
  GICv2m MSI Frame (0x0D)
    Type                  : 0x%02X
    Length                : 0x%02X
    Reserved              : 0x%02X
    GIC MSI Frame ID      : 0x%02X
    Physical Base Address : 0x%02X
    Flags                 : 0x%02X
    SPI Count             : 0x%02X
    SPI Base              : 0x%02X
"""%( self.Type, self.Length, self.Reserved, self.GICMSIFrameID, self.PhysicalBaseAddress, self.Flags, self.SPICount, self.SPIBase )

class ACPI_TABLE_APIC_GIC_REDISTRIBUTOR(namedtuple('ACPI_TABLE_APIC_GIC_REDISTRIBUTOR', 'Type Length Reserved DiscoverRangeBaseAdd DiscoverRangeLength')):
    __slots__ = ()
    def __str__(self):
        return """
  GICR Redistributor Structure (0x0E)
    Type                  : 0x%02X
    Length                : 0x%02X
    Reserved              : 0x%02X
    Discover Range Base   : 0x%02X
    Discover Range Length : 0x%02X
"""%( self.Type, self.Length, self.Reserved, self.DiscoverRangeBaseAdd, self.DiscoverRangeLength )

########################################################################################################
#
# XSDT Table
#
########################################################################################################

class XSDT (ACPI_TABLE):
    def __init__( self ):
        self.Entries = []

    def parse( self, table_content ):
        num_of_tables = len(table_content) / 8
        self.Entries= struct.unpack( ('=%dQ' % num_of_tables), table_content )
        return

    def __str__( self ):
        return """==================================================================
  Extended System Description Table (XSDT)
==================================================================
ACPI Table Entries:
%s
""" %(''.join( ['0x%016X\n' % addr for addr in self.Entries]))

########################################################################################################
#
# RSDT Table
#
########################################################################################################

class RSDT (ACPI_TABLE):
    def __init__( self ):
        self.Entries = []

    def parse( self, table_content ):
        num_of_tables = len(table_content) / 4
        self.Entries= struct.unpack( ('=%dI' % num_of_tables), table_content )
        return

    def __str__( self ):
        return """==================================================================
  Root System Description Table (RSDT)
==================================================================
ACPI Table Entries:
%s
""" %( ''.join( ['0x%016X\n' % addr for addr in self.Entries]))

########################################################################################################
#
# FADT Table
#
########################################################################################################

class FADT (ACPI_TABLE):
    def __init__( self ):
        self.dsdt = None
        self.x_dsdt = None

    def parse( self, table_content ):
        self.dsdt = struct.unpack('<I', table_content[4:8])[0]
        if len(table_content) >= 112:
            self.x_dsdt = struct.unpack('<Q', table_content[104:112])[0]
        else:
            if logger().HAL: logger().log( '[acpi] Cannot find X_DSDT entry in FADT.' )

    def get_DSDT_address_to_use( self ):
        dsdt_address_to_use = None
        if self.x_dsdt is None:
            if self.dsdt != 0:
                dsdt_address_to_use = self.dsdt
        else:
            if self.x_dsdt != 0 and self.dsdt == 0:
                dsdt_address_to_use = self.x_dsdt
            elif self.x_dsdt == 0 and self.dsdt != 0:
                dsdt_address_to_use = self.dsdt
            elif self.x_dsdt != 0 and self.x_dsdt == self.dsdt:
                dsdt_address_to_use = self.x_dsdt
        return dsdt_address_to_use

    def __str__( self ):
        return """------------------------------------------------------------------
  Fixed ACPI Description Table (FADT) Contents
------------------------------------------------------------------
  DSDT   : %s
  X_DSDT : %s
""" % ( ('0x%08X' % self.dsdt), ('0x%016X' % self.x_dsdt) if self.x_dsdt is not None else 'Not found')

########################################################################################################
#
# BGRT Table
#
########################################################################################################

class BGRT (ACPI_TABLE):
    def __init__( self ):
        return

    def parse(self, table_content):
        self.Version = struct.unpack('<H', table_content[0:2])[0]
        self.Status = struct.unpack('<b', table_content[2:3])[0]
	self.ImageType = struct.unpack('<b', table_content[3:4])[0]
        self.ImageAddress = struct.unpack('<Q', table_content[4:12])[0]
        self.ImageOffsetX = struct.unpack('<I', table_content[12:16])[0]
        self.ImageOffsetY = struct.unpack('<I', table_content[16:20])[0]
        if(self.Status is 0):
            self.OrientationOffset = '0 degrees'
        elif(self.Status is 1):
            self.OrientationOffset = '90 degrees'
        elif(self.Status is 2):
            self.OrientationOffset = '180 degrees'
        elif(self.Status is 3):
            self.OrientationOffset = '270 degrees'
        else:
            self.OrientationOffset = 'Reserved bits are used'
	if(self.ImageType is 0):
            self.ImageTypeStr = ' - Bitmap'
        else:
            self.ImageTypeStr = 'Reserved'

    def __str__(self):
        return """
------------------------------------------------------------------
  Version          	 			: %d
  Status           	 			: %d
   Clockwise Orientation Offset 	: %s
  Image Type        			: %d %s
  Image Address      			: %s
  Image Offset X     			: %s
  Image Offset Y     			: %s
""" % ( self.Version, self.Status, self.OrientationOffset, self.ImageType, self.ImageTypeStr,('0x%016X' % self.ImageAddress), ('0x%08X' % self.ImageOffsetX), ('0x%08X' % self.ImageOffsetY) )

########################################################################################################
#
# BERT Table
#
########################################################################################################

class BERT (ACPI_TABLE):
    def __init__( self, cs ):
        self.cs = cs
        #super(BERT, self).__init__(cs)
        return

    def parseSectionType(self, table_content):
        # Processor Generic: {0x9876CCAD, 0x47B4, 0x4bdb, {0xB6, 0x5E, 0x16, 0xF1, 0x93, 0xC4, 0xF3, 0xDB}}
        # Processor Specific: IA32/X64:{0xDC3EA0B0, 0xA144, 0x4797, {0xB9, 0x5B, 0x53, 0xFA, 0x24, 0x2B, 0x6E, 0x1D}}
        # Processor Specific: IPF: {0xe429faf1, 0x3cb7, 0x11d4, {0xb, 0xca, 0x7, 0x00, 0x80,0xc7, 0x3c, 0x88, 0x81}}
        # Processor Specific: ARM: { 0xE19E3D16, 0xBC11,0x11E4,{0x9C, 0xAA, 0xC2, 0x05,0x1D, 0x5D, 0x46, 0xB0}}
        # Platform Memory: {0xA5BC1114, 0x6F64, 0x4EDE, {0xB8, 0x63, 0x3E, 0x83, 0xED, 0x7C, 0x83, 0xB1}}
        # PCIe: {0xD995E954, 0xBBC1, 0x430F, {0xAD, 0x91, 0xB4, 0x4D, 0xCB,0x3C, 0x6F, 0x35}}
        # Firmware Error Record Reference: {0x81212A96, 0x09ED, 0x4996, {0x94, 0x71, 0x8D, 0x72, 0x9C,0x8E, 0x69, 0xED}}
        # PCI/PCI-X Bus: {0xC5753963, 0x3B84, 0x4095, {0xBF, 0x78, 0xED, 0xDA, 0xD3,0xF9, 0xC9, 0xDD}}
        # PCI Component/Device: {0xEB5E4685, 0xCA66, 0x4769, {0xB6, 0xA2, 0x26, 0x06, 0x8B,0x00, 0x13, 0x26}}
        # DMAr Generic: {0x5B51FEF7, 0xC79D, 0x4434, {0x8F, 0x1B, 0xAA, 0x62, 0xDE, 0x3E, 0x2C, 0x64}}
        # Intel VT for Directed I/O Specific DMAr Section:  {0x71761D37, 0x32B2, 0x45cd, {0xA7, 0xD0, 0xB0, 0xFE 0xDD, 0x93, 0xE8, 0xCF}}
        # IOMMU Specific DMAr Section: {0x036F84E1, 0x7F37, 0x428c, {0xA7, 0x9E, 0x57, 0x5F, 0xDF, 0xAA, 0x84, 0xEC}}
        val1 = struct.unpack('<L', table_content[0:4])[0]
        val2 = struct.unpack('<L', table_content[4:8])[0]
        val3 = struct.unpack('<L', table_content[8:12])[0]
        val4 = struct.unpack('<L', table_content[12:16])[0]
        results = '''%s %s %s %s - ''' % ( ('0x%08X' % val1), ('0x%08X' % val2), ('0x%08X' % val3), ('0x%08X' % val4) )
        """if val1 is 0x9876CCAD and val2 is 0x47B4 and val3 is 0x4bdb and val4 in [0xB6, 0x5E, 0x16, 0xF1, 0x93, 0xC4, 0xF3, 0xDB]:
            return results + '''Generic Processor'''
        elif val1 is 0xDC3EA0B0 and val2 is 0xA144 and val3 is 0x4797 and val4 in [0xB9, 0x5B, 0x53, 0xFA, 0x24, 0x2B, 0x6E, 0x1D]:
            return results + '''Processor Specific: IA32/X64'''
        elif val1 is 0xe429faf1 and val2 is 0x3cb7 and val3 is 0x11d4 and val4 in [0xb, 0xca, 0x7, 0x00, 0x80,0xc7, 0x3c, 0x88, 0x81]:
            return results + '''Processor Specific: IPF'''
        elif val1 is 0xE19E3D16 and val2 is 0xBC11 and val3 is 0x11E4 and val4 in [0x9C, 0xAA, 0xC2, 0x05,0x1D, 0x5D, 0x46, 0xB0]:
            return results + '''Processor Specific: ARM'''
        elif val1 is 0xA5BC1114 and val2 is x6F64 and val3 is 0x4EDE and val4 in [0xB8, 0x63, 0x3E, 0x83, 0xED, 0x7C, 0x83, 0xB1]:
            return results + '''Platform Memory'''
        elif val1 is 0xD995E954 and val2 is 0xBBC1 and val3 is 0x430F and val4 in [0xAD, 0x91, 0xB4, 0x4D, 0xCB,0x3C, 0x6F, 0x35]:
            return results + '''PCIe'''
        elif val1 is 0x81212A96 and val2 is 0x09ED and val3 is 0x4996 and val4 in [0x94, 0x71, 0x8D, 0x72, 0x9C, 0x8E, 0x69, 0xED]:
            return results + '''Firmware Error Record Reference'''
        elif val1 is 0xC5753963 and val2 is 0x3B84 and val3 is 0x4095 and val4 in [0xBF, 0x78, 0xED, 0xDA, 0xD3, 0xF9, 0xC9, 0xDD]:
            return results + '''PCI/PCI-X Bus'''
        elif val1 0xEB5E4685 is and val2 is 0xCA66 and val3 is 0x4769 and val4 in [0xB6, 0xA2, 0x26, 0x06, 0x8B, 0x00, 0x13, 0x26]:
            return results + '''PCI Component/Device'''
        elif val1 is 0x5B51FEF7 and val2 is 0xC79D and val3 is 0x4434 and val4 in [0x8F, 0x1B, 0xAA, 0x62, 0xDE, 0x3E, 0x2C, 0x64]:
            return results + '''DMAr Generic'''
        elif val1 is 0x71761D37 and val2 is 0x32B2 and val3 is 0x45cd and val4 in [0xA7, 0xD0, 0xB0, 0xFE, 0xDD, 0x93, 0xE8, 0xCF]:
            return results + '''Intel VT for Directed I/O Specific DMAr Section'''
        elif val1 is 0x036F84E1 and val2 is 0x7F37 and val3 is 0x428c and val4 in [0xA7, 0x9E, 0x57, 0x5F, 0xDF, 0xAA, 0x84, 0xEC]:
            return results + '''IOMMU Specific DMAr Section'''"""
        return results + '''Unknown'''

    def parseTime(self, table_content):
        seconds = struct.unpack('<B', table_content[0:1])[0]
        minutes = struct.unpack('<B', table_content[1:2])[0]
        hours = struct.unpack('<B', table_content[2:3])[0]
        percision = struct.unpack('<B', table_content[3:4])[0]
        day = struct.unpack('<B', table_content[4:5])[0]
        month = struct.unpack('<B', table_content[5:6])[0]
        year = struct.unpack('<B', table_content[6:7])[0]
        century = struct.unpack('<B', table_content[7:8])[0]
        precision_str = ''
        if percision > 0:
            precision_str = '(time is percise and correlates to time of event)'
        return ''' %d:%d:%d %d/%d/%d%d [m/d/y] %s''' % (hours, minutes, seconds, month, day, century, year, precision_str)

    def parseGenErrorEntries(self, table_content):
        errorSeverities = [ 'Recoverable', 'Fatal', 'Corrected', 'None', 'Unknown severity entry' ]
        sectionType = self.parseSectionType(table_content[0:16])
        errorSeverity = struct.unpack('<L', table_content[16:20])[0]
        revision = struct.unpack('<H', table_content[20:22])[0]
        validationBits = struct.unpack('<B', table_content[22:23])[0]
        flags = struct.unpack('<B', table_content[23:24])[0]
        errDataLen = struct.unpack('<L', table_content[24:28])[0]
        FRU_Id1 = struct.unpack('<L', table_content[28:32])[0]
        FRU_Id2 = struct.unpack('<L', table_content[32:36])[0]
        FRU_Id3 = struct.unpack('<L', table_content[36:40])[0]
        FRU_Id4 = struct.unpack('<L', table_content[40:44])[0]
        FRU_Text = struct.unpack('<20s', table_content[44:64])[0]
        timestamp = struct.unpack('<Q', table_content[64:72])[0]
        timestamp_str = self.parseTime(table_content[64:72])
        if errDataLen > 0:
            data = str(struct.unpack('<P', table_content[72:errDataLen + 72])[0])
        else:
            data = 'None'
        errorSeverity_str = errorSeverities[4]
        if errorSeverity < 4:
            errorSeverity_str = errorSeverities[errorSeverity]
        revision_str = ''
        if revision is not 3:
            revision_str = ' - Should be 0x003'
        FRU_Id_str = ''
        if FRU_Id1 is 0 and FRU_Id2 is 0 and FRU_Id3 is 0 and FRU_Id4 is 0:
            FRU_Id_str = ' - Default value, invalid FRU ID'
        return '''
      Section Type                                  : %s
      Error Severity                                : %s - %s
      Revision                                      : %s%s
      Validation Bits                               : %s
      Flags                                         : %s
        Primary                                     : %s
        Containment Warning                         : %s
        Reset                                       : %s
        Error Threshold Exceeded                    : %s
        Resource Not Accessible                     : %s
        Latent Error                                : %s
        Propagated                                  : %s
        Overflow                                    : %s
        Reserved                                    : %s
      Error Data Length                             : %s ( %d )
      FRU Id                                        : %s %s %s %s%s
      FRU Text                                      : %s
      Timestamp                                     : %d - %s
      Data                                          : %s''' % ( sectionType, errorSeverity, errorSeverity_str, ('0x%04X' % revision), revision_str, ('0x%02X' % validationBits), ('0x%02X' % flags), ('0x%02X' % (flags & 1)), ('0x%02X' % (flags & 2)), ('0x%02X' % (flags & 4)), ('0x%02X' % (flags & 8)), ('0x%02X' % (flags & 16)), ('0x%02X' % (flags & 32)), ('0x%02X' % (flags & 64)), ('0x%02X' % (flags & 128)), ('0x%02X' % (flags & 256)), ('0x%08X' % errDataLen), errDataLen, FRU_Id1, FRU_Id2, FRU_Id3, FRU_Id4, FRU_Id_str, FRU_Text, timestamp, timestamp_str, data )

    def parseErrorBlock(self, table_content):
        errorSeverities = [ 'Recoverable', 'Fatal', 'Corrected', 'None', 'Unknown severity entry' ]
        blockStatus = struct.unpack('<L', table_content[0:4])[0]
        rawDataOffset = struct.unpack('<L', table_content[4:8])[0]
        rawDataLen = struct.unpack('<L', table_content[8:12])[0]
        dataLen = struct.unpack('<L', table_content[12:16])[0]
        errorSeverity = struct.unpack('<L', table_content[16:20])[0]
        genErrorDataEntries = self.parseGenErrorEntries(table_content[20:])
        errorSeverity_str = errorSeverities[4]
        if errorSeverity < 4:
            errorSeverity_str = errorSeverities[errorSeverity]
        self.BootRegion = '''
Generic Error Status Block
    Block Status                                    : %s
      Correctable Error Valid                       : %s
      Uncorrectable Error Valid                     : %s
      Multiple Uncorrectable Errors                 : %s
      Multiple Correctable Errors                   : %s
      Error Data Entry Count                        : %s
      Reserved                                      : %s
    Raw Data Offset                                 : %s ( %d )
    Raw Data Length                                 : %s ( %d )
    Data Length                                     : %s ( %d )
    Error Severity                                  : %s - %s
    Generic Error Data Entries%s
''' % ( ('0x%08X' % blockStatus), ('0x%08X' % (blockStatus & 1)), ('0x%08X' % (blockStatus & 2)),
        ('0x%08X' % (blockStatus & 4)), ('0x%08X' % (blockStatus & 8)), ('0x%08X' % (blockStatus & 1023)),
        ('0x%08X' % (blockStatus & 262143)), ('0x%08X' % rawDataOffset), rawDataOffset, ('0x%08X' % rawDataLen),
        rawDataLen, ('0x%08X' % dataLen), dataLen, ('0x%08X' % errorSeverity), errorSeverity_str, genErrorDataEntries)

    def parse(self, table_content):
        self.BootRegionLen = struct.unpack('<L', table_content[0:4])[0]
        self.BootRegionAddr = struct.unpack('<Q', table_content[4:12])[0]
        bootRegion = self.cs.mem.read_physical_mem( self.BootRegionAddr, self.BootRegionLen )
        self.parseErrorBlock(bootRegion)
        
	
    def __str__(self):
        return """
------------------------------------------------------------------
  Boot Region Length                                : %d
  Boot Region Address	                            : %s
  Boot Region - %s
""" % ( self.BootRegionLen, ('0x%016X' % self.BootRegionAddr), self.BootRegion)

########################################################################################################
#
# EINJ Table
#
########################################################################################################

class EINJ (ACPI_TABLE):
    def __init__( self ):
        return

    def parseAddress(self, table_content):
        addrSpaceID = struct.unpack('<B', table_content[0:1])[0]
        regBitWidth = struct.unpack('<B', table_content[1:2])[0]
        regBitOffset = struct.unpack('<B', table_content[2:3])[0]
        accessSize = struct.unpack('<B', table_content[3:4])[0]
        addr = struct.unpack('<Q', table_content[4:12])[0]
        if addrSpaceID is 0:
            addrSpaceID_str = 'System Memory Space'
        elif addrSpaceID is 1:
            addrSpaceID_str = 'System I/O Space'
        elif addrSpaceID is 2:
            addrSpaceID_str = 'PCI Configuration Space - Error, should be 0 or 1'
        elif addrSpaceID is 3:
            addrSpaceID_str = 'Embedded Controller - Error, should be 0 or 1'
        elif addrSpaceID is 4:
            addrSpaceID_str = 'SMBus - Error, should be 0 or 1'
        elif addrSpaceID is 0x0A:
            addrSpaceID_str = 'Platform Communications Channel (PCC) - Error, should be 0 or 1'
        elif addrSpaceID is 0x7F:
            addrSpaceID_str = 'Functional Fixed Hardware - Error, should be 0 or 1'
        elif addrSpaceID >= 0xC0 and addrSpaceID <= 0xFF:
            addrSpaceID_str = 'OEM Defined - Error, should be 0 or 1'
        else:
            addrSpaceID_str = 'Reserved - Error, should be 0 or 1'
        accessSizeList = ['Undefined (legacy reasons)', 'Byte Access', 'Word Access', 'Dword Access', 'QWord Access', 'Not a defined value, check if defined by Address Space ID']
        if accessSize < 6:
            accessSize_str = accessSizeList[accessSize]
        else:
            accessSize_str = accessSizeList[5]
        return """Generic Address Structure
        Address Space ID                            : %s - %s
        Register Bit Width                          : %s
        Register Bit Offset                         : %s
        Access Size                                 : %s - %s
        Address                                     : %s""" % ( ('0x%02X' % addrSpaceID ), addrSpaceID_str, ('0x%02X' % regBitWidth ), ('0x%02X' % regBitOffset ), ('0x%02X' % accessSize ), accessSize_str, ('0x%016X' % addr ) )

    def parseInjection(self, table_content):
        errorInjectActions = [ 'BEGIN_INJECTION_OPERATION', 'GET_TRIGGER_ERROR_ACTION', 'SET_ERROR_TYPE', 'GET_ERROR_TYPE', 'END_OPERATION', 'EXECUTE_OPERATION', 'CHECK_BUSY_STATUS', 'GET_COMMAND_STATUS', 'SET_ERROR_TYPE_WITH_ADDRESS', 'GET_EXECUTE_OPERATION_TIMING', 'not recognized as valid aciton' ]
        injectionInstructions = [ 'READ_REGISTER', 'READ_REGISTER_VALUE', 'WRITE_REGISTER', 'WRITE_REGISTER_VALUE', 'NOOP', 'not recognized as valid instruction' ]
        injectionAction = struct.unpack('<B', table_content[0:1])[0]
        instruction = struct.unpack('<B', table_content[1:2])[0]
        flags = struct.unpack('<B', table_content[2:3])[0]
        reserved = struct.unpack('<B', table_content[3:4])[0]
        injectionHeaderSz = struct.unpack('<L', table_content[0:4])[0]
        registerRegion = self.parseAddress(table_content[4:16])
        value = struct.unpack('<Q', table_content[16:24])[0]
        mask = struct.unpack('<Q', table_content[24:32])[0]
        if injectionAction < 10:
            injectionAction_str = errorInjectActions[injectionAction]
        elif injectionAction is 255:
            injectionAction_str = 'TRIGGER_ERROR'
        else:
            injectionAction_str = errorInjectActions[10]
        if instruction < 5:
            instruction_str = injectionInstructions[instruction]
        else:
            instruction_str = injectionInstructions[5]
        if flags is 1 and (instruction is 2 or instruction is 3):
            flags_str = ' - PRESERVE_REGISTER'
        elif flags is 0:
            flags_str = ' - Ignore'
        else:
            flags_str = ''
        if reserved is not 0:
            reserved_str = ' - Error, must be 0'
        else:
            reserved_str = ''
        self.results_str += """
  Injection Instruction Entry
    Injection Action                                : %s ( %d ) - %s
    Instruction                                     : %s ( %d ) - %s
    Flags                                           : %s ( %d )%s
    Reserved                                        : %s ( %d )%s
    Register Region - %s
    Value                                           : %s ( %d )
    Mask                                            : %s ( %d )
    """ % ( ('0x%02X' % injectionAction), injectionAction, injectionAction_str, ('0x%02X' % instruction), instruction, instruction_str, ('0x%02X' % flags), flags, flags_str, ('0x%02X' % reserved), reserved, reserved_str, registerRegion, ('0x%016X' % value), value, ('0x%016X' % mask), mask )

    def parseInjectionActionTable(self, table_contents, numInjections):
        curInjection = 0
        while curInjection < numInjections:
            self.parseInjection( table_contents[curInjection*32:(curInjection + 1)*32] )
            curInjection += 1

    def parse(self, table_content):
        injectionHeaderSz = struct.unpack('<L', table_content[0:4])[0]
        injectionFlags = struct.unpack('<B', table_content[4:5])[0]
        reserved1 = struct.unpack('<B', table_content[5:6])[0]
        reserved2 = struct.unpack('<B', table_content[6:7])[0]
        reserved3 = struct.unpack('<B', table_content[7:8])[0]
        reserved3 = reserved3 << 16
        reserved2 = reserved2 << 8
        reserved = reserved3 | reserved2 | reserved1
        injectionEntryCount = struct.unpack('<L', table_content[8:12])[0]
        injection_str = ''
        reserved_str = ''
        if injectionFlags is not 0:
            injection_str = ' - Error, this feild should be 0'
        if reserved is not 0:
            reserved_str = ' - Error, this field should be 0'
        self.results_str = """
------------------------------------------------------------------
  Injection Header Size                             : %s ( %d )
  Injection Flags                                   : %s%s
  Reserved                                          : %s%s
  Injection Entry Count                             : %s ( %d )
  Injection Instruction Entries
""" % ( ('0x%016X' % injectionHeaderSz), injectionHeaderSz, ('0x%02X' % injectionFlags), injection_str, ('0x%06X' % reserved), reserved_str, ('0x%08X' % injectionEntryCount), injectionEntryCount )
        self.parseInjectionActionTable(table_content[12:], injectionEntryCount)
	
    def __str__(self):
        return self.results_str

########################################################################################################
#
# ERST Table
#
########################################################################################################

class ERST (ACPI_TABLE):
    def __init__( self ):
        return

    def parseAddress(self, table_content):
        addrSpaceID = struct.unpack('<B', table_content[0:1])[0]
        regBitWidth = struct.unpack('<B', table_content[1:2])[0]
        regBitOffset = struct.unpack('<B', table_content[2:3])[0]
        accessSize = struct.unpack('<B', table_content[3:4])[0]
        addr = struct.unpack('<Q', table_content[4:12])[0]

        if addrSpaceID is 0:
            addrSpaceID_str = 'System Memory Space'
        elif addrSpaceID is 1:
            addrSpaceID_str = 'System I/O Space'
        elif addrSpaceID is 2:
            addrSpaceID_str = 'PCI Configuration Space'
        elif addrSpaceID is 3:
            addrSpaceID_str = 'Embedded Controller'
        elif addrSpaceID is 4:
            addrSpaceID_str = 'SMBus'
        elif addrSpaceID is 0x0A:
            addrSpaceID_str = 'Platform Communications Channel (PCC)'
        elif addrSpaceID is 0x7F:
            addrSpaceID_str = 'Functional Fixed Hardware'
        elif addrSpaceID >= 0xC0 and addrSpaceID <= 0xFF:
            addrSpaceID_str = 'OEM Defined'
        else:
            addrSpaceID_str = 'Reserved'
	
        accessSizeList = ['Undefined (legacy reasons)', 'Byte Access', 'Word Access', 'Dword Access', 'QWord Access', 'Not a defined value, check if defined by Address Space ID']
        if accessSize < 6:
            accessSize_str = accessSizeList[accessSize]
        else:
            accessSize_str = accessSizeList[5]

        return """Generic Address Structure
        Address Space ID                            : %s - %s
        Register Bit Width                          : %s
        Register Bit Offset                         : %s
        Access Size                                 : %s - %s
        Address                                     : %s""" % ( ('0x%02X' % addrSpaceID ), addrSpaceID_str, ('0x%02X' % regBitWidth ), ('0x%02X' % regBitOffset ), ('0x%02X' % accessSize ), accessSize_str, ('0x%016X' % addr ) )

    def parseActionTable(self, table_content, instrCountEntry):
        curInstruction = 0
        while curInstruction < instrCountEntry:
            self.parseInstructionEntry(table_content[32*curInstruction:])
            curInstruction += 1

    def parseInstructionEntry(self, table_content):
        serializationAction = struct.unpack('<B', table_content[0:1])[0]
        instruction = struct.unpack('<B', table_content[1:2])[0]
        flags = struct.unpack('<B', table_content[2:3])[0]
        reserved = struct.unpack('<B', table_content[3:4])[0]
        registerRegion = self.parseAddress(table_content[4:16])
        value = struct.unpack('<Q', table_content[16:24])[0]
        mask = struct.unpack('<Q', table_content[24:32])[0]
        serializationActions = ['BEGIN_WRITE_OPERATION', 'BEGIN_READ_OPERATION', 'BEGIN_CLEAR_OPERATION', 'END_OPERATION', 'SET_RECORD_OFFESET', 'EXECUTE_OPERATION', 'CHECK_BUSY_STATUS', 'GET_COMMAND_STATUS', 'GET_RECORD_IDENTIFIER', 'SET_RECORD_IDENTIFIER', 'GET_RECORD_COUNT', 'BEGIN_DUMMY_WRITE_OPERATION', 'RESERVED', 'GET_ERROR_LOG_ADDRESS_RANGE', 'GET_ERROR_LOG_ADDRESS_RANGE_LENGTH', 'GET_ERROR_LOG_ADDRESS_RANGE_ATTEIBUTES', 'GET_EXECUTE_OPERATION_TIMINGS']
        serializationInstructions = ['READ_REGISTER', 'READ_REGISTER_VALUE', 'WRITE_REGISTER', 'WRITE_REGISTER_VALUE', 'NOOP', 'LOAD_VAR1', 'LOAD_VAR2', 'STORE_VAR1', 'ADD', 'SUBTRACT', 'ADD_VALUE', 'SUBTRACT_VALUE', 'STALL', 'STALL_WHILE_TRUE', 'SKIP_NEXT_INSTRUCTION_IF_TRUE', 'GOTO', 'SET_SCR_ADDRESS_BASE', 'SET_DST_ADDRESS_BASE', 'MOVE_DATA']
        if serializationAction < 17:
            serializationAction_str = serializationActions[serializationAction]
        else:
            serializationAction_str = 'Unknown'
        if instruction < 17:
            serializationInstr_str = serializationInstructions[instruction]
        else:
            serializationAction_str = 'Unknown'
        if reserved is not 0:
            reserved_str = ' - Error, this should be 0'
        else:
            reserved_str = ''
        if flags is 1:
            flags_str = ' - PRESERVE_REGISTER'
        else:
            flags_str = ''
		
        self.results_str += '''
    Serialization Intruction Entry
      Serialized Action                             : %s - %s
      Instruction                                   : %s - %s
      Flags                                         : %s%s
      Reserved                                      : %s%s
      Register Region - %s
      Value                                         : %s
      Mask                                          : %s
    ''' % ( ('0x%02X' % serializationAction), serializationAction_str, ('0x%02X' % instruction), serializationInstr_str, ('0x%02X' % flags), flags_str, ('0x%02X' % reserved), reserved_str, registerRegion, ('0x%016X' % value), ('0x%016X' % mask) )

    def parse(self, table_content):
        headerSz = struct.unpack('<L', table_content[0:4])[0]
        reserved = struct.unpack('<L', table_content[4:8])[0]
        instrCountEntry = struct.unpack('<L', table_content[8:12])[0]
        if reserved is not 0:
            reserved_str = ' - Error, this should be 0'
        else:
            reserved_str = ''
        self.results_str = """
------------------------------------------------------------------
  Serialization Header Size                       : %s ( %d )
  Reserved                                        : %s%s
  Instruction Count Entry                         : %s ( %d )
  Serialization Action Table
""" % ( ('0x%08X' % headerSz), headerSz, ('0x%08X' % reserved), reserved_str, ('0x%08X' % instrCountEntry), instrCountEntry )
        self.parseActionTable(table_content[12:], instrCountEntry)
	
    def __str__(self):
        return self.results_str

########################################################################################################
#
# HEST Table
#
########################################################################################################

class HEST (ACPI_TABLE):
    def __init__( self ):
        return

    def parseErrEntry(self, table_content):
        type = struct.unpack('<H', table_content[0:2])[0]
        if(type is 0): #Arch Machine Check Execption Structure
            return self.parseAMCES(table_content)
        elif(type is 1): #Arch Corrected Mach Check Structure or ArchitectureDeferred machine Check Structure
            return self.parseAMCS(table_content, type)
        elif(type is 2): #NMI Error Structure
            return self.parseNMIStructure(table_content)
        elif(type is 6 or type is 7 or type is 8): #PCIe Root Port AER Structure or PCIe Device AER Structure or PCIe Bridge AER Structure
            return self.parsePCIe(table_content, type)
        elif(type is 9 or type is 10): #Generic hardware Error Source Structure or Generic Hardware Error Source version 2
            return self.parseGHESS(table_content, type)
        else:
            pass

    def parseNotify(self, table_content):
        types = ['Polled','External Interrupt', 'Local Interrupt', 'SCI', 'NMI', 'CMCI', 'MCE', 'GPI-Signal', 'ARMv8 SEA', 'ARMv8 SEI', 'External Interrupt - GSIV', 'Software Delicated Exception', 'Reserved']
        errorType = struct.unpack('<B', table_content[0:1])[0]
        length = struct.unpack('<B', table_content[1:2])[0]
        configWrEn = struct.unpack('<H', table_content[2:4])[0]
        pollInterval = struct.unpack('<L', table_content[4:8])[0]
        vector = struct.unpack('<L', table_content[8:12])[0]
        switchPollingThreshVal = struct.unpack('<L', table_content[12:16])[0]
        switchPollThresWind = struct.unpack('<L', table_content[16:20])[0]
        errThreshVal = struct.unpack('<L', table_content[20:24])[0]
        errThreshWind = struct.unpack('<L', table_content[24:28])[0]
	
        if errorType <= 12:
            typeStr = types[errorType]
        else:
            typeStr = types[12]

        vector_str = ''
        if errorType is 10:
            vector_str = 'Specifies the GSIV triggerd by error source'
		
        return """Hardware Error Notification Structure
      Type                                        : %d - %s
      Length                                      : %s
      Configuration Write Enable                  : %s
        Type                                      : %d
        Poll Interval                             : %d
        Switch To Polling Threshold Value         : %d
        Switch To Polling Threshold Window        : %d
        Error Threshold Value                     : %d
        Error Threshold Window                    : %d
      Poll Interval                               : %d milliseconds
      Vector                                      : %d%s
      Switch To Polling Threshold Value           : %s
      Switch To Polling Threshold Window          : %d milliseconds
      Error Threshold Value                       : %s
      Error Threshold Window                      : %d milliseconds""" % ( errorType,  typeStr, ('0x%02X' % length), ('0x%04X' % configWrEn ), (configWrEn & 1), (configWrEn & 2), (configWrEn & 4), (configWrEn & 8), (configWrEn & 16), (configWrEn & 32), pollInterval, vector, vector_str, ('0x%08X' % switchPollingThreshVal ), switchPollThresWind, ('0x%08X' % errThreshVal ), errThreshWind)

    def machineBankParser(self, table_content):
        bankNum = struct.unpack('<B', table_content[0:1])[0]
        clearStatus = struct.unpack('<B', table_content[1:2])[0]
        statusDataFormat = struct.unpack('<B', table_content[2:3])[0]
        reserved1 = struct.unpack('<L', table_content[3:4])[0]
        controlRegMsrAddr = struct.unpack('<L', table_content[4:8])[0]
        controlInitData = struct.unpack('<L', table_content[8:16])[0]
        statusRegMSRAddr =struct.unpack('<L', table_content[16:20])[0]
        addrRegMSRAddr = struct.unpack('<L', table_content[20:24])[0]
        miscRegMSTAddr = struct.unpack('<L', table_content[24:28])[0]
	
        if clearStatus is 0:
            clearStatus_str = 'Clear'
        else:
            clearStatus_str = "Don't Clear"
		
        statusDataFormatStrList = ['IA-32 MCA', 'Intel 64 MCA',  'AMD64MCA', 'Reserved']
        if statusDataFormat < 3:
            statusDataFormat_str = statusDataFormatStrList[statusDataFormat]
        else:
            statusDataFormat_str = statusDataFormatStrList[3]

        if controlRegMsrAddr is not 0:
            controlRegMsrAddr_str = ''
        else:
            controlRegMsrAddr_str = ' - Ignore'

        if statusRegMSRAddr is not 0:
            statusRegMSRAddr_str = ''
        else:
            statusRegMSRAddr_str = ' - Ignore'

        if addrRegMSRAddr is not 0:
            addrRegMSRAddr_str = ''
        else:
            addrRegMSRAddr_str = ' - Ignore'

        if miscRegMSTAddr is not 0:
            miscRegMSTAddr_str = ''
        else:
            miscRegMSTAddr_str = ' - Ignore' 
		
        self.resultsStr = self.resultsStr + ("""Machine Check Error Bank Structure
      Bank Number                                 : %s
      Clear Status On Initialization              : %s - %s
      Status Data Format                          : %s - %s
      Reserved                                    : %s
      Control Register MSR Address                : %s%s
      Control Init Data                           : %s
      Status Register MSR Address                 : %s%s
      Address Register MSR Address                : %s%s
      Misc Register MSR Address	                  : %s%s""" % ( ('0x%04X' % bankNum ), ('0x%04X' % clearStatus ), clearStatus_str, ('0x%04X' % statusDataFormat ), statusDataFormat_str, ('0x%04X' % reserved1 ), ('0x%04X' % controlRegMsrAddr ), controlRegMsrAddr_str, ('0x%04X' % controlInitData ), ('0x%04X' % statusRegMSRAddr ), statusRegMSRAddr_str, ('0x%04X' % addrRegMSRAddr ), addrRegMSRAddr_str, ('0x%04X' % miscRegMSTAddr ), miscRegMSTAddr_str ) )

    def parseAddress(self, table_content):
        addrSpaceID = struct.unpack('<B', table_content[0:1])[0]
        regBitWidth = struct.unpack('<B', table_content[1:2])[0]
        regBitOffset = struct.unpack('<B', table_content[2:3])[0]
        accessSize = struct.unpack('<B', table_content[3:4])[0]
        addr = struct.unpack('<Q', table_content[4:12])[0]

        if addrSpaceID is 0:
            addrSpaceID_str = 'System Memory Space'
        elif addrSpaceID is 1:
            addrSpaceID_str = 'System I/O Space'
        elif addrSpaceID is 2:
            addrSpaceID_str = 'PCI Configuration Space'
        elif addrSpaceID is 3:
            addrSpaceID_str = 'Embedded Controller'
        elif addrSpaceID is 4:
            addrSpaceID_str = 'SMBus'
        elif addrSpaceID is 0x0A:
            addrSpaceID_str = 'Platform Communications Channel (PCC)'
        elif addrSpaceID is 0x7F:
            addrSpaceID_str = 'Functional Fixed Hardware'
        elif addrSpaceID >= 0xC0 and addrSpaceID <= 0xFF:
            addrSpaceID_str = 'OEM Defined'
        else:
            addrSpaceID_str = 'Reserved'
	
        accessSizeList = ['Undefined (legacy reasons)', 'Byte Access', 'Word Access', 'Dword Access', 'QWord Access', 'Not a defined value, check if defined by Address Space ID']
        if accessSize < 6:
            accessSize_str = accessSizeList[accessSize]
        else:
            accessSize_str = accessSizeList[5]

        return """Generic Address Structure
      Address Space ID                            : %s - %s
      Register Bit Width                          : %s
      Register Bit Offset                         : %s
      Access Size                                 : %s - %s
      Address                                     : %s""" % ( ('0x%02X' % addrSpaceID ), addrSpaceID_str, ('0x%02X' % regBitWidth ), ('0x%02X' % regBitOffset ), ('0x%02X' % accessSize ), accessSize_str, ('0x%016X' % addr ) )

    def parseAMCES(self, table_content):
        sourceID = struct.unpack('<H', table_content[2:4])[0]
        reserved1 = struct.unpack('<H', table_content[4:6])[0]
        flags = struct.unpack('<B', table_content[6:7])[0]
        enabled = struct.unpack('<B', table_content[7:8])[0]
        recordsToPreAllocate = struct.unpack('<L', table_content[8:12])[0]
        maxSectorsPerRecord = struct.unpack('<L', table_content[12:16])[0]
        globalCapabilityInitData = struct.unpack('<Q', table_content[16:24])[0]
        globalControlInitData = struct.unpack('<Q', table_content[24:32])[0]
        numHardwareBanks = struct.unpack('<B', table_content[32:33])[0]
        reserved2_1 = struct.unpack('<B', table_content[33:34])[0]
        reserved2_2 = struct.unpack('<B', table_content[34:35])[0]
        reserved2_3 = struct.unpack('<B', table_content[35:36])[0]
        reserved2_4 = struct.unpack('<B', table_content[36:37])[0]
        reserved2_5 = struct.unpack('<B', table_content[37:38])[0]
        reserved2_6 = struct.unpack('<B', table_content[38:39])[0]
        reserved2_7 = struct.unpack('<B', table_content[39:40])[0]
        
        if(flags & 1 is 1):
            firmware_first = 1
            firmware_first_str = 'System firmware handles errors from the source first'
        else:
            firmware_first = 0
            firmware_first_str = 'System firmware does not handle errors from the source first'
		
        if(flags & 4 is 4):
            ghes_assist = 1
            ghes_assist_str = 'Additional information given'
        else:
            ghes_assist = 0
            ghes_assist_str = 'Additional information not given'
		
        if(firmware_first is 0):
            ghes_assist_str = 'Bit is reserved'
		
        self.resultsStr = self.resultsStr + ("""
  Architecture Machine Check Exception Structure
    Source ID                                     : %s
    Reserved                                      : %s
    Flags                                         : %s
    FIRMWARE_FIRST                                : %s - %s
    GHES_ASSIST                                   : %s - %s
    Enabled                                       : %s
    Number of Records to Pre-allocate             : %s
    Max Sections Per Record                       : %s
    Global Capability Init Data                   : %s
    Number of Hardware Banks                      : %s
    Reserved                                      : %s %s %s %s %s %s %s
	""" % ( ('0x%04X' % sourceID ),  ('0x%04X' % reserved1 ), ('0x%02X' % flags ), firmware_first , firmware_first_str, ghes_assist , ghes_assist_str, ('0x%02X' % enabled ), ('0x%08X' % recordsToPreAllocate ), ('0x%08X' % maxSectorsPerRecord ), ('0x%016X' % globalCapabilityInitData ), ('0x%016X' % globalControlInitData ), ('0x%02X' %  numHardwareBanks), ('0x%02X' %  reserved2_1), ('0x%02X' %  reserved2_2), ('0x%02X' %  reserved2_3), ('0x%02X' %  reserved2_4), ('0x%02X' %  reserved2_5), ('0x%02X' %  reserved2_6), ('0x%02X' %  reserved2_7) ) )
	curBankNum = 0
        while curBankNum < numHardwareBanks:
            machineBankParser(table_content[40 + i*28:40 + (i+1)*28])
            curBankNum += 1
        return 40 + numHardwareBanks*28
	
    def parseAMCS(self, table_content, type):
        sourceID = struct.unpack('<H', table_content[2:4])[0]
        reserved1 = struct.unpack('<H', table_content[4:6])[0]
        flags = struct.unpack('<B', table_content[6:7])[0]
        enabled = struct.unpack('<B', table_content[7:8])[0]
        recordsToPreAllocate = struct.unpack('<L', table_content[8:12])[0]
        maxSectorsPerRecord = struct.unpack('<L', table_content[12:16])[0]
        notificationStructure = self.parseNotify(table_content[16:44])
        numHardwareBanks = struct.unpack('<B', table_content[44:45])[0]
        reserved2_1 = struct.unpack('<B', table_content[45:46])[0]
        reserved2_2 = struct.unpack('<B', table_content[46:47])[0]
        reserved2_3 = struct.unpack('<B', table_content[47:48])[0]
		
        if(flags & 1 is 1):
            firmware_first = 1
            firmware_first_str = 'System firmware handles errors from the source first'
        else:
            firmware_first = 0
            firmware_first_str = 'System firmware does not handle errors from the source first'
		
        if(flags & 4 is 4):
            ghes_assist = 1
            ghes_assist_str = 'Additional information given'
        else:
            ghes_assist = 0
            ghes_assist_str = 'Additional information not given'
		
        flags_str =''
        if flags is not 1 and flags is not 4 and flags is not 5:
            flags_str = ' - Error, Reserved Bits are not 0'
		
        if(firmware_first is 0):
            ghes_assist_str = 'Bit is reserved'
			
        if type is 1:
            title = 'Architecture Corrected Machine Check Structure'
        else:
            title ='Architecture Deferred Machine Check Structure'
		
        self.resultsStr = self.resultsStr + ("""
  %s
    Source ID         				  : %s
    Reserved                                      : %s
    Flags                                         : %s%s
      FIRMWARE_FIRST                              : %s - %s
      GHES_ASSIST                                 : %s - %s
    Enabled                                       : %s
    Number of Records to Pre-allocate             : %s
    Max Sections Per Record                       : %s
    %s
    Number of Hardware Banks                      : %s
    Reserved                                      : %s %s %s
	""" % ( title, ('0x%04X' % sourceID ),  ('0x%04X' % reserved1 ), ('0x%02X' % flags ), flags_str, firmware_first , firmware_first_str, ghes_assist , ghes_assist_str, ('0x%02X' % enabled ), ('0x%08X' % recordsToPreAllocate ), ('0x%08X' % maxSectorsPerRecord ), notificationStructure, ('0x%02X' %  numHardwareBanks), ('0x%02X' %  reserved2_1), ('0x%02X' %  reserved2_2), ('0x%02X' %  reserved2_3) ) )
        currBank = 0
        while currBank < numHardwareBanks:
            machineBankParser(table_content[48 + i*28:48 + (i+1)*28])
            numHardwareBanks == 1	
        return 48 + numHardwareBanks*28
	
    def parseNMIStructure(self, table_content):
        sourceID = struct.unpack('<H', table_content[2:4])[0]
        reserved = struct.unpack('<L', table_content[4:8])[0]
        numRecordsToPreAllocate = struct.unpack('<L', table_content[8:12])[0]
        maxSectorsPerRecord = struct.unpack('<L', table_content[12:16])[0]
        maxRawDataLength = struct.unpack('<L', table_content[16:20])[0]
		
        if reserved is 0:
            reserved_str = ''
        else:
            reserved_str = ' - Error, not 0'
		
        self.resultsStr = self.resultsStr + ("""
  Architecture NMI Error Structure
    Source ID                                     : %s
    Reserved                                      : %s%s
    Number of Records to Pre-Allocate             : %s
    Max Sections Per Record                       : %s
    Max Raw Data Length                           : %s
	""" % ( ('0x%04X' % sourceID ), ('0x%08X' % reserved ), ('0x%08X' % numRecordsToPreAllocate ), ('0x%08X' % maxSectorsPerRecord ), ('0x%08X' % maxRawDataLength ) ) )
		
        return 20
		
    def parsePCIe(self, table_content, type):
        sourceID = struct.unpack('<H', table_content[2:4])[0]
        reserved1 = struct.unpack('<H', table_content[4:6])[0]
        flags = struct.unpack('<B', table_content[6:7])[0]
        enabled = struct.unpack('<B', table_content[7:8])[0]
        numRecordsToPreAllocate = struct.unpack('<L', table_content[8:12])[0]
        maxSectorsPerRecord = struct.unpack('<L', table_content[12:16])[0]
        bus = struct.unpack('<L', table_content[16:20])[0]
        device = struct.unpack('<H', table_content[20:22])[0]
        function = struct.unpack('<H', table_content[22:24])[0]
        deviceControl = struct.unpack('<H', table_content[24:26])[0]
        reserved2 = struct.unpack('<H', table_content[26:28])[0]
        uncorrectableErrorMask = struct.unpack('<L', table_content[28:32])[0]
        uncorrectableErrorServerity = struct.unpack('<L', table_content[32:36])[0]
        correctableErrorMask = struct.unpack('<L', table_content[36:40])[0]
        advancedErrorCapabilitiesAndControl = struct.unpack('<L', table_content[40:44])[0]
        if type is 6:
            title = 'PCI Express Root Port AER Structure'
            rootErrCommand = struct.unpack('<L', table_content[44:48])[0]
            extra_str = '''
    Root Error Command                            : %s''' %( ('0x%08X' % rootErrCommand ) )
            size = 48
        elif type is 8:
            title = 'PCI Express Bridge AER Structure'
            secondaryUncorrErrMask = struct.unpack('<L', table_content[44:48])[0]
            secondaryUncorrErrServ = struct.unpack('<L', table_content[48:52])[0]
            secondaryAdvCapabAndControl = struct.unpack('<L', table_content[52:56])[0]
            extra_str = '''
    Secondary Uncorrectable Error Mask            : %s
    Secondary Uncorrectable Error Severity        : %s
    Secondary Advanced Capabilities and Control   : %s''' %( ('0x%08X' % secondaryUncorrErrMask ), ('0x%08X' % secondaryUncorrErrServ ), ('0x%08X' % secondaryAdvCapabAndControl ) )
            size = 56
        else:
            title = 'PCI Express Device AER Structure'
            extra_str = ''
            size = 44
		
        if (flags & 1 is 1):
            firmware_first = 1
            firmware_first_str = 'System firmware handles errors from the source first'
        else:
            firmware_first = 0
            firmware_first_str = 'System firmware does not handle errors from the source first'
		
        if (flags & 2 is 2):
            global_flag = 1
            global_flag_str = 'Settings in table are for all PCIe Devices'
        else:
            global_flag = 0
            global_flag_str = 'Settings in table are not for all PCIe Devices'
        flags_str = ''
        reserved2_str = ''
        isGlobal_str =''
        isFirmware_str =''
	
        if flags >= 4:
            flags_str = 'Error, reserved bits are not 0'
        if reserved2 is not 0:
            reserved2_str = ' - Error, reserved bits should be 0'
        if global_flag is not 0:
            isGlobal_str = ' - This field should be ignored since Global is set'
        if firmware_first is not 0:
            isFirmware_str = ' - This field should be ignored since FIRMWARE_FIRST is set'
		    
        self.resultsStr = self.resultsStr + ("""
  %s
    Source ID                                     : %s
    Reserved                                      : %s
    Flags                                         : %s%s
      FIRMWARE_FIRST                              : %s - %s
      GLOBAL                                      : %s - %s
    Enabled                                       : %s
    Number of Records to Pre-Allocate             : %s
    Max Sections Per Record                       : %s
    Bus                                           : %s
    Device                                        : %s%s
    Function                                      : %s%s
    Device Control                                : %s
    Reserved                                      : %s%s
    Uncorrectable Error Mask                      : %s
    Uncorrected Error Severity                    : %s
    Corrected Error Mask                          : %s
    Advanced Error Capabilities and Control       : %s%s
	""" % ( title, ('0x%04X' % sourceID ), ('0x%08X' % reserved1 ), ('0x%02X' % flags ), firmware_first, firmware_first_str, global_flag, global_flag_str, ('0x%08X' % enabled ), isFirmware_str, ('0x%08X' % numRecordsToPreAllocate ), ('0x%08X' % maxSectorsPerRecord ), ('0x%08X' % bus ), ('0x%04X' % device ), isGlobal_str, ('0x%04X' % function ), isGlobal_str, ('0x%04X' % deviceControl ), ('0x%04X' %  reserved2), reserved2_str, ('0x%08X' % uncorrectableErrorMask ), ('0x%08X' % uncorrectableErrorServerity ), ('0x%08X' % correctableErrorMask ), ('0x%08X' % advancedErrorCapabilitiesAndControl ), extra_str ) )
        return size
		
    def parseGHESS(self, table_content, type):
        sourceID = struct.unpack('<H', table_content[2:4])[0]
        relatedSourceID = struct.unpack('<H', table_content[4:6])[0]
        flags = struct.unpack('<B', table_content[6:7])[0]
        enabled = struct.unpack('<B', table_content[7:8])[0]
        numRecordsToPreAllocate = struct.unpack('<L', table_content[8:12])[0]
        maxSectorsPerRecord = struct.unpack('<L', table_content[12:16])[0]
        maxRawDataLength = struct.unpack('<L', table_content[16:20])[0]
        address_str = self.parseAddress(table_content[20:32])
        notification_str = self.parseNotify(table_content[32:60])
        errStatusBlockLen = struct.unpack('<L', table_content[60:64])[0]
        if type is 9:
            title = 'Generic Hardware Error Source Structure'
            extra_str = ''
        else:
            title = 'Generic Hardware Error Source Version 2'
            readAckReg_str = parseAddress(table_content[64:76])
            readAckPresv = struct.unpack('<Q', table_content[76:84])[0]
            readAckWr = struct.unpack('<Q', table_content[84:88])[0]
            extra_str = '''
    Read Ack Register - %s
    Read Ack Preserve                             : %s
    Read Ack Write                                : %s''' % ( readAckReg_str,  ('0x%016X' % readAckPresv ), ('0x%016X' % readAckWr ) )
        if relatedSourceID is 65535:
            relatedSourceID_str = 'Does not represent an alternate souce'
        else:
            relatedSourceID_str = ''
		
        self.resultsStr = self.resultsStr + ("""
  %s
    Source ID                                     : %s
    Related Source Id                             : %s%s
    Flags                                         : %s - Reserved
    Enabled                                       : %s
    Number of Records to Pre-Allocate             : %s
    Max Sections Per Record                       : %s
    Max Raw Data Length                           : %s
    Error Status Address - %s
    %s
    Error Status Block Length                     : %s%s
	""" % ( title, ('0x%04X' % sourceID ), ('0x%08X' % relatedSourceID ), relatedSourceID_str, ('0x%02X' % flags ), ('0x%02X' % enabled ), ('0x%08X' % numRecordsToPreAllocate ), ('0x%08X' % maxSectorsPerRecord ), ('0x%08X' % maxRawDataLength ), address_str, notification_str, ('0x%08X' % errStatusBlockLen ), extra_str ) )
        return 64
		
    def parse(self, table_content):
        self.ErrorSourceCount = struct.unpack('<L', table_content[0:4])[0]
        self.resultsStr = """
------------------------------------------------------------------
  Error Source Count                              : %s
""" % ( self.ErrorSourceCount )
        nextTable = 4
        currErrSource = 0
        while( currErrSource < self.ErrorSourceCount):
            nextTable = nextTable + self.parseErrEntry(table_content[nextTable:])
            currErrSource += 1
        #self.ErrorStructure = struct.unpack('<b', table_content[4:?])[0]
    		
    def __str__(self):
        return self.resultsStr


########################################################################################################
#
# SPMI Table
#
########################################################################################################

class SPMI (ACPI_TABLE):
    def __init__( self ):
        return

    def parseAddress(self, table_content):
        addrSpaceID = struct.unpack('<B', table_content[0:1])[0]
        regBitWidth = struct.unpack('<B', table_content[1:2])[0]
        regBitOffset = struct.unpack('<B', table_content[2:3])[0]
        accessSize = struct.unpack('<B', table_content[3:4])[0]
        addr = struct.unpack('<Q', table_content[4:12])[0]

        if addrSpaceID is 0:
            addrSpaceID_str = 'System Memory Space'
        elif addrSpaceID is 1:
            addrSpaceID_str = 'System I/O Space'
        elif addrSpaceID is 2:
            addrSpaceID_str = 'PCI Configuration Space -- Error, should only be 0 (system memory), 1 (system IO), or 4 (SMBus)'
        elif addrSpaceID is 3:
            addrSpaceID_str = 'Embedded Controller -- Error, should only be 0 (system memory), 1 (system IO), or 4 (SMBus)'
        elif addrSpaceID is 4:
            addrSpaceID_str = 'SMBus'
        elif addrSpaceID is 0x0A:
            addrSpaceID_str = 'Platform Communications Channel (PCC) -- Error, should only be 0 (system memory), 1 (system IO), or 4 (SMBus)'
        elif addrSpaceID is 0x7F:
            addrSpaceID_str = 'Functional Fixed Hardware -- Error, should only be 0 (system memory), 1 (system IO), or 4 (SMBus)'
        elif addrSpaceID >= 0xC0 and addrSpaceID <= 0xFF:
            addrSpaceID_str = 'OEM Defined -- Error, should only be 0 (system memory), 1 (system IO), or 4 (SMBus)'
        else:
            addrSpaceID_str = 'Reserved'
	
        accessSizeList = ['Undefined (legacy reasons)', 'Byte Access', 'Word Access', 'Dword Access', 'QWord Access', 'Not a defined value, check if defined by Address Space ID']
        if accessSize < 6:
            accessSize_str = accessSizeList[accessSize]
        else:
            accessSize_str = accessSizeList[5]

        return """Generic Address Structure
    Address Space ID                            : %s - %s
    Register Bit Width                          : %s
    Register Bit Offset                         : %s
    Access Size                                 : %s - %s
    Address                                     : %s""" % ( ('0x%02X' % addrSpaceID ), addrSpaceID_str, ('0x%02X' % regBitWidth ), ('0x%02X' % regBitOffset ), ('0x%02X' % accessSize ), accessSize_str, ('0x%016X' % addr ) )


    def parseNonUID(self, table_content):
        pciSegGrpNum = struct.unpack('<B', table_content[0:1])[0]
        pciBusNum = struct.unpack('<B', table_content[1:2])[0]
        pciDevNum = struct.unpack('<B', table_content[2:3])[0]
        pciFuncNum = struct.unpack('<B', table_content[3:4])[0]
        return '''  PCI Segment GroupNumber                                 : %s
  PCI Bus Number                                          : %s
  PCI Device Number                                       : %s
  PCI Function Number                                     : %s''' % ( ('0x%02X' % pciSegGrpNum), ('0x%02X' % pciBusNum), ('0x%02X' % pciDevNum), ('0x%02X' % pciFuncNum) )

    def parseUID(self, table_content):
        uid = struct.unpack('<L', table_content[0:4])[0]
        return '''  UID                                                     : %s''' % ( ('0x%02X' % uid) )

    def parse(self, table_content):
        interfaceType = struct.unpack('<B', table_content[0:1])[0]
        reserved1 = struct.unpack('<B', table_content[1:2])[0]
        specRev = struct.unpack('<B', table_content[2:3])[0]
        interruptType = struct.unpack('<H', table_content[3:5])[0]
        gpe = struct.unpack('<B', table_content[5:6])[0]
        reserved2 = struct.unpack('<B', table_content[6:7])[0]
        pciDeviceFlag = struct.unpack('<B', table_content[7:8])[0]
        globalSysInter = struct.unpack('<L', table_content[8:12])[0]
        baseAdder = self.parseAddress(table_content[12:24])
        reserved3 = struct.unpack('<B', table_content[28:29])[0]
        if interfaceType is 1:
            intTypeStr = "Keyboard Controller Style (KCS)"
        elif interfaceType is 2:
            intTypeStr = "Server Management Interface Chip (SMIC)"
        elif interfaceType is 3:
            intTypeStr = "Block Transfer (BT)"
        elif interfaceType is 4:
            intTypeStr = "SMBus System Interface (SSIF)"
        else:
            intTypeStr = "Reserved"
        specRevStr = ('0x%02X' % specRev)
        intType_0 = interruptType & 1
        intType_1 = interruptType & 2 >> 1
        intType_other = interruptType ^ 3 >> 2
        if intType_0 is 1:
            intTypeSCIGPE = "supported"
        else:
            intTypeSCIGPE = "not supported"
        if intType_1 is 1:
            intTypeIO = "supported"
        else:
            intTypeIO = "not supported"
        GPE_str = ''
        if interruptType & 1 is not 1:
            GPE_str = " - should be set to 00h"
        pciDeviceFlag_0 = pciDeviceFlag & 1
        if pciDeviceFlag_0 is 1:
            pci_str = 'For PCi IPMI devices'
            otherStr = self.parseNonUID(table_content[25:28]) 
        else:
            pci_str = 'non-PCI device'
            otherStr = self.parseUID(table_content[25:28])
        pciDeviceFlag_reserved = 1 ^ pciDeviceFlag_0
        globalSysInt_str = ''
        if intType_1 is not 1:
            globalSysInt_str = ' - this field should be 0'
        self.results = '''==================================================================
  Service Processor Management Interface Description Table ( SPMI )
==================================================================
  Interface Type                                          : %s - %s
  Reserved                                                : %s - Must always be 01h to be compatible with any software implementing previous versions of the spec
  Specification Revision (version)                        : %s (%s)
  Interrupt Type                                          : %s
    SCI triggered through GPE                             : %s - %s
    I/0 APIC/SAPIC interrupt (Global System Interrupt)    : %s - %s
    Reserved                                              : %s - Must be 0
  GPE                                                     : %s%s
  Reserved                                                : %s - should be 00h
  PCI Device Flag                                         : %s
    PCI Device Flag                                       : %d
    Reserved                                              : %d - must be 0
  Global System Interrupt                                 : %s%s
  Base Address - %s
%s
  Reserved                                                : %s

''' % ( ('0x%02X' % interfaceType), intTypeStr, ('0x%02X' % reserved1), specRevStr, ('0x%04X' % interruptType), ('0x%02X' % intType_0), ('0x%02X' % intType_1), ('0x%02X' % intType_other), ('0x%02X' % gpe), GPE_str, ('0x%02X' % reserved2), ('0x%02X' % pciDeviceFlag), pciDeviceFlag_0, pciDeviceFlag_reserved, ('0x%08X' % globalSysInter), globalSysInt_str, baseAdder, otherStr, ('0x%02X' % reserved3) )

    def __str__(self):
        return self.results



########################################################################################################
#
# RASF Table
#
########################################################################################################

class RASF (ACPI_TABLE):
    def __init__( self ):
        return

    def parse(self, table_content):
        rpcci1 = struct.unpack('<B', table_content[0:1])[0]
        rpcci2 = struct.unpack('<B', table_content[1:2])[0]
        rpcci3 = struct.unpack('<B', table_content[2:3])[0]
        rpcci4 = struct.unpack('<B', table_content[3:4])[0]
        rpcci5 = struct.unpack('<B', table_content[4:5])[0]
        rpcci6 = struct.unpack('<B', table_content[5:6])[0]
        rpcci7 = struct.unpack('<B', table_content[6:7])[0]
        rpcci8 = struct.unpack('<B', table_content[7:8])[0]
        rpcci9 = struct.unpack('<B', table_content[8:9])[0]
        rpcci10 = struct.unpack('<B', table_content[9:10])[0]
        rpcci11 = struct.unpack('<B', table_content[10:11])[0]
        rpcci12 = struct.unpack('<B', table_content[11:12])[0]
        self.results = '''==================================================================
  ACPI RAS Feature Table ( RASF )
==================================================================
  RASF Platform Communication Channel Identifier          : %s %s %s %s %s %s %s %s %s %s %s %s

''' % ( ('0x%02X' % rpcci1), ('0x%02X' % rpcci2), ('0x%02X' % rpcci3), ('0x%02X' % rpcci4), ('0x%02X' % rpcci5), ('0x%02X' % rpcci6), ('0x%02X' % rpcci7), ('0x%02X' % rpcci8), ('0x%02X' % rpcci9), ('0x%02X' % rpcci10), ('0x%02X' % rpcci11), ('0x%02X' % rpcci12) )

    def __str__(self):
        return self.results



########################################################################################################
#
# MSCT Table
#
########################################################################################################

class MSCT (ACPI_TABLE):
    def __init__( self ):
        return

    def parseProx(self, table_content, val):
        rev = struct.unpack('<B', table_content[0:1])[0]
        length = struct.unpack('<B', table_content[1:2])[0]
        maxDomRangeL = struct.unpack('<L', table_content[2:6])[0]
        maxDomRangeH = struct.unpack('<L', table_content[6:10])[0]
        maxProcCap = struct.unpack('<L', table_content[10:14])[0]
        maxMemCap = struct.unpack('<Q', table_content[14:22])[0]
        maxProcCap_str = ''
        maxMemCap_str = ''
        if maxProcCap is 0:
            maxProcCap_str = ' - Proximity domains do not contain a processor'
        if maxMemCap is 0:
            maxMemCap_str = '- Proximity domains do not contain memory'
        return '''
    Maximum Proximity Domain Informaiton Structure[%d]
      Revision                                              : %s ( %d )
      Length                                                : %s ( %d )
      Proximity Domain Range (low)                          : %s
      Proximity Domain Range (high)                         : %s
      Maximum Processor Capacity                            : %s ( %d )%s
      Maximum Memory Capacity                               : %s ( %d ) bytes %s
''' % ( val, ('0x%02X' % rev), rev, ('0x%02X' % length), length, ('0x%04X' % maxDomRangeL), ('0x%04X' % maxDomRangeH), ('0x%04X' % maxProcCap), maxProcCap, maxProcCap_str, ('0x%016X' % maxMemCap), maxMemCap, maxMemCap_str )

    def parseProxDomInfoStruct( self, table_contents, num):
        val = 0
        result = ''
        while val < num:
            result = result + self.parseProx(table_contents[22*val: 22*(val + 1)], val)
            val = val + 1
        return result

    def parse(self, table_content):
        offsetProxDomInfo = struct.unpack('<L', table_content[0:4])[0]
        maxNumProxDoms = struct.unpack('<L', table_content[4:8])[0]
	maxNumClockDoms = struct.unpack('<L', table_content[8:12])[0]
        maxPhysAddr = struct.unpack('<Q', table_content[12:20])[0]
        proxDomInfoStructStr = self.parseProxDomInfoStruct( table_content[20: ], maxNumProxDoms )
        self.results = '''==================================================================
  Maximum System Characteristics Table ( MSCT )
==================================================================
  Offset to Proximity Domain Information Structure        : %s
  Maximum Number of Proximity Domains                     : %s ( %d )
  Maximum Number of Clock Domains                         : %s ( %d )
  Maximum Physical Address                                : %s
  Proximity Domain  Information Structure%s

''' % ( ('0x%08X' % offsetProxDomInfo), ('0x%08X' % maxNumProxDoms), maxNumProxDoms, ('0x%08X' % maxNumClockDoms), maxNumClockDoms, ('0x%016X' % maxPhysAddr), proxDomInfoStructStr )

    def __str__(self):
        return self.results


########################################################################################################
#
# NFIT Table
#
########################################################################################################

class NFIT (ACPI_TABLE):
    def __init__( self, header ):
        length = struct.unpack('<L', header[4:8])[0]
        self.total_length = length
        return

    def platCapStruct(self, tableLen, table_content):
        highestValidCap = struct.unpack('<B', table_content[4:5])[0]
        reserved1_1 = struct.unpack('<B', table_content[5:6])[0]
        reserved1_2 = struct.unpack('<B', table_content[6:7])[0]
        reserved1_3 = struct.unpack('<B', table_content[7:8])[0]
        capabilities = struct.unpack('<L', table_content[8:12])[0]
        cap1 = capabilities & 1
        cap2 = capabilities & 2
        cap3 = capabilities & 4
        capRes = capabilities & ~(7)
        reserved2 = struct.unpack('<L', table_content[12:16])[0]
        if cap1 is 1:
            cap1_str = 'Platform ensures the entire CPU store data path is flushed to persistent memory on system power loss'
        else:
            cap1_str = 'Platform does not ensure the entire CPU store data path is flushed to persistent memory on system power loss'
        if cap2 is 2:
            cap2_str = 'Platform provides mehanisms to automatically flush outstanding write data from the memory controller to persistent memory in the event of power loss'
        else:
            if cap1 is 1:
                cap2_str = 'Platform does not provides mehanisms to automatically flush outstanding write data from the memory controller to persistent memory in the event of power loss'
            else:
             cap2_str = 'This should be set to 1 - Platform does not support'
        if cap3 is 4:
            cap3_str = 'Platform supports mirroring multiple byte addressable persistent memory regions together'
        else:
            cap3_str = 'Platform does not support mirroring multiple byte addressable persistent memory regions together'
        return '''
    Platform Capabilities Structure [Type 7]
      Length                                                      : %s ( %d bytes )
      Highest Valid Capability                                    : %s
      Reserved                                                    : %s %s %s
      Capabilities                                                : %s
        CPU Cache Flush to NVDIMM Durability on Power Loss        : %s - %s
        Mem Controller Flush to NVDIMM Durability on Power Loss   : %s - %s
        Byte Addressible Persistent Mem Hw Mirroring Capable      : %s - %s
        Reserved                                                  : %s
      Reserved                                                    : %s
''' % ( ('0x%04X' % tableLen), tableLen, ('0x%02X' % highestValidCap), ('0x%02X' % reserved1_1), ('0x%02X' % reserved1_2), ('0x%02X' % reserved1_3), ('0x%08X' % capabilities), ('0x%08X' % cap1), cap1_str, ('0x%08X' % cap2), cap2_str, ('0x%08X' % cap3), cap3_str, ('0x%08X' % capRes) , ('0x%08X' % reserved2))

    def flushHintAddrStruct(self, tableLen, table_content):
        nfitDevHandle = struct.unpack('<L', table_content[4:8])[0]
        numFlushHintAddr = struct.unpack('<L', table_content[4:8])[0]
        reserved = struct.unpack('<L', table_content[4:8])[0]
        curLine = 0
        lines = ''
        while curLine < numFlushHintAddr:
            lineInfo = struct.unpack('<Q', table_content[curLine*8 + 8:curLine*8 + 16])[0]
            lines += '''
        Flush Hint Address %s                                     : %s ''' % ( (curLine + 1), ('0x%016X' % lineInfo))
            curLine += 1
        return (curLine - 1)*8 + 16, '''
    Flush Hint Address Structure [Type 6]
      Length                                                      : %s ( %d bytes )
      NFIT Device Handle                                          : %s
      Number of Flush Hint Addresses in this Structure            : %s ( %d )
      Reserved                                                    : %s
      Flush Hint Addresses%s
''' % ( ('0x%04X' % tableLen), tableLen, ('0x%08X' % nfitDevHandle), ('0x%08X' % numFlushHintAddr), numFlushHintAddr, ('0x%08X' % reserved), lines)

    def nvdimmBlockDataWindowsRegionStruct(self, tableLen, table_content):
        nvdimmControlRegionStructureIndex = struct.unpack('<H', table_content[4:6])[0]
        numBlockDataWindows = struct.unpack('<H', table_content[6:8])[0]
        blockDataWindowsStartOffset = struct.unpack('<Q', table_content[8:16])[0]
        szBlckDataWindow = struct.unpack('<Q', table_content[16:24])[0]
        blckAccMemCap = struct.unpack('<Q', table_content[24:32])[0]
        begAddr = struct.unpack('<Q', table_content[32:40])[0]
        return '''
    NVDIMM Block Data Region Structure [Type 5]
      Length                                                      : %s ( %d bytes )
      NVDIMM Control Region Structure Index                       : %s - Should not be 0
      Number of Block Data Windows                                : %s ( %d )
      Block Data Window Start Offest                              : %s ( %d bytes )
      Size of Block Data Window                                   : %s ( %d bytes )
      Block Accessible Memory Capacity                            : %s ( %d bytes )
      Start Addr for 1st Block in Block Accessible Mem            : %s ( %d bytes )
''' % ( ('0x%04X' % tableLen), tableLen, ('0x%04X' % nvdimmControlRegionStructureIndex), ('0x%04X' % numBlockDataWindows), numBlockDataWindows, ('0x%016X' % blockDataWindowsStartOffset), blockDataWindowsStartOffset, ('0x%016X' % szBlckDataWindow), szBlckDataWindow, ('0x%016X' % blckAccMemCap), blckAccMemCap, ('0x%016X' % begAddr), begAddr )

    def nvdimmControlRegionStructMark(self, tableLen, table_content):
        nvdimmControlRegionStructureIndex = struct.unpack('<H', table_content[4:6])[0]
        vendorID = struct.unpack('<H', table_content[6:8])[0]
        deviceID = struct.unpack('<H', table_content[8:10])[0]
        revID = struct.unpack('<H', table_content[10:12])[0]
        subsystemVendorID = struct.unpack('<H', table_content[12:14])[0]
        subsysDevID = struct.unpack('<H', table_content[14:16])[0]
        subsysRevID = struct.unpack('<H', table_content[16:18])[0]
        validFields = struct.unpack('<B', table_content[18:19])[0]
        manLocation = struct.unpack('<B', table_content[19:20])[0]
        manDate = struct.unpack('<H', table_content[20:22])[0]
        #need more parsing of the date
        reserved = struct.unpack('<H', table_content[22:24])[0]
        serialNum = struct.unpack('<L', table_content[24:28])[0]
        regionFormatInterfaceCode = struct.unpack('<H', table_content[28:30])[0]
        rfic1 = struct.unpack('<B', table_content[28:29])[0]
        rfic2 = struct.unpack('<B', table_content[29:30])[0]
        rfic_r1 = rfic1 & 224
        rfic_fif = rfic1 & 31
        rfic_r2 = rfic2 & 224
        rfic_fcf = rfic2 & 31
        numBlockControlWindows = struct.unpack('<H', table_content[30:32])[0]
        cont_str = 'ERROR - Table is shorter than expected.'
        if numBlockControlWindows is not 0:
            szBlckControlWindow = struct.unpack('<Q', table_content[32:40])[0]
            commandRegOffset = struct.unpack('<Q', table_content[40:48])[0]
            szCommandReg = struct.unpack('<Q', table_content[48:56])[0]
            statusRegOffset = struct.unpack('<Q', table_content[56:64])[0]
            szStatus = struct.unpack('<Q', table_content[64:72])[0]
            nvdimmControlRegionFl = struct.unpack('<H', table_content[72:74])[0]
            reserved2_1 = struct.unpack('<B', table_content[74:75])[0]
            reserved2_2 = struct.unpack('<B', table_content[75:76])[0]
            reserved2_3 = struct.unpack('<B', table_content[76:77])[0]
            reserved2_4 = struct.unpack('<B', table_content[77:78])[0]
            reserved2_5 = struct.unpack('<B', table_content[78:79])[0]
            reserved2_6 = struct.unpack('<B', table_content[79:80])[0]
            cont_str = '''      Size of Block Control Windows                               : %s (%d bytes)
      Command Reg Offset in Block Control Windows                 : %s
      Size of Command Register in Block Control Windows           : %s
      Status Register Offset in Block Control Windows             : %s
      Size of Status Register in Block Control Windows            : %s
      NVDIMM Control Region Flag                                  : %s
      Reserved                                                    : %s %s %s %s %s %s
%s''' % ( ('0x%016X' % szBlckControlWindow), szBlckControlWindow, ('0x%016X' % commandRegOffset), ('0x%016X' % szCommandReg), ('0x%016X' % statusRegOffset), ('0x%016X' % szStatus), ('0x%04X' % nvdimmControlRegionFl), ('0x%02X' % reserved2_1), ('0x%02X' % reserved2_2), ('0x%02X' % reserved2_3), ('0x%02X' % reserved2_4), ('0x%02X' % reserved2_5), ('0x%02X' % reserved2_6), cont_str )
        valid_0 = validFields & 1
        valid_str = ''
        valid_man_str = ''
        if valid_0 is 0:
            valid_str = 'System is compliant with ACPI 6.0 - Manufacturing Location & Date fields are invalid and should be ignored'
            valid_man_str = 'Value is invalid and should be ignored'
        return '''
    NVDIMM Control Region Structure [Type 4]
      Length                                                      : %s ( %d bytes )
      NVDIMM Control Region Structure Index                       : %s
      Vendor ID                                                   : %s
      Device ID                                                   : %s
      Revision ID                                                 : %s
      Subsystem Vendor ID                                         : %s
      Subsystem Device ID                                         : %s
      Subsystem Revision ID                                       : %s
      Valid Fields                                                : %s
        Bit[0]                                                    : %s%s
      Manufacturing Location                                      : %s%s
      Manufacturing Date                                          : %s%s
      Reserved                                                    : %s
      Serial Number                                               : %s
      Region Format Interface Code                                : %s
        Reserved                                                  : %s
        Function Interface Field                                  : %s
        Reserved                                                  : %s
        Function Class Field                                      : %s
      Number of Block Control Windows                             : %s
''' % ( ('0x%04X' % tableLen), tableLen, ('0x%04X' % nvdimmControlRegionStructureIndex), ('0x%04X' % vendorID), ('0x%04X' % deviceID), ('0x%04X' % revID), ('0x%04X' % subsystemVendorID), ('0x%04X' % subsysDevID), ('0x%04X' % subsysRevID), ('0x%02X' % validFields), valid_0, valid_str, ('0x%02X' % manLocation), valid_man_str, ('0x%04X' % manDate), valid_man_str, ('0x%04X' % reserved), ('0x%08X' % serialNum), ('0x%04X' % regionFormatInterfaceCode), ('0x%02X' % rfic_r1), ('0x%02X' % rfic_fif), ('0x%02X' % rfic_r2), ('0x%02X' % rfic_fcf), ('0x%08X' % numBlockControlWindows) )

    def smbiosManagementInfo(self, tableLen, table_content):
        smbios_tables = ['BIOS Information', 'System Information', 'Baseboard (or Module) Information', 'System Enclosure or Chassis', 'Processor Information', 'Memory Controller Information, obsolete', 'Memory Module Information, obsolete', 'Cache Information', 'Port Connector Information', 'System Slots', 'On Board Devices Information, obsolete', 'OEM Strings', 'System Confirguration Options', 'BIOS Language Information', 'Group Associations', 'System Event Log', 'Physical Memory Array', 'Memory Device', '32-Bit Memory Error Information', 'Memory Array Mapped Address', 'Memory Device Mapped Address', 'Built-in Pointing Device', 'Portable Battery', 'System Reset', 'Hardware Security', 'System Power Controls', 'Voltage Probe', 'Cooling Device', 'Temperature Probe', 'Electrical Current Probe', 'Out-of-Band Remote Address', 'Boot Integrity Services (BIS) Entry Point', 'System Boot Information', '64-Bit Mmemory Error Information', 'Management Device', 'Management Device Component', 'Management Device Threshold Data', 'Memory Channel', 'IPMI Device Information', 'System Power Supply', 'Additional Information', 'Onboard Devices Extended Information', 'Mangement Controller Host Interface']
        reserved = struct.unpack('<L', table_content[4:8])[0]
        curPos = 8
        dataStr = ''
        return '''
    SMBIOS Management Information Structure [Type 3]
      Length                                                      : %s ( %d bytes )
      Reserved                                                    : %s
----Infinite loop occurs here.  Unable to further parse without more work to program.----
''' % ( ('0x%04X' % tableLen), tableLen, ('0x%08X' % reserved))
        while curPos < tableLen:
            smbios_table_type = struct.unpack('<B', table_content[curPos:curPos+1])[0]
            smbios_table_length = struct.unpack('<B', table_content[curPos + 1:curPos + 2])[0]
            smbios_table_name = 'Unknown'
            if smbios_table_type > 0 and smbios_table_type < 43:
                smbios_table_name = smbios_tables[smbios_table_type]
            elif smbios_table_type is 126:
                smbios_table_name =  'Inactive'
            elif smbios_table_type is 127:
                smbios_table_name = 'End-of-Table'
            cur_smbios_table_pos = 2
            smbios_table_data_str = ''
            while cur_smbios_table_pos < smbios_table_length:
                entry = struct.unpack('<B', table_content[curPos + cur_smbios_table_pos:curPos + cur_smbios_table_pos + 1])[0]
                smbios_table_data_str += '''%s ''' % ('0x%02X' % entry)
                cur_smbios_table_pos += 1
            dataStr += '''
      SMBIOS Table - %s
        Table Type                                                : %s ( %d ) - %s
        Table Length                                              : %s ( %d bytes )
        Data
          %s''' % (smbios_table_name, ('0x%02X' % smbios_table_type), smbios_table_type, smbios_table_name, ('0x%02X' % smbios_table_length), smbios_table_length, smbios_table_data_str)
        return '''
    SMBIOS Management Information Structure
      Length                                                      : %s ( %d bytes )%s
      Reserved                                                    : %s
''' % ( ('0x%04X' % tableLen), tableLen, ('0x%08X' % reserved), dataStr)

    def interleave(self, tableLen, table_content):
        interleaveStructureIndex = struct.unpack('<H', table_content[4:6])[0]
        reserved = struct.unpack('<H', table_content[6:8])[0]
        numLinesDescribed = struct.unpack('<L', table_content[8:12])[0]
        lineSz = struct.unpack('<L', table_content[12:16])[0]
        curLine = 0
        lines = ''
        while curLine < numLinesDescribed:
            lineInfo = struct.unpack('<L', table_content[curLine*4 + 16:curLine*4 + 20])[0]
            lines += '''
        Line %d Offset                                            : %s ( %d bytes ) ''' % ( (curLine + 1), ('0x%08X' % lineInfo), lineInfo)
            curLine +=1
        return (curLine -1)*4 + 20, '''
    Interleave Structure [Type 2]
      Length                                                      : %s ( %d bytes )
      Reserved                                                    : %s
      Number of Lines Described                                   : %s ( %d )
      Line Size                                                   : %s ( %d bytes )
      Lines %s
''' % ( ('0x%04X' % tableLen), tableLen, ('0x%04X' % reserved), ('0x%08X' % numLinesDescribed), numLinesDescribed, ('0x%08X' % lineSz), lineSz, lines)
    
    def parseMAP(self, tableLen, table_content):
        nfitDeviceHandle = struct.unpack('<L', table_content[4:8])[0]
        nvdimmPhysID = struct.unpack('<H', table_content[8:10])[0]
        nvdimmRegionID = struct.unpack('<H', table_content[10:12])[0]
        spaRangeStructureIndex = struct.unpack('<H', table_content[12:14])[0]
        nvdimmControlRegionSz = struct.unpack('<H', table_content[14:16])[0]
        nvdimmRegionSz = struct.unpack('<Q', table_content[16:24])[0]
        regionOffset = struct.unpack('<Q', table_content[24:32])[0]
        nvdimmPhysicalAddressRegionBase = struct.unpack('<Q', table_content[32:40])[0]
        interleaveStructIndex = struct.unpack('<H', table_content[40:42])[0]
        interleaveWays = struct.unpack('<H', table_content[42:44])[0]
        nvdimmStateFlags = struct.unpack('<H', table_content[44:46])[0]
        reserve = struct.unpack('<H', table_content[46:48])[0]
        return '''
    NVDIMM Region Mapping Structure [Type 1]
      Length                                                      : %s ( %d bytes )
      NFIT Device Handle                                          : %s
      NVDIMM Physical ID                                          : %s
      NVDIMM Region ID                                            : %s
      SPA Range Structure Index                                   : %s
      NVDIMM Control Region Structure Index                       : %s
      NVDIMM Region Size                                          : %s
      Region Offset                                               : %s
      NVDIMM Physical Address Region Base                         : %s
      Interleave Structure Index                                  : %s
      Interleave Ways                                             : %s
      NVDIMM State Flags                                          : %s
      Reserved                                                    : %s
''' % ( ('0x%04X' % tableLen), tableLen, ('0x%08X' % nfitDeviceHandle), ('0x%04X' % nvdimmPhysID), ('0x%04X' % nvdimmRegionID), ('0x%04X' % spaRangeStructureIndex), ('0x%016X' % nvdimmControlRegionSz), ('0x%016X' % nvdimmRegionSz), ('0x%016X' % regionOffset ), ('0x%016X' % nvdimmPhysicalAddressRegionBase), ('0x%04X' % interleaveStructIndex), ('0x%04X' % interleaveWays), ('0x%04X' % nvdimmStateFlags), ('0x%04X' % reserve) )

    def parseSPA(self, tableLen, table_content):
        volitileMemGUID = [ int('0x7305944f', 16) , int('0xfdda', 16), int('0x44e3', 16), int('0xb1', 16), int('0x6c', 16), int('0x3f', 16), int('0x22', 16), int('0xd2', 16), int('0x52', 16), int('0xe5', 16), int('0xd0', 16)]
        byteAddrPMGUID = [ int('0x66f0d379', 16) , int('0xb4f3', 16), int('0x4074', 16), int('0xac', 16), int('0x43', 16), int('0x0d', 16), int('0x33', 16), int('0x18', 16), int('0xb7', 16), int('0x8c', 16), int('0xdb', 16)]
        nvdimmControlRegionGUID = [ int('0x92f701f6', 16) , int('0x13b4', 16), int('0x405d', 16), int('0x91', 16), int('0x0b', 16), int('0x29', 16), int('0x93', 16), int('0x67', 16), int('0xe8', 16), int('0x23', 16), int('0x4c', 16)]
        nvdimmBlckDataWindowRegionGUID = [ int('0x91af0530', 16) , int('0x5d86', 16), int('0x470e', 16), int('0xa6', 16), int('0xb0', 16), int('0x0a', 16), int('0x2d', 16), int('0xb9', 16), int('0x40', 16), int('0x82', 16), int('0x49', 16)]
        ramDiskVirtualDiskVolGUID = [ int('0x77ab535a', 16) , int('0x45fc', 16), int('0x624b', 16), int('0x55', 16), int('0x60', 16), int('0xf7', 16), int('0xb2', 16), int('0x81', 16), int('0xd1', 16), int('0xf9', 16), int('0x6e', 16)]
        ramDiskVirtualCDVolGUID = [ int('0x3d5abd30', 16) , int('0x4175', 16), int('0x87ce', 16), int('0x6d', 16), int('0x64', 16), int('0xd2', 16), int('0xad', 16), int('0xe5', 16), int('0x23', 16), int('0xc4', 16), int('0xbb', 16)]
        ramDiskVirtualDiskPersisGUID = [ int('0x5cea02c9', 16) , int('0x4d07', 16), int('0x69d3', 16), int('0x26', 16), int('0x9f', 16), int('0x44', 16), int('0x96', 16), int('0xfb', 16), int('0xe0', 16), int('0x96', 16), int('0xf9', 16)]
        ramDiskVirtualCDPersisGUID = [ int('0x08018188', 16) , int('0x42cd', 16), int('0xbb48', 16), int('0x10', 16), int('0x0f', 16), int('0x53', 16), int('0x87', 16), int('0xd5', 16), int('0x3d', 16), int('0xed', 16), int('0x3d', 16)]
        spaRangeStructure = struct.unpack('<H', table_content[4:6])[0]
        flags = struct.unpack('<H', table_content[6:8])[0]
        flag1 = flags&1
        flag2 = flags&2
        flag3 = flags>>2
        reserved = struct.unpack('<L', table_content[8:12])[0]
        proximityDomain = struct.unpack('<L', table_content[12:16])[0]
        addressRangeTypeGUID_1 = struct.unpack('<L', table_content[16:20])[0]
        addressRangeTypeGUID_2 = struct.unpack('<H', table_content[20:22])[0]
        addressRangeTypeGUID_3 = struct.unpack('<H', table_content[22:24])[0]
        addressRangeTypeGUID_4 = struct.unpack('<B', table_content[24:25])[0]
        addressRangeTypeGUID_5 = struct.unpack('<B', table_content[25:26])[0]
        addressRangeTypeGUID_6 = struct.unpack('<B', table_content[26:27])[0]
        addressRangeTypeGUID_7 = struct.unpack('<B', table_content[27:28])[0]
        addressRangeTypeGUID_8 = struct.unpack('<B', table_content[28:29])[0]
        addressRangeTypeGUID_9 = struct.unpack('<B', table_content[29:30])[0]
        addressRangeTypeGUID_10 = struct.unpack('<B', table_content[30:31])[0]
        addressRangeTypeGUID_11 = struct.unpack('<B', table_content[31:32])[0]
        systemPARangeBase = struct.unpack('<Q', table_content[32:40])[0]
        SPARLen = struct.unpack('<Q', table_content[40:48])[0]
        addrRangeMemMapAttr = struct.unpack('<Q', table_content[48:56])[0]
        spaRangeStructure_str = ''
        if spaRangeStructure is 0:
            spaRangeStructure_str = ' - Value of 0 is reserved and shall not be used as an index'
        if flag1 is 1:
            flag1_str = ' - Control region only for hot add/online operation'
        else:
            flag1_str = ' - Control region not only for hot add/online operation'
        if flag2 is 1:
            flag2str = ' - Data in proximity region is valid'
        else:
            flag2_str = ' - Data in proximity region is not valid'
        if addrRangeMemMapAttr & 1 is 1:
            flag2str = 'EFI_MEMORY_UC'
        elif addrRangeMemMapAttr & 2 is 2:
            flag2str = 'EFI_MEMORY_WC'
        elif addrRangeMemMapAttr & 4 is 4:
            flag2str = 'EFI_MEMORY_WT'
        elif addrRangeMemMapAttr & 8 is 8:
            flag2str = 'EFI_MEMORY_WB'
        elif addrRangeMemMapAttr & 16 is 16:
            flag2str = 'EFI_MEMORY_UCE'
        elif addrRangeMemMapAttr & 4096 is 4096:
            flag2str = 'EFI_MEMORY_WP'
        elif addrRangeMemMapAttr & 8192 is 8192:
            flag2str = 'EFI_MEMORY_RP'
        elif addrRangeMemMapAttr& 16384 is 16384:
            flag2str = 'EFI_MEMORY_XP'
        elif addrRangeMemMapAttr is 32768 is 32768:
            flag2str = 'EFI_MEMORY_NV'
        elif addrRangeMemMapAttr is 65536 is 65536:
            flag2str = 'EFI_MEMORY_MORE_RELIABLE'
        else:
            flag2_str = 'undefined'
        addressRangeTypeGUID = [ addressRangeTypeGUID_1, addressRangeTypeGUID_2, addressRangeTypeGUID_3, addressRangeTypeGUID_4, addressRangeTypeGUID_5, addressRangeTypeGUID_6, addressRangeTypeGUID_7, addressRangeTypeGUID_8, addressRangeTypeGUID_9, addressRangeTypeGUID_10, addressRangeTypeGUID_11]
        if addressRangeTypeGUID == volitileMemGUID:
            artg_str = 'Volitile Memory Region'
        elif addressRangeTypeGUID == byteAddrPMGUID:
            artg_str = 'Byte Addressable Persistent Memory (PM) Region'
        elif addressRangeTypeGUID == nvdimmControlRegionGUID:
            artg_str = 'NVDIMM Control Region'
        elif addressRangeTypeGUID == nvdimmBlckDataWindowRegionGUID:
            artg_str = 'NVDIMM Block Data Window Region'
        elif addressRangeTypeGUID == ramDiskVirtualDiskVolGUID:
            artg_str = 'RAM Disk supporting a Virtual Disk Region - Volitile (volitile memory region containing raw disk format)'
        elif addressRangeTypeGUID == ramDiskVirtualCDVolGUID:
            artg_str = 'RAM Disk supporting a Virtual CD Region - Volitile (volitile memory region containing an ISO image)'
        elif addressRangeTypeGUID == ramDiskVirtualDiskPersisGUID:
            artg_str = 'RAM Disk supporting Virtual Disk Region - Persistent (persistent memroy region containing raw disk format)'
        elif addressRangeTypeGUID == ramDiskVirtualCDPersisGUID:
            artg_str = 'RAM Disk supporting a Virtual CD Region - Persistent (persistent memory region containing an ISO image)'
        else:
            artg_str = 'Not in specification, could be a vendor defined GUID'
        return '''
    System Physical Address (SPA) Range Structure [Type 1]
      Length                                                      : %s ( %d bytes )
      SPA Range Structure Index                                   : %s%s
      Flags                                                       : %s
        Bit[0] (Add/Online Operation Only)                        : %s%s
        Bit[1] (Proximity Domain Validity)                        : %s%s
        Bits[15:2]                                                : %s - Reserved
      Reserved                                                    : %s
      Proximity Domain                                            : %s - must match value in SRAT table
      Address Range Type GUID                                     : %s %s %s %s %s %s %s %s %s %s %s - %s
      System Physical Address Range Base                          : %s
      System Physical Address Range Length                        : %s (%d bytes)
      Address Range Memory Mapping Attribute                      : %s
''' % ( ('0x%04X' % tableLen), tableLen, ('0x%04X' % spaRangeStructure), spaRangeStructure_str, ('0x%04X' % flags), ('0x%04X' % flag1), flag1_str, ('0x%04X' % flag2), flag2_str, ('0x%04X' % flag3), ('0x%08X' % reserved), ('0x%08X' %  proximityDomain ), ('0x%08X' %  addressRangeTypeGUID_1 ), ('0x%04X' %  addressRangeTypeGUID_2 ), ('0x%04X' %  addressRangeTypeGUID_3 ), ('0x%02X' %  addressRangeTypeGUID_4 ), ('0x%02X' %  addressRangeTypeGUID_5 ), ('0x%02X' %  addressRangeTypeGUID_6 ), ('0x%02X' %  addressRangeTypeGUID_7 ), ('0x%02X' %  addressRangeTypeGUID_8 ), ('0x%02X' %  addressRangeTypeGUID_9 ), ('0x%02X' %  addressRangeTypeGUID_10 ), ('0x%02X' %  addressRangeTypeGUID_11 ), artg_str, ('0x%016X' %  systemPARangeBase ), ('0x%016X' %  SPARLen ), SPARLen, ('0x%016X' %  addrRangeMemMapAttr ))

    def parseStructures(self, table_content):
        notFinished = True
        curPos = 0
        result = ''
        while notFinished:
            tableType = struct.unpack('<H', table_content[curPos:curPos+2])[0]
            tableLen = struct.unpack('<H', table_content[curPos+2:curPos+4])[0]
            result += ''' Length:                    %d''' % (self.total_length)
            if tableType is 0:
                result += self.parseSPA( tableLen, table_content[curPos:] )
                curPos = curPos + tableLen
            elif tableType is 1:
                result += self.parseMAP( tableLen, table_content[curPos:] )
                curPos = curPos + tableLen
            elif tableType is 2:
                sz, result_str = self.interleave( tableLen, table_content[curPos:] )
                result += result_str
                curPos = curPos + tableLen
            elif tableType is 3:
                result += self.smbiosManagementInfo( tableLen, table_content[curPos:] )
                curPos = curPos + tableLen
            elif tableType is 4:
                result += self.nvdimmControlRegionStructMark( tableLen, table_content[curPos:] )
                curPos += tableLen
            elif tableType is 5:
                result += self.nvdimmBlockDataWindowsRegionStruct( tableLen, table_content[curPos:] )
                curPos = curPos + tableLen
            elif tableType is 6:
                sz, result_str = self.flushHintAddrStruct( tableLen, table_content[curPos:] )
                result += result_str
                curPos = curPos + tableLen
            elif tableType is 7:
                result += self.platCapStruct( tableLen, table_content[curPos:] )
                curPos = curPos + tableLen
            else:
                pass
            if curPos >= self.total_length:
                notFinished = False
        return result

    def parse(self, table_content):
        reserved = struct.unpack('<L', table_content[0:4])[0]
        NFITstructures = self.parseStructures( table_content[4:] )
        self.results = '''==================================================================
  NVDIMM Firmware Interface Table ( NFIT )
==================================================================
  Reserved                                                      : %s
  NFIT Structures%s

''' % ( ('0x%08X' % reserved), NFITstructures )

    def __str__(self):
        return self.results
