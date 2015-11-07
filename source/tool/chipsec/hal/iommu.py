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




"""
Access to IOMMU engines
"""

from chipsec.logger import *

import chipsec.hal.iobar
import chipsec.hal.mmio

IOMMU_ENGINE_DEFAULT = 'VTD'
IOMMU_ENGINE_GFX     = 'GFXVTD'


IOMMU_ENGINES = {
  IOMMU_ENGINE_GFX    : 'GFXVTBAR',
  IOMMU_ENGINE_DEFAULT: 'VTBAR'
}


class IOMMUError (RuntimeError):
    pass

class iommu:
    def __init__( self, cs ):
        self.cs = cs

    def get_IOMMU_Base_Address( self, iommu_engine ):
        if iommu_engine in IOMMU_ENGINES: vtd_base_name = IOMMU_ENGINES[iommu_engine]
        else: raise IOMMUError, ('IOMMUError: unknown IOMMU engine 0x%X' % iommu_engine )

        if chipsec.hal.mmio.is_MMIO_BAR_defined( self.cs, vtd_base_name ):
            (base, size) = chipsec.hal.mmio.get_MMIO_BAR_base_address( self.cs, vtd_base_name )
        else:
            raise IOMMUError, ('IOMMUError: IOMMU BAR %s is not defined in the config' % vtd_base_name )
        
        return base

    def is_IOMMU_Engine_Enabled( self, iommu_engine ):
        if iommu_engine in IOMMU_ENGINES: vtd_base_name = IOMMU_ENGINES[iommu_engine]
        else: raise IOMMUError, ('IOMMUError: unknown IOMMU engine 0x%X' % iommu_engine )
        return chipsec.hal.mmio.is_MMIO_BAR_defined( self.cs, vtd_base_name ) and chipsec.hal.mmio.is_MMIO_BAR_enabled( self.cs, vtd_base_name )

    def is_IOMMU_Translation_Enabled( self, iommu_engine ):
        tes = chipsec.chipset.read_register_field( self.cs, IOMMU_ENGINES[ iommu_engine ] + '_GSTS', 'TES' )
        return (1==tes)

    def set_IOMMU_Translation( self, iommu_engine, te ):
        return chipsec.chipset.write_register_field( self.cs, IOMMU_ENGINES[ iommu_engine ] + '_GCMD', 'TE', te )


    def dump_IOMMU_configuration( self, iommu_engine ):
        logger().log( "==================================================================" )
        vtd = IOMMU_ENGINES[ iommu_engine ]
        logger().log( "[iommu] %s IOMMU Engine Configuration" % iommu_engine )
        logger().log( "==================================================================" )
        logger().log( "Base register (BAR)       : %s" % vtd )
        reg = chipsec.chipset.read_register( self.cs, vtd )
        logger().log( "BAR register value        : 0x%X" % reg )
        base    = self.get_IOMMU_Base_Address( iommu_engine )
        logger().log( "MMIO base                 : 0x%016X" % base )
        logger().log( "------------------------------------------------------------------" )
        ver_min = chipsec.chipset.read_register_field( self.cs, vtd + '_VER', 'MIN' )
        ver_max = chipsec.chipset.read_register_field( self.cs, vtd + '_VER', 'MAX' )
        logger().log( "Version                   : %X.%X" % (ver_max,ver_min) )
        enabled = self.is_IOMMU_Engine_Enabled( iommu_engine )
        logger().log( "Engine enabled            : %d" % enabled )
        te      = self.is_IOMMU_Translation_Enabled( iommu_engine )
        logger().log( "Translation enabled       : %d" % te )
        rtaddr_rta = chipsec.chipset.read_register_field( self.cs, vtd + '_RTADDR', 'RTA' )
        logger().log( "Root Table Address        : 0x%016X" % rtaddr_rta )
        irta = chipsec.chipset.read_register_field( self.cs, vtd + '_IRTA', 'IRTA' )
        logger().log( "Interrupt Remapping Table : 0x%016X" % irta )
        logger().log( "------------------------------------------------------------------" )
        logger().log( "Protected Memory:" )
        pmen_epm = chipsec.chipset.read_register_field( self.cs, vtd + '_PMEN', 'EPM' )
        pmen_prs = chipsec.chipset.read_register_field( self.cs, vtd + '_PMEN', 'PRS' )
        logger().log( "  Enabled                 : %d" % pmen_epm )
        logger().log( "  Status                  : %d" % pmen_prs )
        plmbase  = chipsec.chipset.read_register_field( self.cs, vtd + '_PLMBASE', 'PLMB' )
        plmlimit = chipsec.chipset.read_register_field( self.cs, vtd + '_PLMLIMIT', 'PLML' )
        phmbase  = chipsec.chipset.read_register_field( self.cs, vtd + '_PHMBASE', 'PHMB' )
        phmlimit = chipsec.chipset.read_register_field( self.cs, vtd + '_PHMLIMIT', 'PHML' )
        logger().log( "  Low Memory Base         : 0x%016X" % plmbase )
        logger().log( "  Low Memory Limit        : 0x%016X" % plmlimit )
        logger().log( "  High Memory Base        : 0x%016X" % phmbase )
        logger().log( "  High Memory Limit       : 0x%016X" % phmlimit )
        logger().log( "------------------------------------------------------------------" )
        logger().log( "Capabilities:\n" )
        cap_reg = chipsec.chipset.read_register( self.cs, vtd + '_CAP' )
        chipsec.chipset.print_register( self.cs, vtd + '_CAP', cap_reg )
        ecap_reg = chipsec.chipset.read_register( self.cs, vtd + '_ECAP' )
        chipsec.chipset.print_register( self.cs, vtd + '_ECAP', ecap_reg )
        logger().log( '' )

    def dump_IOMMU_status( self, iommu_engine ):
        vtd = IOMMU_ENGINES[ iommu_engine ]
        logger().log( "==================================================================" )
        logger().log( "[iommu] %s IOMMU Engine Status:" % iommu_engine )
        logger().log( "==================================================================" )
        gsts_reg = chipsec.chipset.read_register( self.cs, vtd + '_GSTS' )
        chipsec.chipset.print_register( self.cs, vtd + '_GSTS', gsts_reg )
        fsts_reg = chipsec.chipset.read_register( self.cs, vtd + '_FSTS' )
        chipsec.chipset.print_register( self.cs, vtd + '_FSTS', fsts_reg )
        frcdl_reg = chipsec.chipset.read_register( self.cs, vtd + '_FRCDL' )
        chipsec.chipset.print_register( self.cs, vtd + '_FRCDL', frcdl_reg )
        frcdh_reg = chipsec.chipset.read_register( self.cs, vtd + '_FRCDH' )
        chipsec.chipset.print_register( self.cs, vtd + '_FRCDH', frcdh_reg )
        ics_reg = chipsec.chipset.read_register( self.cs, vtd + '_ICS' )
        chipsec.chipset.print_register( self.cs, vtd + '_ICS', ics_reg )
