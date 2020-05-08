#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2020, Intel Corporation
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

from chipsec.hal import hal_base, mmio, paging

IOMMU_ENGINE_DEFAULT = 'VTD'
IOMMU_ENGINE_GFX     = 'GFXVTD'


IOMMU_ENGINES = {
  IOMMU_ENGINE_GFX    : 'GFXVTBAR',
  IOMMU_ENGINE_DEFAULT: 'VTBAR'
}


class IOMMUError (RuntimeError):
    pass

class IOMMU(hal_base.HALBase):

    def __init__(self, cs):
        super(IOMMU, self).__init__(cs)
        self.mmio = mmio.MMIO(cs)

    def get_IOMMU_Base_Address( self, iommu_engine ):
        if iommu_engine in IOMMU_ENGINES: vtd_base_name = IOMMU_ENGINES[iommu_engine]
        else: raise IOMMUError ('IOMMUError: unknown IOMMU engine 0x{:X}'.format(iommu_engine) )

        if self.mmio.is_MMIO_BAR_defined(vtd_base_name):
            (base, size) = self.mmio.get_MMIO_BAR_base_address(vtd_base_name)
        else:
            raise IOMMUError ('IOMMUError: IOMMU BAR {} is not defined in the config'.format(vtd_base_name))
        return base

    def is_IOMMU_Engine_Enabled( self, iommu_engine ):
        if iommu_engine in IOMMU_ENGINES: vtd_base_name = IOMMU_ENGINES[iommu_engine]
        else: raise IOMMUError ('IOMMUError: unknown IOMMU engine 0x{:X}'.format(iommu_engine) )
        return self.mmio.is_MMIO_BAR_defined(vtd_base_name) and self.mmio.is_MMIO_BAR_enabled(vtd_base_name)

    def is_IOMMU_Translation_Enabled( self, iommu_engine ):
        tes = self.cs.read_register_field( IOMMU_ENGINES[ iommu_engine ] + '_GSTS', 'TES' )
        return (1==tes)

    def set_IOMMU_Translation( self, iommu_engine, te ):
        return self.cs.write_register_field( IOMMU_ENGINES[ iommu_engine ] + '_GCMD', 'TE', te )


    def dump_IOMMU_configuration( self, iommu_engine ):
        self.logger.log( "==================================================================" )
        vtd = IOMMU_ENGINES[ iommu_engine ]
        self.logger.log( "[iommu] {} IOMMU Engine Configuration".format(iommu_engine) )
        self.logger.log( "==================================================================" )
        self.logger.log( "Base register (BAR)       : {}".format(vtd) )
        reg = self.cs.read_register( vtd )
        self.logger.log( "BAR register value        : 0x{:X}".format(reg) )
        base    = self.get_IOMMU_Base_Address( iommu_engine )
        self.logger.log( "MMIO base                 : 0x{:016X}".format(base) )
        self.logger.log( "------------------------------------------------------------------" )
        ver_min = self.cs.read_register_field( vtd + '_VER', 'MIN' )
        ver_max = self.cs.read_register_field( vtd + '_VER', 'MAX' )
        self.logger.log( "Version                   : {:X}.{:X}".format(ver_max,ver_min) )
        enabled = self.is_IOMMU_Engine_Enabled( iommu_engine )
        self.logger.log( "Engine enabled            : {:d}".format(enabled) )
        te      = self.is_IOMMU_Translation_Enabled( iommu_engine )
        self.logger.log( "Translation enabled       : {:d}".format(te) )
        rtaddr_rta = self.cs.read_register_field( vtd + '_RTADDR', 'RTA', True )
        self.logger.log( "Root Table Address        : 0x{:016X}".format(rtaddr_rta) )
        irta = self.cs.read_register_field( vtd + '_IRTA', 'IRTA' )
        self.logger.log( "Interrupt Remapping Table : 0x{:016X}".format(irta) )
        self.logger.log( "------------------------------------------------------------------" )
        self.logger.log( "Protected Memory:" )
        pmen_epm = self.cs.read_register_field( vtd + '_PMEN', 'EPM' )
        pmen_prs = self.cs.read_register_field( vtd + '_PMEN', 'PRS' )
        self.logger.log( "  Enabled                 : {:d}".format(pmen_epm) )
        self.logger.log( "  Status                  : {:d}".format(pmen_prs) )
        plmbase  = self.cs.read_register_field( vtd + '_PLMBASE', 'PLMB' )
        plmlimit = self.cs.read_register_field( vtd + '_PLMLIMIT', 'PLML' )
        phmbase  = self.cs.read_register_field( vtd + '_PHMBASE', 'PHMB' )
        phmlimit = self.cs.read_register_field( vtd + '_PHMLIMIT', 'PHML' )
        self.logger.log( "  Low Memory Base         : 0x{:016X}".format(plmbase) )
        self.logger.log( "  Low Memory Limit        : 0x{:016X}".format(plmlimit) )
        self.logger.log( "  High Memory Base        : 0x{:016X}".format(phmbase) )
        self.logger.log( "  High Memory Limit       : 0x{:016X}".format(phmlimit) )
        self.logger.log( "------------------------------------------------------------------" )
        self.logger.log( "Capabilities:\n" )
        cap_reg = self.cs.read_register( vtd + '_CAP' )
        self.cs.print_register( vtd + '_CAP', cap_reg )
        ecap_reg = self.cs.read_register( vtd + '_ECAP' )
        self.cs.print_register( vtd + '_ECAP', ecap_reg )
        self.logger.log( '' )


    def dump_IOMMU_page_tables( self, iommu_engine ):
        vtd = IOMMU_ENGINES[ iommu_engine ]
        te  = self.is_IOMMU_Translation_Enabled( iommu_engine )
        self.logger.log( "[iommu] Translation enabled    : {:d}".format(te) )
        rtaddr_reg = self.cs.read_register( vtd + '_RTADDR' )
        rtaddr_rta = self.cs.get_register_field( vtd + '_RTADDR', rtaddr_reg, 'RTA', True )
        rtaddr_rtt = self.cs.get_register_field( vtd + '_RTADDR', rtaddr_reg, 'RTT' )
        #rtaddr_rta = self.cs.read_register_field( vtd + '_RTADDR', 'RTA', True )
        #rtaddr_rtt = self.cs.read_register_field( vtd + '_RTADDR', 'RTT' )
        self.logger.log( "[iommu] Root Table Address/Type: 0x{:016X}/{:X}".format(rtaddr_rta,rtaddr_rtt) )

        ecap_reg   = self.cs.read_register( vtd + '_ECAP' )
        ecs        = self.cs.get_register_field( vtd + '_ECAP', ecap_reg, 'ECS' )
        pasid      = self.cs.get_register_field( vtd + '_ECAP', ecap_reg, 'PASID' )
        self.logger.log( '[iommu] PASID / ECS            : {:X} / {:X}'.format(pasid, ecs))

        if 0xFFFFFFFFFFFFFFFF != rtaddr_reg:
            if te:
                self.logger.log( '[iommu] dumping VT-d page table hierarchy at 0x{:016X} (vtd_context_{:08X})..'.format(rtaddr_rta,rtaddr_rta) )
                paging_vtd = paging.c_vtd_page_tables( self.cs )
                paging_vtd.read_vtd_context('vtd_context_{:08X}'.format(rtaddr_rta), rtaddr_rta)
                self.logger.log( '[iommu] total VTd domains: {:d}'.format(len(paging_vtd.domains)))
                for domain in paging_vtd.domains:
                    paging_vtd.read_pt_and_show_status('vtd_{:08X}'.format(domain), 'VTd', domain)
                    #if paging_vtd.failure: self.logger.error( "couldn't dump VT-d page tables" )    
            else:
                self.logger.log( "[iommu] translation via VT-d engine '{}' is not enabled".format(iommu_engine) )
        else:
            self.logger.error( "cannot access VT-d registers" )


    def dump_IOMMU_status( self, iommu_engine ):
        vtd = IOMMU_ENGINES[ iommu_engine ]
        self.logger.log( "==================================================================" )
        self.logger.log( "[iommu] {} IOMMU Engine Status:".format(iommu_engine) )
        self.logger.log( "==================================================================" )
        gsts_reg = self.cs.read_register( vtd + '_GSTS' )
        self.cs.print_register( vtd + '_GSTS', gsts_reg )
        fsts_reg = self.cs.read_register( vtd + '_FSTS' )
        self.cs.print_register( vtd + '_FSTS', fsts_reg )
        frcdl_reg = self.cs.read_register( vtd + '_FRCDL' )
        self.cs.print_register( vtd + '_FRCDL', frcdl_reg )
        frcdh_reg = self.cs.read_register( vtd + '_FRCDH' )
        self.cs.print_register( vtd + '_FRCDH', frcdh_reg )
        ics_reg = self.cs.read_register( vtd + '_ICS' )
        self.cs.print_register( vtd + '_ICS', ics_reg )
