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
Access to IOMMU engines
"""

from chipsec.hal import hal_base, mmio, paging
from chipsec.library.exceptions import IOMMUError

IOMMU_ENGINE_DEFAULT = 'VTD'
IOMMU_ENGINE_GFX = 'GFXVTD'


IOMMU_ENGINES = {
    IOMMU_ENGINE_GFX: 'GFXVTBAR',
    IOMMU_ENGINE_DEFAULT: 'VTBAR'
}


class IOMMU(hal_base.HALBase):

    def __init__(self, cs):
        super(IOMMU, self).__init__(cs)
        self.mmio = mmio.MMIO(cs)

    def get_IOMMU_Base_Address(self, iommu_engine: str) -> int:
        if iommu_engine in IOMMU_ENGINES:
            vtd_base_name = IOMMU_ENGINES[iommu_engine]
        else:
            raise IOMMUError(f'IOMMUError: unknown IOMMU engine 0x{iommu_engine:X}')

        if self.mmio.is_MMIO_BAR_defined(vtd_base_name):
            (base, _) = self.mmio.get_MMIO_BAR_base_address(vtd_base_name)
        else:
            raise IOMMUError(f'IOMMUError: IOMMU BAR {vtd_base_name} is not defined in the config')
        return base

    def is_IOMMU_Engine_Enabled(self, iommu_engine: str) -> bool:
        if iommu_engine in IOMMU_ENGINES:
            vtd_base_name = IOMMU_ENGINES[iommu_engine]
        else:
            raise IOMMUError(f'IOMMUError: unknown IOMMU engine 0x{iommu_engine:X}')
        return self.mmio.is_MMIO_BAR_defined(vtd_base_name) and self.mmio.is_MMIO_BAR_enabled(vtd_base_name)

    def is_IOMMU_Translation_Enabled(self, iommu_engine: str) -> bool:
        tes = self.cs.register.read_field(f'{IOMMU_ENGINES[iommu_engine]}_GSTS', 'TES')
        return (1 == tes)

    def set_IOMMU_Translation(self, iommu_engine: str, te: int) -> bool:
        return self.cs.register.write_field(f'{IOMMU_ENGINES[iommu_engine]}_GCMD', 'TE', te)

    def dump_IOMMU_configuration(self, iommu_engine: str) -> None:
        self.logger.log("==================================================================")
        vtd = IOMMU_ENGINES[iommu_engine]
        self.logger.log(f'[iommu] {iommu_engine} IOMMU Engine Configuration')
        self.logger.log("==================================================================")
        self.logger.log(f'Base register (BAR)       : {vtd}')
        reg = self.cs.register.read(vtd)
        self.logger.log(f'BAR register value        : 0x{reg:X}')
        if reg == 0:
            return
        base = self.get_IOMMU_Base_Address(iommu_engine)
        self.logger.log(f'MMIO base                 : 0x{base:016X}')
        self.logger.log("------------------------------------------------------------------")
        ver_min = self.cs.register.read_field(f'{vtd}_VER', 'MIN')
        ver_max = self.cs.register.read_field(f'{vtd}_VER', 'MAX')
        self.logger.log(f'Version                   : {ver_max:X}.{ver_min:X}')
        enabled = self.is_IOMMU_Engine_Enabled(iommu_engine)
        self.logger.log(f'Engine enabled            : {enabled:d}')
        te = self.is_IOMMU_Translation_Enabled(iommu_engine)
        self.logger.log(f'Translation enabled       : {te:d}')
        rtaddr_rta = self.cs.register.read_field(f'{vtd}_RTADDR', 'RTA', True)
        self.logger.log(f'Root Table Address        : 0x{rtaddr_rta:016X}')
        irta = self.cs.register.read_field(f'{vtd}_IRTA', 'IRTA')
        self.logger.log(f'Interrupt Remapping Table : 0x{irta:016X}')
        self.logger.log("------------------------------------------------------------------")
        self.logger.log("Protected Memory:")
        pmen_epm = self.cs.register.read_field(f'{vtd}_PMEN', 'EPM')
        pmen_prs = self.cs.register.read_field(f'{vtd}_PMEN', 'PRS')
        self.logger.log(f'  Enabled                 : {pmen_epm:d}')
        self.logger.log(f'  Status                  : {pmen_prs:d}')
        plmbase = self.cs.register.read_field(f'{vtd}_PLMBASE', 'PLMB')
        plmlimit = self.cs.register.read_field(f'{vtd}_PLMLIMIT', 'PLML')
        phmbase = self.cs.register.read_field(f'{vtd}_PHMBASE', 'PHMB')
        phmlimit = self.cs.register.read_field(f'{vtd}_PHMLIMIT', 'PHML')
        self.logger.log(f'  Low Memory Base         : 0x{plmbase:016X}')
        self.logger.log(f'  Low Memory Limit        : 0x{plmlimit:016X}')
        self.logger.log(f'  High Memory Base        : 0x{phmbase:016X}')
        self.logger.log(f'  High Memory Limit       : 0x{phmlimit:016X}')
        self.logger.log("------------------------------------------------------------------")
        self.logger.log("Capabilities:\n")
        cap_reg = self.cs.register.read(f'{vtd}_CAP')
        self.cs.register.print(f'{vtd}_CAP', cap_reg)
        ecap_reg = self.cs.register.read(f'{vtd}_ECAP')
        self.cs.register.print(f'{vtd}_ECAP', ecap_reg)
        self.logger.log('')

    def dump_IOMMU_page_tables(self, iommu_engine: str) -> None:
        vtd = IOMMU_ENGINES[iommu_engine]
        if self.cs.register.read(vtd) == 0:
            self.logger.log(f'[iommu] {vtd} value is zero')
            return
        te = self.is_IOMMU_Translation_Enabled(iommu_engine)
        self.logger.log(f'[iommu] Translation enabled    : {te:d}')
        rtaddr_reg = self.cs.register.read(f'{vtd}_RTADDR')
        rtaddr_rta = self.cs.register.get_field(f'{vtd}_RTADDR', rtaddr_reg, 'RTA', True)
        rtaddr_rtt = self.cs.register.get_field(f'{vtd}_RTADDR', rtaddr_reg, 'RTT')
        self.logger.log(f'[iommu] Root Table Address/Type: 0x{rtaddr_rta:016X}/{rtaddr_rtt:X}')

        ecap_reg = self.cs.register.read(f'{vtd}_ECAP')
        ecs = self.cs.register.get_field(f'{vtd}_ECAP', ecap_reg, 'ECS')
        pasid = self.cs.register.get_field(f'{vtd}_ECAP', ecap_reg, 'PASID')
        self.logger.log(f'[iommu] PASID / ECS            : {pasid:X} / {ecs:X}')

        if 0xFFFFFFFFFFFFFFFF != rtaddr_reg:
            if te:
                self.logger.log(f'[iommu] Dumping VT-d page table hierarchy at 0x{rtaddr_rta:016X} (vtd_context_{rtaddr_rta:08X})')
                paging_vtd = paging.c_vtd_page_tables(self.cs)
                paging_vtd.read_vtd_context(f'vtd_context_{rtaddr_rta:08X}', rtaddr_rta)
                self.logger.log(f'[iommu] Total VTd domains: {len(paging_vtd.domains):d}')
                for domain in paging_vtd.domains:
                    paging_vtd.read_pt_and_show_status(f'vtd_{domain:08X}', 'VTd', domain)
            else:
                self.logger.log(f"[iommu] translation via VT-d engine '{iommu_engine}' is not enabled")
        else:
            self.logger.log_error("Cannot access VT-d registers")

    def dump_IOMMU_status(self, iommu_engine: str) -> None:
        vtd = IOMMU_ENGINES[iommu_engine]
        self.logger.log('==================================================================')
        self.logger.log(f'[iommu] {iommu_engine} IOMMU Engine Status:')
        self.logger.log('==================================================================')
        if self.cs.register.read(vtd) == 0:
            self.logger.log(f'[iommu] {vtd} value is zero')
            return None
        gsts_reg = self.cs.register.read(f'{vtd}_GSTS')
        self.cs.register.print(f'{vtd}_GSTS', gsts_reg)
        fsts_reg = self.cs.register.read(f'{vtd}_FSTS')
        self.cs.register.print(f'{vtd}_FSTS', fsts_reg)
        frcdl_reg = self.cs.register.read(f'{vtd}_FRCDL')
        self.cs.register.print(f'{vtd}_FRCDL', frcdl_reg)
        frcdh_reg = self.cs.register.read(f'{vtd}_FRCDH')
        self.cs.register.print(f'{vtd}_FRCDH', frcdh_reg)
        ics_reg = self.cs.register.read(f'{vtd}_ICS')
        self.cs.register.print(f'{vtd}_ICS', ics_reg)
        return None
