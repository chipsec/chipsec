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

from chipsec.hal import hal_base
from chipsec.hal.common import mmio
from chipsec.library.exceptions import IOMMUError
from chipsec.library import paging
from chipsec.library.strings import join_hex_values, join_int_values

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
        gsts_obj = self.cs.register.get_list_by_name(f'{IOMMU_ENGINES[iommu_engine]}_GSTS')
        return gsts_obj.is_all_field_value(1, 'TES')

    def set_IOMMU_Translation(self, iommu_engine: str, te: int) -> bool:
        try:
            gcmd_list = self.cs.register.get_list_by_name(f'{IOMMU_ENGINES[iommu_engine]}_GCMD')
            gcmd_list.write_field('TE', te)
        except Exception:
            return False
        return True

    def dump_IOMMU_configuration(self, iommu_engine: str) -> None:
        self.logger.log("==================================================================")
        vtd = IOMMU_ENGINES[iommu_engine]
        self.logger.log(f'[iommu] {iommu_engine} IOMMU Engine Configuration')
        self.logger.log("==================================================================")
        self.logger.log(f'Base register (BAR)       : {vtd}')
        bar_obj = self.cs.register.get_list_by_name(vtd)
        bar = join_hex_values(bar_obj.read(), "")
        self.logger.log(f'BAR register value        : {bar}')
        if bar_obj.is_all_value(0):
            return
        base = self.get_IOMMU_Base_Address(iommu_engine)
        self.logger.log(f'MMIO base                 : 0x{base:016X}')
        self.logger.log("------------------------------------------------------------------")
        ver_obj = self.cs.register.get_list_by_name(f'{vtd}_VER')
        ver_min = ver_obj.read_field('MIN')
        ver_max = ver_obj.get_field('MAX')
        if len(ver_max) == len(ver_min):
            for max, min in ver_max, ver_min:
                self.logger.log(f'Version                   : {max:X}.{min:X}')
        enabled = self.is_IOMMU_Engine_Enabled(iommu_engine)
        self.logger.log(f'Engine enabled            : {enabled:d}')
        te = self.is_IOMMU_Translation_Enabled(iommu_engine)
        self.logger.log(f'Translation enabled       : {te:d}')
        rtaddr_obj = self.cs.register.get_list_by_name(f'{vtd}_RTADDR')
        rtaddr_rta = join_hex_values(rtaddr_obj.read_field('RTA', True))
        self.logger.log(f'Root Table Address        : {rtaddr_rta}')
        irta_obj = self.cs.register.get_list_by_name(f'{vtd}_IRTA')
        irta = join_hex_values(irta_obj.read_field('IRTA'))
        self.logger.log(f'Interrupt Remapping Table : {irta}')
        self.logger.log("------------------------------------------------------------------")
        self.logger.log("Protected Memory:")
        pmen_obj = self.cs.register.get_list_by_name(f'{vtd}_PMEN')
        pmen_epm = join_int_values(pmen_obj.read_field('EPM'))
        pmen_prs = join_int_values(pmen_obj.get_field('PRS'))
        self.logger.log(f'  Enabled                 : {pmen_epm}')
        self.logger.log(f'  Status                  : {pmen_prs}')
        plmbase_obj = self.cs.register.get_list_by_name(f'{vtd}_PLMBASE')
        plmbase = join_hex_values(plmbase_obj.read_field('PLMB'), size="016")
        plmlimit_obj = self.cs.register.get_list_by_name(f'{vtd}_PLMLIMIT')
        plmlimit = join_hex_values(plmlimit_obj.read_field('PLML'), size="016")
        phmbase_obj = self.cs.register.get_list_by_name(f'{vtd}_PHMBASE')
        phmbase = join_hex_values(phmbase_obj.read_field('PHMB'), size="016")
        phmlimit_obj = self.cs.register.get_list_by_name(f'{vtd}_PHMLIMIT')
        phmlimit = join_hex_values(phmlimit_obj.read_field('PHML'), size="016")
        self.logger.log(f'  Low Memory Base         : {plmbase}')
        self.logger.log(f'  Low Memory Limit        : {plmlimit}')
        self.logger.log(f'  High Memory Base        : {phmbase}')
        self.logger.log(f'  High Memory Limit       : {phmlimit}')
        self.logger.log("------------------------------------------------------------------")
        self.logger.log("Capabilities:\n")
        self.cs.register.get_list_from_name(f'{vtd}_CAP').read_and_print()
        self.cs.register.get_list_from_name(f'{vtd}_ECAP').read_and_print()
        self.logger.log('')

    def dump_IOMMU_page_tables(self, iommu_engine: str) -> None:
        vtd = IOMMU_ENGINES[iommu_engine]
        vtd_obj = self.cs.register.get_list_by_name(vtd)
        vtd_obj.read()
        if vtd_obj.is_all_value(0):
            self.logger.log(f'[iommu] {vtd} value is zero')
            return
        te = self.is_IOMMU_Translation_Enabled(iommu_engine)
        self.logger.log(f'[iommu] Translation enabled    : {te:d}')
        rtaddr_reg = self.cs.register.get_list_from_name(f'{vtd}_RTADDR')
        rtaddr_rta = rtaddr_reg.read_field('RTA', True)
        rtaddr_rtt = rtaddr_reg.get_field('RTT')
        for rta, rtt in rtaddr_rta, rtaddr_rtt:
            self.logger.log(f'[iommu] Root Table Address/Type: 0x{rta:016X}/{rtt:X}')

        ecap_reg = self.cs.register.get_list_from_name(f'{vtd}_ECAP')
        ecap_ecs = ecap_reg.read_field('ECS')
        ecap_pasid = ecap_reg.get_field('PASID')
        for ecs, pasid in ecap_ecs, ecap_pasid:
            self.logger.log(f'[iommu] PASID / ECS            : {pasid:X} / {ecs:X}')

        if not rtaddr_reg.is_any_value(0xFFFFFFFFFFFFFFFF):
            if te:
                self.logger.log(f'[iommu] Dumping VT-d page table hierarchy at 0x{rtaddr_rta[0]:016X} (vtd_context_{rtaddr_rta[0]:08X})')
                paging_vtd = paging.c_vtd_page_tables(self.cs) # TODO
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
        vtd_obj = self.cs.register.get_list_by_name(vtd)
        vtd_obj.read()
        if vtd_obj.is_all_value(0):
            self.logger.log(f'[iommu] {vtd} value is zero')
            return None
        self.cs.register.get_list_from_name(f'{vtd}_GSTS').read_and_print()
        self.cs.register.get_list_from_name(f'{vtd}_FSTS').read_and_print()
        self.cs.register.get_list_from_name(f'{vtd}_FRCDL').read_and_print()
        self.cs.register.get_list_from_name(f'{vtd}_FRCDH').read_and_print()
        self.cs.register.get_list_from_name(f'{vtd}_ICS').read_and_print()
        return None


haldata = {"arch":[hal_base.HALBase.MfgIds.Any], 'name': ['IOMMU']}
