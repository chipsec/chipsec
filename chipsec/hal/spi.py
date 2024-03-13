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
Access to SPI Flash parts

usage:
    >>> read_spi( spi_fla, length )
    >>> write_spi( spi_fla, buf )
    >>> erase_spi_block( spi_fla )
    >>> get_SPI_JEDEC_ID()
    >>> get_SPI_JEDEC_ID_decoded()

.. note::
    !! IMPORTANT:
    Size of the data chunk used in SPI read cycle (in bytes)
    default = maximum 64 bytes (remainder is read in 4 byte chunks)

    If you want to change logic to read SPI Flash in 4 byte chunks:
    SPI_READ_WRITE_MAX_DBC = 4

    @TBD: SPI write cycles operate on 4 byte chunks (not optimized yet)

    Approximate performance (on 2-core SMT Intel Core i5-4300U (Haswell) CPU 1.9GHz):
    SPI read: ~7 sec per 1MB (with DBC=64)
"""

import struct
import time
from typing import Dict, Tuple, Optional
from chipsec.library.defines import ALIGNED_4KB, BIT0, BIT1, BIT2, BIT5
from chipsec.library.file import write_file, read_file
from chipsec.library.logger import print_buffer_bytes
from chipsec.hal import hal_base, mmio
from chipsec.hal.spi_jedec_ids import JEDEC_ID
from chipsec.library.exceptions import SpiRuntimeError, UnimplementedAPIError

SPI_READ_WRITE_MAX_DBC = 64
SPI_READ_WRITE_DEF_DBC = 4
SFDP_HEADER = 0x50444653

SPI_MAX_PR_COUNT = 5
SPI_FLA_SHIFT = 12
SPI_FLA_PAGE_MASK = ALIGNED_4KB

SPI_MMIO_BASE_LENGTH = 0x200
PCH_RCBA_SPI_HSFSTS_SCIP = BIT5                          # SPI cycle in progress
PCH_RCBA_SPI_HSFSTS_AEL = BIT2                          # Access Error Log
PCH_RCBA_SPI_HSFSTS_FCERR = BIT1                          # Flash Cycle Error
PCH_RCBA_SPI_HSFSTS_FDONE = BIT0                          # Flash Cycle Done

PCH_RCBA_SPI_HSFCTL_FCYCLE_READ = 0                             # Flash Cycle Read
PCH_RCBA_SPI_HSFCTL_FCYCLE_WRITE = 2                             # Flash Cycle Write
PCH_RCBA_SPI_HSFCTL_FCYCLE_ERASE = 3                             # Flash Cycle Block Erase
PCH_RCBA_SPI_HSFCTL_FCYCLE_SFDP = 5
PCH_RCBA_SPI_HSFCTL_FCYCLE_JEDEC = 6                             # Flash Cycle Read JEDEC ID
PCH_RCBA_SPI_HSFCTL_FCYCLE_FGO = BIT0                          # Flash Cycle GO

PCH_RCBA_SPI_FADDR_MASK = 0x07FFFFFF                      # SPI Flash Address Mask [0:26]

PCH_RCBA_SPI_FREGx_LIMIT_MASK = 0x7FFF0000                    # Size
PCH_RCBA_SPI_FREGx_BASE_MASK = 0x00007FFF                    # Base

PCH_RCBA_SPI_OPTYPE_RDNOADDR = 0x00
PCH_RCBA_SPI_OPTYPE_WRNOADDR = 0x01
PCH_RCBA_SPI_OPTYPE_RDADDR = 0x02
PCH_RCBA_SPI_OPTYPE_WRADDR = 0x03

PCH_RCBA_SPI_FDOC_FDSS_FSDM = 0x0000                        # Flash Signature and Descriptor Map
PCH_RCBA_SPI_FDOC_FDSS_COMP = 0x1000                        # Component
PCH_RCBA_SPI_FDOC_FDSS_REGN = 0x2000                        # Region
PCH_RCBA_SPI_FDOC_FDSS_MSTR = 0x3000                        # Master
PCH_RCBA_SPI_FDOC_FDSI_MASK = 0x0FFC                        # Flash Descriptor Section Index

# agregated SPI Flash commands
HSFCTL_READ_CYCLE = ((PCH_RCBA_SPI_HSFCTL_FCYCLE_READ << 1) | PCH_RCBA_SPI_HSFCTL_FCYCLE_FGO)
HSFCTL_WRITE_CYCLE = ((PCH_RCBA_SPI_HSFCTL_FCYCLE_WRITE << 1) | PCH_RCBA_SPI_HSFCTL_FCYCLE_FGO)
HSFCTL_ERASE_CYCLE = ((PCH_RCBA_SPI_HSFCTL_FCYCLE_ERASE << 1) | PCH_RCBA_SPI_HSFCTL_FCYCLE_FGO)
HSFCTL_JEDEC_CYCLE = ((PCH_RCBA_SPI_HSFCTL_FCYCLE_JEDEC << 1) | PCH_RCBA_SPI_HSFCTL_FCYCLE_FGO)
HSFCTL_SFDP_CYCLE = ((PCH_RCBA_SPI_HSFCTL_FCYCLE_SFDP << 1) | PCH_RCBA_SPI_HSFCTL_FCYCLE_FGO)

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# FGO bit cleared (for safety ;)
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#HSFCTL_WRITE_CYCLE = ( (PCH_RCBA_SPI_HSFCTL_FCYCLE_WRITE<<1) )
#HSFCTL_ERASE_CYCLE = ( (PCH_RCBA_SPI_HSFCTL_FCYCLE_ERASE<<1) )

HSFSTS_CLEAR = (PCH_RCBA_SPI_HSFSTS_AEL | PCH_RCBA_SPI_HSFSTS_FCERR | PCH_RCBA_SPI_HSFSTS_FDONE)

#
# Hardware Sequencing Flash Status (HSFSTS)
#
SPI_HSFSTS_OFFSET = 0x04
# HSFSTS bit masks
SPI_HSFSTS_FLOCKDN_MASK = (1 << 15)
SPI_HSFSTS_FDOPSS_MASK = (1 << 13)

#
# Flash Regions
#

SPI_REGION_NUMBER_IN_FD = 12

FLASH_DESCRIPTOR = 0
BIOS = 1
ME = 2
GBE = 3
PLATFORM_DATA = 4
FREG5 = 5
FREG6 = 6
FREG7 = 7
EMBEDDED_CONTROLLER = 8
FREG9 = 9
FREG10 = 10
FREG11 = 11

SPI_REGION: Dict[int, str] = {
    FLASH_DESCRIPTOR: 'FREG0_FLASHD',
    BIOS: 'FREG1_BIOS',
    ME: 'FREG2_ME',
    GBE: 'FREG3_GBE',
    PLATFORM_DATA: 'FREG4_PD',
    FREG5: 'FREG5',
    FREG6: 'FREG6',
    FREG7: 'FREG7',
    EMBEDDED_CONTROLLER: 'FREG8_EC',
    FREG9: 'FREG9',
    FREG10: 'FREG10',
    FREG11: 'FREG11'
}

SPI_REGION_NAMES: Dict[int, str] = {
    FLASH_DESCRIPTOR: 'Flash Descriptor',
    BIOS: 'BIOS',
    ME: 'Intel ME',
    GBE: 'GBe',
    PLATFORM_DATA: 'Platform Data',
    FREG5: 'Flash Region 5',
    FREG6: 'Flash Region 6',
    FREG7: 'Flash Region 7',
    EMBEDDED_CONTROLLER: 'Embedded Controller',
    FREG9: 'Flash Region 9',
    FREG10: 'Flash Region 10',
    FREG11: 'Flash Region 11'
}

#
# Flash Descriptor Master Defines
#

MASTER_HOST_CPU_BIOS = 0
MASTER_ME = 1
MASTER_GBE = 2
MASTER_EC = 3

SPI_MASTER_NAMES: Dict[int, str] = {
    MASTER_HOST_CPU_BIOS: 'CPU',
    MASTER_ME: 'ME',
    MASTER_GBE: 'GBe',
    MASTER_EC: 'EC'
}

# @TODO: DEPRECATED


def get_SPI_region(flreg: int) -> Tuple[int, int]:
    range_base = (flreg & PCH_RCBA_SPI_FREGx_BASE_MASK) << SPI_FLA_SHIFT
    range_limit = ((flreg & PCH_RCBA_SPI_FREGx_LIMIT_MASK) >> 4)
    range_limit |= SPI_FLA_PAGE_MASK
    return (range_base, range_limit)


class SPI(hal_base.HALBase):

    def __init__(self, cs):
        super(SPI, self).__init__(cs)
        self.mmio = mmio.MMIO(cs)
        self.rcba_spi_base = self.get_SPI_MMIO_base()
        # We try to map SPIBAR in the process memory, this will increase the
        # speed of MMIO access later on.
        try:
            self.cs.helper.map_io_space(self.rcba_spi_base, SPI_MMIO_BASE_LENGTH, 0)
        except UnimplementedAPIError:
            pass

        # Reading definitions of SPI flash controller registers
        # which are required to send SPI cycles once for performance reasons
        self.hsfs_off = self.cs.register.get_def("HSFS")['offset']
        self.hsfc_off = self.cs.register.get_def("HSFC")['offset']
        self.faddr_off = self.cs.register.get_def("FADDR")['offset']
        self.fdata0_off = self.cs.register.get_def("FDATA0")['offset']
        self.fdata1_off = self.cs.register.get_def("FDATA1")['offset']
        self.fdata2_off = self.cs.register.get_def("FDATA2")['offset']
        self.fdata3_off = self.cs.register.get_def("FDATA3")['offset']
        self.fdata4_off = self.cs.register.get_def("FDATA4")['offset']
        self.fdata5_off = self.cs.register.get_def("FDATA5")['offset']
        self.fdata6_off = self.cs.register.get_def("FDATA6")['offset']
        self.fdata7_off = self.cs.register.get_def("FDATA7")['offset']
        self.fdata8_off = self.cs.register.get_def("FDATA8")['offset']
        self.fdata9_off = self.cs.register.get_def("FDATA9")['offset']
        self.fdata10_off = self.cs.register.get_def("FDATA10")['offset']
        self.fdata11_off = self.cs.register.get_def("FDATA11")['offset']
        self.fdata12_off = self.cs.register.get_def("FDATA12")['offset']
        self.fdata13_off = self.cs.register.get_def("FDATA13")['offset']
        self.fdata14_off = self.cs.register.get_def("FDATA14")['offset']
        self.fdata15_off = self.cs.register.get_def("FDATA15")['offset']
        self.bios_ptinx = self.cs.register.get_def("BIOS_PTINX")['offset']
        self.bios_ptdata = self.cs.register.get_def("BIOS_PTDATA")['offset']

        self.logger.log_hal("[spi] Reading SPI flash controller registers definitions:")
        self.logger.log_hal(f'      HSFS   offset = 0x{self.hsfs_off:04X}')
        self.logger.log_hal(f'      HSFC   offset = 0x{self.hsfc_off:04X}')
        self.logger.log_hal(f'      FADDR  offset = 0x{self.faddr_off:04X}')
        self.logger.log_hal(f'      FDATA0 offset = 0x{self.fdata0_off:04X}')

    def get_SPI_MMIO_base(self) -> int:
        spi_base = 0
        if self.mmio.is_MMIO_BAR_defined('SPIBAR'):
            (spi_base, _) = self.mmio.get_MMIO_BAR_base_address('SPIBAR')
        else:
            self.logger.log_hal('[spi] get_SPI_MMIO_base(): SPIBAR not defined. Returning spi_base = 0.')
        self.logger.log_hal(f'[spi] SPI MMIO base: 0x{spi_base:016X} (assuming below 4GB)')
        return spi_base

    def spi_reg_read(self, reg: int, size: int = 4) -> int:
        return self.mmio.read_MMIO_reg(self.rcba_spi_base, reg, size)

    def spi_reg_write(self, reg: int, value: int, size: int = 4) -> Optional[int]:
        return self.mmio.write_MMIO_reg(self.rcba_spi_base, reg, value, size)

    def get_SPI_region(self, spi_region_id: int) -> Tuple[int, int, int]:
        freg_name = SPI_REGION[spi_region_id]
        if not self.cs.register.is_defined(freg_name):
            return (0, 0, 0)
        freg = self.cs.register.read(freg_name)
        # Region Base corresponds to FLA bits 24:12
        range_base = self.cs.register.get_field(freg_name, freg, 'RB') << SPI_FLA_SHIFT
        # Region Limit corresponds to FLA bits 24:12
        range_limit = self.cs.register.get_field(freg_name, freg, 'RL') << SPI_FLA_SHIFT
        # FLA bits 11:0 are assumed to be FFFh for the limit comparison
        range_limit |= SPI_FLA_PAGE_MASK
        return (range_base, range_limit, freg)

    SpiRegions = Dict[int, Tuple[int, int, int, str, int]]

    # all_regions = True : return all SPI regions
    # all_regions = False: return only available SPI regions (limit >= base)
    def get_SPI_regions(self, all_regions: bool = True) -> SpiRegions:
        spi_regions: Dict[int, Tuple[int, int, int, str, int]] = {}
        for r in SPI_REGION:
            (range_base, range_limit, freg) = self.get_SPI_region(r)
            if range_base is None:
                continue
            if all_regions or (range_limit >= range_base):
                range_size = range_limit - range_base + 1
                spi_regions[r] = (range_base, range_limit, range_size, SPI_REGION_NAMES[r], freg)
        return spi_regions

    def get_SPI_Protected_Range(self, pr_num: int) -> Tuple[int, int, int, int, int, int]:
        if pr_num > SPI_MAX_PR_COUNT:
            return (0, 0, 0, 0, 0, 0)

        pr_name = f'PR{pr_num:x}'
        pr_j_reg = self.cs.register.get_def(pr_name)['offset']
        pr_j = self.cs.register.read(pr_name)

        # Protected Range Base corresponds to FLA bits 24:12
        base = self.cs.register.get_field(pr_name, pr_j, 'PRB') << SPI_FLA_SHIFT
        # Protected Range Limit corresponds to FLA bits 24:12
        limit = self.cs.register.get_field(pr_name, pr_j, 'PRL') << SPI_FLA_SHIFT

        wpe = (0 != self.cs.register.get_field(pr_name, pr_j, 'WPE'))
        rpe = (0 != self.cs.register.get_field(pr_name, pr_j, 'RPE'))

        # Check if this is a valid PRx config
        if wpe or rpe:
            # FLA bits 11:0 are assumed to be FFFh for the limit comparison
            limit |= SPI_FLA_PAGE_MASK

        return (base, limit, wpe, rpe, pr_j_reg, pr_j)

    ##############################################################################################################
    # SPI configuration
    ##############################################################################################################

    def display_SPI_Flash_Descriptor(self) -> None:
        self.logger.log("============================================================")
        self.logger.log("SPI Flash Descriptor")
        self.logger.log("------------------------------------------------------------")
        self.logger.log("\nFlash Signature and Descriptor Map:")
        for j in range(5):
            self.cs.register.write('FDOC', (PCH_RCBA_SPI_FDOC_FDSS_FSDM | (j << 2)))
            fdod = self.cs.register.read('FDOD')
            self.logger.log(f'{fdod:08X}')

        self.logger.log("\nComponents:")
        for j in range(3):
            self.cs.register.write('FDOC', (PCH_RCBA_SPI_FDOC_FDSS_COMP | (j << 2)))
            fdod = self.cs.register.read('FDOD')
            self.logger.log(f'{fdod:08X}')

        self.logger.log("\nRegions:")
        for j in range(5):
            self.cs.register.write('FDOC', (PCH_RCBA_SPI_FDOC_FDSS_REGN | (j << 2)))
            fdod = self.cs.register.read('FDOD')
            self.logger.log(f'{fdod:08X}')

        self.logger.log("\nMasters:")
        for j in range(3):
            self.cs.register.write('FDOC', (PCH_RCBA_SPI_FDOC_FDSS_MSTR | (j << 2)))
            fdod = self.cs.register.read('FDOD')
            self.logger.log(f'{fdod:08X}')

    def display_SPI_opcode_info(self) -> None:
        self.logger.log("============================================================")
        self.logger.log("SPI Opcode Info")
        self.logger.log("------------------------------------------------------------")
        preop = self.cs.register.read('PREOP')
        self.logger.log(f'PREOP : 0x{preop:04X}')
        optype = self.cs.register.read('OPTYPE')
        self.logger.log(f'OPTYPE: 0x{optype:04X}')
        opmenu_lo = self.cs.register.read('OPMENU_LO')
        opmenu_hi = self.cs.register.read('OPMENU_HI')
        opmenu = ((opmenu_hi << 32) | opmenu_lo)
        self.logger.log(f'OPMENU: 0x{opmenu:016X}')
        self.logger.log('')
        preop0 = preop & 0xFF
        preop1 = (preop >> 8) & 0xFF
        self.logger.log(f'Prefix Opcode 0 = 0x{preop0:02X}')
        self.logger.log(f'Prefix Opcode 1 = 0x{preop1:02X}')

        self.logger.log("------------------------------------------------------------")
        self.logger.log("Opcode # | Opcode | Optype | Description")
        self.logger.log("------------------------------------------------------------")
        for j in range(8):
            optype_j = ((optype >> j * 2) & 0x3)
            if (PCH_RCBA_SPI_OPTYPE_RDNOADDR == optype_j):
                desc = 'SPI read cycle without address'
            elif (PCH_RCBA_SPI_OPTYPE_WRNOADDR == optype_j):
                desc = 'SPI write cycle without address'
            elif (PCH_RCBA_SPI_OPTYPE_RDADDR == optype_j):
                desc = 'SPI read cycle with address'
            elif (PCH_RCBA_SPI_OPTYPE_WRADDR == optype_j):
                desc = 'SPI write cycle with address'
            else:
                desc = ''
            self.logger.log(f'Opcode{j:d}  | 0x{(opmenu >> j * 8) & 0xFF:02X}   | {optype_j:x}      | {desc} ')

    def display_SPI_Flash_Regions(self) -> None:
        self.logger.log("------------------------------------------------------------")
        self.logger.log("Flash Region             | FREGx Reg | Base     | Limit     ")
        self.logger.log("------------------------------------------------------------")
        regions = self.get_SPI_regions()
        for (region_id, region) in regions.items():
            base, limit, size, name, freg = region
            self.logger.log(f'{region_id:d} {name:22} | {freg:08X}  | {base:08X} | {limit:08X} ')

    def display_BIOS_region(self) -> None:
        bfpreg = self.cs.register.read('BFPR')
        base = self.cs.register.get_field('BFPR', bfpreg, 'PRB') << SPI_FLA_SHIFT
        limit = self.cs.register.get_field('BFPR', bfpreg, 'PRL') << SPI_FLA_SHIFT
        limit |= SPI_FLA_PAGE_MASK
        self.logger.log("BIOS Flash Primary Region")
        self.logger.log("------------------------------------------------------------")
        self.logger.log(f'BFPREG = {bfpreg:08X}:')
        self.logger.log(f'  Base  : {base:08X}')
        self.logger.log(f'  Limit : {limit:08X}')

    def display_SPI_Ranges_Access_Permissions(self) -> None:
        self.logger.log("SPI Flash Region Access Permissions")
        self.logger.log("------------------------------------------------------------")
        fracc = self.cs.register.read('FRAP')
        if self.logger.HAL:
            self.cs.register.print('FRAP', fracc)
        brra = self.cs.register.get_field('FRAP', fracc, 'BRRA')
        brwa = self.cs.register.get_field('FRAP', fracc, 'BRWA')
        bmrag = self.cs.register.get_field('FRAP', fracc, 'BMRAG')
        bmwag = self.cs.register.get_field('FRAP', fracc, 'BMWAG')
        self.logger.log('')
        self.logger.log(f'BIOS Region Write Access Grant ({bmwag:02X}):')
        regions = self.get_SPI_regions()
        for region_id in regions:
            self.logger.log(f'  {SPI_REGION[region_id]:12}: {0 != bmwag & (1 << region_id):1d}')
        self.logger.log(f'BIOS Region Read Access Grant ({bmrag:02X}):')
        for region_id in regions:
            self.logger.log(f'  {SPI_REGION[region_id]:12}: {0 != bmrag & (1 << region_id):1d}')
        self.logger.log(f'BIOS Region Write Access ({brwa:02X}):')
        for region_id in regions:
            self.logger.log(f'  {SPI_REGION[region_id]:12}: {0 != brwa & (1 << region_id):1d}')
        self.logger.log(f'BIOS Region Read Access ({brra:02X}):')
        for region_id in regions:
            self.logger.log(f'  {SPI_REGION[region_id]:12}: {0 != brra & (1 << region_id):1d}')

    def display_SPI_Protected_Ranges(self) -> None:
        self.logger.log("SPI Protected Ranges")
        self.logger.log("------------------------------------------------------------")
        self.logger.log("PRx (offset) | Value    | Base     | Limit    | WP? | RP?")
        self.logger.log("------------------------------------------------------------")
        for j in range(5):
            (base, limit, wpe, rpe, pr_reg_off, pr_reg_value) = self.get_SPI_Protected_Range(j)
            self.logger.log(f'PR{j:d} ({pr_reg_off:02X})     | {pr_reg_value:08X} | {base:08X} | {limit:08X} | {wpe:d}   | {rpe:d} ')

    def display_SPI_map(self) -> None:
        self.logger.log("============================================================")
        self.logger.log("SPI Flash Map")
        self.logger.log("------------------------------------------------------------")
        self.logger.log('')
        self.display_BIOS_region()
        self.logger.log('')
        self.display_SPI_Flash_Regions()
        self.logger.log('')
        self.display_SPI_Flash_Descriptor()
        self.logger.log('')
        self.display_SPI_opcode_info()
        self.logger.log('')
        self.logger.log("============================================================")
        self.logger.log("SPI Flash Protection")
        self.logger.log("------------------------------------------------------------")
        self.logger.log('')
        self.display_SPI_Ranges_Access_Permissions()
        self.logger.log('')
        self.logger.log("BIOS Region Write Protection")
        self.logger.log("------------------------------------------------------------")
        self.display_BIOS_write_protection()
        self.logger.log('')
        self.display_SPI_Protected_Ranges()
        self.logger.log('')

    ##############################################################################################################
    # BIOS Write Protection
    ##############################################################################################################

    def display_BIOS_write_protection(self) -> None:
        if self.cs.register.is_defined('BC'):
            reg_value = self.cs.register.read('BC')
            self.cs.register.print('BC', reg_value)
        else:
            if self.logger.HAL:
                self.logger.log_error("Could not locate the definition of 'BIOS Control' register..")

    def disable_BIOS_write_protection(self) -> bool:
        if self.logger.HAL:
            self.display_BIOS_write_protection()
        ble = self.cs.control.get('BiosLockEnable')
        bioswe = self.cs.control.get('BiosWriteEnable')
        smmbwp = self.cs.control.get('SmmBiosWriteProtection')

        if smmbwp == 1:
            self.logger.log_hal("[spi] SMM BIOS write protection (SmmBiosWriteProtection) is enabled")

        if bioswe == 1:
            self.logger.log_hal("[spi] BIOS write protection (BiosWriteEnable) is not enabled")
            return True
        elif ble == 0:
            self.logger.log_hal("[spi] BIOS write protection is enabled but not locked. Disabling..")
        else:  # bioswe == 0 and ble == 1
            self.logger.log_hal("[spi] BIOS write protection is enabled. Attempting to disable..")

        # Set BiosWriteEnable control bit
        self.cs.control.set('BiosWriteEnable', 1)

        # read BiosWriteEnable back to check if BIOS writes are enabled
        bioswe = self.cs.control.get('BiosWriteEnable')

        if self.logger.HAL:
            self.display_BIOS_write_protection()
        if self.logger.HAL:
            protection = 'disabled' if bioswe else 'still enabled'
            self.logger.log_important(f'BIOS write protection is {protection} (BiosWriteEnable = {bioswe:d})')

        return (bioswe == 1)

    ##############################################################################################################
    # SPI Controller access functions
    ##############################################################################################################

    def _wait_SPI_flash_cycle_done(self) -> bool:
        self.logger.log_hal('[spi] Wait for SPI cycle ready/done...')
        hsfsts = 0
        cycle_done = False

        for i in range(1000):
            # time.sleep(0.001)
            hsfsts = self.spi_reg_read(self.hsfs_off, 1)

            #cycle_done = (hsfsts & Cfg.Cfg.PCH_RCBA_SPI_HSFSTS_FDONE) and (0 == (hsfsts & Cfg.PCH_RCBA_SPI_HSFSTS_SCIP))
            cycle_done = not (hsfsts & PCH_RCBA_SPI_HSFSTS_SCIP)
            if cycle_done:
                break

        if not cycle_done:
            self.logger.log_hal('[spi] SPI cycle still in progress. Waiting 0.1 sec...')
            time.sleep(0.1)
            hsfsts = self.spi_reg_read(self.hsfs_off, 1)
            cycle_done = not (hsfsts & PCH_RCBA_SPI_HSFSTS_SCIP)

        if cycle_done:
            self.logger.log_hal('[spi] Clear FDONE/FCERR/AEL bits...')
            self.spi_reg_write(self.hsfs_off, HSFSTS_CLEAR, 1)
            hsfsts = self.spi_reg_read(self.hsfs_off, 1)
            cycle_done = not ((hsfsts & PCH_RCBA_SPI_HSFSTS_AEL) or (hsfsts & PCH_RCBA_SPI_HSFSTS_FCERR))

        self.logger.log_hal(f'[spi] HSFS: 0x{hsfsts:02X}')

        return cycle_done

    def _send_spi_cycle(self, hsfctl_spi_cycle_cmd: int, dbc: int, spi_fla: int) -> bool:
        self.logger.log_hal(f'[spi] > Send SPI cycle 0x{hsfctl_spi_cycle_cmd:x} to address 0x{spi_fla:08X}')

        # No need to check for SPI cycle DONE status before each cycle
        # DONE status is checked once before entire SPI operation

        self.spi_reg_write(self.faddr_off, (spi_fla & PCH_RCBA_SPI_FADDR_MASK))
        # Other options ;)
        #chipsec.chipset.write_register( self.cs, "FADDR", (spi_fla & Cfg.PCH_RCBA_SPI_FADDR_MASK) )
        #write_MMIO_reg( self.cs, spi_base, self.faddr_off, (spi_fla & Cfg.PCH_RCBA_SPI_FADDR_MASK) )
        #self.cs.mem.write_physical_mem_dword( spi_base + self.faddr_off, (spi_fla & Cfg.PCH_RCBA_SPI_FADDR_MASK) )

        if self.logger.HAL:
            _faddr = self.spi_reg_read(self.faddr_off)
            self.logger.log(f'[spi] FADDR: 0x{_faddr:08X}')

        self.logger.log_hal(f'[spi] SPI cycle GO (DBC <- 0x{dbc:02X}, HSFC <- 0x{hsfctl_spi_cycle_cmd:x})')

        if (HSFCTL_ERASE_CYCLE != hsfctl_spi_cycle_cmd):
            self.spi_reg_write(self.hsfc_off + 0x1, dbc, 1)

        self.spi_reg_write(self.hsfc_off, hsfctl_spi_cycle_cmd, 1)
        #self.spi_reg_write( self.hsfc_off, ((dbc<<8)|hsfctl_spi_cycle_cmd), 2 )

        # Read HSFC back (logging only)
        if self.logger.HAL:
            _hsfc = self.spi_reg_read(self.hsfc_off, 1)
            self.logger.log(f'[spi] HSFC: 0x{_hsfc:04X}')

        cycle_done = self._wait_SPI_flash_cycle_done()
        if not cycle_done:
            self.logger.log_warning("SPI cycle not done")
        else:
            self.logger.log_hal('[spi] < SPI cycle done')

        return cycle_done

    def check_hardware_sequencing(self) -> None:
        # Test if the flash decriptor is valid (and hardware sequencing enabled)
        fdv = self.cs.register.read_field('HSFS', 'FDV')
        if fdv == 0:
            self.logger.log_error("HSFS.FDV is 0, hardware sequencing is disabled")
            raise SpiRuntimeError("Chipset does not support hardware sequencing")

    #
    # SPI Flash operations
    #

    def read_spi_to_file(self, spi_fla: int, data_byte_count: int, filename: str) -> bytes:
        buf = self.read_spi(spi_fla, data_byte_count)
        if buf is None:
            return b''
        if filename is not None:
            write_file(filename, buf)
        else:
            print_buffer_bytes(buf, 16)
        return buf

    def write_spi_from_file(self, spi_fla: int, filename: str) -> bool:
        buf = read_file(filename)
        return self.write_spi(spi_fla, buf)
        # return self.write_spi( spi_fla, struct.unpack('B'*len(buf), buf) )

    def read_spi(self, spi_fla: int, data_byte_count: int) -> bytes:

        self.check_hardware_sequencing()

        buf = bytearray()
        dbc = SPI_READ_WRITE_DEF_DBC
        if (data_byte_count >= SPI_READ_WRITE_MAX_DBC):
            dbc = SPI_READ_WRITE_MAX_DBC

        n = data_byte_count // dbc
        r = data_byte_count % dbc
        if self.logger.UTIL_TRACE or self.logger.HAL:
            self.logger.log(f'[spi] Reading 0x{data_byte_count:x} bytes from SPI at FLA = 0x{spi_fla:x} (in {n:d} 0x{dbc:x}-byte chunks + 0x{r:x}-byte remainder)')

        cycle_done = self._wait_SPI_flash_cycle_done()
        if not cycle_done:
            self.logger.log_error("SPI cycle not ready")
            return b''

        for i in range(n):
            self.logger.log_hal(f'[spi] Reading chunk {i:d} of 0x{dbc:x} bytes from 0x{spi_fla + i * dbc:x}')
            if not self._send_spi_cycle(HSFCTL_READ_CYCLE, dbc - 1, spi_fla + i * dbc):
                self.logger.log_error("SPI flash read failed")
            else:
                for fdata_idx in range(0, dbc // 4):
                    dword_value = self.spi_reg_read(self.fdata0_off + fdata_idx * 4)
                    if self.logger.HAL:
                        self.logger.log(f'[spi] FDATA00 + 0x{fdata_idx * 4:x}: 0x{dword_value:x}')
                    buf += struct.pack("I", dword_value)

        if (0 != r):
            self.logger.log_hal(f'[spi] Reading remaining 0x{r:x} bytes from 0x{spi_fla + n * dbc:x}')
            if not self._send_spi_cycle(HSFCTL_READ_CYCLE, r - 1, spi_fla + n * dbc):
                self.logger.log_error("SPI flash read failed")
            else:
                t = 4
                n_dwords = (r + 3) // 4
                for fdata_idx in range(0, n_dwords):
                    dword_value = self.spi_reg_read(self.fdata0_off + fdata_idx * 4)
                    if self.logger.HAL:
                        self.logger.log(f'[spi] FDATA00 + 0x{fdata_idx * 4:x}: 0x{dword_value:08X}')
                    if (fdata_idx == (n_dwords - 1)) and (0 != r % 4):
                        t = r % 4
                    for j in range(t):
                        buf += struct.pack('B', (dword_value >> (8 * j)) & 0xff)

        self.logger.log_hal('[spi] Buffer read from SPI:')
        if self.logger.HAL:
            print_buffer_bytes(buf)

        return buf

    def write_spi(self, spi_fla: int, buf: bytes) -> bool:

        self.check_hardware_sequencing()

        write_ok = True
        data_byte_count = len(buf)
        dbc = 4
        n = data_byte_count // dbc
        r = data_byte_count % dbc
        if self.logger.UTIL_TRACE or self.logger.HAL:
            self.logger.log(f'[spi] Writing 0x{data_byte_count:x} bytes to SPI at FLA = 0x{spi_fla:x} (in {n:d} 0x{dbc:x}-byte chunks + 0x{r:x}-byte remainder)')

        cycle_done = self._wait_SPI_flash_cycle_done()
        if not cycle_done:
            self.logger.log_error("SPI cycle not ready")
            return False

        for i in range(n):
            if self.logger.UTIL_TRACE or self.logger.HAL:
                self.logger.log(f'[spi] Writing chunk {i:d} of 0x{dbc:x} bytes to 0x{spi_fla + i * dbc:x}')
            dword_value = ((buf[i * dbc + 3]) << 24) | ((buf[i * dbc + 2]) << 16) | ((buf[i * dbc + 1]) << 8) | (buf[i * dbc])
            if self.logger.HAL:
                self.logger.log(f'[spi] in FDATA00 = 0x{dword_value:08X}')
            self.spi_reg_write(self.fdata0_off, dword_value)
            if not self._send_spi_cycle(HSFCTL_WRITE_CYCLE, dbc - 1, spi_fla + i * dbc):
                write_ok = False
                self.logger.log_error("SPI flash write cycle failed")

        if (0 != r):
            if self.logger.UTIL_TRACE or self.logger.HAL:
                self.logger.log(f'[spi] Writing remaining 0x{r:x} bytes to FLA = 0x{spi_fla + n * dbc:x}')
            dword_value = 0
            for j in range(r):
                dword_value |= (buf[n * dbc + j] << 8 * j)
            if self.logger.HAL:
                self.logger.log(f'[spi] in FDATA00 = 0x{dword_value:08X}')
            self.spi_reg_write(self.fdata0_off, dword_value)
            if not self._send_spi_cycle(HSFCTL_WRITE_CYCLE, r - 1, spi_fla + n * dbc):
                write_ok = False
                self.logger.log_error("SPI flash write cycle failed")

        return write_ok

    def erase_spi_block(self, spi_fla: int) -> bool:

        self.check_hardware_sequencing()

        if self.logger.UTIL_TRACE or self.logger.HAL:
            self.logger.log(f'[spi] Erasing SPI Flash block @ 0x{spi_fla:x}')

        cycle_done = self._wait_SPI_flash_cycle_done()
        if not cycle_done:
            self.logger.log_error("SPI cycle not ready")
            return cycle_done

        erase_ok = self._send_spi_cycle(HSFCTL_ERASE_CYCLE, 0, spi_fla)
        if not erase_ok:
            self.logger.log_error("SPI Flash erase cycle failed")

        return erase_ok

    #
    # SPI SFDP operations
    #
    def ptmesg(self, offset: int) -> int:
        self.spi_reg_write(self.bios_ptinx, offset)
        self.spi_reg_read(self.bios_ptinx)
        return self.spi_reg_read(self.bios_ptdata)

    def get_SPI_SFDP(self) -> bool:
        ret = False
        for component in range(0, 2):
            self.logger.log(f'Scanning for Flash device {component + 1:d}')
            offset = 0x0000 | (component << 14)
            sfdp_signature = self.ptmesg(offset)
            if sfdp_signature == SFDP_HEADER:
                self.logger.log(f'  * Found valid SFDP header for Flash device {component + 1:d}')
                ret = True
            else:
                self.logger.log(f"  * Didn't find a valid SFDP header for Flash device {component + 1:d}")
                continue
            # Increment offset to read second dword of SFDP header structure
            sfdp_data = self.ptmesg(offset + 0x4)
            sfdp_minor_version = sfdp_data & 0xFF
            sfdp_major_version = (sfdp_data >> 8) & 0xFF
            self.logger.log(f'    SFDP version number: {sfdp_major_version}.{sfdp_minor_version}')
            num_of_param_headers = ((sfdp_data >> 16) & 0xFF) + 1
            self.logger.log(f'    Number of parameter headers: {num_of_param_headers:d}')
            # Set offset to read 1st Parameter Table in the SFDP header structure
            offset = offset | 0x1000
            parameter_1 = self.ptmesg(offset)
            param1_minor_version = (parameter_1 >> 8) & 0xFF
            param1_major_version = (parameter_1 >> 16) & 0xFF
            param1_length = (parameter_1 >> 24) & 0xFF
            self.logger.log("  * Parameter Header 1 (JEDEC)")
            self.logger.log(f'    ** Parameter version number: {param1_major_version}.{param1_minor_version}')
            self.logger.log(f'    ** Parameter length in double words: {hex(param1_length)}')
            if (num_of_param_headers > 1) and self.cs.register.has_field('HSFS', 'FCYCLE'):
                self.check_hardware_sequencing()
                self.spi_reg_write(self.fdata12_off, 0x00000000)
                self.spi_reg_write(self.fdata13_off, 0x00000000)
                self.spi_reg_write(self.fdata14_off, 0x00000000)
                self.spi_reg_write(self.fdata15_off, 0x00000000)
                if not self._send_spi_cycle(HSFCTL_SFDP_CYCLE, 0x3F, 0):
                    self.logger.log_error('SPI SFDP signature cycle failed')
                    continue
                pTable_offset_list = []
                pTable_length = []
                # Calculate which fdata_offset registers to read, based on number of parameter headers present
                for i in range(1, num_of_param_headers):
                    self.logger.log(f'  * Parameter Header:{i + 1:d}')
                    data_reg_1 = f'self.fdata{str(2 + (2 * i))}_off'
                    data_reg_2 = f'self.fdata{str(2 + (2 * i) + 1)}_off'
                    data_dword_1 = self.spi_reg_read(eval(data_reg_1))
                    data_dword_2 = self.spi_reg_read(eval(data_reg_2))
                    id_manuf = (data_dword_2 & 0xFF000000) >> 16 | (data_dword_1 & 0xFF)
                    param_minor_version = (data_dword_1 >> 8) & 0xFF
                    param_major_version = (data_dword_1 >> 16) & 0xFF
                    param_length = (data_dword_1 >> 24) & 0xFF
                    param_table_pointer = (data_dword_2 & 0x00FFFFFF)
                    self.logger.log(f'    ** Parameter version number:{param_major_version}.{param_minor_version}')
                    self.logger.log(f'    ** Parameter length in double words: {hex(param_length)}')
                    self.logger.log(f'    ** Parameter ID: {hex(id_manuf)}')
                    self.logger.log(f'    ** Parameter Table Pointer(byte address): {hex(param_table_pointer)} ')
                    pTable_offset_list.append(param_table_pointer)
                    pTable_length.append(param_length)
            offset = 0x0000 | (component << 14)
            # Set offset to read 1st Parameter table ( JEDEC Basic Flash Parameter Table) content and Parse it
            offset = offset | 0x2000
            self.logger.log("                                ")
            self.logger.log("  * 1'st Parameter Table Content ")
            for count in range(1, param1_length + 1):
                sfdp_data = self.ptmesg(offset)
                offset += 4
                self.cs.register.print(f'DWORD{count}', sfdp_data)
        return ret

    #
    # SPI JEDEC ID operations
    #

    def get_SPI_JEDEC_ID(self) -> int:

        if self.cs.register.has_field('HSFS', 'FCYCLE'):
            self.check_hardware_sequencing()

            if not self._send_spi_cycle(HSFCTL_JEDEC_CYCLE, 4, 0):
                self.logger.log_error('SPI JEDEC ID cycle failed')
            id = self.spi_reg_read(self.fdata0_off)
        else:
            return False

        return ((id & 0xFF) << 16) | (id & 0xFF00) | ((id >> 16) & 0xFF)

    def get_SPI_JEDEC_ID_decoded(self) -> Tuple[int, str, str]:

        jedec_id = self.get_SPI_JEDEC_ID()
        if jedec_id is False:
            return (False, '', '')
        manu = JEDEC_ID.MANUFACTURER.get((jedec_id >> 16) & 0xff, 'Unknown')
        part = JEDEC_ID.DEVICE.get(jedec_id, 'Unknown')

        return (jedec_id, manu, part)
