# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2025, Intel Corporation
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

from collections import namedtuple
import struct
from typing import Dict
from chipsec.library.defines import ALIGNED_4KB
from chipsec.library.logger import logger


SPI_FREGx_LIMIT_MASK = 0x7FFF0000  # Limit
SPI_FREGx_BASE_MASK = 0x00007FFF  # Base
SPI_FLA_SHIFT = 12
SPI_FLA_PAGE_MASK = ALIGNED_4KB

#
# Flash Regions
#

SPI_REGION_tuple = namedtuple('SpiRegion', 'name value base limit')
SPI_REGION_NUMBER_IN_FD = 16

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
FREG12 = 12
FREG13 = 13
FREG14 = 14
FREG15 = 15

SPI_FLASH_DESCRIPTOR_SIGNATURE = struct.pack('=I', 0x0FF0A55A)
SPI_FLASH_DESCRIPTOR_SIZE = 0x1000

SPI_REGION: Dict[int, str] = {
    FLASH_DESCRIPTOR: '8086.SPIBAR.FREG0_FLASHD',
    BIOS: '8086.SPIBAR.FREG1_BIOS',
    ME: '8086.SPIBAR.FREG2_ME',
    GBE: '8086.SPIBAR.FREG3_GBE',
    PLATFORM_DATA: '8086.SPIBAR.FREG4_PD',
    FREG5: '8086.SPIBAR.FREG5',
    FREG6: '8086.SPIBAR.FREG6',
    FREG7: '8086.SPIBAR.FREG7',
    EMBEDDED_CONTROLLER: '8086.SPIBAR.FREG8_EC',
    FREG9: '8086.SPIBAR.FREG9',
    FREG10: '8086.SPIBAR.FREG10',
    FREG11: '8086.SPIBAR.FREG11',
    FREG12: '8086.SPIBAR.FREG12',
    FREG13: '8086.SPIBAR.FREG13',
    FREG14: '8086.SPIBAR.FREG14',
    FREG15: '8086.SPIBAR.FREG15'
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
    FREG11: 'Flash Region 11',
    FREG12: 'Flash Region 12',
    FREG13: 'Flash Region 13',
    FREG14: 'Flash Region 14',
    FREG15: 'Flash Region 15'
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


def print_SPI_Flash_Regions(regions):
    logger().log("------------------------------------------------------------")
    logger().log("Flash Region             | FREGx Reg | Base     | Limit     ")
    logger().log("------------------------------------------------------------")
    for (region_id, region) in regions.items():
        used_str = '(not used)' if region.base > region.limit else ''
        logger().log(f'{region_id:d} {region.name:22} | {region.value:08X}  | {region.base:08X} | {region.limit:08X} {used_str} ')
