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
Access to Memory (DRAM) Serial Presence Detect (SPD) EEPROM

References:

http://www.jedec.org/sites/default/files/docs/4_01_02R19.pdf
http://www.jedec.org/sites/default/files/docs/4_01_02_10R17.pdf
http://www.jedec.org/sites/default/files/docs/4_01_02_11R24.pdf
http://www.jedec.org/sites/default/files/docs/4_01_02_12R23A.pdf
https://www.simmtester.com/News/PublicationArticle/184
https://www.simmtester.com/News/PublicationArticle/153
https://www.simmtester.com/News/PublicationArticle/101
http://en.wikipedia.org/wiki/Serial_presence_detect
"""

import struct
from typing import Any, List
from collections import namedtuple

from chipsec.library.logger import logger, print_buffer_bytes

SPD_SMBUS_ADDRESS = 0xA0  # A2, A4, A6, A8, AA, AC, AE
SPD_SMBUS_ADDRESS_DIMM0 = SPD_SMBUS_ADDRESS
SPD_SMBUS_ADDRESS_DIMM1 = SPD_SMBUS_ADDRESS + 0x2
SPD_SMBUS_ADDRESS_DIMM2 = SPD_SMBUS_ADDRESS + 0x4
SPD_SMBUS_ADDRESS_DIMM3 = SPD_SMBUS_ADDRESS + 0x6
SPD_SMBUS_ADDRESS_DIMM4 = SPD_SMBUS_ADDRESS + 0x8
SPD_SMBUS_ADDRESS_DIMM5 = SPD_SMBUS_ADDRESS + 0xA
SPD_SMBUS_ADDRESS_DIMM6 = SPD_SMBUS_ADDRESS + 0xC
SPD_SMBUS_ADDRESS_DIMM7 = SPD_SMBUS_ADDRESS + 0xE
MAX_DIMM_SPD_COUNT = 8

SPD_DIMMS = {}
for i in range(MAX_DIMM_SPD_COUNT):
    SPD_DIMMS[SPD_SMBUS_ADDRESS + i * 2] = f'DIMM{i:d}'

SPD_DIMM_ADDRESSES = {}
for i in range(MAX_DIMM_SPD_COUNT):
    SPD_DIMM_ADDRESSES[f'DIMM{i:d}'] = SPD_SMBUS_ADDRESS + i * 2

###############################################################################
#
# SPD Decode
#
# References:
# http://www.jedec.org/sites/default/files/docs/4_01_02R19.pdf
# http://www.jedec.org/sites/default/files/docs/4_01_02_10R17.pdf
# http://www.jedec.org/sites/default/files/docs/4_01_02_11R24.pdf
# http://www.jedec.org/sites/default/files/docs/4_01_02_12R23A.pdf
# http://www.simmtester.com/page/news/showpubnews.asp?num=184
# http://www.simmtester.com/page/news/showpubnews.asp?num=153
# http://www.simmtester.com/page/news/showpubnews.asp?num=101
# http://en.wikipedia.org/wiki/Serial_presence_detect
#
# @TODO: add decode of other fields
#
###############################################################################

#
# DDR/DDR2/DDR3/DDR4 SPD
#
SPD_OFFSET_DRAM_DEVICE_TYPE = 2  # Fundamental Memory (DRAM) Type

#
# DDR SPD
#
SPD_OFFSET_DDR_SPD_BYTES = 0
SPD_OFFSET_DDR_SPD_SIZE = 1
SPD_OFFSET_DDR_ROW_ADDRESS_COUNT = 3
SPD_OFFSET_DDR_COL_ADDRESS_COUNT = 4
SPD_OFFSET_DDR_BANKDS_COUNT = 5
SPD_OFFSET_DDR_MODULE_WIDTH_LOW = 6
SPD_OFFSET_DDR_MODULE_WIDTH_HIGH = 7
SPD_OFFSET_DDR_VOLTAGE_IFACE_LEVEL = 8
SPD_OFFSET_DDR_CLOCK_FREQUENCY = 9
SPD_OFFSET_DDR_tAC = 10
SPD_OFFSET_DDR_DIMM_CONFIGURATION_TYPE = 11
SPD_OFFSET_DDR_REFRESH_RATE_TYPE = 12
SPD_OFFSET_DDR_PRIMARY_SDRAM_WIDTH = 13
SPD_OFFSET_DDR_ECC_SDRAM_WIDTH = 14
SPD_OFFSET_DDR_tCCD_MIN = 15

#
# DDR3 SPD
#
SPD_OFFSET_DDR3_SPD_BYTES = 0  # SPD Bytes Written, Device Size, CRC coverage/range
SPD_OFFSET_DDR3_SPD_REVISION = 1  # SPD Revision
SPD_OFFSET_DDR3_MODULE_TYPE = 3  # Module Type
SPD_OFFSET_DDR3_SDRAM_DENSITY_BANKS = 4  # SDRAM Density and Banks
SPD_OFFSET_DDR3_SDRAM_ADDRESSING = 5  # SDRAM Addressing
SPD_OFFSET_DDR3_VDD = 6  # Module Nominal Voltage, VDD
SPD_OFFSET_DDR3_MODULE_ORGANIZATION = 7  # Module Organization
SPD_OFFSET_DDR3_MEMORY_BUS_WIDTH_ECC = 8  # Module Memory Bus Width
SPD_OFFSET_DDR3_FTB = 9  # Fine Time Base (FTB) Divident / Divisor
SPD_OFFSET_DDR3_MTB_DIVIDENT = 10  # Medium Time Base (MTB) Divident
SPD_OFFSET_DDR3_MTB_DIVISOR = 11  # Medium Time Base (MTB) Divisor
SPD_OFFSET_DDR3_tCK_MIN = 12  # SDRAM Minimum Cycle Time (tCKmin)
SPD_OFFSET_DDR3_RESERVED13 = 13  # Reserved
SPD_OFFSET_DDR3_CAS_LATENCY_LOW = 14  # CAS Latencies Supported, LSB
SPD_OFFSET_DDR3_CAS_LATENCY_HIGH = 15  # CAS Latencies Supported, MSB

#
# DDR4 SPD
#
# Base Configuration and DRAM Parameters
SPD_OFFSET_DDR4_SPD_BYTES = 0  # SPD Bytes Written, Device Size, CRC coverage/range
SPD_OFFSET_DDR4_SPD_REVISION = 1  # SPD Revision
SPD_OFFSET_DDR4_MODULE_TYPE = 3  # Module Type
SPD_OFFSET_DDR4_SDRAM_DENSITY_BANKS = 4  # SDRAM Density and Banks
SPD_OFFSET_DDR4_SDRAM_ADDRESSING = 5  # SDRAM Addressing
SPD_OFFSET_DDR4_SDRAM_PACKAGE_TYPE = 6  # SDRAM Package Type
SPD_OFFSET_DDR4_OPTIONAL_FEATURES = 7  # SDRAM Optional Features
SPD_OFFSET_DDR4_THERMAL_AND_REFRESH = 8  # SDRAM Thermal and Refresh Options
SPD_OFFSET_DDR4_OPTIONAL_FEATURES_1 = 9  # Other Optional Features
SPD_OFFSET_DDR4_RESERVED10 = 10  # Reserved (must be 0x00)
SPD_OFFSET_DDR4_VDD = 11  # Module Nominal Voltage, VDD
SPD_OFFSET_DDR4_MODULE_ORGANIZATION = 12  # Module Organization
SPD_OFFSET_DDR4_MEMORY_BUS_WIDTH_ECC = 13  # Module Memory Bus Width
SPD_OFFSET_DDR4_MODULE_THERMAL_SENSOR = 14  # Module Thermal Sensor
SPD_OFFSET_DDR4_MODULE_TYPE_EXTENDED = 15  # Extended Module Type


#
# Fundamental Memory Type
# Ref: http://www.jedec.org/sites/default/files/docs/4_01_02_01R12.pdf
#
DRAM_DEVICE_TYPE_FPM_DRAM = 0x1
DRAM_DEVICE_TYPE_EDO = 0x2
DRAM_DEVICE_TYPE_PIPELINED_NIBBLE = 0x3
DRAM_DEVICE_TYPE_SDR = 0x4
DRAM_DEVICE_TYPE_MULTIPLEXED_ROM = 0x5
DRAM_DEVICE_TYPE_DDR = 0x7
DRAM_DEVICE_TYPE_DDR2 = 0x8
DRAM_DEVICE_TYPE_DDR3 = 0x0B
DRAM_DEVICE_TYPE_DDR4 = 0x0C
DRAM_DEVICE_TYPE = {
    DRAM_DEVICE_TYPE_FPM_DRAM: 'Standard Fast Page Mode DRAM',
    DRAM_DEVICE_TYPE_EDO: 'EDO DRAM',
    DRAM_DEVICE_TYPE_PIPELINED_NIBBLE: 'Pipelined Nibble',
    DRAM_DEVICE_TYPE_SDR: 'Sync DRAM (SDRAM)',
    DRAM_DEVICE_TYPE_MULTIPLEXED_ROM: 'Multiplexed ROM',
    DRAM_DEVICE_TYPE_DDR: 'DDR SDRAM',
    DRAM_DEVICE_TYPE_DDR2: 'DDR2 SDRAM',
    DRAM_DEVICE_TYPE_DDR3: 'DDR3 SDRAM',
    DRAM_DEVICE_TYPE_DDR4: 'DDR4 SDRAM'
}

MODULE_TYPE_UNDEFINED = 0x0
MODULE_TYPE_RDIMM = 0x1
MODULE_TYPE_UDIMM = 0x2
MODULE_TYPE_SODIMM = 0x3
MODULE_TYPE_LRDIMM = 0x4
MODULE_TYPE = {
    MODULE_TYPE_UNDEFINED: 'Undefined',
    MODULE_TYPE_RDIMM: 'Registered Long DIMM',
    MODULE_TYPE_UDIMM: 'Unbuffered Long DIMM',
    MODULE_TYPE_SODIMM: 'Small Outline DIMM',
    MODULE_TYPE_LRDIMM: 'LR-DIMM'
}

SPD_REVISION_0_0 = 0x00
SPD_REVISION_0_7 = 0x07
SPD_REVISION_0_8 = 0x08
SPD_REVISION_0_9 = 0x09
SPD_REVISION_1_0 = 0x10
SPD_REVISION_1_1 = 0x11
SPD_REVISION_1_2 = 0x12
SPD_REVISION_1_3 = 0x13


def SPD_REVISION(revision: int) -> str:
    return (f'{revision >> 4:d}.{revision & 0xF:d}')


def dram_device_type_name(dram_type: int) -> str:
    dt_name = DRAM_DEVICE_TYPE[dram_type] if dram_type in DRAM_DEVICE_TYPE else 'unknown'
    return dt_name


def module_type_name(module_type: int) -> str:
    mt_name = MODULE_TYPE[module_type] if module_type in MODULE_TYPE else 'unknown'
    return mt_name


SPD_DDR_FORMAT = '=4B'


class SPD_DDR(namedtuple('SPD_DDR', 'SPDBytes TotalBytes DeviceType RowAddressCount')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""------------------------------------------------------------------
SPD DDR
------------------------------------------------------------------
[0] Number of SPD bytes written: 0x{self.SPDBytes:02X}
[1] Total number of bytes      : 0x{self.TotalBytes:02X}
[2] DRAM Memory Type           : 0x{self.DeviceType:02X} ({dram_device_type_name(self.DeviceType)})
[3] Number of Row Addresses    : 0x{self.RowAddressCount:02X}
------------------------------------------------------------------
"""


SPD_DDR2_FORMAT = '=4B'


class SPD_DDR2(namedtuple('SPD_DDR2', 'SPDBytes TotalBytes DeviceType RowAddressCount')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""------------------------------------------------------------------
SPD DDR2
------------------------------------------------------------------
[0] Number of SPD bytes written: 0x{self.SPDBytes:02X}
[1] Total number of bytes      : 0x{self.TotalBytes:02X}
[2] DRAM Memory Type           : 0x{self.DeviceType:02X} ({dram_device_type_name(self.DeviceType)})
[3] Number of Row Addresses    : 0x{self.RowAddressCount:02X}
------------------------------------------------------------------
"""


SPD_DDR3_FORMAT = '=16B'


class SPD_DDR3(namedtuple('SPD_DDR3', 'SPDBytes Revision DeviceType ModuleType ChipSize Addressing Voltages ModuleOrg BusWidthECC FTB MTBDivident MTBDivisor tCKMin RsvdD CASLo CASHi')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""------------------------------------------------------------------
SPD DDR3
------------------------------------------------------------------
[0x00] SPD Bytes Written, Device Size, CRC: 0x{self.SPDBytes:02X}
[0x01] SPD Revision                       : 0x{self.Revision:02X} ({SPD_REVISION(self.Revision)})
[0x02] DRAM Memory Type                   : 0x{self.DeviceType:02X} ({dram_device_type_name(self.DeviceType)})
[0x03] Module Type                        : 0x{self.ModuleType:02X} ({module_type_name(self.ModuleType)})
[0x04] SDRAM Density and Banks            : 0x{self.ChipSize:02X}
[0x05] SDRAM Addressing (Row/Column Bits) : 0x{self.Addressing:02X}
[0x06] Module Nominal Voltage, VDD        : 0x{self.Voltages:02X}
[0x07] Module Organization                : 0x{self.ModuleOrg:02X}
[0x08] Module Memory Bus Width, ECC       : 0x{self.BusWidthECC:02X}
[0x09] FTB Divident/Divisor               : 0x{self.FTB:02X}
[0x0A] MTB Divident                       : 0x{self.MTBDivident:02X}
[0x0B] MTB Divisor                        : 0x{self.MTBDivisor:02X}
[0x0C] SDRAM Minimum Cycle Time (tCKmin)  : 0x{self.tCKMin:02X}
[0x0D] Reserved                           : 0x{self.RsvdD:02X}
[0x0E] CAS Latencies Supported (LSB)      : 0x{self.CASLo:02X}
[0x0F] CAS Latencies Supported (MSB)      : 0x{self.CASHi:02X}
------------------------------------------------------------------
"""


SPD_DDR4_FORMAT = '=16B'


class SPD_DDR4(namedtuple('SPD_DDR4', 'SPDBytes Revision DeviceType ModuleType Density Addressing PackageType OptFeatures ThermalRefresh OptFeatures1 ReservedA VDD ModuleOrg BusWidthECC ThermSensor ModuleTypeExt')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""------------------------------------------------------------------
SPD DDR4
------------------------------------------------------------------
Base Configuration and DRAM Parameters
[0x00] SPD Bytes Written, Device Size, CRC: 0x{self.SPDBytes:02X}
[0x01] SPD Revision                       : 0x{self.Revision:02X} ({SPD_REVISION(self.Revision)})
[0x02] DRAM Memory Type                   : 0x{self.DeviceType:02X} ({dram_device_type_name(self.DeviceType)})
[0x03] Module Type                        : 0x{self.ModuleType:02X} ({module_type_name(self.ModuleType)})
[0x04] SDRAM Density and Banks            : 0x{self.Density:02X}
[0x05] SDRAM Addressing (Row/Column Bits) : 0x{self.Addressing:02X}
[0x06] SDRAM Package Type                 : 0x{self.PackageType:02X}
[0x07] SDRAM Optional Features            : 0x{self.OptFeatures:02X}
[0x08] SDRAM Thermal and Refresh Options  : 0x{self.ThermalRefresh:02X}
[0x09] Other Optional Features            : 0x{self.OptFeatures1:02X}
[0x0A] Reserved (== 0x00)                 : 0x{self.ReservedA:02X}
[0x0B] Module Nominal Voltage, VDD        : 0x{self.VDD:02X}
[0x0C] Module Organization                : 0x{self.ModuleOrg:02X}
[0x0D] Module Memory Bus Width            : 0x{self.BusWidthECC:02X}
[0x0E] Module Thermal Sensor              : 0x{self.ThermSensor:02X}
[0x0F] Extended Module Type               : 0x{self.ModuleTypeExt:02X}
------------------------------------------------------------------
"""


###############################################################################
#
# Main SPD HAL component class
#
###############################################################################

class SPD:
    def __init__(self, smbus):
        self.smbus = smbus

    def read_byte(self, offset: int, device: int = SPD_SMBUS_ADDRESS) -> int:
        return self.smbus.read_byte(device, offset)

    def write_byte(self, offset: int, value: int, device: int = SPD_SMBUS_ADDRESS) -> bool:
        return self.smbus.write_byte(device, offset, value)

    def read_range(self, start_offset: int, size: int, device: int = SPD_SMBUS_ADDRESS) -> bytes:
        return bytes(self.read_byte(start_offset + i, device) for i in range(size))

    def write_range(self, start_offset: int, buffer: bytes, device: int = SPD_SMBUS_ADDRESS) -> bool:
        for i, b in enumerate(buffer):
            self.write_byte(start_offset + i, b, device)
        return True

    def dump_spd_rom(self, device: int = SPD_SMBUS_ADDRESS) -> bytes:
        return self.read_range(0x0, 0x100, device)

    #
    # Decoding certain bytes of DIMM SPD: may be dependent on the DRAM type
    #
    def getDRAMDeviceType(self, device: int = SPD_SMBUS_ADDRESS) -> int:
        dram_type = self.read_byte(SPD_OFFSET_DRAM_DEVICE_TYPE, device)
        logger().log_hal(f'[spd][0x{device:02X}] DRAM Device Type (byte 2): 0x{dram_type:01X}')
        return dram_type

    def getModuleType(self, device: int = SPD_SMBUS_ADDRESS) -> int:
        module_type = self.read_byte(SPD_OFFSET_DDR3_MODULE_TYPE, device)
        logger().log_hal(f'[spd][0x{device:02X}] Module Type (byte 3): 0x{module_type:01X}')
        return module_type

    def isECC(self, device: int = SPD_SMBUS_ADDRESS) -> bool:
        device_type = self.getDRAMDeviceType(device)
        ecc_supported = False
        ecc_off = 0
        ecc = None
        if DRAM_DEVICE_TYPE_DDR3 == device_type:
            ecc_off = SPD_OFFSET_DDR3_MEMORY_BUS_WIDTH_ECC
            ecc = self.read_byte(ecc_off, device)
            ecc_supported = (0xB == ecc)
        elif DRAM_DEVICE_TYPE_DDR4 == device_type:
            ecc_off = SPD_OFFSET_DDR4_MEMORY_BUS_WIDTH_ECC
            ecc = self.read_byte(ecc_off, device)
            ecc_supported = (0xB == ecc)
        elif DRAM_DEVICE_TYPE_DDR == device_type or DRAM_DEVICE_TYPE_DDR2 == device_type:
            ecc_off = SPD_OFFSET_DDR_DIMM_CONFIGURATION_TYPE
            ecc = self.read_byte(ecc_off, device)
            ecc_supported = (0x2 == ecc)
            ecc_width = self.read_byte(SPD_OFFSET_DDR_ECC_SDRAM_WIDTH, device)
            logger().log_hal(f'[spd][0x{device:02X}] DDR/DDR2 ECC width (byte {SPD_OFFSET_DDR_ECC_SDRAM_WIDTH:d}): 0x{ecc_width:02X}')

        if logger().HAL:
            if ecc is None:
                logger().log(f'[spd][0x{device:02X}] Unable to determine ECC support')
            else:
                not_str = '' if ecc_supported else 'not '
                logger().log(f'[spd][0x{device:02X}] ECC is {not_str}supported by the DIMM (byte {ecc_off:d} = 0x{ecc:02X})')
        return ecc_supported

    def detect(self) -> List[int]:
        _dimms = []
        for d in SPD_DIMMS:
            if self.isSPDPresent(d):
                _dimms.append(d)
        if logger().HAL:
            logger().log('Detected the following SPD devices:')
            for _dimm in _dimms:
                logger().log(f"{SPD_DIMMS[_dimm]}: 0x{_dimm:02X}")
        return _dimms

    def isSPDPresent(self, device: int = SPD_SMBUS_ADDRESS) -> bool:
        device_type = self.getDRAMDeviceType(device)
        is_spd_present = (device_type != 0xFF)
        not_str = '' if is_spd_present else 'not '
        logger().log_hal(f'[spd][0x{device:02X}] Detecting SPD.. {not_str}found (DRAM memory type = 0x{device_type:X})')
        return is_spd_present

    def decode(self, device: int = SPD_SMBUS_ADDRESS) -> None:
        spd: Any = None
        device_type = self.getDRAMDeviceType(device)
        spd_buffer = self.dump_spd_rom(device)
        logger().log(f'[spd][0x{device:02X}] Serial Presence Detect (SPD) EEPROM contents:')
        print_buffer_bytes(spd_buffer)

        if DRAM_DEVICE_TYPE_DDR == device_type:
            spd = SPD_DDR(*struct.unpack_from(SPD_DDR_FORMAT, spd_buffer))
        elif DRAM_DEVICE_TYPE_DDR2 == device_type:
            spd = SPD_DDR2(*struct.unpack_from(SPD_DDR2_FORMAT, spd_buffer))
        elif DRAM_DEVICE_TYPE_DDR3 == device_type:
            spd = SPD_DDR3(*struct.unpack_from(SPD_DDR3_FORMAT, spd_buffer))
        elif DRAM_DEVICE_TYPE_DDR4 == device_type:
            spd = SPD_DDR4(*struct.unpack_from(SPD_DDR4_FORMAT, spd_buffer))
        else:
            logger().log_warning('[spd] Unsupported SPD format')

        if spd is not None:
            logger().log(str(spd))
