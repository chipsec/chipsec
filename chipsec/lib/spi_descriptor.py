# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2022, Intel Corporation

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# Contact information:
# chipsec@intel.com


"""
SPI Flash Descriptor binary parsing functionality

"""

import struct

from chipsec.hal.spi import SPI_REGION_NUMBER_IN_FD, FLASH_DESCRIPTOR, PCH_RCBA_SPI_FREGx_BASE_MASK
from chipsec.hal.spi import SPI_REGION_NAMES, SPI_FLA_SHIFT, SPI_FLA_PAGE_MASK
from chipsec.hal.spi import PCH_RCBA_SPI_FREGx_LIMIT_MASK

SPI_FLASH_DESCRIPTOR_SIGNATURE = struct.pack('=I', 0x0FF0A55A)
SPI_FLASH_DESCRIPTOR_SIZE = 0x1000


def get_spi_flash_descriptor(rom):
    pos = rom.find(SPI_FLASH_DESCRIPTOR_SIGNATURE)
    if (-1 == pos or pos < 0x10):
        return (-1, None)
    fd_off = pos - 0x10
    fd = rom[fd_off: fd_off + SPI_FLASH_DESCRIPTOR_SIZE]
    return (fd_off, fd)


def get_SPI_master(flmstr):
    requester_id = (flmstr & 0xFFFF)
    master_region_ra = ((flmstr >> 16) & 0xFF)
    master_region_wa = ((flmstr >> 24) & 0xFF)
    return (requester_id, master_region_ra, master_region_wa)


def get_spi_regions(fd):
    pos = fd.find(SPI_FLASH_DESCRIPTOR_SIGNATURE)
    if not (pos == 0x10):
        return None

    flmap0 = struct.unpack_from('=I', fd[0x14:0x18])[0]
    # Flash Region Base Address (bits [23:16])
    frba = ((flmap0 & 0x00FF0000) >> 12)
    # Number of Regions (bits [26:24])
    nr = (((flmap0 & 0xFF000000) >> 24) & 0x7)

    flregs = [None] * SPI_REGION_NUMBER_IN_FD
    for r in range(SPI_REGION_NUMBER_IN_FD):
        flreg_off = frba + r * 4
        flreg = struct.unpack_from('=I', fd[flreg_off:flreg_off + 0x4])[0]
        base = (flreg & PCH_RCBA_SPI_FREGx_BASE_MASK) << SPI_FLA_SHIFT
        limit = ((flreg & PCH_RCBA_SPI_FREGx_LIMIT_MASK) >> 4)
        limit |= SPI_FLA_PAGE_MASK
        notused = (base > limit)
        flregs[r] = (r, SPI_REGION_NAMES[r], flreg, base, limit, notused)

    fd_size = flregs[FLASH_DESCRIPTOR][4] - flregs[FLASH_DESCRIPTOR][3] + 1
    fd_notused = flregs[FLASH_DESCRIPTOR][5]
    if fd_notused or (fd_size != SPI_FLASH_DESCRIPTOR_SIZE):
        return None

    return flregs
