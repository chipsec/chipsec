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
SPI Flash Descriptor binary parsing functionality


usage:
    >>> fd = read_file( fd_file )
    >>> parse_spi_flash_descriptor( fd )
"""

import struct
from typing import Dict, List, Optional, Tuple
from chipsec.library.logger import logger, print_buffer_bytes
from chipsec.library.intel.spi import SPI_REGION_NAMES, SPI_FREGx_BASE_MASK, SPI_FLA_SHIFT, SPI_FREGx_LIMIT_MASK, SPI_FLA_PAGE_MASK, SPI_REGION_tuple, print_SPI_Flash_Regions
from chipsec.library.intel.spi import SPI_REGION_NUMBER_IN_FD, FLASH_DESCRIPTOR, SPI_MASTER_NAMES, SPI_FLASH_DESCRIPTOR_SIZE, SPI_FLASH_DESCRIPTOR_SIGNATURE


def get_spi_flash_descriptor(rom: bytes) -> Tuple[int, bytes]:
    pos = rom.find(SPI_FLASH_DESCRIPTOR_SIGNATURE)
    if (-1 == pos or pos < 0x10):
        return (-1, b'')
    fd_off = pos - 0x10
    fd = rom[fd_off: fd_off + SPI_FLASH_DESCRIPTOR_SIZE]
    return (fd_off, fd)


def get_SPI_master(flmstr: int) -> Tuple[int, int, int]:
    requester_id = (flmstr & 0xFFFF)
    master_region_ra = ((flmstr >> 16) & 0xFF)
    master_region_wa = ((flmstr >> 24) & 0xFF)
    return (requester_id, master_region_ra, master_region_wa)


def get_spi_regions(fd: bytes) -> Optional[List[Tuple[int, str, int, int, int, bool]]]:
    pos = fd.find(SPI_FLASH_DESCRIPTOR_SIGNATURE)
    if not (pos == 0x10):
        return None

    flmap0 = struct.unpack_from('=I', fd[0x14:0x18])[0]
    # Flash Region Base Address (bits [23:16])
    frba = ((flmap0 & 0x00FF0000) >> 12)

    flregs = {}
    for r in range(SPI_REGION_NUMBER_IN_FD):
        flreg_off = frba + r * 4
        flreg = struct.unpack_from('=I', fd[flreg_off:flreg_off + 0x4])[0]
        base = (flreg & SPI_FREGx_BASE_MASK) << SPI_FLA_SHIFT
        limit = ((flreg & SPI_FREGx_LIMIT_MASK) >> 4) | SPI_FLA_PAGE_MASK
        flregs[r] = SPI_REGION_tuple(SPI_REGION_NAMES[r], flreg, base, limit)

    fd_size = flregs[FLASH_DESCRIPTOR].limit - flregs[FLASH_DESCRIPTOR].base + 1
    fd_notused = flregs[FLASH_DESCRIPTOR].base > flregs[FLASH_DESCRIPTOR].limit
    if fd_notused or (fd_size != SPI_FLASH_DESCRIPTOR_SIZE):
        return None

    return flregs


def parse_spi_flash_descriptor(cs, rom: bytes) -> None:
    if not (isinstance(rom, str) or isinstance(rom, bytes)):
        logger().log_error(f'Invalid fd object type {type(rom)}')
        return

    pos = rom.find(SPI_FLASH_DESCRIPTOR_SIGNATURE)
    if (-1 == pos) or (pos < 0x10):
        desc_signature = struct.unpack('=I', SPI_FLASH_DESCRIPTOR_SIGNATURE)[0]
        logger().log_error(f'Valid SPI flash descriptor is not found (should have signature {desc_signature:08X})')
        return None

    fd_off = pos - 0x10
    logger().log(f'[spi_fd] Valid SPI flash descriptor found at offset 0x{fd_off:08X}')

    logger().log('')
    logger().log('########################################################')
    logger().log('# SPI FLASH DESCRIPTOR')
    logger().log('########################################################')
    logger().log('')

    fd = rom[fd_off: fd_off + SPI_FLASH_DESCRIPTOR_SIZE]
    fd_sig = struct.unpack_from('=I', fd[0x10:0x14])[0]

    logger().log(f'+ 0x0000 Reserved : 0x{fd[0x0:0xF].hex().upper()}')
    logger().log(f'+ 0x0010 Signature: 0x{fd_sig:08X}')

    #
    # Flash Descriptor Map Section
    #
    flmap0 = struct.unpack_from('=I', fd[0x14:0x18])[0]
    flmap0_obj = cs.register.get_list_by_name('8086.SPI.FLMAP0')[0]
    flmap0_obj.value = flmap0

    flmap1 = struct.unpack_from('=I', fd[0x18:0x1C])[0]
    flmap1_obj = cs.register.get_list_by_name('8086.SPI.FLMAP1')[0]
    flmap1_obj.value = flmap1

    flmap2 = struct.unpack_from('=I', fd[0x1C:0x20])[0]
    flmap2_obj = cs.register.get_list_by_name('8086.SPI.FLMAP2')[0]
    flmap2_obj.value = flmap2

    fcba = flmap0_obj.get_field('FCBA') << 4
    nc = flmap0_obj.get_field('NC') + 1
    frba = flmap0_obj.get_field('FRBA') << 4

    logger().log('')
    logger().log('+ 0x0014 Flash Descriptor Map:')
    logger().log('========================================================')
    logger().log(f'  Flash Component Base Address: 0x{fcba:08X}')
    logger().log(f'  Flash Region Base Address   : 0x{frba:08X}')
    logger().log(f'  Number of Flash Components  : {nc:d}')

    nr = SPI_REGION_NUMBER_IN_FD
    if flmap0_obj.has_field('NR'):
        nr = flmap0_obj.get_field('NR')
        if nr == 0:
            logger().log_warning('only 1 region (FD) is found. Looks like flash descriptor binary is from Skylake platform or later. Try with option --platform')
        nr += 1
        logger().log(f'  Number of Regions           : {nr:d}')

    fmba = flmap1_obj.get_field('FMBA') << 4
    nm = flmap1_obj.get_field('NM')
    fpsba = flmap1_obj.get_field('FPSBA') << 4
    psl = flmap1_obj.get_field('PSL')

    logger().log(f'  Flash Master Base Address   : 0x{fmba:08X}')
    logger().log(f'  Number of Masters           : {nm:d}')
    logger().log(f'  Flash PCH Strap Base Address: 0x{fpsba:08X}')
    logger().log(f'  PCH Strap Length            : 0x{psl:X}')

    flmap2_obj.print()

    #
    # Flash Descriptor Component Section
    #
    logger().log('')
    logger().log(f'+ 0x{fcba:04X} Component Section:')
    logger().log('========================================================')

    flcomp = struct.unpack_from('=I', fd[fcba + 0x0:fcba + 0x4])[0]
    logger().log(f'+ 0x{fcba:04X} FLCOMP   : 0x{flcomp:08X}')
    flil = struct.unpack_from('=I', fd[fcba + 0x4:fcba + 0x8])[0]
    logger().log(f'+ 0x{fcba + 0x4:04X} FLIL     : 0x{flil:08X}')
    flpb = struct.unpack_from('=I', fd[fcba + 0x8:fcba + 0xC])[0]
    logger().log(f'+ 0x{fcba + 0x8:04X} FLPB     : 0x{flpb:08X}')

    #
    # Flash Descriptor Region Section
    #
    logger().log('')
    logger().log(f'+ 0x{frba:04X} Region Section:')
    logger().log('========================================================')

    flregs = get_spi_regions(fd)
    print_SPI_Flash_Regions(flregs)

    #
    # Flash Descriptor Master Section
    #
    logger().log('')
    logger().log(f'+ 0x{fmba:04X} Master Section:')
    logger().log('========================================================')

    flmstrs: Dict[int, Tuple[int, int]] = {}
    for m in range(nm):
        flmstr_off = fmba + m * 4
        flmstr = struct.unpack_from('=I', fd[flmstr_off:flmstr_off + 0x4])[0]
        flmstr_obj = cs.register.get_list_by_name('8086.SPI.FLMSTR1')[0]
        flmstr_obj.value = flmstr
        master_region_ra = flmstr_obj.get_field('MRRA')
        master_region_wa = flmstr_obj.get_field('MRWA')
        flmstrs[m] = (master_region_ra, master_region_wa)
        logger().log(f'+ 0x{flmstr_off:04X} FLMSTR{m + 1:d}   : 0x{flmstr:08X}')

    logger().log('')
    logger().log('Master Read/Write Access to Flash Regions')
    logger().log('--------------------------------------------------------')
    s = ' Region                 '
    for m in range(nm):
        if m in SPI_MASTER_NAMES:
            s = f'{s}| {SPI_MASTER_NAMES[m]:9}'
        else:
            s = f'{s}| Master {m:-2d}'
    logger().log(s)
    logger().log('--------------------------------------------------------')
    for r in range(nr):
        s = f'{r:-2d} {SPI_REGION_NAMES[r]:20s} '
        for m in range(nm):
            access_s = ''
            mask = (0x1 << r)
            if (flmstrs[m][0] & mask):
                access_s += 'R'
            if (flmstrs[m][1] & mask):
                access_s += 'W'
            s = f'{s}| {access_s:9}'
        logger().log(s)

    #
    # Flash Descriptor Upper Map Section
    #
    logger().log('')
    logger().log(f'+ 0x{0xEFC:04X} Flash Descriptor Upper Map:')
    logger().log('========================================================')

    flumap1 = struct.unpack_from('=I', fd[0xEFC:0xF00])[0]
    logger().log(f'+ 0x{0xEFC:04X} FLUMAP1   : 0x{flumap1:08X}')

    vtba = ((flumap1 & 0x000000FF) << 4)
    vtl = (((flumap1 & 0x0000FF00) >> 8) & 0xFF)
    logger().log(f'  VSCC Table Base Address    = 0x{vtba:08X}')
    logger().log(f'  VSCC Table Length          = 0x{vtl:02X}')

    #
    # OEM Section
    #
    logger().log('')
    logger().log(f'+ 0x{0xF00:04X} OEM Section:')
    logger().log('========================================================')
    print_buffer_bytes(fd[0xF00:])

    logger().log('')
    logger().log('########################################################')
    logger().log('# END OF SPI FLASH DESCRIPTOR')
    logger().log('########################################################')
