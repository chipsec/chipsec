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
from chipsec.hal import spi

SPI_FLASH_DESCRIPTOR_SIGNATURE = struct.pack('=I', 0x0FF0A55A)
SPI_FLASH_DESCRIPTOR_SIZE = 0x1000


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

    flregs = []
    for r in range(spi.SPI_REGION_NUMBER_IN_FD):
        flreg_off = frba + r * 4
        flreg = struct.unpack_from('=I', fd[flreg_off:flreg_off + 0x4])[0]
        (base, limit) = spi.get_SPI_region(flreg)
        notused = (base > limit)
        flregs.append((r, spi.SPI_REGION_NAMES[r], flreg, base, limit, notused))

    fd_size = flregs[spi.FLASH_DESCRIPTOR][4] - flregs[spi.FLASH_DESCRIPTOR][3] + 1
    fd_notused = flregs[spi.FLASH_DESCRIPTOR][5]
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
    flmap1 = struct.unpack_from('=I', fd[0x18:0x1C])[0]
    flmap2 = struct.unpack_from('=I', fd[0x1C:0x20])[0]
    cs.register.print('FLMAP0', flmap0)
    cs.register.print('FLMAP1', flmap1)
    cs.register.print('FLMAP2', flmap2)

    fcba = cs.register.get_field('FLMAP0', flmap0, 'FCBA')
    nc = cs.register.get_field('FLMAP0', flmap0, 'NC')
    frba = cs.register.get_field('FLMAP0', flmap0, 'FRBA')
    fcba = fcba << 4
    frba = frba << 4
    nc += 1
    logger().log('')
    logger().log('+ 0x0014 Flash Descriptor Map:')
    logger().log('========================================================')
    logger().log(f'  Flash Component Base Address: 0x{fcba:08X}')
    logger().log(f'  Flash Region Base Address   : 0x{frba:08X}')
    logger().log(f'  Number of Flash Components  : {nc:d}')

    nr = spi.SPI_REGION_NUMBER_IN_FD
    if cs.register.has_field('FLMAP0', 'NR'):
        nr = cs.register.get_field('FLMAP0', flmap0, 'NR')
        if nr == 0:
            logger().log_warning('only 1 region (FD) is found. Looks like flash descriptor binary is from Skylake platform or later. Try with option --platform')
        nr += 1
        logger().log(f'  Number of Regions           : {nr:d}')

    fmba = cs.register.get_field('FLMAP1', flmap1, 'FMBA')
    nm = cs.register.get_field('FLMAP1', flmap1, 'NM')
    fpsba = cs.register.get_field('FLMAP1', flmap1, 'FPSBA')
    psl = cs.register.get_field('FLMAP1', flmap1, 'PSL')
    fmba = fmba << 4
    fpsba = fpsba << 4
    logger().log(f'  Flash Master Base Address   : 0x{fmba:08X}')
    logger().log(f'  Number of Masters           : {nm:d}')
    logger().log(f'  Flash PCH Strap Base Address: 0x{fpsba:08X}')
    logger().log(f'  PCH Strap Length            : 0x{psl:X}')

    fcpusba = cs.register.get_field('FLMAP2', flmap2, 'FCPUSBA')
    cpusl = cs.register.get_field('FLMAP2', flmap2, 'CPUSL')
    logger().log(f'  Flash CPU Strap Base Address: 0x{fcpusba:08X}')
    logger().log(f'  CPU Strap Length            : 0x{cpusl:X}')

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

    flregs: Dict[int, Tuple[int, int, int, str]] = {}
    for r in range(nr):
        flreg_off = frba + r * 4
        flreg = struct.unpack_from('=I', fd[flreg_off:flreg_off + 0x4])[0]
        if not cs.register.is_defined(f'FLREG{r:d}'):
            continue
        base = cs.register.get_field((f'FLREG{r:d}'), flreg, 'RB') << spi.SPI_FLA_SHIFT
        limit = cs.register.get_field((f'FLREG{r:d}'), flreg, 'RL') << spi.SPI_FLA_SHIFT
        notused = '(not used)' if base > limit or flreg == 0xFFFFFFFF else ''
        flregs[r] = (flreg, base, limit, notused)
        logger().log(f'+ 0x{flreg_off:04X} FLREG{r:d}   : 0x{flreg:08X} {notused}')

    logger().log('')
    logger().log('Flash Regions')
    logger().log('--------------------------------------------------------')
    logger().log(' Region                | FLREGx    | Base     | Limit   ')
    logger().log('--------------------------------------------------------')
    for r in flregs:
        if flregs[r]:
            logger().log(f'{r:d} {spi.SPI_REGION_NAMES[r]:20s} | {flregs[r][0]:08X}  | {flregs[r][1]:08X} | {flregs[r][2]:08X} {flregs[r][3]}')

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
        master_region_ra = cs.register.get_field('FLMSTR1', flmstr, 'MRRA')
        master_region_wa = cs.register.get_field('FLMSTR1', flmstr, 'MRWA')
        flmstrs[m] = (master_region_ra, master_region_wa)
        logger().log(f'+ 0x{flmstr_off:04X} FLMSTR{m + 1:d}   : 0x{flmstr:08X}')

    logger().log('')
    logger().log('Master Read/Write Access to Flash Regions')
    logger().log('--------------------------------------------------------')
    s = ' Region                 '
    for m in range(nm):
        if m in spi.SPI_MASTER_NAMES:
            s = f'{s}| {spi.SPI_MASTER_NAMES[m]:9}'
        else:
            s = f'{s}| Master {m:-2d}'
    logger().log(s)
    logger().log('--------------------------------------------------------')
    for r in range(nr):
        s = f'{r:-2d} {spi.SPI_REGION_NAMES[r]:20s} '
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
