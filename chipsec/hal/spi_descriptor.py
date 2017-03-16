#!/usr/bin/python
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



# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
# (c) 2010-2012 Intel Corporation
#
# -------------------------------------------------------------------------------

"""
SPI Flash Descriptor binary parsing functionality


usage:
    >>> fd = read_file( fd_file )
    >>> parse_spi_flash_descriptor( fd )
"""

__version__ = '1.0'

import struct
import sys
import time

from chipsec.logger import *
from chipsec.file import *

from chipsec.cfg.common import *
from chipsec.hal import spi

SPI_FLASH_DESCRIPTOR_SIGNATURE = struct.pack('=I', 0x0FF0A55A )
SPI_FLASH_DESCRIPTOR_SIZE      = 0x1000


def get_spi_flash_descriptor( rom ):
    pos = rom.find( SPI_FLASH_DESCRIPTOR_SIGNATURE )
    if (-1 == pos or pos < 0x10):
        return (-1, None)
    fd_off = pos - 0x10
    fd = rom[ fd_off : fd_off + SPI_FLASH_DESCRIPTOR_SIZE ]
    return (fd_off, fd)

def get_SPI_master( flmstr ):
    requester_id  = (flmstr & 0xFFFF)
    master_region_ra = ((flmstr >> 16) & 0xFF)
    master_region_wa = ((flmstr >> 24) & 0xFF)
    return (requester_id, master_region_ra, master_region_wa)

def get_spi_regions( fd ):
    pos = fd.find( SPI_FLASH_DESCRIPTOR_SIGNATURE )
    if not (pos == 0x10):
        return None

    flmap0 = struct.unpack_from( '=I', fd[0x14:0x18] )[0]
    # Flash Region Base Address (bits [23:16])
    frba = ( (flmap0 & 0x00FF0000) >> 12 )
    # Number of Regions (bits [26:24])
    nr   = ( ((flmap0 & 0xFF000000) >> 24) & 0x7 )

    flregs = [None] * spi.SPI_REGION_NUMBER_IN_FD
    for r in range( spi.SPI_REGION_NUMBER_IN_FD ):
        flreg_off = frba + r*4
        flreg = struct.unpack_from( '=I', fd[flreg_off:flreg_off + 0x4] )[0]
        (base,limit) = spi.get_SPI_region(flreg)
        notused = (base > limit)
        flregs[r] = (r, spi.SPI_REGION_NAMES[r],flreg,base,limit,notused)

    fd_size    = flregs[spi.FLASH_DESCRIPTOR][4] - flregs[spi.FLASH_DESCRIPTOR][3] + 1
    fd_notused = flregs[spi.FLASH_DESCRIPTOR][5]
    if fd_notused or (fd_size != SPI_FLASH_DESCRIPTOR_SIZE):
        return None

    return flregs



def parse_spi_flash_descriptor( cs, rom ):
    if not (type(rom) == str):
        logger().error('Invalid fd object type %s'%type(rom))
        return

    pos = rom.find( SPI_FLASH_DESCRIPTOR_SIGNATURE )
    if (-1 == pos or pos < 0x10):
        logger().error( 'Valid SPI flash descriptor is not found (should have signature %08X)' % struct.unpack('=I',SPI_FLASH_DESCRIPTOR_SIGNATURE) )
        return None

    fd_off = pos - 0x10
    logger().log( '[spi_fd] Valid SPI flash descriptor found at offset 0x%08X' % fd_off )

    logger().log( '' )
    logger().log( '########################################################' )
    logger().log( '# SPI FLASH DESCRIPTOR' )
    logger().log( '########################################################' )
    logger().log( '' )

    fd     = rom[ fd_off : fd_off + SPI_FLASH_DESCRIPTOR_SIZE ]
    fd_sig = struct.unpack_from( '=I', fd[0x10:0x14] )

    logger().log( '+ 0x0000 Reserved : %016s' % fd[0x0:0xF].encode('hex').upper() )
    logger().log( '+ 0x0010 Signature: 0x%08X' % fd_sig )

    #
    # Flash Descriptor Map Section
    #
    flmap0 = struct.unpack_from( '=I', fd[0x14:0x18] )[0]
    flmap1 = struct.unpack_from( '=I', fd[0x18:0x1C] )[0]
    flmap2 = struct.unpack_from( '=I', fd[0x1C:0x20] )[0]
    cs.print_register('FLMAP0', flmap0)
    cs.print_register('FLMAP1', flmap1)
    cs.print_register('FLMAP2', flmap2)

    fcba = cs.get_register_field('FLMAP0', flmap0, 'FCBA')
    nc   = cs.get_register_field('FLMAP0', flmap0, 'NC')
    frba = cs.get_register_field('FLMAP0', flmap0, 'FRBA')
    fcba = fcba << 4
    frba = frba << 4
    nc  += 1
    logger().log( '' )
    logger().log( '+ 0x0014 Flash Descriptor Map:' )
    logger().log( '========================================================' )
    logger().log( '  Flash Component Base Address: 0x%08X' % fcba )
    logger().log( '  Flash Region Base Address   : 0x%08X' % frba )
    logger().log( '  Number of Flash Components  : %d' % nc )

    nr = spi.SPI_REGION_NUMBER_IN_FD
    if cs.register_has_field('FLMAP0', 'NR'):
        nr = cs.get_register_field('FLMAP0', flmap0, 'NR')
        if nr == 0:
            logger().warn( 'only 1 region (FD) is found. Looks like flash descriptor binary is from Skylake platform or later. Try with option --platform' )
        nr += 1
        logger().log( '  Number of Regions           : %d' % nr )

    fmba  = cs.get_register_field('FLMAP1', flmap1, 'FMBA')
    nm    = cs.get_register_field('FLMAP1', flmap1, 'NM')
    fpsba = cs.get_register_field('FLMAP1', flmap1, 'FPSBA')
    psl   = cs.get_register_field('FLMAP1', flmap1, 'PSL')
    fmba  = fmba << 4
    fpsba = fpsba << 4
    logger().log( '  Flash Master Base Address   : 0x%08X' % fmba )
    logger().log( '  Number of Masters           : %d' % nm )
    logger().log( '  Flash PCH Strap Base Address: 0x%08X' % fpsba )
    logger().log( '  PCH Strap Length            : 0x%X' % psl )

    fcpusba = cs.get_register_field('FLMAP2', flmap2, 'FCPUSBA')
    cpusl   = cs.get_register_field('FLMAP2', flmap2, 'CPUSL')
    logger().log( '  Flash CPU Strap Base Address: 0x%08X' % fcpusba )
    logger().log( '  CPU Strap Length            : 0x%X' % cpusl )

    #
    # Flash Descriptor Component Section
    #
    logger().log( '' )
    logger().log( '+ 0x%04X Component Section:' % fcba )
    logger().log( '========================================================' )

    flcomp = struct.unpack_from( '=I', fd[fcba+0x0:fcba+0x4] )[0]
    logger().log( '+ 0x%04X FLCOMP   : 0x%08X' % (fcba, flcomp) )
    flil   = struct.unpack_from( '=I', fd[fcba+0x4:fcba+0x8] )[0]
    logger().log( '+ 0x%04X FLIL     : 0x%08X' % (fcba+0x4, flil) )
    flpb   = struct.unpack_from( '=I', fd[fcba+0x8:fcba+0xC] )[0]
    logger().log( '+ 0x%04X FLPB     : 0x%08X' % (fcba+0x8, flpb) )

    #
    # Flash Descriptor Region Section
    #
    logger().log( '' )
    logger().log( '+ 0x%04X Region Section:' % frba )
    logger().log( '========================================================' )

    flregs = [None] * nr
    for r in range(nr):
        flreg_off = frba + r*4
        flreg = struct.unpack_from( '=I', fd[flreg_off:flreg_off + 0x4] )[0]
        if not cs.is_register_defined('FLREG%d' % r): continue
        base  = cs.get_register_field(('FLREG%d' % r), flreg, 'RB' ) << spi.SPI_FLA_SHIFT
        limit = cs.get_register_field(('FLREG%d' % r), flreg, 'RL' ) << spi.SPI_FLA_SHIFT
        notused = '(not used)' if base > limit or flreg == 0xFFFFFFFF else ''
        flregs[r] = (flreg,base,limit,notused)
        logger().log( '+ 0x%04X FLREG%d   : 0x%08X %s' % (flreg_off,r,flreg,notused) )
        #cs.print_register(('FLREG%d' % r), flreg)

    logger().log('')
    logger().log( 'Flash Regions' )
    logger().log( '--------------------------------------------------------' )
    logger().log( ' Region                | FLREGx    | Base     | Limit   ' )
    logger().log( '--------------------------------------------------------' )
    for r in range(nr):
        if flregs[r]: logger().log( '%d %-020s | %08X  | %08X | %08X %s' % (r, spi.SPI_REGION_NAMES[r],flregs[r][0],flregs[r][1],flregs[r][2],flregs[r][3]) )

    #
    # Flash Descriptor Master Section
    #
    logger().log( '' )
    logger().log( '+ 0x%04X Master Section:' % fmba )
    logger().log( '========================================================' )

    flmstrs = [None] * nm #spi.SPI_MASTER_NUMBER_IN_FD
    for m in range(nm):
        flmstr_off = fmba + m*4
        flmstr = struct.unpack_from( '=I', fd[flmstr_off:flmstr_off + 0x4] )[0]
        master_region_ra = cs.get_register_field( 'FLMSTR1', flmstr, 'MRRA' )
        master_region_wa = cs.get_register_field( 'FLMSTR1', flmstr, 'MRWA' )
        flmstrs[m] = (master_region_ra, master_region_wa)
        logger().log( '+ 0x%04X FLMSTR%d   : 0x%08X' % (flmstr_off,m,flmstr) )

    logger().log('')
    logger().log( 'Master Read/Write Access to Flash Regions' )
    logger().log( '--------------------------------------------------------' )
    s = ' Region                '
    for m in range(nm):
        s = s + '| ' + ('%-6s' % spi.SPI_MASTER_NAMES[m])
    logger().log( s )
    logger().log( '--------------------------------------------------------' )
    for r in range(nr):
        s = '%d %-020s ' % (r, spi.SPI_REGION_NAMES[r])
        for m in range(nm):
            access_s = ''
            mask = (0x1 << r) & 0xFF
            if (flmstrs[m][0] & mask): access_s += 'R'
            if (flmstrs[m][1] & mask): access_s += 'W'
            s = s + '| ' + ('%-6s' % access_s)
        logger().log( s )

    #
    # Flash Descriptor Upper Map Section
    #
    logger().log( '' )
    logger().log( '+ 0x%04X Flash Descriptor Upper Map:' % 0xEFC )
    logger().log( '========================================================' )

    flumap1 = struct.unpack_from( '=I', fd[0xEFC:0xF00] )[0]
    logger().log( '+ 0x%04X FLUMAP1   : 0x%08X' % (0xEFC, flumap1) )

    vtba = ( (flumap1 & 0x000000FF) << 4 )
    vtl  = ( ((flumap1 & 0x0000FF00) >> 8) & 0xFF )
    logger().log( '  VSCC Table Base Address    = 0x%08X' % vtba )
    logger().log( '  VSCC Table Length          = 0x%02X' % vtl )

    #
    # OEM Section
    #
    logger().log( '' )
    logger().log( '+ 0x%04X OEM Section:' % 0xF00 )
    logger().log( '========================================================' )
    print_buffer( fd[0xF00:] )

    logger().log( '' )
    logger().log( '########################################################' )
    logger().log( '# END OF SPI FLASH DESCRIPTOR' )
    logger().log( '########################################################' )
