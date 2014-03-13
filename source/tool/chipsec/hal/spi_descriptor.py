#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2014, Intel Corporation
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
## \addtogroup hal
# chipsec/hal/spi_descriptor.py
# ===========================================
# SPI Flash Descriptor binary parsing functionality
#
# ~~~
# #usage:
#   fd = read_file( fd_file )
#   parse_spi_flash_descriptor( fd )
# ~~~
#
__version__ = '1.0'

import struct
import sys
import time

from chipsec.logger import *
from chipsec.file import *

from chipsec.cfg.common import *
from chipsec.hal.spi import *

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

    flregs = [None]*SPI_REGION_NUMBER_IN_FD
    for r in range( SPI_REGION_NUMBER_IN_FD ):
        flreg_off = frba + r*4
        flreg = struct.unpack_from( '=I', fd[flreg_off:flreg_off + 0x4] )[0]
        (base,limit) = get_SPI_region( flreg )
        notused = (base > limit)
        flregs[r] = (r,SPI_REGION_NAMES[r],flreg,base,limit,notused)

    fd_size    = flregs[FLASH_DESCRIPTOR][4] - flregs[FLASH_DESCRIPTOR][3] + 1
    fd_notused = flregs[FLASH_DESCRIPTOR][5]
    if fd_notused or (fd_size != SPI_FLASH_DESCRIPTOR_SIZE):
        return None

    return flregs



def parse_spi_flash_descriptor( rom ):
    if not (type(rom) == str):
        logger().error('Invalid fd object type %s'%type(rom))
        return
    
    pos = rom.find( SPI_FLASH_DESCRIPTOR_SIGNATURE )
    if (-1 == pos or pos < 0x10):
       logger().error( 'Valid SPI flash descriptor is not found (should have signature %08X)' % SPI_FLASH_DESCRIPTOR_SIGNATURE )
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
    #parse_spi_flash_descriptor_flmap( fd )
    logger().log( '' )
    logger().log( '+ 0x0014 Flash Descriptor Map:' )
    logger().log( '========================================================' )

    flmap0 = struct.unpack_from( '=I', fd[0x14:0x18] )[0]
    flmap1 = struct.unpack_from( '=I', fd[0x18:0x1C] )[0]
    flmap2 = struct.unpack_from( '=I', fd[0x1C:0x20] )[0]
    logger().log( '+ 0x0014 FLMAP0   : 0x%08X' % flmap0 )
    
    # Flash Component Base Address (bits [7:0])
    fcba = ( (flmap0 & 0x000000FF) << 4 )   
    # Number of Components (bits [9:8])
    nc   = ( ((flmap0 & 0x0000FF00) >> 8) & 0x3 )   
    # Flash Region Base Address (bits [23:16])
    frba = ( (flmap0 & 0x00FF0000) >> 12 )   
    # Number of Regions (bits [26:24])
    nr   = ( ((flmap0 & 0xFF000000) >> 24) & 0x7 )   
    logger().log( '  Flash Component Base Address        = 0x%08X' % fcba )
    logger().log( '  Number of Flash Components          = %d' % nc )
    logger().log( '  Flash Region Base Address           = 0x%08X' % frba )
    logger().log( '  Number of Flash Regions             = %d' % nr )

    logger().log( '+ 0x0018 FLMAP1   : 0x%08X' % flmap1 )

    # Flash Master Base Address (bits [7:0])
    fmba  = ( (flmap1 & 0x000000FF) << 4 )   
    # Number of Masters (bits [9:8])
    nm    = ( ((flmap1 & 0x0000FF00) >> 8) & 0x3 )   
    logger().log( '  Flash Master Base Address           = 0x%08X' % fmba )
    logger().log( '  Number of Masters                   = %d' % nm )

    logger().log( '+ 0x001C FLMAP2   : 0x%08X' % flmap2 )

    # ICC Register Init Base Address (bits [23:16])
    iccriba = ( (flmap2 & 0x00FF0000) >> 12 )   
    logger().log( '  ICC Register Init Base Address      = 0x%08X' % iccriba )

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

    flregs = [None]*SPI_REGION_NUMBER_IN_FD
    for r in range( SPI_REGION_NUMBER_IN_FD ):
        flreg_off = frba + r*4
        flreg = struct.unpack_from( '=I', fd[flreg_off:flreg_off + 0x4] )[0]
        (base,limit) = get_SPI_region( flreg )
        notused = ''
        if base > limit:
           notused = '(not used)'
        flregs[r] = (flreg,base,limit,notused)
        logger().log( '+ 0x%04X FLREG%d   : 0x%08X %s' % (flreg_off,r,flreg,notused) )

    logger().log('')
    logger().log( 'Flash Regions' )
    logger().log( '--------------------------------------------------------' )
    logger().log( ' Region                | FLREGx    | Base     | Limit   ' )
    logger().log( '--------------------------------------------------------' )
    for r in range( SPI_REGION_NUMBER_IN_FD ):
        logger().log( '%d %-020s | %08X  | %08X | %08X %s' % (r,SPI_REGION_NAMES[r],flregs[r][0],flregs[r][1],flregs[r][2],flregs[r][3]) )

    #
    # Flash Descriptor Master Section
    #
    logger().log( '' )
    logger().log( '+ 0x%04X Master Section:' % fmba )
    logger().log( '========================================================' )

    flmstrs = [None]*SPI_MASTER_NUMBER_IN_FD
    for m in range( SPI_MASTER_NUMBER_IN_FD ):
        flmstr_off = fmba + m*4
        flmstr = struct.unpack_from( '=I', fd[flmstr_off:flmstr_off + 0x4] )[0]
        (requester_id, master_region_ra, master_region_wa) = get_SPI_master( flmstr )
        flmstrs[m] = (flmstr, requester_id, master_region_ra, master_region_wa)
        logger().log( '+ 0x%04X FLMSTR%d   : 0x%08X' % (flmstr_off,m,flmstr) )
 
    logger().log('')
    logger().log( 'Master Read/Write Access to Flash Regions' )
    logger().log( '--------------------------------------------------------' )
    s = ' Region                '
    for m in range( SPI_MASTER_NUMBER_IN_FD ):
        s = s + '| ' + ('%-9s' % SPI_MASTER_NAMES[m])
    logger().log( s )
    logger().log( '--------------------------------------------------------' )
    for r in range( SPI_REGION_NUMBER_IN_FD ):
        s = '%d %-020s ' % (r,SPI_REGION_NAMES[r])
        for m in range( SPI_MASTER_NUMBER_IN_FD ):
            access_s = ''
            mask = (0x1 << r) & 0xFF
            if (flmstrs[m][2] & mask):
                access_s = access_s + 'R'
            if (flmstrs[m][3] & mask):
                access_s = access_s + 'W'
            s = s + '| ' + ('%-9s' % access_s)
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
