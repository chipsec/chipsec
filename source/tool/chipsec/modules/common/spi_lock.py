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





## \addtogroup modules
# __chipsec/modules/common/spi_lock.py__  - Checks that the SPI Flash Controller configuration is locked
# if it is not locked other Flash Program Registers can be written
#
#
#

from chipsec.module_common import *

from chipsec.hal.spi import *

logger = logger()


def check_spi_lock():
    logger.start_test( "SPI Flash Controller Configuration Lock" )

    spi_locked = 0
    hsfsts_reg_value = cs.mem.read_physical_mem_dword( get_PCH_RCBA_SPI_base(cs) + SPI_HSFSTS_OFFSET )
    logger.log( '[*] HSFSTS register = 0x%08X' % hsfsts_reg_value )
    logger.log( '    FLOCKDN = %u' % ((hsfsts_reg_value & SPI_HSFSTS_FLOCKDN_MASK)>>15) )

    if 0 != (hsfsts_reg_value & SPI_HSFSTS_FLOCKDN_MASK):
        spi_locked = 1
        logger.log_passed_check( "SPI Flash Controller configuration is locked" )
    else:
        logger.log_failed_check( "SPI Flash Controller configuration is not locked" )

    return spi_locked==1

def run( module_argv ):
    return check_spi_lock()


