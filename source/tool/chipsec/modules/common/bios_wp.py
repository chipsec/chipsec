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
# __chipsec/modules/common/bios.py__ - checks if BIOS Write Protection HW mechanisms are enabled
#



from chipsec.module_common import *

from chipsec.hal.mmio import *
from chipsec.hal.spi import *

import fnmatch
import os

logger = logger()
spi    = SPI( cs )

def check_BIOS_write_protection():
    logger.start_test( "BIOS Region Write Protection" )
    #
    # BIOS Control (BC) 0:31:0 PCIe CFG register
    #
    reg_value = cs.pci.read_byte( 0, 31, 0, LPC_BC_REG_OFF )
    BcRegister = LPC_BC_REG( reg_value, (reg_value>>5)&0x1, (reg_value>>4)&0x1, (reg_value>>2)&0x3, (reg_value>>1)&0x1, reg_value&0x1 )
    logger.log( BcRegister )

    # Is the BIOS flash region write protected?
    write_protected = 0
    if 1 == BcRegister.BLE and 0 == BcRegister.BIOSWE:
       if 1 == BcRegister.SMM_BWP:
          logger.log_good( "BIOS region write protection is enabled (writes restricted to SMM)" )
          write_protected = 1
       else:
          logger.log_important( "Enhanced SMM BIOS region write protection has not been enabled (SMM_BWP is not used)" )
    else:
       logger.log_bad( "BIOS region write protection is disabled!" )

    return write_protected == 1

def check_SPI_protected_ranges():
    #logger.start_test( "SPI Protected Ranges" )
    (bios_base,bios_limit,bios_freg) = spi.get_SPI_region( BIOS )
    logger.log( "\n[*] BIOS Region: Base = 0x%08X, Limit = 0x%08X" % (bios_base,bios_limit) )
    spi.display_SPI_Protected_Ranges()

    pr_cover_bios = False
    pr_partial_cover_bios = False
#    for j in range(5):
#        (base,limit,wpe,rpe,pr_reg_off,pr_reg_value) = spi.get_SPI_Protected_Range( j )
#        if (wpe == 1 and base < limit and base <= bios_base and limit >= bios_limit):
#            pr_cover_bios = True
#        if (wpe == 1 and base < limit and limit > bios_base):
#            pr_partial_cover_bios = True

    areas_to_protect  = [(bios_base, bios_limit)]
    protected_areas = list()


    for j in range(5):
        (base,limit,wpe,rpe,pr_reg_off,pr_reg_value) = spi.get_SPI_Protected_Range( j )
        if base > limit: continue
        if wpe == 1:
            for area in areas_to_protect:
                # overlap bottom
                start,end = area
                if base <= start and limit >= start:
                    if limit > end:
                        areas_to_protect.remove(area)
                    else:
                        areas_to_protect.remove(area)
                        area = (limit+1,end)
                        areas_to_protect.append(area)
                        
                # overlap top
                elif base <= end and limit >= end:
                    if base < start:
                        areas_to_protect.remove(area)
                    else:
                        areas_to_protect.remove(area)
                        area = (start,base-1)
                        areas_to_protect.append(area)
                        start,end = area
                # split
                elif base > start and limit < end:
                    areas_to_protect.remove(area)
                    areas_to_protect.append((start,base-1))
                    areas_to_protect.append((limit+1, end))


    if (len(areas_to_protect)  == 0):
        pr_cover_bios = True
    else:
        if (len(areas_to_protect) != 1 or areas_to_protect[0] != (bios_base,bios_limit)):
            pr_partial_cover_bios = True

    if pr_partial_cover_bios:
       logger.log( '' )
       logger.log_important( "SPI protected ranges write-protect parts of BIOS region (other parts of BIOS can be modified)" )

    else:
        if not pr_cover_bios:
            logger.log( '' )
            logger.log_important( "None of the SPI protected ranges write-protect BIOS region" )

    return pr_cover_bios

# --------------------------------------------------------------------------
# run( module_argv )
# Required function: run here all tests from this module
# --------------------------------------------------------------------------
def run( module_argv ):
    wp = check_BIOS_write_protection()    
    spr = check_SPI_protected_ranges()
    #spi.display_SPI_Ranges_Access_Permissions()
    #check_SMI_locks()

    logger.log('')
    if wp:
        if spr:  logger.log_passed_check( "BIOS is write protected (by SMM and SPI Protected Ranges)" )
        else:    logger.log_passed_check( "BIOS is write protected" )
    else:
        if spr:  logger.log_passed_check( "SPI Protected Ranges are configured to write protect BIOS" )
        else:
            logger.log_important( 'BIOS should enable all available SMM based write protection mechanisms or configure SPI protected ranges to protect the entire BIOS region' )
            logger.log_failed_check( "BIOS is NOT protected completely" )

    return wp or spr
