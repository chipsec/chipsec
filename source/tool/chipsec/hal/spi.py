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
# chipsec/hal/spi.py
# =========================
# Access to SPI Flash parts
# ~~~
# #usage:
#     read_spi( spi_fla, length )
#     write_spi( spi_fla, buf )
#     erase_spi_block( spi_fla )
# ~~~
#
__version__ = '1.0'

import struct
import sys
import time

import chipsec.chipset
from chipsec.file import *
from chipsec.hal.hal_base import HALBase
from chipsec.hal.mmio import *

#
# !! IMPORTANT:
# Size of the data chunk used in SPI read cycle (in bytes)
# default = maximum 64 bytes (remainder is read in 4 byte chunks)
#
# If you want to change logic to read SPI Flash in 4 byte chunks:
# SPI_READ_WRITE_MAX_DBC = 4
#
# SPI write cycles operate on 4 byte chunks (not optimized yet)
#
# Approximate performance (on 2 core HT Sandy Bridge CPU 2.6GHz):
#   SPI read:  ~25 sec per 1MB (DBC=64)
#   SPI write: ~140 sec per 1MB (DBC=4)
# 
SPI_READ_WRITE_MAX_DBC = 64
SPI_READ_WRITE_DEF_DBC = 4


# agregated SPI Flash commands
HSFCTL_READ_CYCLE = ( (Cfg.PCH_RCBA_SPI_HSFCTL_FCYCLE_READ<<1) | Cfg.PCH_RCBA_SPI_HSFCTL_FCYCLE_FGO)
HSFCTL_WRITE_CYCLE = ( (Cfg.PCH_RCBA_SPI_HSFCTL_FCYCLE_WRITE<<1) | Cfg.PCH_RCBA_SPI_HSFCTL_FCYCLE_FGO)
HSFCTL_ERASE_CYCLE = ( (Cfg.PCH_RCBA_SPI_HSFCTL_FCYCLE_ERASE<<1) | Cfg.PCH_RCBA_SPI_HSFCTL_FCYCLE_FGO)

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# FGO bit cleared (for safety ;)
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#HSFCTL_WRITE_CYCLE = ( (Cfg.PCH_RCBA_SPI_HSFCTL_FCYCLE_WRITE<<1) )
#HSFCTL_ERASE_CYCLE = ( (Cfg.PCH_RCBA_SPI_HSFCTL_FCYCLE_ERASE<<1) )

HSFSTS_CLEAR = (Cfg.PCH_RCBA_SPI_HSFSTS_AEL | Cfg.PCH_RCBA_SPI_HSFSTS_FCERR | Cfg.PCH_RCBA_SPI_HSFSTS_FDONE)

#
# Hardware Sequencing Flash Status (HSFSTS)
#
SPI_HSFSTS_OFFSET = 0x04
# HSFSTS bit masks
SPI_HSFSTS_FLOCKDN_MASK = (1 << 15)
SPI_HSFSTS_FDOPSS_MASK  = (1 << 13)

SPI_REGION_NUMBER       = 7
SPI_REGION_NUMBER_IN_FD = 5

FLASH_DESCRIPTOR  = 0
BIOS              = 1
ME                = 2
GBE               = 3
PLATFORM_DATA     = 4
DEVICE_EXPANSION  = 5
SECONDARY_BIOS    = 6

SPI_REGION = {
 FLASH_DESCRIPTOR  : Cfg.PCH_RCBA_SPI_FREG0_FLASHD,
 BIOS              : Cfg.PCH_RCBA_SPI_FREG1_BIOS,
 ME                : Cfg.PCH_RCBA_SPI_FREG2_ME,
 GBE               : Cfg.PCH_RCBA_SPI_FREG3_GBE,
 PLATFORM_DATA     : Cfg.PCH_RCBA_SPI_FREG4_PLATFORM_DATA,
 DEVICE_EXPANSION  : Cfg.PCH_RCBA_SPI_FREG5_DEVICE_EXPANSION,
 SECONDARY_BIOS    : Cfg.PCH_RCBA_SPI_FREG6_SECONDARY_BIOS
}

SPI_REGION_NAMES = {
 FLASH_DESCRIPTOR  : 'Flash Descriptor',
 BIOS              : 'BIOS',
 ME                : 'Intel ME',
 GBE               : 'GBe',
 PLATFORM_DATA     : 'Platform Data',
 DEVICE_EXPANSION  : 'Device Expansion',
 SECONDARY_BIOS    : 'Secondary BIOS'
}

#
# Flash Descriptor Master Defines
#
SPI_MASTER_NUMBER_IN_FD = 3

MASTER_HOST_CPU_BIOS    = 0
MASTER_ME               = 1
MASTER_GBE              = 2

SPI_MASTER_NAMES = {
 MASTER_HOST_CPU_BIOS : 'CPU/BIOS',
 MASTER_ME            : 'ME',
 MASTER_GBE           : 'GBe'
}


class SpiRuntimeError (RuntimeError):
    pass
class SpiAccessError (RuntimeError):
    pass


def get_SPI_region( flreg ):
    range_base  = (flreg & Cfg.PCH_RCBA_SPI_FREGx_BASE_MASK) << 12
    range_limit = ((flreg & Cfg.PCH_RCBA_SPI_FREGx_LIMIT_MASK) >> 4)
    range_limit = range_limit + 0xFFF # + 4kB
    return (range_base, range_limit)

# Fallback option when XML config is not available: using hardcoded config
def get_SPI_MMIO_base_fallback( cs ):
    reg_value = cs.pci.read_dword( Cfg.SPI_MMIO_BUS, Cfg.SPI_MMIO_DEV, Cfg.SPI_MMIO_FUN, Cfg.SPI_MMIO_REG_OFFSET )
    spi_base = ((reg_value >> Cfg.SPI_BASE_ADDR_SHIFT) << Cfg.SPI_BASE_ADDR_SHIFT) + Cfg.SPI_MMIO_BASE_OFFSET
    if logger().VERBOSE: logger().log( "[spi] SPI MMIO base: 0x%016X (assuming below 4GB)" % spi_base )
    return spi_base

def get_SPI_MMIO_base( cs ):
    if is_MMIO_BAR_defined( cs, 'SPIBAR' ):
        (spi_base,spi_size) = get_MMIO_BAR_base_address( cs, 'SPIBAR' )
    else:
        spi_base = get_SPI_MMIO_base_fallback( cs )
    if logger().VERBOSE: logger().log( "[spi] SPI MMIO base: 0x%016X (assuming below 4GB)" % spi_base )
    return spi_base

class SPI:
    def __init__( self, cs ):
        self.cs = cs
        self.rcba_spi_base = get_SPI_MMIO_base( self.cs )

    def spi_reg_read( self, reg ):
        return read_MMIO_reg( self.cs, self.rcba_spi_base, reg )

    def spi_reg_write( self, reg, value ):
        return write_MMIO_reg( self.cs, self.rcba_spi_base, reg, value )


    def get_SPI_region( self, spi_region_id ):
        freg = self.spi_reg_read( SPI_REGION[ spi_region_id ] )
        #range_base  = (freg & Cfg.PCH_RCBA_SPI_FREGx_BASE_MASK) << 12
        #range_limit = ((freg & Cfg.PCH_RCBA_SPI_FREGx_LIMIT_MASK) >> 4)
        #range_limit = range_limit + 0xFFF # + 4kB
        ##if range_limit >= range_base:
        ##   range_limit = range_limit + 0xFFF # + 4kB
        (range_base, range_limit) = get_SPI_region( freg )
        return (range_base, range_limit, freg)

    # all_regions = True : return all SPI regions
    # all_regions = False: return only available SPI regions (limit >= base)
    def get_SPI_regions( self, all_regions ):
        spi_regions = {}
        for r in SPI_REGION:
            (range_base, range_limit, freg) = self.get_SPI_region( r )
            if all_regions or (range_limit >= range_base):
                range_size = range_limit - range_base + 1
                spi_regions[r] = (range_base, range_limit, range_size, SPI_REGION_NAMES[r])
        return spi_regions

    def get_SPI_Protected_Range( self, pr_num ):
        if ( pr_num > 5 ):
            return None

        pr_j_reg = Cfg.PCH_RCBA_SPI_PR0 + pr_num*4
        pr_j  = self.spi_reg_read( pr_j_reg )
        base = (pr_j & Cfg.PCH_RCBA_SPI_PR0_PRB_MASK) << 12
        limit = (pr_j & Cfg.PCH_RCBA_SPI_PR0_PRL_MASK) >> 4
        wpe = ((pr_j & Cfg.PCH_RCBA_SPI_PR0_WPE) != 0)
        rpe = ((pr_j & Cfg.PCH_RCBA_SPI_PR0_RPE) != 0)
        return (base,limit,wpe,rpe,pr_j_reg,pr_j)

    ##############################################################################################################
    # SPI configuration
    ##############################################################################################################

    def display_SPI_Flash_Descriptor( self ):
        logger().log( "============================================================" )
        logger().log( "SPI Flash Descriptor" )
        logger().log( "------------------------------------------------------------" )
        logger().log( "\nFlash Signature and Descriptor Map:" )
        for j in range(5):
            self.spi_reg_write( Cfg.PCH_RCBA_SPI_FDOC, (Cfg.PCH_RCBA_SPI_FDOC_FDSS_FSDM|(j<<2)) )
            fdod = self.spi_reg_read( Cfg.PCH_RCBA_SPI_FDOD )
            logger().log( "%08X" % fdod )

        logger().log( "\nComponents:" )
        for j in range(3):
            self.spi_reg_write( Cfg.PCH_RCBA_SPI_FDOC, (Cfg.PCH_RCBA_SPI_FDOC_FDSS_COMP|(j<<2)) )
            fdod = self.spi_reg_read( Cfg.PCH_RCBA_SPI_FDOD )
            logger().log( "%08X" % fdod )

        logger().log( "\nRegions:" )
        for j in range(5):
            self.spi_reg_write( Cfg.PCH_RCBA_SPI_FDOC, (Cfg.PCH_RCBA_SPI_FDOC_FDSS_REGN|(j<<2)) )
            fdod = self.spi_reg_read( Cfg.PCH_RCBA_SPI_FDOD )
            logger().log( "%08X" % fdod )

        logger().log( "\nMasters:" )
        for j in range(3):
            self.spi_reg_write( Cfg.PCH_RCBA_SPI_FDOC, (Cfg.PCH_RCBA_SPI_FDOC_FDSS_MSTR|(j<<2)) )
            fdod = self.spi_reg_read( Cfg.PCH_RCBA_SPI_FDOD )
            logger().log( "%08X" % fdod )


    def display_SPI_opcode_info( self ):
        logger().log( "============================================================" )
        logger().log( "SPI Opcode Info" )
        logger().log( "------------------------------------------------------------" )
        optype = (self.spi_reg_read( Cfg.PCH_RCBA_SPI_OPTYPE ) & 0xFFFF)
        logger().log( "OPTYPE = 0x%04X" % optype )
        opmenu_lo = self.spi_reg_read( Cfg.PCH_RCBA_SPI_OPMENU )
        opmenu_hi = self.spi_reg_read( Cfg.PCH_RCBA_SPI_OPMENU + 0x4 )
        opmenu = ((opmenu_hi << 32)|opmenu_lo)
        logger().log( "OPMENU = 0x%016X" % opmenu )

        logger().log( "------------------------------------------------------------" )
        logger().log( "Opcode # | Opcode | Optype | Description" )
        logger().log( "------------------------------------------------------------" )
        
        for j in range(8):
           optype_j = ((optype >> j*2) & 0x3)
           if (Cfg.PCH_RCBA_SPI_OPTYPE_RDNOADDR == optype_j):
             desc = 'SPI read cycle without address'
           elif (Cfg.PCH_RCBA_SPI_OPTYPE_WRNOADDR == optype_j):
             desc = 'SPI write cycle without address'
           elif (Cfg.PCH_RCBA_SPI_OPTYPE_RDADDR == optype_j):
             desc = 'SPI read cycle with address'
           elif (Cfg.PCH_RCBA_SPI_OPTYPE_WRADDR == optype_j):
             desc = 'SPI write cycle with address'
           logger().log( "Opcode%d  | 0x%02X   | %X      | %s " % (j,((opmenu >> j*8) & 0xFF),optype_j,desc) )

    def display_SPI_Flash_Regions( self ):
        logger().log( "------------------------------------------------------------" )
        logger().log( "Flash Region             | FREGx Reg | Base     | Limit     " )
        logger().log( "------------------------------------------------------------" )
        (base,limit,freg) = self.get_SPI_region( FLASH_DESCRIPTOR )
        logger().log( "0 Flash Descriptor (FD)  | %08X  | %08X | %08X " % (freg,base,limit) )
        (base,limit,freg) = self.get_SPI_region( BIOS )
        logger().log( "1 BIOS                   | %08X  | %08X | %08X " % (freg,base,limit) )
        (base,limit,freg) = self.get_SPI_region( ME )
        logger().log( "2 Management Engine (ME) | %08X  | %08X | %08X " % (freg,base,limit) )
        (base,limit,freg) = self.get_SPI_region( GBE )
        logger().log( "3 GBe                    | %08X  | %08X | %08X " % (freg,base,limit) )
        (base,limit,freg) = self.get_SPI_region( PLATFORM_DATA )
        logger().log( "4 Platform Data (PD)     | %08X  | %08X | %08X " % (freg,base,limit) )
        (base,limit,freg) = self.get_SPI_region( DEVICE_EXPANSION )
        logger().log( "5 Device Expansion (DE)  | %08X  | %08X | %08X " % (freg,base,limit) )
        (base,limit,freg) = self.get_SPI_region( SECONDARY_BIOS )
        logger().log( "6 Secondary BIOS (SB)    | %08X  | %08X | %08X " % (freg,base,limit) )

    def display_BIOS_region( self ):
        bfpreg = self.spi_reg_read( Cfg.PCH_RCBA_SPI_BFPR )
        logger().log( "BIOS Flash Primary Region" )
        logger().log( "------------------------------------------------------------" )
        logger().log( "BFPREG = %08X:" % bfpreg )
        logger().log( "  Base  : %08X" % ((bfpreg & Cfg.PCH_RCBA_SPI_FREGx_BASE_MASK) << 12) )
        logger().log( "  Limit : %08X" % ((bfpreg & Cfg.PCH_RCBA_SPI_FREGx_LIMIT_MASK) >> 4) )
        logger().log( "  Shadowed BIOS Select: %d" % ((bfpreg & Cfg.BIT31)>>31) )


    def display_SPI_Ranges_Access_Permissions( self ):
        logger().log( "SPI Flash Region Access Permissions" )
        logger().log( "------------------------------------------------------------" )
        fracc  = self.spi_reg_read( Cfg.PCH_RCBA_SPI_FRAP )
        logger().log( "FRAP = %08X" % fracc )
        logger().log( "BIOS Region Write Access Grant (%02X):" % ((fracc & Cfg.PCH_RCBA_SPI_FRAP_BMWAG_MASK)>>16) )
        logger().log( "  BIOS: %1d" % (fracc&Cfg.PCH_RCBA_SPI_FRAP_BMWAG_BIOS   != 0) )
        logger().log( "  ME  : %1d" % (fracc&Cfg.PCH_RCBA_SPI_FRAP_BMWAG_ME     != 0) )
        logger().log( "  GBe : %1d" % (fracc&Cfg.PCH_RCBA_SPI_FRAP_BMWAG_GBE    != 0) )
        logger().log( "BIOS Region Read Access Grant (%02X):" % ((fracc & Cfg.PCH_RCBA_SPI_FRAP_BMRAG_MASK)>>16) )
        logger().log( "  BIOS: %1d" % (fracc&Cfg.PCH_RCBA_SPI_FRAP_BMRAG_BIOS   != 0) )
        logger().log( "  ME  : %1d" % (fracc&Cfg.PCH_RCBA_SPI_FRAP_BMRAG_ME     != 0) )
        logger().log( "  GBe : %1d" % (fracc&Cfg.PCH_RCBA_SPI_FRAP_BMRAG_GBE    != 0) )
        logger().log( "BIOS Write Access (%02X):" % ((fracc & Cfg.PCH_RCBA_SPI_FRAP_BRWA_MASK)>>8) )
        logger().log( "  FD  : %1d" % (fracc&Cfg.PCH_RCBA_SPI_FRAP_BRWA_FLASHD != 0) )
        logger().log( "  BIOS: %1d" % (fracc&Cfg.PCH_RCBA_SPI_FRAP_BRWA_BIOS   != 0) )
        logger().log( "  ME  : %1d" % (fracc&Cfg.PCH_RCBA_SPI_FRAP_BRWA_ME     != 0) )
        logger().log( "  GBe : %1d" % (fracc&Cfg.PCH_RCBA_SPI_FRAP_BRWA_GBE    != 0) )
        logger().log( "  PD  : %1d" % (fracc&Cfg.PCH_RCBA_SPI_FRAP_BRWA_PD     != 0) )
        logger().log( "  DE  : %1d" % (fracc&Cfg.PCH_RCBA_SPI_FRAP_BRWA_DE     != 0) )
        logger().log( "  SB  : %1d" % (fracc&Cfg.PCH_RCBA_SPI_FRAP_BRWA_SB     != 0) )
        logger().log( "BIOS Read Access (%02X):" % (fracc & Cfg.PCH_RCBA_SPI_FRAP_BRRA_MASK) )
        logger().log( "  FD  : %1d" % (fracc&Cfg.PCH_RCBA_SPI_FRAP_BRRA_FLASHD != 0) )
        logger().log( "  BIOS: %1d" % (fracc&Cfg.PCH_RCBA_SPI_FRAP_BRRA_BIOS   != 0) )
        logger().log( "  ME  : %1d" % (fracc&Cfg.PCH_RCBA_SPI_FRAP_BRRA_ME     != 0) )
        logger().log( "  GBe : %1d" % (fracc&Cfg.PCH_RCBA_SPI_FRAP_BRRA_GBE    != 0) )
        logger().log( "  PD  : %1d" % (fracc&Cfg.PCH_RCBA_SPI_FRAP_BRRA_PD     != 0) )
        logger().log( "  DE  : %1d" % (fracc&Cfg.PCH_RCBA_SPI_FRAP_BRRA_DE     != 0) )
        logger().log( "  SB  : %1d" % (fracc&Cfg.PCH_RCBA_SPI_FRAP_BRRA_SB     != 0) )


    def display_SPI_Protected_Ranges( self ):
        logger().log( "SPI Protected Ranges" )
        logger().log( "------------------------------------------------------------" )
        logger().log( "PRx (offset) | Value    | Base     | Limit    | WP? | RP?" )
        logger().log( "------------------------------------------------------------" )
        for j in range(5):
           (base,limit,wpe,rpe,pr_reg_off,pr_reg_value) = self.get_SPI_Protected_Range( j )
           logger().log( "PR%d (%02X)     | %08X | %08X | %08X | %d   | %d " % (j,pr_reg_off,pr_reg_value,base,limit,wpe,rpe) )

    def display_SPI_map( self ):
        logger().log( "============================================================" )
        logger().log( "SPI Flash Map" )
        logger().log( "------------------------------------------------------------" )
        logger().log('')
        self.display_BIOS_region()
        logger().log('')
        self.display_SPI_Flash_Regions()
        logger().log('')
        self.display_SPI_Flash_Descriptor()
        logger().log('')
        self.display_SPI_opcode_info()
        logger().log('')
        logger().log( "============================================================" )
        logger().log( "SPI Flash Protection" )
        logger().log( "------------------------------------------------------------" )
        logger().log('')
        self.display_SPI_Ranges_Access_Permissions()
        logger().log('')
        logger().log( "BIOS Region Write Protection" )
        logger().log( "------------------------------------------------------------" )
        (BC, val) = self.get_BIOS_Control()
        logger().log( BC )
        self.display_SPI_Protected_Ranges()
        logger().log('')


    ##############################################################################################################
    # BIOS Write Protection
    ##############################################################################################################

    def get_BIOS_Control_fallback( self ):
        #
        # BIOS Control (BC) 0:31:0 PCIe CFG register
        #
        reg_value = self.cs.pci.read_byte( 0, 31, 0, Cfg.LPC_BC_REG_OFF )
        BcRegister = Cfg.LPC_BC_REG( reg_value, (reg_value>>5)&0x1, (reg_value>>4)&0x1, (reg_value>>2)&0x3, (reg_value>>1)&0x1, reg_value&0x1 )
        return (BcRegister, reg_value)

    def get_BIOS_Control( self ):
        if chipsec.chipset.is_register_defined( self.cs, 'BC' ):
            reg_value = chipsec.chipset.read_register( self.cs, 'BC' )
            BcRegister = Cfg.LPC_BC_REG( reg_value, (reg_value>>5)&0x1, (reg_value>>4)&0x1, (reg_value>>2)&0x3, (reg_value>>1)&0x1, reg_value&0x1 )
            return (BcRegister, reg_value)
        else:
            return self.get_BIOS_Control_fallback()


    def disable_BIOS_write_protection( self ):
        (BcRegister, reg_value) = self.get_BIOS_Control()
        if logger().VERBOSE: logger().log( BcRegister )

        if BcRegister.BLE and (not BcRegister.BIOSWE):
           logger().log( "[spi] BIOS write protection enabled" )
           return False
        elif BcRegister.BIOSWE:
           logger().log( "[spi] BIOS write protection not enabled. What a surprise" )
           return True
        else:
           logger().log( "[spi] BIOS write protection enabled but not locked. Disabling.." )

        reg_value |= 0x1
        chipsec.chipset.write_register( self.cs, 'BC', reg_value )
        #self.cs.pci.write_byte( 0, 31, 0, Cfg.LPC_BC_REG_OFF, reg_value )
        (BcRegister, reg_value) = self.get_BIOS_Control()
        if logger().VERBOSE: logger().log( BcRegister )
        if BcRegister.BIOSWE:
           logger().log_important( "BIOS write protection is disabled" )
           return True
        else:
           return False

    ##############################################################################################################
    # SPI Controller access functions
    ##############################################################################################################

    def _wait_SPI_flash_cycle_done(self):
        if logger().VERBOSE:
           logger().log( "[spi] wait for SPI cycle ready/done.." )

        spi_base = self.rcba_spi_base

        for i in range(1000):
            #time.sleep(0.001)
            hsfsts = self.cs.mem.read_physical_mem_byte( spi_base + Cfg.PCH_RCBA_SPI_HSFSTS )
            #hsfsts = self.spi_reg_read( Cfg.PCH_RCBA_SPI_HSFSTS ) 
            #cycle_done = (hsfsts & Cfg.Cfg.PCH_RCBA_SPI_HSFSTS_FDONE) and (0 == (hsfsts & Cfg.PCH_RCBA_SPI_HSFSTS_SCIP)) 
            cycle_done = not (hsfsts & Cfg.PCH_RCBA_SPI_HSFSTS_SCIP)
            if cycle_done:
               break

        if not cycle_done:
           if logger().VERBOSE:
              logger().log( "[spi] SPI cycle still in progress. Waiting 0.1 sec.." )
           time.sleep(0.1)
           hsfsts = self.cs.mem.read_physical_mem_byte( spi_base + Cfg.PCH_RCBA_SPI_HSFSTS )
           cycle_done = not (hsfsts & Cfg.PCH_RCBA_SPI_HSFSTS_SCIP)

        if cycle_done:
           if logger().VERBOSE:
              logger().log( "[spi] clear FDONE/FCERR/AEL bits.." )
           self.cs.mem.write_physical_mem_byte( spi_base + Cfg.PCH_RCBA_SPI_HSFSTS, HSFSTS_CLEAR )
           hsfsts = self.cs.mem.read_physical_mem_byte( spi_base + Cfg.PCH_RCBA_SPI_HSFSTS )
           cycle_done = not ((hsfsts & Cfg.PCH_RCBA_SPI_HSFSTS_AEL) or (hsfsts & Cfg.PCH_RCBA_SPI_HSFSTS_FCERR))

        if logger().VERBOSE:
           logger().log( "[spi] HSFSTS: 0x%02X" % hsfsts )
              
        return cycle_done

    def _send_spi_cycle(self, hsfctl_spi_cycle_cmd, dbc, spi_fla ):
        if logger().VERBOSE:
           logger().log( "[spi] > send SPI cycle 0x%X to address 0x%08X.." % (hsfctl_spi_cycle_cmd, spi_fla) )

        spi_base = self.rcba_spi_base  

        # No need to check for SPI cycle DONE status before each cycle
        # DONE status is checked once before entire SPI operation
    
        self.cs.mem.write_physical_mem_dword( spi_base + Cfg.PCH_RCBA_SPI_FADDR, (spi_fla & Cfg.PCH_RCBA_SPI_FADDR_MASK) )
        _faddr = self.spi_reg_read( Cfg.PCH_RCBA_SPI_FADDR ) 
        if logger().VERBOSE:
           logger().log( "[spi] FADDR: 0x%08X" % _faddr )
    
        if logger().VERBOSE:
           logger().log( "[spi] SPI cycle GO (DBC <- 0x%02X, HSFCTL <- 0x%X)" % (dbc, hsfctl_spi_cycle_cmd) )
        if ( HSFCTL_ERASE_CYCLE != hsfctl_spi_cycle_cmd ):
           self.cs.mem.write_physical_mem_byte( spi_base + Cfg.PCH_RCBA_SPI_HSFCTL + 0x1, dbc ) 
        self.cs.mem.write_physical_mem_byte( spi_base + Cfg.PCH_RCBA_SPI_HSFCTL, hsfctl_spi_cycle_cmd ) 
        # Read HSFCTL back
        hsfctl = self.cs.mem.read_physical_mem_word( spi_base + Cfg.PCH_RCBA_SPI_HSFCTL )
        if logger().VERBOSE:
           logger().log( "[spi] HSFCTL: 0x%04X" % hsfctl )
    
        cycle_done = self._wait_SPI_flash_cycle_done()
        if not cycle_done:
           logger().warn( "SPI cycle not done" )
        else:
           if logger().VERBOSE:
              logger().log( "[spi] < SPI cycle done" )

        return cycle_done

    #
    # SPI Flash operations
    #

    def read_spi_to_file(self, spi_fla, data_byte_count, filename ):
        buf = self.read_spi( spi_fla, data_byte_count )
        if buf is None:
            return None
        if filename is not None:
           write_file( filename, struct.pack('c'*len(buf), *buf) )
        else:
           print_buffer( buf, 16 )
        return buf

    def write_spi_from_file(self, spi_fla, filename ):
        buf = read_file( filename )
        return self.write_spi( spi_fla, struct.unpack('c'*len(buf), buf) )
        #return self.write_spi( spi_fla, struct.unpack('B'*len(buf), buf) )

    def read_spi(self, spi_fla, data_byte_count ):
        spi_base = self.rcba_spi_base  
        buf = []      

        dbc = SPI_READ_WRITE_DEF_DBC
        if (data_byte_count >= SPI_READ_WRITE_MAX_DBC):
           dbc = SPI_READ_WRITE_MAX_DBC

        n = data_byte_count / dbc
        r = data_byte_count % dbc
        if logger().UTIL_TRACE or logger().VERBOSE:
           logger().log( "[spi] reading 0x%x bytes from SPI at FLA = 0x%X (in %d 0x%x-byte chunks + 0x%x-byte remainder)" % (data_byte_count, spi_fla, n, dbc, r) )

        cycle_done = self._wait_SPI_flash_cycle_done()
        if not cycle_done:
           logger().error( "SPI cycle not ready" )
           return None

        for i in range(n):
           if logger().UTIL_TRACE or logger().VERBOSE:
              logger().log( "[spi] reading chunk %d of 0x%x bytes from 0x%X" % (i, dbc, spi_fla + i*dbc) )
           if not self._send_spi_cycle( HSFCTL_READ_CYCLE, dbc-1, spi_fla + i*dbc ):
              logger().error( "SPI flash read failed" )
           else:
              #buf += self.cs.mem.read_physical_mem( spi_base + Cfg.PCH_RCBA_SPI_FDATA00, dbc )
              for fdata_idx in range(0,dbc/4):
                  dword_value = self.spi_reg_read( Cfg.PCH_RCBA_SPI_FDATA00 + fdata_idx*4 ) 
                  if logger().VERBOSE:
                     logger().log( "[spi] FDATA00 + 0x%x: 0x%X" % (fdata_idx*4, dword_value) )
                  buf += [ chr((dword_value>>(8*j))&0xff) for j in range(4) ]
                  #buf += tuple( struct.pack("I", dword_value) )
        if (0 != r):
           if logger().UTIL_TRACE or logger().VERBOSE:
              logger().log( "[spi] reading remaining 0x%x bytes from 0x%X" % (r, spi_fla + n*dbc) )
           if not self._send_spi_cycle( HSFCTL_READ_CYCLE, r-1, spi_fla + n*dbc ):
              logger().error( "SPI flash read failed" )
           else:
              t = 4
              n_dwords = (r+3)/4
              for fdata_idx in range(0, n_dwords):
                  dword_value = self.spi_reg_read( Cfg.PCH_RCBA_SPI_FDATA00 + fdata_idx*4 ) 
                  if logger().VERBOSE:
                     logger().log( "[spi] FDATA00 + 0x%x: 0x%08X" % (fdata_idx*4, dword_value) )
                  if (fdata_idx == (n_dwords-1)) and (0 != r%4):
                     t = r%4  
                  buf += [ chr((dword_value >> (8*j)) & 0xff) for j in range(t) ]
           
        if logger().VERBOSE:
           logger().log( "[spi] buffer read from SPI:" )
           print_buffer( buf )

        return buf

    def write_spi(self, spi_fla, buf ):
        write_ok = True
        spi_base = self.rcba_spi_base  
        data_byte_count = len(buf)     
        dbc = 4       
        n = data_byte_count / dbc
        r = data_byte_count % dbc
        if logger().UTIL_TRACE or logger().VERBOSE:
           logger().log( "[spi] writing 0x%x bytes to SPI at FLA = 0x%X (in %d 0x%x-byte chunks + 0x%x-byte remainder)" % (data_byte_count, spi_fla, n, dbc, r) )

        cycle_done = self._wait_SPI_flash_cycle_done()
        if not cycle_done:
           logger().error( "SPI cycle not ready" )
           return None

        for i in range(n):
           if logger().UTIL_TRACE or logger().VERBOSE:
              logger().log( "[spi] writing chunk %d of 0x%x bytes to 0x%X" % (i, dbc, spi_fla + i*dbc) )
           dword_value = (ord(buf[i*dbc + 3]) << 24) | (ord(buf[i*dbc + 2]) << 16) | (ord(buf[i*dbc + 1]) << 8) | ord(buf[i*dbc])
           if logger().VERBOSE:
              logger().log( "[spi] in FDATA00 = 0x%08x" % dword_value )
           self.cs.mem.write_physical_mem_dword( spi_base + Cfg.PCH_RCBA_SPI_FDATA00, dword_value )
           if not self._send_spi_cycle( HSFCTL_WRITE_CYCLE, dbc-1, spi_fla + i*dbc ):
              write_ok = False
              logger().error( "SPI flash write cycle failed" )

        if (0 != r):
           if logger().UTIL_TRACE or logger().VERBOSE:
              logger().log( "[spi] writing remaining 0x%x bytes to FLA = 0x%X" % (r, spi_fla + n*dbc) )
           dword_value = 0
           for j in range(r):
              dword_value |= (ord(buf[n*dbc + j]) << 8*j)
           if logger().VERBOSE:
              logger().log( "[spi] in FDATA00 = 0x%08x" % dword_value )
           self.cs.mem.write_physical_mem_dword( spi_base + Cfg.PCH_RCBA_SPI_FDATA00, dword_value )
           if not self._send_spi_cycle( HSFCTL_WRITE_CYCLE, r-1, spi_fla + n*dbc ):
              write_ok = False
              logger().error( "SPI flash write cycle failed" )
           
        return write_ok

    def erase_spi_block(self, spi_fla ):
        if logger().UTIL_TRACE or logger().VERBOSE:
           logger().log( "[spi] Erasing SPI Flash block @ 0x%X" % spi_fla )

        cycle_done = self._wait_SPI_flash_cycle_done()
        if not cycle_done:
           logger().error( "SPI cycle not ready" )
           return None

        erase_ok = self._send_spi_cycle( HSFCTL_ERASE_CYCLE, 0, spi_fla )
        if not erase_ok:
           logger().error( "SPI Flash erase cycle failed" )

        return erase_ok
