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
from chipsec.cfg.common import *
from chipsec.logger import *
from chipsec.hal.mmio import *
from chipsec.file import *

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

##############################################################################################################
# SPI Host Interface Registers
##############################################################################################################

PCH_RCBA_SPI_BFPR                  = 0x00  # BIOS Flash Primary Region Register (= FREG1)

PCH_RCBA_SPI_HSFSTS                = 0x04  # Hardware Sequencing Flash Status Register
PCH_RCBA_SPI_HSFSTS_FLOCKDN        = Cfg.BIT15                         # Flash Configuration Lock-Down
PCH_RCBA_SPI_HSFSTS_FDV            = Cfg.BIT14                         # Flash Descriptor Valid
PCH_RCBA_SPI_HSFSTS_FDOPSS         = Cfg.BIT13                         # Flash Descriptor Override Pin-Strap Status
PCH_RCBA_SPI_HSFSTS_SCIP           = Cfg.BIT5                          # SPI cycle in progress
PCH_RCBA_SPI_HSFSTS_BERASE_MASK    = (Cfg.BIT4 | Cfg.BIT3)                 # Block/Sector Erase Size
PCH_RCBA_SPI_HSFSTS_BERASE_256B    = 0x00                          # Block/Sector = 256 Bytes
PCH_RCBA_SPI_HSFSTS_BERASE_4K      = 0x01                          # Block/Sector = 4K Bytes
PCH_RCBA_SPI_HSFSTS_BERASE_8K      = 0x10                          # Block/Sector = 8K Bytes
PCH_RCBA_SPI_HSFSTS_BERASE_64K     = 0x11                          # Block/Sector = 64K Bytes
PCH_RCBA_SPI_HSFSTS_AEL            = Cfg.BIT2                          # Access Error Log
PCH_RCBA_SPI_HSFSTS_FCERR          = Cfg.BIT1                          # Flash Cycle Error
PCH_RCBA_SPI_HSFSTS_FDONE          = Cfg.BIT0                          # Flash Cycle Done

PCH_RCBA_SPI_HSFCTL                = 0x06  # Hardware Sequencing Flash Control Register
PCH_RCBA_SPI_HSFCTL_FSMIE          = Cfg.BIT15                         # Flash SPI SMI Enable
PCH_RCBA_SPI_HSFCTL_FDBC_MASK      = 0x3F00                        # Flash Data Byte Count, Count = FDBC + 1.
PCH_RCBA_SPI_HSFCTL_FCYCLE_MASK    = 0x0006                        # Flash Cycle
PCH_RCBA_SPI_HSFCTL_FCYCLE_READ    = 0                             # Flash Cycle Read
PCH_RCBA_SPI_HSFCTL_FCYCLE_WRITE   = 2                             # Flash Cycle Write
PCH_RCBA_SPI_HSFCTL_FCYCLE_ERASE   = 3                             # Flash Cycle Block Erase
PCH_RCBA_SPI_HSFCTL_FCYCLE_FGO     = Cfg.BIT0                          # Flash Cycle GO

PCH_RCBA_SPI_FADDR               = 0x08  # SPI Flash Address
PCH_RCBA_SPI_FADDR_MASK          = 0x07FFFFFF                      # SPI Flash Address Mask [0:26]

PCH_RCBA_SPI_FDATA00             = 0x10  # SPI Data 00 (32 bits)
PCH_RCBA_SPI_FDATA01             = 0x14  
PCH_RCBA_SPI_FDATA02             = 0x18  
PCH_RCBA_SPI_FDATA03             = 0x1C  
PCH_RCBA_SPI_FDATA04             = 0x20  
PCH_RCBA_SPI_FDATA05             = 0x24  
PCH_RCBA_SPI_FDATA06             = 0x28  
PCH_RCBA_SPI_FDATA07             = 0x2C  
PCH_RCBA_SPI_FDATA08             = 0x30  
PCH_RCBA_SPI_FDATA09             = 0x34  
PCH_RCBA_SPI_FDATA10             = 0x38  
PCH_RCBA_SPI_FDATA11             = 0x3C  
PCH_RCBA_SPI_FDATA12             = 0x40  
PCH_RCBA_SPI_FDATA13             = 0x44  
PCH_RCBA_SPI_FDATA14             = 0x48  
PCH_RCBA_SPI_FDATA15             = 0x4C  

# SPI Flash Regions Access Permisions Register
PCH_RCBA_SPI_FRAP                = 0x50
PCH_RCBA_SPI_FRAP_BMWAG_MASK     = 0xFF000000                    
PCH_RCBA_SPI_FRAP_BMWAG_GBE      = Cfg.BIT27                         
PCH_RCBA_SPI_FRAP_BMWAG_ME       = Cfg.BIT26                         
PCH_RCBA_SPI_FRAP_BMWAG_BIOS     = Cfg.BIT25                         
PCH_RCBA_SPI_FRAP_BMRAG_MASK     = 0x00FF0000                    
PCH_RCBA_SPI_FRAP_BMRAG_GBE      = Cfg.BIT19                         
PCH_RCBA_SPI_FRAP_BMRAG_ME       = Cfg.BIT18                         
PCH_RCBA_SPI_FRAP_BMRAG_BIOS     = Cfg.BIT17                         
PCH_RCBA_SPI_FRAP_BRWA_MASK      = 0x0000FF00                    
PCH_RCBA_SPI_FRAP_BRWA_SB        = Cfg.BIT14                         
PCH_RCBA_SPI_FRAP_BRWA_DE        = Cfg.BIT13                         
PCH_RCBA_SPI_FRAP_BRWA_PD        = Cfg.BIT12                         
PCH_RCBA_SPI_FRAP_BRWA_GBE       = Cfg.BIT11                         
PCH_RCBA_SPI_FRAP_BRWA_ME        = Cfg.BIT10                         
PCH_RCBA_SPI_FRAP_BRWA_BIOS      = Cfg.BIT9                          
PCH_RCBA_SPI_FRAP_BRWA_FLASHD    = Cfg.BIT8                          
PCH_RCBA_SPI_FRAP_BRRA_MASK      = 0x000000FF                    
PCH_RCBA_SPI_FRAP_BRRA_SB        = Cfg.BIT6                          
PCH_RCBA_SPI_FRAP_BRRA_DE        = Cfg.BIT5                          
PCH_RCBA_SPI_FRAP_BRRA_PD        = Cfg.BIT4                          
PCH_RCBA_SPI_FRAP_BRRA_GBE       = Cfg.BIT3                          
PCH_RCBA_SPI_FRAP_BRRA_ME        = Cfg.BIT2                          
PCH_RCBA_SPI_FRAP_BRRA_BIOS      = Cfg.BIT1                          
PCH_RCBA_SPI_FRAP_BRRA_FLASHD    = Cfg.BIT0                          

# Flash Region Registers
PCH_RCBA_SPI_FREG0_FLASHD           = 0x54  # Flash Region 0 (Flash Descriptor)
PCH_RCBA_SPI_FREG1_BIOS             = 0x58  # Flash Region 1 (BIOS)
PCH_RCBA_SPI_FREG2_ME               = 0x5C  # Flash Region 2 (ME)
PCH_RCBA_SPI_FREG3_GBE              = 0x60  # Flash Region 3 (GbE)
PCH_RCBA_SPI_FREG4_PLATFORM_DATA    = 0x64  # Flash Region 4 (Platform Data)
PCH_RCBA_SPI_FREG5_DEVICE_EXPANSION = 0x68  # Flash Region 5 (Device Expansion)
PCH_RCBA_SPI_FREG6_SECONDARY_BIOS   = 0x6C  # Flash Region 6 (Secondary BIOS)

PCH_RCBA_SPI_FREGx_LIMIT_MASK    = 0x7FFF0000                    # Size
PCH_RCBA_SPI_FREGx_BASE_MASK     = 0x00007FFF                    # Base

# Protected Range Registers
PCH_RCBA_SPI_PR0                 = 0x74  # Protected Region 0 Register
PCH_RCBA_SPI_PR0_WPE             = Cfg.BIT31                         # Write Protection Enable
PCH_RCBA_SPI_PR0_PRL_MASK        = 0x7FFF0000                    # Protected Range Limit Mask
PCH_RCBA_SPI_PR0_RPE             = Cfg.BIT15                         # Read Protection Enable
PCH_RCBA_SPI_PR0_PRB_MASK        = 0x00007FFF                    # Protected Range Base Mask
PCH_RCBA_SPI_PR1                 = 0x78
PCH_RCBA_SPI_PR1_WPE             = Cfg.BIT31
PCH_RCBA_SPI_PR1_PRL_MASK        = 0x7FFF0000
PCH_RCBA_SPI_PR1_RPE             = Cfg.BIT15
PCH_RCBA_SPI_PR1_PRB_MASK        = 0x00007FFF
PCH_RCBA_SPI_PR2                 = 0x7C
PCH_RCBA_SPI_PR2_WPE             = Cfg.BIT31
PCH_RCBA_SPI_PR2_PRL_MASK        = 0x7FFF0000
PCH_RCBA_SPI_PR2_RPE             = Cfg.BIT15 
PCH_RCBA_SPI_PR2_PRB_MASK        = 0x00007FFF
PCH_RCBA_SPI_PR3                 = 0x80
PCH_RCBA_SPI_PR3_WPE             = Cfg.BIT31
PCH_RCBA_SPI_PR3_PRL_MASK        = 0x7FFF0000
PCH_RCBA_SPI_PR3_RPE             = Cfg.BIT15                         
PCH_RCBA_SPI_PR3_PRB_MASK        = 0x00007FFF                    
PCH_RCBA_SPI_PR4                 = 0x84  
PCH_RCBA_SPI_PR4_WPE             = Cfg.BIT31 
PCH_RCBA_SPI_PR4_PRL_MASK        = 0x7FFF0000
PCH_RCBA_SPI_PR4_RPE             = Cfg.BIT15     
PCH_RCBA_SPI_PR4_PRB_MASK        = 0x00007FFF

PCH_RCBA_SPI_OPTYPE              = 0x96  # Opcode Type Configuration
PCH_RCBA_SPI_OPTYPE7_MASK        = (Cfg.BIT15 | Cfg.BIT14)
PCH_RCBA_SPI_OPTYPE6_MASK        = (Cfg.BIT13 | Cfg.BIT12)
PCH_RCBA_SPI_OPTYPE5_MASK        = (Cfg.BIT11 | Cfg.BIT10)
PCH_RCBA_SPI_OPTYPE4_MASK        = (Cfg.BIT9 | Cfg.BIT8)  
PCH_RCBA_SPI_OPTYPE3_MASK        = (Cfg.BIT7 | Cfg.BIT6)  
PCH_RCBA_SPI_OPTYPE2_MASK        = (Cfg.BIT5 | Cfg.BIT4)  
PCH_RCBA_SPI_OPTYPE1_MASK        = (Cfg.BIT3 | Cfg.BIT2)  
PCH_RCBA_SPI_OPTYPE0_MASK        = (Cfg.BIT1 | Cfg.BIT0)  
PCH_RCBA_SPI_OPTYPE_RDNOADDR     = 0x00
PCH_RCBA_SPI_OPTYPE_WRNOADDR     = 0x01
PCH_RCBA_SPI_OPTYPE_RDADDR       = 0x02
PCH_RCBA_SPI_OPTYPE_WRADDR       = 0x03

PCH_RCBA_SPI_OPMENU              = 0x98  # Opcode Menu Configuration

PCH_RCBA_SPI_FDOC                = 0xB0  # Flash Descriptor Observability Control Register
PCH_RCBA_SPI_FDOC_FDSS_MASK      = (Cfg.BIT14 | Cfg.BIT13 | Cfg.BIT12)       # Flash Descritor Section Select
PCH_RCBA_SPI_FDOC_FDSS_FSDM      = 0x0000                        # Flash Signature and Descriptor Map
PCH_RCBA_SPI_FDOC_FDSS_COMP      = 0x1000                        # Component
PCH_RCBA_SPI_FDOC_FDSS_REGN      = 0x2000                        # Region
PCH_RCBA_SPI_FDOC_FDSS_MSTR      = 0x3000                        # Master
PCH_RCBA_SPI_FDOC_FDSI_MASK      = 0x0FFC                        # Flash Descriptor Section Index

PCH_RCBA_SPI_FDOD                = 0xB4  # Flash Descriptor Observability Data Register

# agregated SPI Flash commands
HSFCTL_READ_CYCLE = ( (PCH_RCBA_SPI_HSFCTL_FCYCLE_READ<<1) | PCH_RCBA_SPI_HSFCTL_FCYCLE_FGO)
HSFCTL_WRITE_CYCLE = ( (PCH_RCBA_SPI_HSFCTL_FCYCLE_WRITE<<1) | PCH_RCBA_SPI_HSFCTL_FCYCLE_FGO)
HSFCTL_ERASE_CYCLE = ( (PCH_RCBA_SPI_HSFCTL_FCYCLE_ERASE<<1) | PCH_RCBA_SPI_HSFCTL_FCYCLE_FGO)

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# FGO bit cleared (for safety ;)
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#HSFCTL_WRITE_CYCLE = ( (PCH_RCBA_SPI_HSFCTL_FCYCLE_WRITE<<1) )
#HSFCTL_ERASE_CYCLE = ( (PCH_RCBA_SPI_HSFCTL_FCYCLE_ERASE<<1) )

HSFSTS_CLEAR = (PCH_RCBA_SPI_HSFSTS_AEL | PCH_RCBA_SPI_HSFSTS_FCERR | PCH_RCBA_SPI_HSFSTS_FDONE)

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
 FLASH_DESCRIPTOR  : PCH_RCBA_SPI_FREG0_FLASHD,
 BIOS              : PCH_RCBA_SPI_FREG1_BIOS,
 ME                : PCH_RCBA_SPI_FREG2_ME,
 GBE               : PCH_RCBA_SPI_FREG3_GBE,
 PLATFORM_DATA     : PCH_RCBA_SPI_FREG4_PLATFORM_DATA,
 DEVICE_EXPANSION  : PCH_RCBA_SPI_FREG5_DEVICE_EXPANSION,
 SECONDARY_BIOS    : PCH_RCBA_SPI_FREG6_SECONDARY_BIOS
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
    range_base  = (flreg & PCH_RCBA_SPI_FREGx_BASE_MASK) << 12
    range_limit = ((flreg & PCH_RCBA_SPI_FREGx_LIMIT_MASK) >> 4)
    range_limit = range_limit + 0xFFF # + 4kB
    return (range_base, range_limit)

def get_SPI_MMIO_base( cs ):
    reg_value = cs.pci.read_dword( Cfg.SPI_MMIO_BUS, Cfg.SPI_MMIO_DEV, Cfg.SPI_MMIO_FUN, Cfg.SPI_MMIO_REG_OFFSET )
    spi_base = ((reg_value >> Cfg.SPI_BASE_ADDR_SHIFT) << Cfg.SPI_BASE_ADDR_SHIFT) + Cfg.SPI_MMIO_BASE_OFFSET
    if logger().VERBOSE: logger().log( "[spi] SPI MMIO base: 0x%016X (assuming below 4GB)" % spi_base )
    return spi_base


class SPI:
    def __init__( self, cs ):
        self.cs = cs
        #self.rcba_spi_base = get_MMIO_base_address( self.cs, MMIO_BAR_LPCRCBA_SPI )
        self.rcba_spi_base = get_SPI_MMIO_base( self.cs )

    def spi_reg_read( self, reg ):
        return read_MMIO_reg( self.cs, self.rcba_spi_base, reg )

    def spi_reg_write( self, reg, value ):
        return write_MMIO_reg( self.cs, self.rcba_spi_base, reg, value )


    def get_SPI_region( self, spi_region_id ):
        freg = self.spi_reg_read( SPI_REGION[ spi_region_id ] )
        #range_base  = (freg & PCH_RCBA_SPI_FREGx_BASE_MASK) << 12
        #range_limit = ((freg & PCH_RCBA_SPI_FREGx_LIMIT_MASK) >> 4)
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

        pr_j_reg = PCH_RCBA_SPI_PR0 + pr_num*4
        pr_j  = self.spi_reg_read( pr_j_reg )
        base = (pr_j & PCH_RCBA_SPI_PR0_PRB_MASK) << 12
        limit = (pr_j & PCH_RCBA_SPI_PR0_PRL_MASK) >> 4
        wpe = ((pr_j & PCH_RCBA_SPI_PR0_WPE) != 0)
        rpe = ((pr_j & PCH_RCBA_SPI_PR0_RPE) != 0)
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
            self.spi_reg_write( PCH_RCBA_SPI_FDOC, (PCH_RCBA_SPI_FDOC_FDSS_FSDM|(j<<2)) )
            fdod = self.spi_reg_read( PCH_RCBA_SPI_FDOD )
            logger().log( "%08X" % fdod )

        logger().log( "\nComponents:" )
        for j in range(3):
            self.spi_reg_write( PCH_RCBA_SPI_FDOC, (PCH_RCBA_SPI_FDOC_FDSS_COMP|(j<<2)) )
            fdod = self.spi_reg_read( PCH_RCBA_SPI_FDOD )
            logger().log( "%08X" % fdod )

        logger().log( "\nRegions:" )
        for j in range(5):
            self.spi_reg_write( PCH_RCBA_SPI_FDOC, (PCH_RCBA_SPI_FDOC_FDSS_REGN|(j<<2)) )
            fdod = self.spi_reg_read( PCH_RCBA_SPI_FDOD )
            logger().log( "%08X" % fdod )

        logger().log( "\nMasters:" )
        for j in range(3):
            self.spi_reg_write( PCH_RCBA_SPI_FDOC, (PCH_RCBA_SPI_FDOC_FDSS_MSTR|(j<<2)) )
            fdod = self.spi_reg_read( PCH_RCBA_SPI_FDOD )
            logger().log( "%08X" % fdod )


    def display_SPI_opcode_info( self ):
        logger().log( "============================================================" )
        logger().log( "SPI Opcode Info" )
        logger().log( "------------------------------------------------------------" )
        optype = (self.spi_reg_read( PCH_RCBA_SPI_OPTYPE ) & 0xFFFF)
        logger().log( "OPTYPE = 0x%04X" % optype )
        opmenu_lo = self.spi_reg_read( PCH_RCBA_SPI_OPMENU )
        opmenu_hi = self.spi_reg_read( PCH_RCBA_SPI_OPMENU + 0x4 )
        opmenu = ((opmenu_hi << 32)|opmenu_lo)
        logger().log( "OPMENU = 0x%016X" % opmenu )

        logger().log( "------------------------------------------------------------" )
        logger().log( "Opcode # | Opcode | Optype | Description" )
        logger().log( "------------------------------------------------------------" )
        
        for j in range(8):
           optype_j = ((optype >> j*2) & 0x3)
           if (PCH_RCBA_SPI_OPTYPE_RDNOADDR == optype_j):
             desc = 'SPI read cycle without address'
           elif (PCH_RCBA_SPI_OPTYPE_WRNOADDR == optype_j):
             desc = 'SPI write cycle without address'
           elif (PCH_RCBA_SPI_OPTYPE_RDADDR == optype_j):
             desc = 'SPI read cycle with address'
           elif (PCH_RCBA_SPI_OPTYPE_WRADDR == optype_j):
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
        bfpreg = self.spi_reg_read( PCH_RCBA_SPI_BFPR )
        logger().log( "BIOS Flash Primary Region" )
        logger().log( "------------------------------------------------------------" )
        logger().log( "BFPREG = %08X:" % bfpreg )
        logger().log( "  Base  : %08X" % ((bfpreg & PCH_RCBA_SPI_FREGx_BASE_MASK) << 12) )
        logger().log( "  Limit : %08X" % ((bfpreg & PCH_RCBA_SPI_FREGx_LIMIT_MASK) >> 4) )
        logger().log( "  Shadowed BIOS Select: %d" % ((bfpreg & Cfg.BIT31)>>31) )


    def display_SPI_Ranges_Access_Permissions( self ):
        logger().log( "SPI Flash Region Access Permissions" )
        logger().log( "------------------------------------------------------------" )
        fracc  = self.spi_reg_read( PCH_RCBA_SPI_FRAP )
        logger().log( "FRAP = %08X" % fracc )
        logger().log( "BIOS Region Write Access Grant (%02X):" % ((fracc & PCH_RCBA_SPI_FRAP_BMWAG_MASK)>>16) )
        logger().log( "  BIOS: %1d" % (fracc&PCH_RCBA_SPI_FRAP_BMWAG_BIOS   != 0) )
        logger().log( "  ME  : %1d" % (fracc&PCH_RCBA_SPI_FRAP_BMWAG_ME     != 0) )
        logger().log( "  GBe : %1d" % (fracc&PCH_RCBA_SPI_FRAP_BMWAG_GBE    != 0) )
        logger().log( "BIOS Region Read Access Grant (%02X):" % ((fracc & PCH_RCBA_SPI_FRAP_BMRAG_MASK)>>16) )
        logger().log( "  BIOS: %1d" % (fracc&PCH_RCBA_SPI_FRAP_BMRAG_BIOS   != 0) )
        logger().log( "  ME  : %1d" % (fracc&PCH_RCBA_SPI_FRAP_BMRAG_ME     != 0) )
        logger().log( "  GBe : %1d" % (fracc&PCH_RCBA_SPI_FRAP_BMRAG_GBE    != 0) )
        logger().log( "BIOS Write Access (%02X):" % ((fracc & PCH_RCBA_SPI_FRAP_BRWA_MASK)>>8) )
        logger().log( "  FD  : %1d" % (fracc&PCH_RCBA_SPI_FRAP_BRWA_FLASHD != 0) )
        logger().log( "  BIOS: %1d" % (fracc&PCH_RCBA_SPI_FRAP_BRWA_BIOS   != 0) )
        logger().log( "  ME  : %1d" % (fracc&PCH_RCBA_SPI_FRAP_BRWA_ME     != 0) )
        logger().log( "  GBe : %1d" % (fracc&PCH_RCBA_SPI_FRAP_BRWA_GBE    != 0) )
        logger().log( "  PD  : %1d" % (fracc&PCH_RCBA_SPI_FRAP_BRWA_PD     != 0) )
        logger().log( "  DE  : %1d" % (fracc&PCH_RCBA_SPI_FRAP_BRWA_DE     != 0) )
        logger().log( "  SB  : %1d" % (fracc&PCH_RCBA_SPI_FRAP_BRWA_SB     != 0) )
        logger().log( "BIOS Read Access (%02X):" % (fracc & PCH_RCBA_SPI_FRAP_BRRA_MASK) )
        logger().log( "  FD  : %1d" % (fracc&PCH_RCBA_SPI_FRAP_BRRA_FLASHD != 0) )
        logger().log( "  BIOS: %1d" % (fracc&PCH_RCBA_SPI_FRAP_BRRA_BIOS   != 0) )
        logger().log( "  ME  : %1d" % (fracc&PCH_RCBA_SPI_FRAP_BRRA_ME     != 0) )
        logger().log( "  GBe : %1d" % (fracc&PCH_RCBA_SPI_FRAP_BRRA_GBE    != 0) )
        logger().log( "  PD  : %1d" % (fracc&PCH_RCBA_SPI_FRAP_BRRA_PD     != 0) )
        logger().log( "  DE  : %1d" % (fracc&PCH_RCBA_SPI_FRAP_BRRA_DE     != 0) )
        logger().log( "  SB  : %1d" % (fracc&PCH_RCBA_SPI_FRAP_BRRA_SB     != 0) )


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

    def get_BIOS_Control( self ):
        #
        # BIOS Control (BC) 0:31:0 PCIe CFG register
        #
        reg_value = self.cs.pci.read_byte( 0, 31, 0, Cfg.LPC_BC_REG_OFF )
        BcRegister = Cfg.LPC_BC_REG( reg_value, (reg_value>>5)&0x1, (reg_value>>4)&0x1, (reg_value>>2)&0x3, (reg_value>>1)&0x1, reg_value&0x1 )
        return (BcRegister, reg_value)

    def disable_BIOS_write_protection( self ):
        (BcRegister, reg_value) = self.get_BIOS_Control()
        if logger().VERBOSE:
           logger().log( BcRegister )

        if BcRegister.BLE and (not BcRegister.BIOSWE):
           logger().log( "[spi] BIOS write protection enabled" )
           return False
        elif BcRegister.BIOSWE:
           logger().log( "[spi] BIOS write protection not enabled. What a surprise" )
           return True
        else:
           logger().log( "[spi] BIOS write protection enabled but not locked. Disabling.." )

        reg_value |= 0x1
        self.cs.pci.write_byte( 0, 31, 0, Cfg.LPC_BC_REG_OFF, reg_value )
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
            hsfsts = self.cs.mem.read_physical_mem_byte( spi_base + PCH_RCBA_SPI_HSFSTS )
            #hsfsts = self.spi_reg_read( PCH_RCBA_SPI_HSFSTS ) 
            #cycle_done = (hsfsts & PCH_RCBA_SPI_HSFSTS_FDONE) and (0 == (hsfsts & PCH_RCBA_SPI_HSFSTS_SCIP)) 
            cycle_done = not (hsfsts & PCH_RCBA_SPI_HSFSTS_SCIP)
            if cycle_done:
               break

        if not cycle_done:
           if logger().VERBOSE:
              logger().log( "[spi] SPI cycle still in progress. Waiting 0.1 sec.." )
           time.sleep(0.1)
           hsfsts = self.cs.mem.read_physical_mem_byte( spi_base + PCH_RCBA_SPI_HSFSTS )
           cycle_done = not (hsfsts & PCH_RCBA_SPI_HSFSTS_SCIP)

        if cycle_done:
           if logger().VERBOSE:
              logger().log( "[spi] clear FDONE/FCERR/AEL bits.." )
           self.cs.mem.write_physical_mem_byte( spi_base + PCH_RCBA_SPI_HSFSTS, HSFSTS_CLEAR )
           hsfsts = self.cs.mem.read_physical_mem_byte( spi_base + PCH_RCBA_SPI_HSFSTS )
           cycle_done = not ((hsfsts & PCH_RCBA_SPI_HSFSTS_AEL) or (hsfsts & PCH_RCBA_SPI_HSFSTS_FCERR))

        if logger().VERBOSE:
           logger().log( "[spi] HSFSTS: 0x%02X" % hsfsts )
              
        return cycle_done

    def _send_spi_cycle(self, hsfctl_spi_cycle_cmd, dbc, spi_fla ):
        if logger().VERBOSE:
           logger().log( "[spi] > send SPI cycle 0x%X to address 0x%08X.." % (hsfctl_spi_cycle_cmd, spi_fla) )

        spi_base = self.rcba_spi_base  

        # No need to check for SPI cycle DONE status before each cycle
        # DONE status is checked once before entire SPI operation
    
        self.cs.mem.write_physical_mem_dword( spi_base + PCH_RCBA_SPI_FADDR, (spi_fla & PCH_RCBA_SPI_FADDR_MASK) )
        _faddr = self.spi_reg_read( PCH_RCBA_SPI_FADDR ) 
        if logger().VERBOSE:
           logger().log( "[spi] FADDR: 0x%08X" % _faddr )
    
        if logger().VERBOSE:
           logger().log( "[spi] SPI cycle GO (DBC <- 0x%02X, HSFCTL <- 0x%X)" % (dbc, hsfctl_spi_cycle_cmd) )
        if ( HSFCTL_ERASE_CYCLE != hsfctl_spi_cycle_cmd ):
           self.cs.mem.write_physical_mem_byte( spi_base + PCH_RCBA_SPI_HSFCTL + 0x1, dbc ) 
        self.cs.mem.write_physical_mem_byte( spi_base + PCH_RCBA_SPI_HSFCTL, hsfctl_spi_cycle_cmd ) 
        # Read HSFCTL back
        hsfctl = self.cs.mem.read_physical_mem_word( spi_base + PCH_RCBA_SPI_HSFCTL )
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
              #buf += self.cs.mem.read_physical_mem( spi_base + PCH_RCBA_SPI_FDATA00, dbc )
              for fdata_idx in range(0,dbc/4):
                  dword_value = self.spi_reg_read( PCH_RCBA_SPI_FDATA00 + fdata_idx*4 ) 
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
                  dword_value = self.spi_reg_read( PCH_RCBA_SPI_FDATA00 + fdata_idx*4 ) 
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
           self.cs.mem.write_physical_mem_dword( spi_base + PCH_RCBA_SPI_FDATA00, dword_value )
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
           self.cs.mem.write_physical_mem_dword( spi_base + PCH_RCBA_SPI_FDATA00, dword_value )
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
