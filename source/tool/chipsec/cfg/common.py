#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2016, Intel Corporation
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
# (c) 2010 - 2012 Intel Corporation
#
# -------------------------------------------------------------------------------
#

__version__ = '1.0'

import struct
from collections import namedtuple

from chipsec.defines import *

class Cfg:
    def __init__(self):
        self.CONFIG_PCI    = {}
        self.REGISTERS     = {}
        self.MMIO_BARS     = {}
        self.IO_BARS       = {}
        self.MEMORY_RANGES = {}
        self.CONTROLS      = {}
        self.XML_CONFIG_LOADED = False
        #pass

    ##############################################################################
    # CPU common configuration
    ##############################################################################

    # ----------------------------------------------------------------------------
    # Device 0 MMIO BARs
    # ----------------------------------------------------------------------------
    PCI_MCHBAR_REG_OFF            = 0x48

    PCI_PCIEXBAR_REG_OFF          = 0x60
    PCI_PCIEXBAR_REG_LENGTH_MASK  = (0x3 << 1)
    PCI_PCIEXBAR_REG_LENGTH_256MB = 0x0
    PCI_PCIEXBAR_REG_LENGTH_128MB = 0x1
    PCI_PCIEXBAR_REG_LENGTH_64MB  = 0x2
    PCI_PCIEXBAR_REG_ADMSK64      = (1 << 26)
    PCI_PCIEXBAR_REG_ADMSK128     = (1 << 27)
    PCI_PCIEXBAR_REG_ADMSK256     = 0xF0000000

    PCI_DMIBAR_REG_OFF            = 0x68

    # ----------------------------------------------------------------------------
    # Device 2 (Processor Graphics/Display) MMIO BARs
    # ----------------------------------------------------------------------------
    PCI_GTTMMADR_REG_OFF          = 0x10
    PCI_GMADR_REG_OFF             = 0x18

    # ----------------------------------------------------------------------------
    # HD Audio device configuration
    # ----------------------------------------------------------------------------
    PCI_HDA_DEV                   = 0x3
    PCI_HDA_MMC_REG_OFF           = 0x62
    PCI_HDA_MMAL_REG_OFF          = 0x64
    PCI_HDA_MMAH_REG_OFF          = 0x68
    PCI_HDA_MMD_REG_OFF           = 0x6C

    PCI_HDAUDIOBAR_REG_OFF        = 0x10

    # ----------------------------------------------------------------------------
    # CPU MSRs
    # ----------------------------------------------------------------------------
    MTRR_MEMTYPE_UC = 0x0
    MTRR_MEMTYPE_WC = 0x1
    MTRR_MEMTYPE_WT = 0x4
    MTRR_MEMTYPE_WP = 0x5
    MTRR_MEMTYPE_WB = 0x6
    MemType = {
      MTRR_MEMTYPE_UC: 'Uncacheable (UC)',
      MTRR_MEMTYPE_WB: 'Write Combining (WC)',
      MTRR_MEMTYPE_WT: 'Write-through (WT)',
      MTRR_MEMTYPE_WP: 'Write-protected (WP)',
      MTRR_MEMTYPE_WB: 'Writeback (WB)'
    }


    IA32_MSR_CORE_THREAD_COUNT                   = 0x35
    IA32_MSR_CORE_THREAD_COUNT_THREADCOUNT_MASK  = 0xFFFF
    IA32_MSR_CORE_THREAD_COUNT_CORECOUNT_MASK    = 0xFFFF0000

    ##############################################################################
    # PCH common configuration
    ##############################################################################

    #----------------------------------------------------------------------------
    # SPI Host Interface Registers
    #----------------------------------------------------------------------------

    PCH_RCBA_SPI_HSFSTS_SCIP           = BIT5                          # SPI cycle in progress
    PCH_RCBA_SPI_HSFSTS_BERASE_MASK    = (BIT4 | BIT3)                 # Block/Sector Erase Size
    PCH_RCBA_SPI_HSFSTS_BERASE_256B    = 0x00                          # Block/Sector = 256 Bytes
    PCH_RCBA_SPI_HSFSTS_BERASE_4K      = 0x01                          # Block/Sector = 4K Bytes
    PCH_RCBA_SPI_HSFSTS_BERASE_8K      = 0x10                          # Block/Sector = 8K Bytes
    PCH_RCBA_SPI_HSFSTS_BERASE_64K     = 0x11                          # Block/Sector = 64K Bytes
    PCH_RCBA_SPI_HSFSTS_AEL            = BIT2                          # Access Error Log
    PCH_RCBA_SPI_HSFSTS_FCERR          = BIT1                          # Flash Cycle Error
    PCH_RCBA_SPI_HSFSTS_FDONE          = BIT0                          # Flash Cycle Done

    PCH_RCBA_SPI_HSFCTL_FCYCLE_MASK    = 0x0006                        # Flash Cycle
    PCH_RCBA_SPI_HSFCTL_FCYCLE_READ    = 0                             # Flash Cycle Read
    PCH_RCBA_SPI_HSFCTL_FCYCLE_WRITE   = 2                             # Flash Cycle Write
    PCH_RCBA_SPI_HSFCTL_FCYCLE_ERASE   = 3                             # Flash Cycle Block Erase
    PCH_RCBA_SPI_HSFCTL_FCYCLE_FGO     = BIT0                          # Flash Cycle GO

    #PCH_RCBA_SPI_FADDR               = 0x08  # SPI Flash Address
    PCH_RCBA_SPI_FADDR_MASK          = 0x07FFFFFF                      # SPI Flash Address Mask [0:26]

    PCH_RCBA_SPI_FREGx_LIMIT_MASK    = 0x7FFF0000                    # Size
    PCH_RCBA_SPI_FREGx_BASE_MASK     = 0x00007FFF                    # Base

    # Protected Range Registers
    PCH_RCBA_SPI_PR0_WPE             = BIT31                         # Write Protection Enable
    PCH_RCBA_SPI_PR0_PRL_MASK        = 0x7FFF0000                    # Protected Range Limit Mask
    PCH_RCBA_SPI_PR0_RPE             = BIT15                         # Read Protection Enable
    PCH_RCBA_SPI_PR0_PRB_MASK        = 0x00007FFF                    # Protected Range Base Mask

    PCH_RCBA_SPI_OPTYPE_RDNOADDR     = 0x00
    PCH_RCBA_SPI_OPTYPE_WRNOADDR     = 0x01
    PCH_RCBA_SPI_OPTYPE_RDADDR       = 0x02
    PCH_RCBA_SPI_OPTYPE_WRADDR       = 0x03

    PCH_RCBA_SPI_FDOC_FDSS_FSDM      = 0x0000                        # Flash Signature and Descriptor Map
    PCH_RCBA_SPI_FDOC_FDSS_COMP      = 0x1000                        # Component
    PCH_RCBA_SPI_FDOC_FDSS_REGN      = 0x2000                        # Region
    PCH_RCBA_SPI_FDOC_FDSS_MSTR      = 0x3000                        # Master
    PCH_RCBA_SPI_FDOC_FDSI_MASK      = 0x0FFC                        # Flash Descriptor Section Index

    # ----------------------------------------------------------------------------
    # PCI 0/31/0: PCH LPC Root Complex
    # ----------------------------------------------------------------------------
    PCI_B0D31F0_LPC_DEV = 31
    PCI_B0D31F0_LPC_FUN = 0

    CFG_REG_PCH_LPC_PMBASE = 0x40 # ACPI I/O Base (PMBASE/ABASE)

    LPC_RCBA_REG_OFFSET   = 0xF0
    RCBA_BASE_ADDR_SHIFT  = 14

    # ----------------------------------------------------------------------------
    # SPI Controller MMIO
    # ----------------------------------------------------------------------------
    SPI_MMIO_BUS          = 0
    SPI_MMIO_DEV          = PCI_B0D31F0_LPC_DEV
    SPI_MMIO_FUN          = PCI_B0D31F0_LPC_FUN
    SPI_MMIO_REG_OFFSET   = 0xF0
    SPI_BASE_ADDR_SHIFT   = 14
    SPI_MMIO_BASE_OFFSET  = 0x3800  # Base address of the SPI host interface registers off of RCBA
    #SPI_MMIO_BASE_OFFSET = 0x3020  # Old (ICH8 and older) SPI registers base


    SPI_BIOS_CONTROL_OFFSET = 0xDC # BIOS Control Register


    CFG_REG_PCH_SMB_HCFG_HST_EN           = BIT0   # SMBus Host Enable


    # ----------------------------------------------------------------------------
    # PCH I/O Base Registers
    # ----------------------------------------------------------------------------

    TCOBASE_ABASE_OFFSET = 0x60
