#!/usr/local/bin/python
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
# (c) 2010 - 2012 Intel Corporation
#
# -------------------------------------------------------------------------------
#
## \addtogroup config
# __chipsec/cfg/common.py__ - common configuration
__version__ = '1.0'

import struct
from collections import namedtuple

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

    BIT0 = 0x0001
    BIT1 = 0x0002
    BIT2 = 0x0004
    BIT3 = 0x0008
    BIT4 = 0x0010
    BIT5 = 0x0020
    BIT6 = 0x0040
    BIT7 = 0x0080
    BIT8 = 0x0100
    BIT9 = 0x0200
    BIT10 = 0x0400
    BIT11 = 0x0800
    BIT12 = 0x1000
    BIT13 = 0x2000
    BIT14 = 0x4000
    BIT15 = 0x8000
    BIT16 = 0x00010000
    BIT17 = 0x00020000
    BIT18 = 0x00040000
    BIT19 = 0x00080000
    BIT20 = 0x00100000
    BIT21 = 0x00200000
    BIT22 = 0x00400000
    BIT23 = 0x00800000
    BIT24 = 0x01000000
    BIT25 = 0x02000000
    BIT26 = 0x04000000
    BIT27 = 0x08000000
    BIT28 = 0x10000000
    BIT29 = 0x20000000
    BIT30 = 0x40000000
    BIT31 = 0x80000000
    BIT32 = 0x100000000
    BIT33 = 0x200000000
    BIT34 = 0x400000000
    BIT35 = 0x800000000
    BIT36 = 0x1000000000
    BIT37 = 0x2000000000
    BIT38 = 0x4000000000
    BIT39 = 0x8000000000
    BIT40 = 0x10000000000
    BIT41 = 0x20000000000
    BIT42 = 0x40000000000
    BIT43 = 0x80000000000
    BIT44 = 0x100000000000
    BIT45 = 0x200000000000
    BIT46 = 0x400000000000
    BIT47 = 0x800000000000
    BIT48 = 0x1000000000000
    BIT49 = 0x2000000000000
    BIT50 = 0x4000000000000
    BIT51 = 0x8000000000000
    BIT52 = 0x10000000000000
    BIT53 = 0x20000000000000
    BIT54 = 0x40000000000000
    BIT55 = 0x80000000000000
    BIT56 = 0x100000000000000
    BIT57 = 0x200000000000000
    BIT58 = 0x400000000000000
    BIT59 = 0x800000000000000
    BIT60 = 0x1000000000000000
    BIT61 = 0x2000000000000000
    BIT62 = 0x4000000000000000
    BIT63 = 0x8000000000000000


    BOUNDARY_4KB   = 0x1000
    BOUNDARY_1MB   = 0x100000
    BOUNDARY_8MB   = 0x800000
    BOUNDARY_64MB  = 0x4000000
    BOUNDARY_128MB = 0x8000000
    BOUNDARY_256MB = 0x10000000
    BOUNDARY_512MB = 0x20000000
    BOUNDARY_1GB   = 0x40000000
    BOUNDARY_2GB   = 0x80000000
    BOUNDARY_4GB   = 0x100000000

    ALIGNED_4KB   = 0xFFF
    ALIGNED_1MB   = 0xFFFFF
    ALIGNED_8MB   = 0x7FFFFF
    ALIGNED_64MB  = 0x3FFFFFF
    ALIGNED_128MB = 0x7FFFFFF
    ALIGNED_256MB = 0xFFFFFFF

    ##############################################################################
    # CPU common configuration
    ##############################################################################
    PCI_BUS0 = 0x0

    # ----------------------------------------------------------------------------
    # Device 0 PCIe Config
    # ----------------------------------------------------------------------------

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

    PCI_SMRAMC_BUS                = 0
    PCI_SMRAMC_DEV                = 0
    PCI_SMRAMC_FUN                = 0
    PCI_SMRAMC_REG_OFF            = 0x88 # 0x9D before Sandy Bridge


    # ----------------------------------------------------------------------------
    # Device 2 (Processor Graphics/Display) MMIO BARs
    # ----------------------------------------------------------------------------
    PCI_GTDE_DEV                  = 2

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
    IA32_MTRRCAP_MSR            = 0xFE
    IA32_MTRRCAP_SMRR_MASK      = 0x800

    IA32_FEATURE_CONTROL_MSR    = 0x3A
    IA32_FEATURE_CTRL_LOCK_MASK = 0x1

    IA32_SMRR_BASE_MSR          = 0x1F2
    IA32_SMRR_BASE_MEMTYPE_MASK = 0x7
    IA32_SMRR_BASE_BASE_MASK    = 0xFFFFF000

    IA32_SMRR_MASK_MSR          = 0x1F3
    IA32_SMRR_MASK_VLD_MASK     = 0x800
    IA32_SMRR_MASK_MASK_MASK    = 0xFFFFF000

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

    MSR_PLATFORM_INFO      = 0xCE

    ##############################################################################
    # PCH common configuration
    ##############################################################################

    #----------------------------------------------------------------------------
    # SPI Host Interface Registers
    #----------------------------------------------------------------------------

    PCH_RCBA_SPI_BFPR                  = 0x00  # BIOS Flash Primary Region Register (= FREG1)

    PCH_RCBA_SPI_HSFSTS                = 0x04  # Hardware Sequencing Flash Status Register
    PCH_RCBA_SPI_HSFSTS_FLOCKDN        = BIT15                         # Flash Configuration Lock-Down
    PCH_RCBA_SPI_HSFSTS_FDV            = BIT14                         # Flash Descriptor Valid
    PCH_RCBA_SPI_HSFSTS_FDOPSS         = BIT13                         # Flash Descriptor Override Pin-Strap Status
    PCH_RCBA_SPI_HSFSTS_SCIP           = BIT5                          # SPI cycle in progress
    PCH_RCBA_SPI_HSFSTS_BERASE_MASK    = (BIT4 | BIT3)                 # Block/Sector Erase Size
    PCH_RCBA_SPI_HSFSTS_BERASE_256B    = 0x00                          # Block/Sector = 256 Bytes
    PCH_RCBA_SPI_HSFSTS_BERASE_4K      = 0x01                          # Block/Sector = 4K Bytes
    PCH_RCBA_SPI_HSFSTS_BERASE_8K      = 0x10                          # Block/Sector = 8K Bytes
    PCH_RCBA_SPI_HSFSTS_BERASE_64K     = 0x11                          # Block/Sector = 64K Bytes
    PCH_RCBA_SPI_HSFSTS_AEL            = BIT2                          # Access Error Log
    PCH_RCBA_SPI_HSFSTS_FCERR          = BIT1                          # Flash Cycle Error
    PCH_RCBA_SPI_HSFSTS_FDONE          = BIT0                          # Flash Cycle Done

    PCH_RCBA_SPI_HSFCTL                = 0x06  # Hardware Sequencing Flash Control Register
    PCH_RCBA_SPI_HSFCTL_FSMIE          = BIT15                         # Flash SPI SMI Enable
    PCH_RCBA_SPI_HSFCTL_FDBC_MASK      = 0x3F00                        # Flash Data Byte Count, Count = FDBC + 1.
    PCH_RCBA_SPI_HSFCTL_FCYCLE_MASK    = 0x0006                        # Flash Cycle
    PCH_RCBA_SPI_HSFCTL_FCYCLE_READ    = 0                             # Flash Cycle Read
    PCH_RCBA_SPI_HSFCTL_FCYCLE_WRITE   = 2                             # Flash Cycle Write
    PCH_RCBA_SPI_HSFCTL_FCYCLE_ERASE   = 3                             # Flash Cycle Block Erase
    PCH_RCBA_SPI_HSFCTL_FCYCLE_FGO     = BIT0                          # Flash Cycle GO

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

    # Flash Region Registers
    PCH_RCBA_SPI_FREG0_FLASHD           = 0x54  # Flash Region 0 (Flash Descriptor)
    PCH_RCBA_SPI_FREG1_BIOS             = 0x58  # Flash Region 1 (BIOS)
    PCH_RCBA_SPI_FREG2_ME               = 0x5C  # Flash Region 2 (ME)
    PCH_RCBA_SPI_FREG3_GBE              = 0x60  # Flash Region 3 (GbE)
    PCH_RCBA_SPI_FREG4_PLATFORM_DATA    = 0x64  # Flash Region 4 (Platform Data)
    PCH_RCBA_SPI_FREG5                  = 0x68  # Flash Region 5
    PCH_RCBA_SPI_FREG6                  = 0x6C  # Flash Region 6

    PCH_RCBA_SPI_FREGx_LIMIT_MASK    = 0x7FFF0000                    # Size
    PCH_RCBA_SPI_FREGx_BASE_MASK     = 0x00007FFF                    # Base

    # Protected Range Registers
    PCH_RCBA_SPI_PR0                 = 0x74  # Protected Region 0 Register
    PCH_RCBA_SPI_PR0_WPE             = BIT31                         # Write Protection Enable
    PCH_RCBA_SPI_PR0_PRL_MASK        = 0x7FFF0000                    # Protected Range Limit Mask
    PCH_RCBA_SPI_PR0_RPE             = BIT15                         # Read Protection Enable
    PCH_RCBA_SPI_PR0_PRB_MASK        = 0x00007FFF                    # Protected Range Base Mask
    PCH_RCBA_SPI_PR1                 = 0x78
    PCH_RCBA_SPI_PR1_WPE             = BIT31
    PCH_RCBA_SPI_PR1_PRL_MASK        = 0x7FFF0000
    PCH_RCBA_SPI_PR1_RPE             = BIT15
    PCH_RCBA_SPI_PR1_PRB_MASK        = 0x00007FFF
    PCH_RCBA_SPI_PR2                 = 0x7C
    PCH_RCBA_SPI_PR2_WPE             = BIT31
    PCH_RCBA_SPI_PR2_PRL_MASK        = 0x7FFF0000
    PCH_RCBA_SPI_PR2_RPE             = BIT15
    PCH_RCBA_SPI_PR2_PRB_MASK        = 0x00007FFF
    PCH_RCBA_SPI_PR3                 = 0x80
    PCH_RCBA_SPI_PR3_WPE             = BIT31
    PCH_RCBA_SPI_PR3_PRL_MASK        = 0x7FFF0000
    PCH_RCBA_SPI_PR3_RPE             = BIT15
    PCH_RCBA_SPI_PR3_PRB_MASK        = 0x00007FFF
    PCH_RCBA_SPI_PR4                 = 0x84
    PCH_RCBA_SPI_PR4_WPE             = BIT31
    PCH_RCBA_SPI_PR4_PRL_MASK        = 0x7FFF0000
    PCH_RCBA_SPI_PR4_RPE             = BIT15
    PCH_RCBA_SPI_PR4_PRB_MASK        = 0x00007FFF

    PCH_RCBA_SPI_OPTYPE              = 0x96  # Opcode Type Configuration
    PCH_RCBA_SPI_OPTYPE7_MASK        = (BIT15 | BIT14)
    PCH_RCBA_SPI_OPTYPE6_MASK        = (BIT13 | BIT12)
    PCH_RCBA_SPI_OPTYPE5_MASK        = (BIT11 | BIT10)
    PCH_RCBA_SPI_OPTYPE4_MASK        = (BIT9 | BIT8)
    PCH_RCBA_SPI_OPTYPE3_MASK        = (BIT7 | BIT6)
    PCH_RCBA_SPI_OPTYPE2_MASK        = (BIT5 | BIT4)
    PCH_RCBA_SPI_OPTYPE1_MASK        = (BIT3 | BIT2)
    PCH_RCBA_SPI_OPTYPE0_MASK        = (BIT1 | BIT0)
    PCH_RCBA_SPI_OPTYPE_RDNOADDR     = 0x00
    PCH_RCBA_SPI_OPTYPE_WRNOADDR     = 0x01
    PCH_RCBA_SPI_OPTYPE_RDADDR       = 0x02
    PCH_RCBA_SPI_OPTYPE_WRADDR       = 0x03

    PCH_RCBA_SPI_OPMENU              = 0x98  # Opcode Menu Configuration

    PCH_RCBA_SPI_FDOC                = 0xB0  # Flash Descriptor Observability Control Register
    PCH_RCBA_SPI_FDOC_FDSS_MASK      = (BIT14 | BIT13 | BIT12)       # Flash Descriptor Section Select
    PCH_RCBA_SPI_FDOC_FDSS_FSDM      = 0x0000                        # Flash Signature and Descriptor Map
    PCH_RCBA_SPI_FDOC_FDSS_COMP      = 0x1000                        # Component
    PCH_RCBA_SPI_FDOC_FDSS_REGN      = 0x2000                        # Region
    PCH_RCBA_SPI_FDOC_FDSS_MSTR      = 0x3000                        # Master
    PCH_RCBA_SPI_FDOC_FDSI_MASK      = 0x0FFC                        # Flash Descriptor Section Index

    PCH_RCBA_SPI_FDOD                = 0xB4  # Flash Descriptor Observability Data Register

    # ----------------------------------------------------------------------------
    # PCI 0/31/0: PCH LPC Root Complex
    # ----------------------------------------------------------------------------
    PCI_B0D31F0_LPC_DEV = 31
    PCI_B0D31F0_LPC_FUN = 0

    LPC_BC_REG_OFF        = 0xDC #  BIOS Control (BC)
    GEN_PMCON = 0xA0

    class LPC_BC_REG( namedtuple('LPC_BC_REG', 'value SMM_BWP TSS SRC BLE BIOSWE') ):
        __slots__ = ()
        def __str__(self):
            return """[*] BIOS Control = 0x%02X
    [05] SMM_BWP = %u (SMM BIOS Write Protection)
    [04] TSS     = %u (Top Swap Status)
    [01] BLE     = %u (BIOS Lock Enable)
    [00] BIOSWE  = %u (BIOS Write Enable)
    """ % ( self.value, self.SMM_BWP, self.TSS, self.BLE, self.BIOSWE )


    CFG_REG_PCH_LPC_PMBASE = 0x40 # ACPI I/O Base (PMBASE/ABASE)
    CFG_REG_PCH_LPC_PMBASE_MASK = ~0x1
    CFG_REG_PCH_LPC_ACTL   = 0x44 # ACPI Control  (ACTL)
    CFG_REG_PCH_LPC_GBA    = 0x48 # GPIO I/O Base (GBA)
    CFG_REG_PCH_LPC_GC     = 0x4C # GPIO Control  (GC)

    # PMBASE registers
    PMBASE_SMI_EN         = 0x30 # SMI_EN offset in PMBASE (ABASE)

    LPC_RCBA_REG_OFFSET   = 0xF0
    RCBA_BASE_ADDR_SHIFT  = 14

    # ----------------------------------------------------------------------------
    # SPI Controller MMIO
    # ----------------------------------------------------------------------------
    SPI_MMIO_BUS          = PCI_BUS0
    SPI_MMIO_DEV          = PCI_B0D31F0_LPC_DEV
    SPI_MMIO_FUN          = PCI_B0D31F0_LPC_FUN
    SPI_MMIO_REG_OFFSET   = 0xF0
    SPI_BASE_ADDR_SHIFT   = 14
    SPI_MMIO_BASE_OFFSET  = 0x3800  # Base address of the SPI host interface registers off of RCBA
    #SPI_MMIO_BASE_OFFSET = 0x3020  # Old (ICH8 and older) SPI registers base


    SPI_BIOS_CONTROL_OFFSET = 0xDC # BIOS Control Register



    # ----------------------------------------------------------------------------
    # PCI B0:D31:F3 SMBus Controller
    # ----------------------------------------------------------------------------
    PCI_B0D31F3_SMBUS_CTRLR_DEV = 31
    PCI_B0D31F3_SMBUS_CTRLR_FUN = 0x3
    #0x8C22, 0x9C22 # HSW
    #0x1C22 # SNB
    #0x1E22 # IVB 0x0154
    PCI_B0D31F3_SMBUS_CTRLR_DID = 0x1C22

    CFG_REG_PCH_SMB_CMD  = 0x04                    # D31:F3 Command

    CFG_REG_PCH_SMB_SBA  = 0x20                    # SMBus Base Address
    CFG_REG_PCH_SMB_SBA_BASE_ADDRESS_MASK = 0xFFE0 # Base Address
    CFG_REG_PCH_SMB_SBA_IO                = BIT0   # I/O Space Indicator

    CFG_REG_PCH_SMB_HCFG = 0x40                    # D31:F3 Host Configuration
    CFG_REG_PCH_SMB_HCFG_SPD_WD           = BIT4   # SPD_WD
    CFG_REG_PCH_SMB_HCFG_SSRESET          = BIT3   # Soft SMBus Reset
    CFG_REG_PCH_SMB_HCFG_I2C_EN           = BIT2   # I2C Enable
    CFG_REG_PCH_SMB_HCFG_SMB_SMI_EN       = BIT1   # SMBus SMI Enable
    CFG_REG_PCH_SMB_HCFG_HST_EN           = BIT0   # SMBus Host Enable
    class SMB_HCFG_REG( namedtuple('SMB_HCFG_REG', 'value SPD_WD SSRESET I2C_EN SMB_SMI_EN HST_EN') ):
        __slots__ = ()
        def __str__(self):
            return """[*] SMBus Host Config (BDF 0:31:0 + 0x%X) = 0x%02X
    [04] SPD_WD     = %u (SPD_WD)
    [03] SSRESET    = %u (Soft SMBus Reset)
    [02] I2C_EN     = %u (I2C Enable)
    [01] SMB_SMI_EN = %u (SMBus SMI Enable)
    [00] HST_EN     = %u (Host Enable)
    """ % ( Cfg.CFG_REG_PCH_SMB_HCFG, self.value, self.SPD_WD, self.SSRESET, self.I2C_EN, self.SMB_SMI_EN, self.HST_EN )


    # ----------------------------------------------------------------------------
    # PCH I/O Base Registers
    # ----------------------------------------------------------------------------

    TCOBASE_ABASE_OFFSET = 0x60


    # ----------------------------------------------------------------------------
    # PCH RCBA
    # ----------------------------------------------------------------------------


    RCBA_GENERAL_CONFIG_OFFSET = 0x3400  # Offset of BIOS General Configuration memory mapped registers base in RCBA

    RCBA_GC_RC_REG_OFFSET      = 0x0     # RTC Configuration (RC) register

    RCBA_GC_GCS_REG_OFFSET     = 0x10    # General Control and Status (GCS) register
    RCBA_GC_GCS_REG_BILD_MASK  = 0x1     # BIOS Interface Lock-Down (BILD)
    RCBA_GC_GCS_REG_BBS_MASK   = 0xC00   # Boot BIOS Straps (BBS) - PCI/SPI/LPC
    RCBA_GC_BUC_REG_OFFSET     = 0x14    # Backup Control (BUC) register
    RCBA_GC_BUC_REG_TS_MASK    = 0x1     # Top-Swap strap (TS)


    def scan_single_bit_mask(self,mask):
        for bit in range(0,7):
            if mask>>bit  == 1:
                return bit
