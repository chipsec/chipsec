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
# (c) 2010-2012 Intel Corporation
#
# -------------------------------------------------------------------------------

"""
Functionality encapsulating interrupt generation
CPU Interrupts specific functions (SMI, NMI)

usage:
    >>> send_SMI_APMC( 0xDE )
    >>> send_NMI()
"""

#TODO IPIs through Local APIC??

__version__ = '1.0'

import struct
import sys

from chipsec.logger import *
from chipsec.cfg.common import *

SMI_APMC_PORT = 0xB2

NMI_TCO1_CTL = 0x8 # NMI_NOW is bit [8] in TCO1_CTL (or bit [1] in TCO1_CTL + 1)
NMI_NOW      = 0x1


class Interrupts:
    def __init__( self, cs ):
        self.cs = cs

    def send_SW_SMI( self, thread_id, SMI_code_port_value, SMI_data_port_value, _rax, _rbx, _rcx, _rdx, _rsi, _rdi ):
        SMI_code_data = (SMI_data_port_value << 8 | SMI_code_port_value)
        if logger().HAL:
            logger().log( "[intr] sending SW SMI: code port 0x%02X <- 0x%02X, data port 0x%02X <- 0x%02X (0x%04X)" % (SMI_APMC_PORT, SMI_code_port_value, SMI_APMC_PORT+1, SMI_data_port_value, SMI_code_data) )
            logger().log( "       RAX = 0x%016X (AX will be overwridden with values of SW SMI ports B2/B3)" % _rax )
            logger().log( "       RBX = 0x%016X" % _rbx )
            logger().log( "       RCX = 0x%016X" % _rcx )
            logger().log( "       RDX = 0x%016X (DX will be overwridden with 0x00B2)" % _rdx )
            logger().log( "       RSI = 0x%016X" % _rsi )
            logger().log( "       RDI = 0x%016X" % _rdi )
        return self.cs.helper.send_sw_smi( thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi )

    def send_SMI_APMC( self, SMI_code_port_value, SMI_data_port_value ):
        SMI_code_data = (SMI_data_port_value << 8 | SMI_code_port_value)
        if logger().HAL: logger().log( "[intr] sending SMI via APMC ports: code 0xB2 <- 0x%02X, data 0xB3 <- 0x%02X (0x%04X)" % (SMI_code_port_value, SMI_data_port_value, SMI_code_data) )
        return self.cs.io.write_port_word( SMI_APMC_PORT, SMI_code_data )


    def get_PMBASE(self):
        return (self.cs.pci.read_dword( 0, 31, 0, Cfg.CFG_REG_PCH_LPC_PMBASE ) & ~0x1)

    def get_TCOBASE(self):
        return (self.get_PMBASE() + Cfg.TCOBASE_ABASE_OFFSET)


    def send_NMI( self ):
        if logger().HAL: logger().log( "[intr] sending NMI# through TCO1_CTL[NMI_NOW]" )
        tcobase = self.get_TCOBASE()
        return self.cs.io.write_port_byte( tcobase + NMI_TCO1_CTL + 1, NMI_NOW )
