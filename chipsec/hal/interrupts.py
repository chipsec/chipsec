#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2019, Intel Corporation
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

import struct
import sys
import uuid

from chipsec.hal import hal_base
from chipsec.logger import logger
from chipsec.cfg.common import *
from chipsec.hal.acpi import ACPI
from chipsec.hal.acpi_tables import UEFI_TABLE, GAS
from chipsec.hal.uefi_common import EFI_GUID_DEFINED_SECTION

SMI_APMC_PORT = 0xB2

NMI_TCO1_CTL = 0x8 # NMI_NOW is bit [8] in TCO1_CTL (or bit [1] in TCO1_CTL + 1)
NMI_NOW      = 0x1


class Interrupts(hal_base.HALBase):

    def __init__(self,cs):
        super(Interrupts, self).__init__(cs)

    def send_SW_SMI( self, thread_id, SMI_code_port_value, SMI_data_port_value, _rax, _rbx, _rcx, _rdx, _rsi, _rdi ):
        SMI_code_data = (SMI_data_port_value << 8 | SMI_code_port_value)
        if logger().HAL:
            logger().log( "[intr] sending SW SMI: code port 0x{:02X} <- 0x{:02X}, data port 0x{:02X} <- 0x{:02X} (0x{:04X})".format(SMI_APMC_PORT, SMI_code_port_value, SMI_APMC_PORT+1, SMI_data_port_value, SMI_code_data) )
            logger().log( "       RAX = 0x{:016X} (AX will be overwridden with values of SW SMI ports B2/B3)".format(_rax) )
            logger().log( "       RBX = 0x{:016X}".format(_rbx) )
            logger().log( "       RCX = 0x{:016X}".format(_rcx) )
            logger().log( "       RDX = 0x{:016X} (DX will be overwridden with 0x00B2)".format(_rdx) )
            logger().log( "       RSI = 0x{:016X}".format(_rsi) )
            logger().log( "       RDI = 0x{:016X}".format(_rdi) )
        return self.cs.helper.send_sw_smi( thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi )

    def send_SMI_APMC( self, SMI_code_port_value, SMI_data_port_value ):
        SMI_code_data = (SMI_data_port_value << 8 | SMI_code_port_value)
        if logger().HAL: logger().log( "[intr] sending SMI via APMC ports: code 0xB2 <- 0x{:02X}, data 0xB3 <- 0x{:02X} (0x{:04X})".format(SMI_code_port_value, SMI_data_port_value, SMI_code_data) )
        return self.cs.io.write_port_word( SMI_APMC_PORT, SMI_code_data )


    def get_PMBASE(self):
        return (self.cs.pci.read_dword( 0, 31, 0, Cfg.CFG_REG_PCH_LPC_PMBASE ) & ~0x1)

    def get_TCOBASE(self):
        return (self.get_PMBASE() + Cfg.TCOBASE_ABASE_OFFSET)


    def send_NMI( self ):
        if logger().HAL: logger().log( "[intr] sending NMI# through TCO1_CTL[NMI_NOW]" )
        tcobase = self.get_TCOBASE()
        return self.cs.io.write_port_byte( tcobase + NMI_TCO1_CTL + 1, NMI_NOW )

    def find_ACPI_SMI_Buffer(self):
        if logger().HAL: logger().log("Parsing ACPI tables to identify Communication Buffer")
        _acpi = ACPI(self.cs).get_ACPI_table("UEFI")
        if len(_acpi):
            _uefi = UEFI_TABLE()
            _uefi.parse(_acpi[0][1])
            if logger().HAL: logger().log(str(_uefi))
            return _uefi.get_commbuf_info() 
        if logger().HAL: logger().log("Unable to find Communication Buffer")
        return None

    def send_ACPI_SMI(self, thread_id, smi_num, buf_addr, invoc_reg, guid, data):
        #Prepare Communication Data buffer
        #typedef struct {
        #   EFI_GUID HeaderGuid;
        #   UINTN MessageLength;
        #   UINT8 Data[ANYSIZE_ARRAY];
        # } EFI_SMM_COMMUNICATE_HEADER;
        _guid = uuid.UUID(guid)
        data_hdr = _guid + struct.pack("Q",len(data)) + data
        if not invoc_reg is None:
            #need to write data_hdr to comm buffer
            tmp_buf = self.cs.helper.write_physical_mem(buf_addr,len(data_hdr),data_hdr)
            #USING GAS need to write buf_addr into invoc_reg
            if invoc_reg.addrSpaceID is 0:
                self.cs.helper.write_physical_mem(invoc_reg.addr,invoc_reg.access_size,buf_addr)
                #check for return status
                ret_buf = self.cs.helper.read_physical_mem(buf_addr,8)
            elif invoc_reg.addrSpaceID is 1:
                self.cs.helper.write_io_port(invoc_reg.addr,invoc_reg.access_size,buf_addr)
                #check for return status
                ret_buf = self.cs.helper.read_io_port(buf_addr,8)
            else:
                logger().error("Functionality is currently not implemented")
                ret_buf = None
            return ret_buf

        else:
            #Wait for Communication buffer to be empty
            buf = 1
            while not buf == "\x00\x00":
                buf = self.cs.helper.read_physical_mem(buf_addr,2)
            #write data to commbuffer
            tmp_buf = self.cs.helper.write_physical_mem(buf_addr,len(data_hdr),data_hdr)
            #call SWSMI
            self.send_SW_SMI(thread_id,smi_num,0,0,0,0,0,0,0)
            #clear CommBuffer
            self.cs.helper.write_physical_mem(buf_addr,len(data_hdr),"\x00"*len(data_hdr))
            return None
