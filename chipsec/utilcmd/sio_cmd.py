#!/usr/bin/env python
#
# *********************************************************
# 
#                   PRE-RELEASE NOTICE
#
#        This file contains pre-release functionality
#        Please do not distribute this file publicly
#
# *********************************************************
#
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
#
# Authors:
#  HC Wang
#


from chipsec.logger import  logger
from chipsec.command import BaseCommand

import chipsec.defines
from chipsec.file import *
from chipsec.cfg.common import *
#from chipsec.hal.pci    import *
#from chipsec.hal.io    import *
from chipsec.helper import oshelper

PCI_LPC_EN_OFFSET = 0x82
PCI_LPC_DEC_OFFSET = 0x080
LPC_COM_A_DEC_RANGE_BIT = 0x07
LPC_COM_B_DEC_RANGE_BIT = 0x70

UART_TX_BUFFER_OFFSET = 0x00
UART_BAUD_LOW_OFFSET = 0x00
UART_BAUD_HIGH_OFFSET = 0x01
UART_FCR_OFFSET = 0x02
UART_LCR_OFFSET = 0x03
UART_MCR_OFFSET = 0x04
UART_LSR_OFFSET = 0x05

# ###################################################################
#
# Super I/O attached on LPC dump utility
#
# ###################################################################
class SIOCommand(BaseCommand):
    """
    >>> chipsec_util sio

    Examples:

    >>> chipsec_util sio
    """
    __logic_device_id = None
    __decode_range = None
    __active = None
    __uart_divisor = None
    
    def __init__(self, argv, cs=None):
        self.argv = argv
        self.logger = chipsec.logger.logger()
        self.cs = cs
        
    def requires_driver(self):
        # No driver required when printing the util documentation
        #if len(self.argv) < 2:
        #    return False
        return True

    def is_com_en(self, port='a'):
        if port == 'a':
            return bool(self.cs.pci.read_byte( 0, Cfg.PCI_B0D31F0_LPC_DEV, Cfg.PCI_B0D31F0_LPC_FUN, PCI_LPC_EN_OFFSET ) & BIT0)
        else:
            return bool(self.cs.pci.read_byte( 0, Cfg.PCI_B0D31F0_LPC_DEV, Cfg.PCI_B0D31F0_LPC_FUN, PCI_LPC_EN_OFFSET ) & BIT1)

    def get_com_port_decode_range(self, port='a'):
        if port == 'a':
            decode_range = self.cs.pci.read_byte( 0, Cfg.PCI_B0D31F0_LPC_DEV, Cfg.PCI_B0D31F0_LPC_FUN, PCI_LPC_DEC_OFFSET ) & LPC_COM_A_DEC_RANGE_BIT
        else:
            decode_range = (self.cs.pci.read_byte( 0, Cfg.PCI_B0D31F0_LPC_DEV, Cfg.PCI_B0D31F0_LPC_FUN, PCI_LPC_DEC_OFFSET ) & LPC_COM_B_DEC_RANGE_BIT) >> 4
            
        if decode_range == 0x00:
            return 0x3F8
        elif decode_range == 0x01:
            return 0x2F8
        elif decode_range == 0x05:
            return 0x2E8
        elif decode_range == 0x07:
            return 0x3E8

    def dump_lpc_com_port_status(self, port='a'):
        if self.is_com_en(port) == True:
            self.logger.log( "LPC COM %s is enabled." % port.upper())
            
            com_range = self.get_com_port_decode_range(port)
            
            com_port = None
            if com_range == 0x3F8:
                com_port = 1
            elif com_range == 0x2F8:
                com_port = 2
            elif com_range == 0x3E8:
                com_port = 3
            elif com_range == 0x2E8:
                com_port = 4

            if com_port != None:
                self.logger.log( "  decode range: 0x%X, port: COM%d" % (com_range, com_port))

    def dump_sio_config_space(self, index=0x2E, logic_device_id=2):
        self.logger.log("Dump 0x%X SIO config space" % index)
        self.cs.io.write_port_byte(index, 0x00)
        val = self.cs.io.read_port_byte(index + 1)
        if val == 0xFF:
            self.logger.log( "SIO config space 0x%X is NA" % index)
            return

        # Unlock config space
        self.cs.io.write_port_byte(index, 0x5A)

        # Switch logic device
        self.cs.io.write_port_byte(index, 0x07)
        self.cs.io.write_port_byte(index + 1, logic_device_id)

        # Dump logic device ID
        self.cs.io.write_port_byte(index, 0x07)
        self.__logic_device_id = self.cs.io.read_port_byte(index + 1)
        self.logger.log( "Logic device ID: 0x%X" % self.__logic_device_id)

        # Dump decode range
        self.cs.io.write_port_byte(index, 0x60) 
        self.__decode_range = self.cs.io.read_port_byte(index + 1) << 8
        self.cs.io.write_port_byte(index, 0x61) 
        self.__decode_range |= self.cs.io.read_port_byte(index + 1)
        self.logger.log( "decode range: 0x%X" % self.__decode_range)

        # Dump active
        self.cs.io.write_port_byte(index, 0x30)
        self.__active = self.cs.io.read_port_byte(index + 1) & BIT0
        self.logger.log( "Active: %d" % self.__active)

        # Lock config space
        self.cs.io.write_port_byte(index, 0xA5)
        self.logger.log("")

    def config_lcr(self, decode_range=0x3F8, data_bit=8, stop_bit=1, parity=None):
        # read LCR
        line_control_register = self.cs.io.read_port_byte(decode_range + UART_LCR_OFFSET)
        self.logger.log("  LCR: 0x%X" % line_control_register)

        # set date bit
        line_control_register |= (data_bit - 0x05)

        # set stop bit
        if stop_bit == 1:
            line_control_register &= (~BIT2)
        else:
            line_control_register |= BIT2

        # set parity
        if parity == None:
            line_control_register &= (~(BIT3 | BIT4 | BIT5))
        elif parity == "even":
            line_control_register |= (BIT3 | BIT4)
            line_control_register &= (~BIT5)
        else:
            line_control_register |= BIT3
            line_control_register &= (~(BIT4 | BIT5))
        
        # write back LCR
        self.cs.io.write_port_byte(decode_range + UART_LCR_OFFSET, line_control_register)
        line_control_register = self.cs.io.read_port_byte(decode_range + UART_LCR_OFFSET)
        self.logger.log("  write back  LCR: 0x%X" % line_control_register)

    def config_baud_rate(self, decode_range=0x3F8, clock=1843200, baud_rate=115200):
        line_control_register = self.cs.io.read_port_byte(decode_range + UART_LCR_OFFSET)
        line_control_register |= BIT7
        self.cs.io.write_port_byte(decode_range + UART_LCR_OFFSET, line_control_register)

        self.__uart_divisors = clock / (baud_rate * 16)
        if ((clock % (baud_rate * 16)) >= (baud_rate * 8)):
            self.__uart_divisors += 1
        self.logger.log( "  Baud rate: 0x%X" % self.__uart_divisors)
        
        self.cs.io.write_port_byte(decode_range + UART_BAUD_LOW_OFFSET, self.__uart_divisors & 0xFF)
        self.cs.io.write_port_byte(decode_range + UART_BAUD_HIGH_OFFSET, self.__uart_divisors >> 8)

        line_control_register &= (~BIT7)
        self.cs.io.write_port_byte(decode_range + UART_LCR_OFFSET, line_control_register)
        
    def config_uart(self, decode_range=0x3F8,
                          clock=1843200,
                          baud_rate=115200,
                          data_bit=8,
                          stop_bit=1,
                          parity=None):
        self.logger.log("Config UART...")

        # wait for the serial port to be ready
        while(self.cs.io.read_port_byte(decode_range + UART_LSR_OFFSET) & (BIT6 | BIT5) != (BIT6 | BIT5)):
            self.logger.log("  waiting for UART ready to config...")
        
        self.config_baud_rate(decode_range, clock, baud_rate)
        self.config_lcr(decode_range, data_bit, stop_bit, parity)

        # enable 64-bit FIFO
        self.cs.io.write_port_byte(decode_range + UART_FCR_OFFSET, 0x00)
        self.cs.io.write_port_byte(decode_range + UART_FCR_OFFSET, 0x07 | BIT0 | BIT5)

        # put the modem into reset state
        self.cs.io.write_port_byte(decode_range + UART_MCR_OFFSET, 0x00)

    def write_uart(self, decode_range=0x3F8, message="test"):
        for char in message:
            while((self.cs.io.read_port_byte(decode_range + UART_LSR_OFFSET) & BIT6) != BIT6):
                self.logger.log("  waiting for FIFO empty...")

            # not implement for hand shaking (flow control) yet
            self.cs.io.write_port_byte(decode_range + UART_TX_BUFFER_OFFSET, ord(char))
        
    
    def run(self):        
        #if 2 > len(self.argv):
        #    print SIOCommand.__doc__
        #    return
        self.logger.log("Dump LPC COM port status:")
        self.dump_lpc_com_port_status('a')
        self.dump_lpc_com_port_status('b')
        self.logger.log("")

        self.dump_sio_config_space(0x2E)
        #self.dump_sio_config_space(0x4E)

        self.config_uart()

        while(True):
            self.write_uart()

commands = { 'sio': SIOCommand }
