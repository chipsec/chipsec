#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2017, Intel Corporation
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



"""
The pci command can enumerate PCI/PCIe devices, enumerate expansion ROMs and allow direct access to PCI configuration registers via bus/device/function.
"""

import time

import chipsec_util

from chipsec.command    import BaseCommand
from chipsec.hal.pci    import *
from chipsec.logger     import pretty_print_hex_buffer

# PCIe Devices and Configuration Registers
class PCICommand(BaseCommand):
    """
    >>> chipsec_util pci enumerate
    >>> chipsec_util pci <bus> <device> <function> <offset> [width] [value]
    >>> chipsec_util pci dump [<bus> <device> <function>]
    >>> chipsec_util pci xrom [<bus> <device> <function>] [xrom_address]
    >>> chipsec_util pci cmd [mask] [class] [subclass]

    Examples:

    >>> chipsec_util pci enumerate
    >>> chipsec_util pci 0 0 0 0x00
    >>> chipsec_util pci 0 0 0 0x88 byte 0x1A
    >>> chipsec_util pci 0 0x1F 0 0xDC 1 0x1
    >>> chipsec_util pci 0 0 0 0x98 dword 0x004E0040
    >>> chipsec_util pci dump
    >>> chipsec_util pci dump 0 0 0
    >>> chipsec_util pci xrom
    >>> chipsec_util pci xrom 3 0 0 0xFEDF0000
    >>> chipsec_util pci cmd
    >>> chipsec_util pci cmd 1
    """

    def requires_driver(self):
        # No driver required when printing the util documentation
        if len(self.argv) < 3:
            return False
        return True

    def run(self):
        if len(self.argv) < 3:
            print (PCICommand.__doc__)
            return

        op = self.argv[2]
        t = time.time()

        if ( 'enumerate' == op ):
            self.logger.log( "[CHIPSEC] Enumerating available PCIe devices.." )
            print_pci_devices( self.cs.pci.enumerate_devices() )
            self.logger.log( "[CHIPSEC] (pci) time elapsed {:.3f}".format(time.time()-t) )
            return

        elif ( 'dump' == op ):

            if len(self.argv) == 3:
                self.logger.log( "[CHIPSEC] dumping configuration of available PCI devices.." )
                self.cs.pci.print_pci_config_all()

            elif len(self.argv) > 5:
                bus       = int(self.argv[3],16)
                device    = int(self.argv[4],16)
                function  = int(self.argv[5],16)
                self.logger.log( "[CHIPSEC] PCI device {:02X}:{:02X}.{:02X} configuration:".format(bus,device,function) )
                cfg_buf = self.cs.pci.dump_pci_config( bus, device, function )
                pretty_print_hex_buffer( cfg_buf )
            else:
                print (PCICommand.__doc__)
                return

        elif ( 'xrom' == op ):

            if len(self.argv) < 5:
                self.logger.log( "[CHIPSEC] enumerating PCI expansion ROMs.." )
                xrom_addr = int(self.argv[3],16) if len(self.argv) == 4 else None
                _xroms = self.cs.pci.enumerate_xroms( True, True, xrom_addr )
                self.logger.log( "[CHIPSEC] found {:d} PCI expansion ROMs".format(len(_xroms)) )
                if len(_xroms) > 0: print_pci_XROMs( _xroms )
            elif len(self.argv) > 5:
                bus       = int(self.argv[3],16)
                device    = int(self.argv[4],16)
                function  = int(self.argv[5],16)
                xrom_addr = int(self.argv[6],16) if len(self.argv) > 6 else None
                self.logger.log( "[CHIPSEC] locating PCI expansion ROM (XROM) of {:02X}:{:02X}.{:02X}...".format(bus,device,function) )
                exists,xrom = self.cs.pci.find_XROM( bus, device, function, True, True, xrom_addr )
                if exists:
                    self.logger.log( "[CHIPSEC] found XROM of {:02X}:{:02X}.{:02X}".format(bus,device,function) )
                    if xrom is not None:
                        self.logger.log( "[CHIPSEC] XROM enabled = {:d}, base = 0x{:08X}, size = 0x{:08X}".format(xrom.en,xrom.base,xrom.size) )
                        if xrom.header is not None: self.logger.log( "[CHIPSEC] XROM header: {}".format(xrom.header) )
                else:
                    self.logger.log( "[CHIPSEC] coudn't find XROM of {:02X}:{:02X}.{:02X}".format(bus,device,function) )
            else:
                print (PCICommand.__doc__)
                return

        elif ('cmd' == op):
            cmd_mask = 0xFFFF
            pci_class = None
            pci_sub_class = None
            if len(self.argv) >= 4:
                cmd_mask = int(self.argv[3],16)
            if len(self.argv) >= 5:
                pci_class = int(self.argv[4],16)
            if len(self.argv) >= 6:
                pci_sub_class = int(self.argv[5],16)
            self.logger.log('BDF     | VID:DID   | CMD  | CLS | Sub CLS')
            self.logger.log('------------------------------------------')
            for (b, d, f, vid, did) in self.cs.pci.enumerate_devices():
                dev_cls = self.cs.pci.read_byte(b, d, f, PCI_HDR_CLS_OFF)
                if pci_class is not None and (dev_cls != pci_class):
                    continue
                dev_sub_cls = self.cs.pci.read_byte(b, d, f, PCI_HDR_SUB_CLS_OFF)
                if pci_sub_class is not None and (dev_sub_cls != pci_sub_class):
                    continue
                cmd_reg = self.cs.pci.read_word(b, d, f, PCI_HDR_CMD_OFF)
                if (cmd_reg & cmd_mask) == 0:
                    continue
                self.logger.log('{:02X}:{:02X}.{:X} | {:04X}:{:04X} | {:04X} | {:02X}  | {:02X}'.format(b, d, f, vid, did, cmd_reg, dev_cls, dev_sub_cls))
        else:

            if len(self.argv) < 6:
                print (PCICommand.__doc__)
                return

            bus      = int(self.argv[2],16)
            device   = int(self.argv[3],16)
            function = int(self.argv[4],16)
            offset   = int(self.argv[5],16)
            width    = 4
            if len(self.argv) > 6:
                width = chipsec_util.get_option_width(self.argv[6]) if chipsec_util.is_option_valid_width(self.argv[6]) else int(self.argv[6],16)

            if 8 == len(self.argv):
                value = int(self.argv[7], 16)
                self.logger.log( "[CHIPSEC] write 0x{:X} to PCI {:02X}:{:02X}.{:02X} + 0x{:02X}".format(value, bus, device, function, offset) )
                if   1 == width: self.cs.pci.write_byte ( bus, device, function, offset, value )
                elif 2 == width: self.cs.pci.write_word ( bus, device, function, offset, value )
                elif 4 == width: self.cs.pci.write_dword( bus, device, function, offset, value )
                else: self.logger.error( "width should be one of {}".format(chipsec_util.CMD_OPTS_WIDTH) )
            else:
                if   1 == width: pci_value = self.cs.pci.read_byte (bus, device, function, offset)
                elif 2 == width: pci_value = self.cs.pci.read_word (bus, device, function, offset)
                elif 4 == width: pci_value = self.cs.pci.read_dword(bus, device, function, offset)
                else:
                    self.logger.error( "width should be one of {}".format(chipsec_util.CMD_OPTS_WIDTH) )
                    return
                self.logger.log( "[CHIPSEC] PCI {:02X}:{:02X}.{:02X} + 0x{:02X}: 0x{:X}".format(bus, device, function, offset, pci_value) )

        self.logger.log( "[CHIPSEC] (pci) time elapsed {:.3f}".format(time.time()-t) )

commands = { 'pci': PCICommand }
