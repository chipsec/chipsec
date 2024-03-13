# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Contact information:
# chipsec@intel.com
#


"""
The pci command can enumerate PCI/PCIe devices, enumerate expansion ROMs and allow direct access to PCI configuration registers via bus/device/function.

>>> chipsec_util pci enumerate
>>> chipsec_util pci read <bus> <device> <function> <offset> [width]
>>> chipsec_util pci write <bus> <device> <function> <offset> <width> <value>
>>> chipsec_util pci dump [<bus>] [<device>] [<function>]
>>> chipsec_util pci xrom [<bus>] [<device>] [<function>] [xrom_address]
>>> chipsec_util pci cmd [mask] [class] [subclass]

Examples:

>>> chipsec_util pci enumerate
>>> chipsec_util pci read 0 0 0 0x00
>>> chipsec_util pci read 0 0 0 0x88 byte
>>> chipsec_util pci write 0 0x1F 0 0xDC 1 0x1
>>> chipsec_util pci write 0 0 0 0x98 dword 0x004E0040
>>> chipsec_util pci dump
>>> chipsec_util pci dump 0 0 0
>>> chipsec_util pci xrom
>>> chipsec_util pci xrom 3 0 0 0xFEDF0000
>>> chipsec_util pci cmd
>>> chipsec_util pci cmd 1
"""

from chipsec.command import BaseCommand, toLoad
from chipsec.library.logger import pretty_print_hex_buffer
from argparse import ArgumentParser
from chipsec_util import get_option_width, is_option_valid_width, CMD_OPTS_WIDTH
from chipsec.hal.pci import print_pci_devices, print_pci_XROMs
from chipsec.hal.pci import PCI_HDR_CLS_OFF, PCI_HDR_SUB_CLS_OFF, PCI_HDR_CMD_OFF

# PCIe Devices and Configuration Registers


class PCICommand(BaseCommand):

    def requirements(self) -> toLoad:
        return toLoad.Driver

    def parse_arguments(self) -> None:
        parser = ArgumentParser(prog='chipsec_util pci', usage=__doc__)
        subparsers = parser.add_subparsers()
        parser_enumerate = subparsers.add_parser('enumerate')
        parser_enumerate.set_defaults(func=self.pci_enumerate)

        parser_read = subparsers.add_parser('read')
        parser_read.add_argument('bus', type=lambda x: int(x, 16), help='Bus (hex)')
        parser_read.add_argument('device', type=lambda x: int(x, 16), help='Device (hex)')
        parser_read.add_argument('function', type=lambda x: int(x, 16), help='Function (hex)')
        parser_read.add_argument('offset', type=lambda x: int(x, 16), help='Offset (hex)')
        parser_read.add_argument('size', type=str, default=None, nargs='?', help='Width')
        parser_read.set_defaults(func=self.pci_read)

        parser_write = subparsers.add_parser('write')
        parser_write.add_argument('bus', type=lambda x: int(x, 16), help='Bus (hex)')
        parser_write.add_argument('device', type=lambda x: int(x, 16), help='Device (hex)')
        parser_write.add_argument('function', type=lambda x: int(x, 16), help='Function (hex)')
        parser_write.add_argument('offset', type=lambda x: int(x, 16), help='Offset (hex)')
        parser_write.add_argument('size', type=str, help='Width')
        parser_write.add_argument('value', type=lambda x: int(x, 16), help='Value (hex)')
        parser_write.set_defaults(func=self.pci_write)

        parser_dump = subparsers.add_parser('dump')
        parser_dump.add_argument('bus', type=lambda x: int(x, 16), nargs='?', default=None, help='Bus (hex)')
        parser_dump.add_argument('device', type=lambda x: int(x, 16), nargs='?', default=None, help='Device (hex)')
        parser_dump.add_argument('function', type=lambda x: int(x, 16), nargs='?', default=None, help='Function (hex)')
        parser_dump.set_defaults(func=self.pci_dump)

        parser_xrom = subparsers.add_parser('xrom')
        parser_xrom.add_argument('bus', type=lambda x: int(x, 16), nargs='?', default=None, help='Bus (hex)')
        parser_xrom.add_argument('device', type=lambda x: int(x, 16), nargs='?', default=None, help='Device (hex)')
        parser_xrom.add_argument('function', type=lambda x: int(x, 16), nargs='?', default=None, help='Function (hex)')
        parser_xrom.add_argument('xrom_addr', type=lambda x: int(x, 16), nargs='?', default=None, help='XROM Address (hex)')
        parser_xrom.set_defaults(func=self.pci_xrom)

        parser_cmd = subparsers.add_parser('cmd')
        parser_cmd.add_argument('cmd_mask', type=lambda x: int(x, 16), default=0xFFFF, nargs='?', help='Mask (hex)')
        parser_cmd.add_argument('pci_class', type=lambda x: int(x, 16), default=None, nargs='?', help='Class (hex)')
        parser_cmd.add_argument('pci_sub_class', type=lambda x: int(x, 16), default=None, nargs='?', help='Subclass (hex)')
        parser_cmd.set_defaults(func=self.pci_cmd)

        parser.parse_args(self.argv, namespace=self)

    def pci_enumerate(self):
        self.logger.log("[CHIPSEC] Enumerating available PCIe devices...")
        print_pci_devices(self.cs.pci.enumerate_devices())

    def pci_dump(self):
        if self.bus is not None:
            if self.device is not None and self.function is not None:
                devices = [(self.bus, self.device, self.function, 0x0000, 0x0000, 0x0000)]
            else:
                devices = self.cs.pci.enumerate_devices(self.bus, self.device, self.function)

            for (_bus, _device, _function, _vid, _did, _rid) in devices:
                self.logger.log("[CHIPSEC] PCI device {:02X}:{:02X}.{:02X} configuration:".format(_bus, _device, _function))
                cfg_buf = self.cs.pci.dump_pci_config(_bus, _device, _function)
                pretty_print_hex_buffer(cfg_buf)
        else:
            self.logger.log("[CHIPSEC] Dumping configuration of available PCI devices...")
            self.cs.pci.print_pci_config_all()

    def pci_xrom(self):
        if self.bus is not None:
            if self.device is not None and self.function is not None:
                devices = [(self.bus, self.device, self.function, 0x0000, 0x0000, 0x000)]
            else:
                devices = self.cs.pci.enumerate_devices(self.bus, self.device, self.function)

            for (_bus, _device, _function, _vid, _did, _rid) in devices:
                self.logger.log("[CHIPSEC] Locating PCI expansion ROM (XROM) of {:02X}:{:02X}.{:02X}...".format(_bus, _device, _function))
                exists, xrom = self.cs.pci.find_XROM(_bus, _device, _function, True, True, self.xrom_addr)
                if exists:
                    self.logger.log("[CHIPSEC] Found XROM of {:02X}:{:02X}.{:02X}".format(_bus, _device, _function))
                    if xrom is not None:
                        self.logger.log("[CHIPSEC] XROM enabled = {:d}, base = 0x{:08X}, size = 0x{:08X}".format(xrom.en, xrom.base, xrom.size))
                        if xrom.header is not None:
                            self.logger.log("[CHIPSEC] XROM header: {}".format(xrom.header))
                else:
                    self.logger.log("[CHIPSEC] Couldn't find XROM of {:02X}:{:02X}.{:02X}".format(_bus, _device, _function))
        else:
            self.logger.log("[CHIPSEC] Enumerating PCI expansion ROMs...")
            _xroms = self.cs.pci.enumerate_xroms(True, True, self.xrom_addr)
            self.logger.log("[CHIPSEC] found {:d} PCI expansion ROMs".format(len(_xroms)))
            if len(_xroms) > 0:
                print_pci_XROMs(_xroms)

    def pci_read(self):
        width = 4
        if self.size is not None:
            width = get_option_width(self.size) if is_option_valid_width(self.size) else int(self.size, 16)

        if 1 == width:
            pci_value = self.cs.pci.read_byte(self.bus, self.device, self.function, self.offset)
        elif 2 == width:
            pci_value = self.cs.pci.read_word(self.bus, self.device, self.function, self.offset)
        elif 4 == width:
            pci_value = self.cs.pci.read_dword(self.bus, self.device, self.function, self.offset)
        else:
            self.logger.log_error("Width should be one of {}".format(CMD_OPTS_WIDTH))
            return
        self.logger.log("[CHIPSEC] PCI {:02X}:{:02X}.{:02X} + 0x{:02X}: 0x{:X}".format(self.bus, self.device, self.function, self.offset, pci_value))

    def pci_write(self):
        width = get_option_width(self.size) if is_option_valid_width(self.size) else int(self.size, 16)

        if 1 == width:
            self.cs.pci.write_byte(self.bus, self.device, self.function, self.offset, self.value)
        elif 2 == width:
            self.cs.pci.write_word(self.bus, self.device, self.function, self.offset, self.value)
        elif 4 == width:
            self.cs.pci.write_dword(self.bus, self.device, self.function, self.offset, self.value)
        else:
            self.logger.log_error("Width should be one of {}".format(CMD_OPTS_WIDTH))
            return
        self.logger.log("[CHIPSEC] Write 0x{:X} to PCI {:02X}:{:02X}.{:02X} + 0x{:02X}".format(self.value, self.bus, self.device, self.function, self.offset))

    def pci_cmd(self):
        self.logger.log('BDF     | VID:DID   | CMD  | CLS | Sub CLS')
        self.logger.log('------------------------------------------')
        for (b, d, f, vid, did, rid) in self.cs.pci.enumerate_devices():
            dev_cls = self.cs.pci.read_byte(b, d, f, PCI_HDR_CLS_OFF)
            if self.pci_class is not None and (dev_cls != self.pci_class):
                continue
            dev_sub_cls = self.cs.pci.read_byte(b, d, f, PCI_HDR_SUB_CLS_OFF)
            if self.pci_sub_class is not None and (dev_sub_cls != self.pci_sub_class):
                continue
            cmd_reg = self.cs.pci.read_word(b, d, f, PCI_HDR_CMD_OFF)
            if (cmd_reg & self.cmd_mask) == 0:
                continue
            self.logger.log('{:02X}:{:02X}.{:X} | {:04X}:{:04X} | {:04X} | {:02X}  | {:02X}'.format(b, d, f, vid, did, cmd_reg, dev_cls, dev_sub_cls))


commands = {'pci': PCICommand}
