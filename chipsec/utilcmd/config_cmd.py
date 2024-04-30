# !/usr/bin/python
# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2021, Intel Corporation
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

# Contact information:
# chipsec@intel.com

"""
>>> chipsec_util config show [config] <name>

Examples:

>>> chipsec_util config show ALL
>>> chipsec_util config show MMIO_BARS
>>> chipsec_util config show REGISTERS BC
"""

from argparse import ArgumentParser

from chipsec.command import BaseCommand, toLoad
from typing import Any, Dict

class CONFIGCommand(BaseCommand):

    def requirements(self) -> toLoad:
        return toLoad.All
    
    def parse_arguments(self) -> None:
        parser = ArgumentParser(usage=__doc__)

        subparsers = parser.add_subparsers()

        # show
        parser_show = subparsers.add_parser('show')
        parser_show.add_argument('config', choices=['CONFIG_PCI', 'REGISTERS', 'MMIO_BARS', 'IO_BARS', 'MEMORY_RANGES', 'CONTROLS', 'BUS', 'LOCKS', 'ALL'])
        parser_show.add_argument('name', type=str, nargs='*', help="Specific Name", default=[])
        parser_show.set_defaults(func=self.show, config="ALL")

        parser.parse_args(self.argv, namespace=self)


    def show(self) -> None:
        if self.config == "ALL":
            config = ['CONFIG_PCI', 'REGISTERS', 'MMIO_BARS', 'IO_BARS', 'MEMORY_RANGES', 'CONTROLS', 'BUS', 'LOCKS']
        else:
            config = [self.config]
        for mconfig in config:
            cfg = getattr(self.cs.Cfg, mconfig)
            if not self.name or len(config) > 1:
                self.name = sorted(cfg.keys())
            self.logger.log(mconfig)
            for name in self.name:
                if mconfig == "REGISTERS":
                    self.logger.log(f'\t{name} - {self.register_details(cfg[name])}')
                elif mconfig == "CONFIG_PCI":
                    self.logger.log(f'\t{name} - {self.pci_details(cfg[name])}')
                elif mconfig == "MMIO_BARS":
                    self.logger.log(f'\t{name} - {self.mmio_details(cfg[name])}')
                elif mconfig == "IO_BARS":
                    self.logger.log(f'\t{name} - {self.io_details(cfg[name])}')
                elif mconfig == "MEMORY_RANGES":
                    self.logger.log(f'\t{name} - {self.mem_details(cfg[name])}')
                elif mconfig == "CONTROLS":
                    self.logger.log(f'\t{name} - {self.control_details(cfg[name])}')
                elif mconfig == "LOCKS":
                    self.logger.log(f'\t{name} - {self.lock_details(cfg[name])}')
                elif mconfig == "BUS":
                    self.logger.log(f'\t{name} - {self.bus_details(cfg[name])}')

    def register_details(self, regi: Dict[str, Any]) -> str:
        ret = ''
        if regi['type'] == 'pcicfg' or regi['type'] == 'mmcfg':
            if 'device' in regi.keys():
                ret = f'device: {regi["device"]}, offset: {regi["offset"]}, size: {regi["size"]}'
            else:
                ret = f'bus: {regi["bus"]}, dev: {regi["dev"]}, func: {regi["fun"]}, offset: {regi["offset"]}, size: {regi["size"]}'
        elif regi['type'] == 'mmio':
            ret = f'bar: {regi["bar"]}, offset: {regi["offset"]}, size: {regi["size"]}'
        elif regi['type'] == 'mm_msgbus':
            ret = f'port: {regi["port"]}, offset: {regi["offset"]}, size: {regi["size"]}'
        elif regi['type'] == 'io':
            ret = f'port: {regi["port"]}, size: {regi["size"]}'
        elif regi['type'] == 'iobar':
            ret = f'bar: {regi["bar"]}, offset: {regi["offset"]}, size: {regi["size"]}'
        elif regi['type'] == 'msr':
            ret = f'msr: {regi["msr"]}, size: {regi["size"]}'
        elif regi['type'] == 'R Byte':
            ret = f'offset: {regi["offset"]}, size: {regi["size"]}'
        elif regi['type'] == 'memory':
            ret = f'access: {regi["access"]}, address: {regi["address"]}, offset: {regi["offset"]}, size: {regi["size"]}'
        if 'FIELDS' in regi.keys():
            for key in regi['FIELDS'].keys():
                extension = (f'\n\t\t{key} - bit {regi["FIELDS"][key]["bit"]}:{int(regi["FIELDS"][key]["size"]) + int(regi["FIELDS"][key]["bit"]) - 1}')
                ret += extension
        return ret

    def pci_details(self, regi: Dict[str, Any]) -> str:
        ret = f'bus: {regi["bus"]}, dev: {regi["dev"]}, func: {regi["fun"]}, vid: {regi["vid"]}, did: {regi["did"] if "did" in regi.keys() else None}'
        return ret

    def mmio_details(self, regi: Dict[str, Any]) -> str:
        regi_size = regi['size'] if 'size' in regi.keys() else None
        fixed_addr = regi['fixed_address'] if 'fixed_address' in regi.keys() else None
        if 'register' in regi.keys():
            ret = f'register: {regi["register"]}, base_field: {regi["base_field"]}, size: {regi_size}, fixed_address: {fixed_addr}'
        else:
            ret = f'bus: {regi["bus"]}, dev: {regi["dev"]}, func: {regi["fun"]}, mask: {regi["mask"]}, width: {regi["width"]}, size: {regi_size}, fixed_address: {fixed_addr}'
        return ret

    def io_details(self, regi: Dict[str, Any]) -> str:
        regi_size = regi['size'] if 'size' in regi.keys() else None
        fixed_addr = regi['fixed_address'] if 'fixed_address' in regi.keys() else None
        if 'register' in regi.keys():
            ret = f'register: {regi["register"]}, base_field: {regi["base_field"]}, size: {regi_size}, fixed_address: {fixed_addr}'
        else:
            ret = f'bus: {regi["bus"]}, dev: {regi["dev"]}, func: {regi["fun"]}, reg: {regi["reg"]}, mask: {regi["mask"]}, size: {regi_size}, fixed_address: {fixed_addr}'
        return ret

    def mem_details(self, regi: Dict[str, Any]) -> str:
        ret = f'access: {regi["access"]}, address: {regi["address"]}, size: {regi["size"]}'
        return ret

    def control_details(self, regi: Dict[str, Any]) -> str:
        ret = f'register: {regi["register"]}, field: {regi["field"]}'
        return ret

    def lock_details(self, regi: Dict[str, Any]) -> str:
        ret = f'register: {regi["register"]}, field: {regi["field"]}, value: {regi["value"]}'
        return ret

    def bus_details(self, regi: str) -> str:
        ret = f'bus: {regi}'
        return ret


commands = {'config': CONFIGCommand}
