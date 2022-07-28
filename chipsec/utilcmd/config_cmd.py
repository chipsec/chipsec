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

from time import time
from argparse import ArgumentParser

from chipsec.command import BaseCommand


class CONFIGCommand(BaseCommand):

    def requires_driver(self):
        parser = ArgumentParser(usage=__doc__)

        subparsers = parser.add_subparsers()

        # show
        parser_show = subparsers.add_parser('show')
        parser_show.add_argument('config', choices=['CONFIG_PCI', 'REGISTERS', 'MMIO_BARS', 'IO_BARS', 'MEMORY_RANGES', 'CONTROLS', 'BUS', 'LOCKS', 'ALL'])
        parser_show.add_argument('name', type=str, nargs='*', help="Specific Name", default=[])
        parser_show.set_defaults(func=self.show, config="ALL")

        parser.parse_args(self.argv[2:], namespace=self)
        return False

    def show(self):
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
                    self.logger.log('\t{} - {}'.format(name, self.register_details(cfg[name])))
                elif mconfig == "CONFIG_PCI":
                    self.logger.log('\t{} - {}'.format(name, self.pci_details(cfg[name])))
                elif mconfig == "MMIO_BARS":
                    self.logger.log('\t{} - {}'.format(name, self.mmio_details(cfg[name])))
                elif mconfig == "IO_BARS":
                    self.logger.log('\t{} - {}'.format(name, self.io_details(cfg[name])))
                elif mconfig == "MEMORY_RANGES":
                    self.logger.log('\t{} - {}'.format(name, self.mem_details(cfg[name])))
                elif mconfig == "CONTROLS":
                    self.logger.log('\t{} - {}'.format(name, self.control_details(cfg[name])))
                elif mconfig == "LOCKS":
                    self.logger.log('\t{} - {}'.format(name, self.lock_details(cfg[name])))
                elif mconfig == "BUS":
                    self.logger.log('\t{} - {}'.format(name, self.bus_details(cfg[name])))

    def register_details(self, regi):
        if regi['type'] == 'pcicfg' or regi['type'] == 'mmcfg':
            if 'device' in regi.keys():
                ret = "device: {}, offset: {}, size: {}".format(regi['device'], regi['offset'], regi['size'])
            else:
                ret = "bus: {}, dev: {}, func: {}, offset: {}, size: {}".format(regi['bus'], regi['dev'], regi['fun'], regi['offset'], regi['size'])
        elif regi['type'] == 'mmio':
            ret = "bar: {}, offset: {}, size: {}".format(regi['bar'], regi['offset'], regi['size'])
        elif regi['type'] == 'mm_msgbus':
            ret = "port: {}, offset: {}, size: {}".format(regi['port'], regi['offset'], regi['size'])
        elif regi['type'] == 'io':
            ret = "port: {}, size: {}".format(regi['port'], regi['size'])
        elif regi['type'] == 'iobar':
            ret = "bar: {}, offset: {}, size: {}".format(regi['bar'], regi['offset'], regi['size'])
        elif regi['type'] == 'msr':
            ret = "msr: {}, size: {}".format(regi['msr'], regi['size'])
        elif regi['type'] == 'R Byte':
            ret = "offset: {}, size: {}".format(regi['offset'], regi['size'])
        elif regi['type'] == 'memory':
            ret = "access: {}, address: {}, offset: {}, size: {}".format(regi['access'], regi['address'], regi['offset'], regi['size'])
        if 'FIELDS' in regi.keys():
            for key in regi['FIELDS'].keys():
                ret += ('\n\t\t{} - bit {}:{}'.format(key, regi['FIELDS'][key]['bit'], int(regi['FIELDS'][key]['size']) + int(regi['FIELDS'][key]['bit']) - 1))
        return ret

    def pci_details(self, regi):
        ret = "bus: {}, dev: {}, func: {}, vid: {}, did: {}".format(regi['bus'], regi['dev'], regi['fun'], regi['vid'], regi['did'] if 'did' in regi.keys() else None)
        return ret

    def mmio_details(self, regi):
        if 'register' in regi.keys():
            ret = "register: {}, base_field: {}, size: {}, fixed_address: {}".format(
                regi['register'], regi['base_field'], regi['size'] if 'size' in regi.keys() else None,
                regi['fixed_address'] if 'fixed_address' in regi.keys() else None)
        else:
            ret = "bus: {}, dev: {}, func: {}, mask: {}, width: {}, size: {}, fixed_address: {}".format(
                regi['bus'], regi['dev'], regi['fun'], regi['mask'], regi['width'],
                regi['size'] if 'size' in regi.keys() else None,
                regi['fixed_address'] if 'fixed_address' in regi.keys() else None)
        return ret

    def io_details(self, regi):
        if 'register' in regi.keys():
            ret = "register: {}, base_field: {}, size: {}, fixed_address: {}".format(
                regi['register'], regi['base_field'], regi['size'] if 'size' in regi.keys() else None,
                regi['fixed_address'] if 'fixed_address' in regi.keys() else None)
        else:
            ret = "bus: {}, dev: {}, func: {}, reg: {}, mask: {}, size: {}, fixed_address: {}".format(
                regi['bus'], regi['dev'], regi['fun'], regi["reg"], regi['mask'],
                regi['size'] if 'size' in regi.keys() else None,
                regi['fixed_address'] if 'fixed_address' in regi.keys() else None)
        return ret

    def mem_details(self, regi):
        ret = "access: {}, address: {}, size: {}".format(regi['access'], regi['address'], regi['size'])
        return ret

    def control_details(self, regi):
        ret = "register: {}, field: {}".format(regi['register'], regi['field'])
        return ret

    def lock_details(self, regi):
        ret = "register: {}, field: {}, value: {}".format(regi['register'], regi['field'], regi['value'])
        return ret

    def bus_details(self, regi):
        ret = "bus: {}".format(regi)
        return ret

    def run(self):
        t = time()
        self.func()
        self.logger.log("[CHIPSEC] (config) time elapsed {:.3f}".format(time() - t))
        return


commands = {'config': CONFIGCommand}
