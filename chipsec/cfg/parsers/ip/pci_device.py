# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2023, Intel Corporation
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

from chipsec.cfg.parsers.ip.generic import GenericConfig


class PCIObj:
    def __init__(self, cfg_obj):
        self.bus = cfg_obj['bus']
        self.dev = cfg_obj['dev']
        self.fun = cfg_obj['fun']
        self.rid = cfg_obj['rid'] if 'rid' in cfg_obj else 0xff

    def __str__(self) -> str:
        ret = f'bus: {self.bus}, dev: {self.dev}, func: {self.fun}'
        ret += f', rid:{self.rid}'
        return ret


class PCIConfig(GenericConfig):
    def __init__(self, cfg_obj):
        self.did = cfg_obj['did'] if 'did' in cfg_obj else None
        if 'name' not in cfg_obj:
            cfg_obj['name'] = self.did
        super(PCIConfig, self).__init__(cfg_obj)
        self.instances = {}
        self.component = cfg_obj['component'] if 'component' in cfg_obj else None
        self.__instCounter = 0
        self.add_obj(cfg_obj)

    def add_obj(self, cfg_obj):
        self.instances[self.__instCounter] = PCIObj(cfg_obj)
        self.__instCounter += 1

    def get_rid(self, bus, dev, fun):
        rid = 0xff
        for inst in self.instances.values():
            if bus in inst.bus and inst.dev == dev and inst.fun == fun:
                rid = inst.rid
                break
        return rid

    def update_name(self, name):
        self.name = name

    def __str__(self) -> str:
        if self.did:
            ret = f'name:{self.name}, did:{self.did:04X}'
        else:
            ret = f'name:{self.name}, did:{self.did}'
        ret += f', component: {self.component}'
        ret += f', config: {self.config}'
        ret += ', instances: ['
        ret += ' '.join(f'{{{str(inst)}}}' for inst in self.instances.values())
        ret += ']'
        return ret
