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


class IOObj:
    def __init__(self, instance):
        self.base = None
        self.size = 0
        self.instance = instance

    def __str__(self) -> str:
        return f'instance: {self.instance}, base: {self.base}'


class IOBarConfig(GenericConfig):
    def __init__(self, cfg_obj):
        super(IOBarConfig, self).__init__(cfg_obj)
        self.device = cfg_obj['device']
        self.register = cfg_obj['register']
        self.base_field = cfg_obj['base_field']
        self.fixed_address = cfg_obj['fixed_address'] if 'fixed_address' in cfg_obj else None
        self.mask = cfg_obj['mask'] if 'mask' in cfg_obj else None
        self.offset = cfg_obj['offset'] if 'offset' in cfg_obj else None
        self.size = cfg_obj['size'] if 'did' in cfg_obj else None
        self.enable_field = cfg_obj['enable_field'] if 'enable_field' in cfg_obj else None
        self.desc = cfg_obj['desc']
        self.instances = {}
        for key in cfg_obj['ids']:
            self.add_obj(key)

    def add_obj(self, key):
        self.instances[key] = IOObj(key)

    def update_base_address(self, base, instance):
        if instance in self.instances:
            self.instances[instance].base = base

    def get_base(self, instance):
        if instance in self.instances:
            return self.instances[instance].base, self.instances[instance].size
        else:
            return (None, 0)

    def __str__(self) -> str:
        ret = f'name: {self.name}, device: {self.device}'
        ret += f', register:{self.register}, base_field:{self.base_field}'
        ret += f', size:{self.size}'
        if self.enable_field:
            ret += f', enable_field:{self.enable_field}'
        ret += f', config: {self.config}'
        if self.fixed_address:
            ret += f', fixed_address:{self.fixed_address}'
        ret += f', desc:{self.desc}'
        ret += ', instances: ['
        ret += ' '.join(f'{{{str(inst)}}}' for (_, inst) in self.instances.items())
        ret += ']'
        return ret
