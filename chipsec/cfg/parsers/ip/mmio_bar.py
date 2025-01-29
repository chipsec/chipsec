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


class MMIOObj:
    def __init__(self, instance):
        self.base = None
        self.size = 0
        self.instance = instance

    def __str__(self) -> str:
        return f'instance: {self.instance}, base: 0x{self.base:X}'


class MMIOBarConfig(GenericConfig):
    def __init__(self, cfg_obj):
        super(MMIOBarConfig, self).__init__(cfg_obj)
        self.device = cfg_obj['device'] if 'device' in cfg_obj else cfg_obj['component'] if 'component' in cfg_obj else None
        self.register = cfg_obj['register']
        self.base_field = cfg_obj['base_field']
        self.size = cfg_obj['size'] if 'did' in cfg_obj else None
        self.desc = cfg_obj['desc'] if 'desc' in cfg_obj else self.name
        self.reg_align = cfg_obj['reg_align'] if 'reg_align' in cfg_obj else None
        self.registerh = cfg_obj['registerh'] if 'registerh' in cfg_obj else None
        self.reg_alignh = cfg_obj['reg_alignh'] if 'reg_alignh' in cfg_obj else None
        self.baseh_field = cfg_obj['baseh_field'] if 'baseh_field' in cfg_obj else None
        self.registertype = cfg_obj['registertype'] if 'registertype' in cfg_obj else None
        self.mmio_base = cfg_obj['mmio_base'] if 'mmio_base' in cfg_obj else None
        self.mmio_align = cfg_obj['mmio_align'] if 'mmio_align' in cfg_obj else None
        self.limit_field = cfg_obj['limit_field'] if 'limit_field' in cfg_obj else None
        self.limit_register = cfg_obj['limit_register'] if 'limit_register' in cfg_obj else None
        self.limit_align = cfg_obj['limit_align'] if 'limit_align' in cfg_obj else None
        self.fixed_address = cfg_obj['fixed_address'] if 'fixed_address' in cfg_obj else None
        self.enable_field = cfg_obj['enable_field'] if 'enable_field' in cfg_obj else None
        self.valid = cfg_obj['valid'] if 'valid' in cfg_obj else None
        self.instances = {}
        for key in cfg_obj['ids']:
            self.add_obj(key)

    def add_obj(self, key):
        self.instances[key] = MMIOObj(key)

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
        ret += f', config: {self.config}'
        if self.reg_align:
            ret += f', reg_align:{self.reg_align}'
        if self.registerh:
            ret += f', registerh:{self.registerh}'
        if self.reg_alignh:
            ret += f', reg_alignh:{self.reg_alignh}'
        if self.baseh_field:
            ret += f', baseh_field:{self.baseh_field}'
        if self.registertype:
            ret += f', registertype:{self.registertype}'
        if self.mmio_base:
            ret += f', mmio_base:{self.mmio_base}'
        if self.mmio_align:
            ret += f', mmio_align:{self.mmio_align}'
        if self.limit_field:
            ret += f', limit_field:{self.limit_field}'
        if self.limit_register:
            ret += f', limit_register:{self.limit_register}'
        if self.limit_align:
            ret += f', limit_align:{self.limit_align}'
        if self.fixed_address:
            ret += f', fixed_address:{self.fixed_address}'
        if self.enable_field:
            ret += f', enable_field:{self.enable_field}'
        if self.valid:
            ret += f', valid:{self.valid}'
        ret += f', desc:{self.desc}'
        ret += ', instances: ['
        ret += ' '.join(f'{{{str(inst)}}}' for (_, inst) in self.instances.items())
        ret += ']'
        return ret
