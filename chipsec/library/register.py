# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2024, Intel Corporation
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
Main functionality to read/write configuration registers based on their XML configuration
"""

from typing import Any, Dict, List, Optional

from chipsec.parsers import BaseConfigHelper
from chipsec.library.logger import logger
from chipsec.library.bits import set_bits, get_bits, make_mask
from chipsec.library.exceptions import CSReadError, UninitializedRegisterError
from chipsec.library.registers.io import IO
from chipsec.library.registers.iobar import IOBar
from chipsec.library.registers.memory import Memory
from chipsec.library.registers.mm_msgbus import MMMsgBus
from chipsec.library.registers.mmcfg import MMCfg
from chipsec.library.registers.mmio import MMIO
from chipsec.library.registers.msgbus import MsgBus
from chipsec.library.registers.msr import MSR
from chipsec.library.registers.pcicfg import PCICfg


class RegisterType:
    PCICFG = 'pcicfg'
    MMCFG = 'mmcfg'
    MMIO = 'mmio'
    MSR = 'msr'
    PORTIO = 'io'
    IOBAR = 'iobar'
    MSGBUS = 'msgbus'
    MM_MSGBUS = 'mm_msgbus'
    MEMORY = 'memory'
    IMA = 'indirect'


class Register:
    def __init__(self, cs):
        self.cs = cs
        self.io = IO(cs)
        self.iobar = IOBar(cs)
        self.memory = Memory(cs)
        self.mm_msgbus = MMMsgBus(cs)
        self.mmcfg = MMCfg(cs)
        self.mmio = MMIO(cs)
        self.msgbus = MsgBus(cs)
        self.msr = MSR(cs)
        self.pcicfg = PCICfg(cs)

    def is_defined(self, reg_name: str) -> bool:
        """Checks if register is defined in the XML config"""
        scope = self.cs.Cfg.get_scope(reg_name)
        vid, device, register, _ = self.cs.Cfg.convert_internal_scope(scope, reg_name)
        try:
            return (self.cs.Cfg.REGISTERS[vid][device].get(register, None) is not None)
        except KeyError:
            return False

    def _get_pci_def(self, reg_def: Dict[str, Any], vid: str, dev_name: str) -> Dict[str, Any]:
        """Return Bus Dev Fun of a PCI register"""
        dev = self.cs.Cfg.CONFIG_PCI[vid][dev_name]
        reg_def['bus'] = dev.bus
        reg_def['dev'] = dev.dev
        reg_def['fun'] = dev.fun
        return reg_def

    def _get_mmmsgbus_def(self, reg_def: Dict[str, Any], vid: str, dev_name: str) -> Dict[str, Any]:
        """Return port address of a MM_MSGBUS register"""
        dev = self.cs.Cfg.MM_MSGBUS[vid][dev_name]
        reg_def['port'] = dev['port']
        return reg_def

    def _get_indirect_def(self, reg_def: Dict[str, Any], vid: str, dev_name: str) -> Dict[str, Any]:
        """Return base index data of a IMA register"""
        dev = self.cs.Cfg.IMA_REGISTERS[vid][dev_name]
        if ('base' in dev):
            reg_def['base'] = dev['base']
        else:
            reg_def['base'] = "0"
        if (dev['index'] in self.cs.Cfg.REGISTERS[vid][dev_name]):
            reg_def['index'] = dev['index']
        else:
            logger().log_error(f'Index register {dev["index"]} not found')
        if (dev['data'] in self.cs.Cfg.REGISTERS[vid][dev_name]):
            reg_def['data'] = dev['data']
        else:
            logger().log_error(f'Data register {dev["data"]} not found')
        return reg_def

    def get_def(self, reg_name: str) -> Dict[str, Any]:
        """Return complete register definition"""
        scope = self.cs.Cfg.get_scope(reg_name)
        vid, dev_name, register, _ = self.cs.Cfg.convert_internal_scope(scope, reg_name)
        reg_def = self.cs.Cfg.REGISTERS[vid][dev_name][register]
        def_type_map = {RegisterType.PCICFG: self._get_pci_def,
                        RegisterType.MMCFG: self._get_pci_def,
                        # RegisterType.MEMORY: self._get_memory_def,
                        RegisterType.MM_MSGBUS: self._get_mmmsgbus_def,
                        RegisterType.IMA: self._get_indirect_def}
        return def_type_map[reg_def["type"]](reg_def, vid, dev_name)

    # rework any call to this function
    def get_list_by_name(self, reg_name: str) -> 'ObjList':
        return self.cs.Cfg.get_objlist(self.cs.Cfg.REGISTERS, reg_name)
    
    def get_list_by_name_without_scope(self, reg_name: str) -> 'ObjList':
        return self.cs.Cfg.get_objlist(self.cs.Cfg.REGISTERS, "*.*." + reg_name)

    def get_instance_by_name(self, reg_name: str, instance: Any):
        for reg_obj in self.cs.Cfg.get_objlist(self.cs.Cfg.REGISTERS, reg_name):
            if reg_obj.instance == instance:
                return reg_obj
        return None #TODO Change to null register object

    def has_field(self, reg_name: str, field_name: str) -> bool:
        """Checks if the register has specific field"""
        reg_defs = self.cs.Cfg.get_objlist(self.cs.Cfg.REGISTERS, reg_name)
        for reg_def in reg_defs:
            try:
                return field_name in reg_def.fields
            except KeyError:
                return False
        return False

    def get_match(self, name: str):
        vid, device, register, field = self.cs.Cfg.convert_internal_scope("", name)
        ret = []
        if vid is None or vid == '*':
            vid = self.cs.Cfg.REGISTERS.keys()
        else:
            vid = [vid]
        for v in vid:
            if v in self.cs.Cfg.REGISTERS:
                if device is None or device == '*':
                    dev = self.cs.Cfg.REGISTERS[v].keys()
                else:
                    dev = [device]
                for d in dev:
                    if d in self.cs.Cfg.REGISTERS[v]:
                        if register is None or register == '*':
                            reg = self.cs.Cfg.REGISTERS[v][d].keys()
                        else:
                            reg = [register]
                        for r in reg:
                            if r in self.cs.Cfg.REGISTERS[v][d]:
                                if field is None or field == '*':
                                    fld = self.cs.Cfg.REGISTERS[v][d][r][0].fields.keys()
                                else:
                                    if field in self.cs.CfgREGISTERS[v][d][r][0].fields:
                                        fld = [field]
                                    else:
                                        fld = []
                                for f in fld:
                                    ret.append(f'{v}.{d}.{r}.{f}')
        return ret

    # def has_all_fields(self, reg_name: str, field_list: List[str]) -> bool:
    #     """Checks if the register as all fields specified in list"""
    #     ret = True
    #     for field in field_list:
    #         ret = ret and self.has_field(reg_name, field)
    #         if not ret:
    #             break
    #     return ret

    # def is_msr(self, reg_name: str) -> bool:
    #     """Returns True if register is type `msr`"""
    #     if self.is_defined(reg_name):
    #         if self.cs.Cfg.REGISTERS[reg_name]['type'].lower() == 'msr':
    #             return True
    #     return False

    # def is_pci(self, reg_name: str) -> bool:
    #     """Returns True if register is type `pcicfg` or `mmcfg`"""
    #     if self.is_defined(reg_name):
    #         reg_def = self.cs.Cfg.REGISTERS[reg_name]
    #         if (reg_def['type'].lower() == 'pcicfg') or (reg_def['type'].lower() == 'mmcfg'):
    #             return True
    #     return False

    # def is_all_ffs(self, reg_name: str, value: int) -> bool:
    #     """Returns True if register value is all 0xFFs"""
    #     if self.is_msr(reg_name):
    #         size = 8
    #     else:
    #         size = self.get_def(reg_name)['size']
    #     return is_all_ones(value, size)

    # def is_field_all_ones(self, reg_name: str, field_name: str, value: int) -> bool:
    #     """Returns True if field value is all ones"""
    #     reg_def = self.get_def(reg_name)
    #     size = reg_def['FIELDS'][field_name]['size']
    #     return is_all_ones(value, size, 1)


class BaseConfigRegisterHelper(BaseConfigHelper):
    def __init__(self, cfg_obj):
        super(BaseConfigRegisterHelper, self).__init__(cfg_obj)
        self.name = cfg_obj['name']
        self.instance = cfg_obj['instance'] if 'instance' in cfg_obj else None
        self.value = None
        self.desc = cfg_obj['desc']
        if 'default' in cfg_obj:
            self.default = cfg_obj['default']
        else:
            self.default = None
        self.fields = cfg_obj['FIELDS']

    def read(self) -> int:
        """Read the object"""
        raise NotImplementedError()

    def write(self, value: int):
        """Write the object"""
        raise NotImplementedError()
    
    def print(self) -> None:
        self.logger.log(str(self))
    
    def __str__(self) -> str:
        return f'{self.name}: {self.value}'

    def print(self) -> None:
        self.logger.log(str(self))

    def __str__(self) -> str:
        return f'{self.name}: {self.value}'

    def set_value(self, value: int) -> None:
        self.value = value

    def set_field(self, field_name: str, field_value: int) -> int:
        field_attrs = self.fields[field_name]
        bit = field_attrs['bit']
        size = field_attrs['size']
        self.value = set_bits(bit, size, self.value, field_value)
        return self.value

    def get_field(self, field_name: str, preserve_field_position: Optional[bool] = False) -> int:
        if self.value is None:
            self.read()
        field_attrs = self.fields[field_name]
        field_bit = field_attrs['bit']
        field_size = field_attrs['size']
        return get_bits(self.value, field_bit, field_size, preserve_field_position)

    def has_field(self, field_name: str) -> bool:
        return self.fields.get(field_name, None) is not None

    def get_mask(self) -> int:
        mask = make_mask(self.size * 8)
        return mask

    def get_field_mask(self, reg_field: str, preserve_field_position: Optional[bool] = False) -> int:
        field_attrs = self.fields[reg_field]
        mask_start = 0
        size = field_attrs['size']
        if preserve_field_position:
            mask_start = field_attrs['bit']
        mask = make_mask(size, mask_start)
        return mask

    def write_field(self, field_name: str, field_value: int, update_value: bool = False) -> None:
        if update_value:
            self.read()
        if self.value is None:
            raise UninitializedRegisterError()
        new_value = self.set_field(field_name, field_value)
        self.write(new_value)

    def read_field(self, field_name: str, preserve_field_position: Optional[bool] = False) -> int:
        self.read()
        return self.get_field(field_name, preserve_field_position)

    def _register_fields_str(self, verbose: bool = False) -> str:
        reg_fields_str = ''
        if self.fields:
            reg_fields_str += '\n'
            # sort fields by their bit position in the register
            sorted_fields = sorted(self.fields.items(), key=lambda field: field[1]['bit'])
            for f in sorted_fields:
                field_attrs = f[1]
                field_bit = field_attrs['bit']
                field_size = field_attrs['size']
                field_mask = 0
                for _ in range(field_size):
                    field_mask = (field_mask << 1) | 1
                field_desc = (' << ' + field_attrs['desc'] + ' ') if (field_attrs['desc'] != '') else ''
                field_default = f'(default: {field_attrs["default"]})' if 'default' in field_attrs and verbose else ''
                field_access = f'(access: {field_attrs["access"]})' if 'access' in field_attrs and verbose else ''
                if self.value is not None:
                    field_value = (self.value >> field_bit) & field_mask
                    reg_fields_str += (f'    [{field_bit:02d}] {f[0]:16} = {field_value:X}{field_access}{field_default}{field_desc}\n')

        if '' != reg_fields_str:
            reg_fields_str = reg_fields_str[:-1]
        return reg_fields_str


class ObjList(list):
    def __init__(self, iterable: list = []):
        super().__init__(iterable)

    def read(self) -> List[int]:
        ret = []
        for inst in self:
            try:
                ret.append(inst.read())
            except CSReadError as err:
                logger().log_debug(f"Error reading instance: {err}")
        return ret
    
    def read_and_print(self):
        self.read()
        self.print()
    
    def read_and_verbose_print(self):
        self.read()
        if logger().VERBOSE:
            self.print()

    def read_field(self, field: str) -> List[int]:
        ret = []
        for inst in self:
            ret.append(inst.read_field(field))
        return ret

    def write(self, value: int) -> None:
        for inst in self:
            inst.write(value)

    def write_field(self, field: str, value: int) -> None:
        for inst in self:
            inst.write_field(field, value)

    def print(self) -> None:
        for inst in self:
            logger().log(inst)

    def is_all_value(self, value: int, mask: Optional[int] = None) -> bool:
        if mask is None:
            return all(inst.value == value for inst in self)
        return all((inst.value & mask) == value for inst in self)

    def is_any_value(self, value: int, mask: Optional[int] = None) -> bool:
        if mask is None:
            return any(inst.value == value for inst in self)
        return any((inst.value & mask) == value for inst in self)

    def is_all_field_value(self, value: int, field: str) -> bool:
        return all(inst.get_field(field) == value for inst in self)

    def is_any_field_value(self, value: int, field: str) -> bool:
        return any(inst.get_field(field) == value for inst in self)


class RegData(object):
    def __init__(self, value, instance):
        self.__value = value
        self.__instance = instance

    @property
    def value(self):
        return self.__value

    @property
    def instance(self):
        return self.__instance

    @value.setter
    def newvalue(self, value):
        self.__value = value
