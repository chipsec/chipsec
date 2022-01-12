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
#
# Contact information:
# chipsec@intel.com
#

from collections import namedtuple
import os
import re
from chipsec.logger import logger
import xml.etree.ElementTree as ET
from chipsec.file import get_main_dir
from chipsec.exceptions import CSConfigError, DeviceNotFoundError

scope_name = namedtuple("scope_name", ["vid", "parent", "name", "fields"], defaults=(None, None, None, None))


class Cfg:
    def __init__(self):
        self.BUS = {}
        self.parent_keys = ["CONFIG_PCI", "MEMORY_RANGES", "MM_MSGBUS", "MSGBUS", "IO", "MSR"]
        self.child_keys = ["MMIO_BARS", "IO_BARS", "IMA_REGISTERS", "REGISTERS", "CONTROLS", "LOCKS", "LOCKEDBY"]
        for key in self.parent_keys + self.child_keys:
            setattr(self, key, {})

    def _get_vid_from_filename(self, fname):
        search_string = re.compile(r'cfg.[0-9a-fA-F]+')
        match = search_string.search(fname)
        vid = match.group(0)[4:]
        return vid

    def _create_vid(self, vid):
        if vid not in self.CONFIG_PCI.keys():
            self.CONFIG_PCI[vid] = {}
            self.CONTROLS[vid] = {}
            self.IMA_REGISTERS[vid] = {}
            self.IO[vid] = {}
            self.IO_BARS[vid] = {}
            self.LOCKS[vid] = {}
            self.LOCKEDBY[vid] = {}
            self.MEMORY_RANGES[vid] = {}
            self.MMIO_BARS[vid] = {}
            self.MSGBUS[vid] = {}
            self.MM_MSGBUS[vid] = {}
            self.REGISTERS[vid] = {}
            self.scope = {None: ''}
            if vid not in self.BUS.keys():
                self.BUS[vid] = {}

    def _update_bus_name(self, xml, vid):
        if "did" in xml.attrib.keys():
            for dv in list(xml.attrib['did'].split(',')):
                if dv[-1].upper() == 'X':
                    rdv = int(dv[:-1], 16) << 4   #  Assume valid hex value with last nibble removed
                    for rdv_value in range(rdv, rdv + 0x10):
                        if rdv_value in self.BUS[vid].keys():
                            self.BUS[vid][xml.attrib['name']] = self.BUS[vid].pop(rdv_value)
                elif '-' in dv:
                    rdv = dv.split('-')
                    for rdv_value in range(int(rdv[0], 16), int(rdv[1], 16) + 1):  #  Assume valid hex values
                        if rdv_value in self.BUS[vid].keys():
                            self.BUS[vid][xml.attrib['name']] = self.BUS[vid].pop(rdv_value)
                else:
                    if dv in self.BUS[vid].keys():
                        self.BUS[vid][xml.attrib['name']] = self.BUS[vid].pop(dv)
        else:
            if "bus" in xml.attrib.keys():
                self.BUS[vid][xml.attrib['name']] = [int(xml.attrib['bus'], 16)]

    def init_cfg_xml(self, fxml, code, pch_code):
        if not os.path.exists(fxml):
            if logger().DEBUG:
                logger().log("[*] Invalid File: '{}'..".format(fxml))
            return
        if logger().DEBUG:
            logger().log("[*] loading platform config from '{}'..".format(fxml))
        vid = self._get_vid_from_filename(fxml)
        self._create_vid(vid)
        try:
            tree = ET.parse(fxml)
        except ET.ParseError as pe:
            logger().log("[*] parser error within '{}'\n{}".format(fxml, pe))
        root = tree.getroot()
        for _cfg in root.iter('configuration'):
            if logger().DEBUG:
                logger().log("[*] loading integrated devices/controllers..")
            for _pci in _cfg.iter('pci'):
                for _device in _pci.iter('device'):
                    self._update_bus_name(_device, vid)
                    _name = _device.attrib['name']
                    del _device.attrib['name']
                    if _name not in self.CONFIG_PCI[vid].keys():
                        self.CONFIG_PCI[vid][_name] = _device.attrib
                        self.MMIO_BARS[vid][_name] = {}
                        self.IO_BARS[vid][_name] = {}
                        self.REGISTERS[vid][_name] = {}
                    else:
                        self.CONFIG_PCI[vid][_name] = _device.attrib  # may want to append opposed to overwrite also may raise error if b:d:f is different and not blank
                    if logger().DEBUG:
                        logger().log("    + {:16}: {}".format(_name, _device.attrib))
                    if 'config' in _device.attrib.keys():
                        self.load_cfg_xml(_device.attrib['config'], _name, vid)

            if logger().DEBUG:
                logger().log("[*] loading memory ranges..")
            for _memory in _cfg.iter('memory'):
                for _range in _memory.iter('range'):
                    _name = _range.attrib['name']
                    del _range.attrib['name']
                    if _name not in self.MEMORY_RANGES[vid].keys():
                        self.MEMORY_RANGES[vid][_name] = _range.attrib
                        self.REGISTERS[vid][_name] = {}
                    else:
                        self.MEMORY_RANGES[vid][_name] = _range.attrib  # may want to append opposed to overwrite
                    if logger().DEBUG:
                        logger().log("    + {:16}: {}".format(_name, _range.attrib))
                    if 'config' in _device.attrib.keys():
                        self.load_cfg_xml(_range.attrib['config'], _name, vid)

            if logger().DEBUG:
                logger().log("[*] loading mm_msgbus ports..")
            for _mm_msgbus in _cfg.iter('mm_msgbus'):
                for _device in _mm_msgbus.iter('definition'):
                    _name = _device.attrib['name']
                    del _device.attrib['name']
                    if _name not in self.MM_MSGBUS[vid].keys():
                        self.MM_MSGBUS[vid][_name] = _device.attrib
                        self.REGISTERS[vid][_name] = {}
                    else:
                        self.MM_MSGBUS[vid][_name] = _device.attrib  # may want to append opposed to overwrite
                    if logger().DEBUG:
                        logger().log("    + {:16}: {}".format(_name, _device.attrib))
                    if 'config' in _device.attrib.keys():
                        self.load_cfg_xml(_device.attrib['config'], _name, vid)

            if logger().DEBUG:
                logger().log("[*] loading msgbus ports..")
            for _msgbus in _cfg.iter('msgbus'):
                for _device in _msgbus.iter('definition'):
                    _name = _device.attrib['name']
                    del _device.attrib['name']
                    if _name not in self.MSGBUS[vid].keys():
                        self.MSGBUS[vid][_name] = _device.attrib
                        self.REGISTERS[vid][_name] = {}
                    else:
                        self.MSGBUS[vid][_name] = _device.attrib  # may want to append opposed to overwrite
                    if logger().DEBUG:
                        logger().log("    + {:16}: {}".format(_name, _device.attrib))
                    if 'config' in _device.attrib.keys():
                        self.load_cfg_xml(_device.attrib['config'], _name, vid)

            if logger().DEBUG:
                logger().log("[*] loading io ports..")
            for _io in _cfg.iter('io'):
                for _device in _io.iter('definition'):
                    _name = _device.attrib['name']
                    del _device.attrib['name']
                    if _name not in self.IO[vid].keys():
                        self.IO[vid][_name] = _device.attrib
                        self.REGISTERS[vid][_name] = {}
                    else:
                        self.IO[vid][_name] = _device.attrib  # may want to append opposed to overwrite
                    if logger().DEBUG:
                        logger().log("    + {:16}: {}".format(_name, _device.attrib))
                    if 'config' in _device.attrib.keys():
                        self.load_cfg_xml(_device.attrib['config'], _name, vid)

            if logger().DEBUG:
                logger().log("[*] loading model specific registers..")
            for _msr in _cfg.iter('msr'):
                for _definition in _msr.iter('definition'):
                    _name = _definition.attrib['name']
                    del _definition.attrib['name']
                    if _name not in self.REGISTERS[vid].keys():
                        self.REGISTERS[vid][_name] = {}
                    if logger().DEBUG:
                        logger().log("    + {:16}: {}".format(_name, _definition.attrib))
                    if 'config' in _definition.attrib.keys():
                        self.load_cfg_xml(_definition.attrib['config'], _name, vid)

    def load_cfg_xml(self, path, name, vid):
        if len(path.split('.')) != 3 and path.endswith('.xml'):
            return
        fxml = os.path.join(get_main_dir(), 'chipsec/cfg', vid, path.split('.')[0], path.split('.', 1)[1])
        if not os.path.exists(fxml):
            return
        tree = ET.parse(fxml)
        root = tree.getroot()
        for _cfg in root.iter('configuration'):
            if logger().DEBUG:
                logger().log("[*] loading MMIO BARs..")
            for _mmio in _cfg.iter('mmio'):
                for _bar in _mmio.iter('bar'):
                    _name = _bar.attrib['name']
                    del _bar.attrib['name']
                    _bar.attrib['register'] = "{}.{}.{}".format(vid, name, _bar.attrib['register'])
                    if _name not in self.MMIO_BARS[vid][name].keys():
                        self.MMIO_BARS[vid][name][_name] = _bar.attrib
                    else:
                        self.MMIO_BARS[vid][name][_name] = _bar.attrib  # may want to append opposed to overwrite
                    if logger().DEBUG:
                        logger().log("    + {:16}: {}".format(_name, _bar.attrib))

            if logger().DEBUG:
                logger().log("[*] loading I/O BARs..")
            for _io in _cfg.iter('io'):
                for _bar in _io.iter('bar'):
                    _name = _bar.attrib['name']
                    _bar.attrib['register'] = "{}.{}.{}".format(vid, name, _bar.attrib['register'])
                    del _bar.attrib['name']
                    if _name not in self.IO_BARS[vid][name].keys():
                        self.IO_BARS[vid][name][_name] = _bar.attrib
                    else:
                        self.IO_BARS[vid][name][_name] = _bar.attrib
                    if logger().DEBUG:
                        logger().log("    + {:16}: {}".format(_name, _bar.attrib))

            if logger().DEBUG:
                logger().log("[*] loading indirect memory accesses definitions..")
            for _indirect in _cfg.iter('indirect'):
                for _ima in _indirect.iter('ima'):
                    _name = _ima.attrib['name']
                    _ima.attrib['index'] = "{}.{}.{}".format(vid, name, _ima.attrib['index'])
                    _ima.attrib['data'] = "{}.{}.{}".format(vid, name, _ima.attrib['data'])
                    del _ima.attrib['name']
                    self.IMA_REGISTERS[vid][name][_name] = _ima.attrib
                    if logger().DEBUG:
                        logger().log("    + {:16}: {}".format(_name, _ima.attrib))

            if logger().DEBUG:
                logger().log("[*] loading configuration registers..")
            for _registers in _cfg.iter('registers'):
                for _register in _registers.iter('register'):
                    _name = _register.attrib['name']
                    if 'desc' not in _register.attrib:
                        _register.attrib['desc'] = _name
                    del _register.attrib['name']
                    if _register.attrib['type'] in ['pcicfg', 'mmcfg', 'mm_msg_bus']:
                        _register.attrib['device'] = name
                    elif _register.attrib['type'] in ['memory']:
                        _register.attrib['range'] = name
                    elif _register.attrib['type'] in ['mmio']:
                        _register.attrib['bar'] = "{}.{}.{}".format(vid, name, _register.attrib['bar'])
                    if _name in self.REGISTERS[vid][name]:
                        reg_fields = self.REGISTERS[vid][name][_name]['FIELDS']
                    else:
                        reg_fields = {}
                    if _register.find('field') is not None:
                        for _field in _register.iter('field'):
                            _field_name = _field.attrib['name']
                            if 'lockedby' in _field.attrib:
                                # lockedby supplied is a different device
                                if _field.attrib['lockedby'].count(".") == 3:
                                    _lockedby = _field.attrib['lockedby']
                                # lockedby is within the same device
                                elif _field.attrib['lockedby'].count(".") <= 1:
                                    _lockedby = "{}.{}.{}".format(vid, name, _field.attrib['lockedby'])
                                else:
                                    raise CSConfigError("Invalid LockedBy register {}".format(_field.attrib['lockedby']))
                                if _lockedby in self.LOCKEDBY[vid].keys():
                                    self.LOCKEDBY[vid][_lockedby].append((_name, _field_name))
                                else:
                                    self.LOCKEDBY[vid][_lockedby] = [(_name, _field_name)]
                            del _field.attrib['name']
                            if 'desc' not in _field.attrib:
                                _field.attrib['desc'] = _field_name
                            reg_fields[_field_name] = _field.attrib
                        _register.attrib['FIELDS'] = reg_fields
                    self.REGISTERS[vid][name][_name] = _register.attrib
                    if logger().DEBUG:
                        logger().log("    + {:16}: {}".format(_name, _register.attrib))

            if logger().DEBUG:
                logger().log("[*] loading controls..")
            for _controls in _cfg.iter('controls'):
                for _control in _controls.iter('control'):
                    _name = _control.attrib['name']
                    del _control.attrib['name']
                    _control.attrib['register'] = "{}.{}.{}".format(vid, name, _control.attrib['register'])
                    self.CONTROLS[_name] = _control.attrib
                    if logger().DEBUG:
                        logger().log("    + {:16}: {}".format(_name, _control.attrib))

            if logger().DEBUG:
                logger().log("[*] loading locks..")
            for _locks in _cfg.iter('locks'):
                for _lock in _locks.iter('lock'):
                    _lock.attrib['register'] = "{}.{}.{}".format(vid, name, _lock.attrib['register'])
                    # name is derived from register and field for consistency
                    if "field" in _lock.attrib:
                        _name = "{}.{}".format(_lock.attrib['register'], _lock.attrib['field'])
                    else:
                        _name = "{}".format(_lock.attrib['register'])
                    if "name" in _lock.attrib:
                        del _lock.attrib['name']
                    self.LOCKS[_name] = _lock.attrib
                    if logger().DEBUG:
                        logger().log("    + {:16}: {}".format(_name, _lock.attrib))

    #
    # Scoping functions
    #

    def set_scope(self, scope):
        self.scope.update(scope)

    def get_scope(self, name):
        if name.count('.') > 0:
            return ''
        elif name in self.scope.keys():
            return self.scope[name]
        else:
            return self.scope[None]

    def clear_scope(self):
        self.scope = {None: ''}

    def convert_internal_scope(self, scope, name):
        if scope:
            sname = scope + '.' + name
        else:
            sname = name
        return scope_name(*sname.split('.', 3))

    ##################################################################################
    #
    # Functions which access configuration of integrated PCI devices (interfaces, controllers)
    # by device name (defined in XML configuration files)
    #
    ##################################################################################

    def get_device_BDF(self, device_name):
        scope = self.get_scope(device_name)
        vid, device, _, _ = self.convert_internal_scope(scope, device_name)
        try:
            device = self.CONFIG_PCI[vid][device]
        except KeyError:
            device = None
        if device is None or device == {}:
            raise DeviceNotFoundError('DeviceNotFound: {}'.format(device_name))
        b = int(device['bus'], 16)
        d = int(device['dev'], 16)
        f = int(device['fun'], 16)
        return (b, d, f)

    def is_register_defined(self, reg_name):
        scope = self.get_scope(reg_name)
        vid, device, register, _ = self.convert_internal_scope(scope, reg_name)
        try:
            return (self.REGISTERS[vid][device].get(register, None) is not None)
        except KeyError:
            return False

    def is_device_defined(self, dev_name):
        scope = self.get_scope(dev_name)
        vid, device, _, _ = self.convert_internal_scope(scope, dev_name)
        if self.CONFIG_PCI[vid].get(device, None) is None:
            return False
        else:
            return True

    def get_mmio_def(self, bar_name):
        scope = self.get_scope(bar_name)
        vid, device, bar, _ = self.convert_internal_scope(scope, bar_name)
        if bar in self.MMIO_BARS[vid][device]:
            return self.MMIO_BARS[vid][device][bar]
        else:
            return None

    def get_io_def(self, bar_name):
        scope = self.get_scope(bar_name)
        vid, device, bar, _ = self.convert_internal_scope(scope, bar_name)
        if bar in self.IO_BARS[vid][device]:
            return self.IO_BARS[vid][device][bar]
        else:
            return None

    def get_register_def(self, reg_name, bus=0):
        scope = self.get_scope(reg_name)
        vid, dev_name, register, _ = self.convert_internal_scope(scope, reg_name)
        reg_def = self.REGISTERS[vid][dev_name][register]
        if "device" in reg_def:
            if reg_def["type"] in ["pcicfg", "mmcfg"]:
                dev = self.CONFIG_PCI[vid][dev_name]
                reg_def['bus'] = dev['bus']
                reg_def['dev'] = dev['dev']
                reg_def['fun'] = dev['fun']
                if dev_name in self.BUS:
                    if bus in self.BUS[vid][dev_name]:
                        reg_def['bus'] = bus
                    else:
                        logger().error("Bus {:d} for '{}' not found.".format(bus, dev_name))
            elif reg_def["type"] == "memory":
                dev = self.MEMORY_RANGES[vid][dev_name]
                reg_def['address'] = dev['address']
                reg_def['access'] = dev['access']
            elif reg_def["type"] == "mm_msgbus":
                dev = self.MM_MSGBUS[vid][dev_name]
                reg_def['port'] = dev['port']
            elif reg_def["type"] == "indirect":
                dev = self.IMA_REGISTERS[vid][dev_name]
                if ('base' in dev):
                    reg_def['base'] = dev['base']
                else:
                    reg_def['base'] = "0"
                if (dev['index'] in self.REGISTERS[vid][dev_name]):
                    reg_def['index'] = dev['index']
                else:
                    logger().error("Index register {} not found".format(dev['index']))
                if (dev['data'] in self.REGISTERS[vid][dev_name]):
                    reg_def['data'] = dev['data']
                else:
                    logger().error("Data register {} not found".format(dev['data']))
        return reg_def

    def get_register_bus(self, reg_name):
        bus = []
        scope = self.get_scope(reg_name)
        vid, device, _, _ = self.convert_internal_scope(scope, reg_name)
        return self.BUS[vid].get(device, bus)

    def get_device_bus(self, dev_name):
        bus = []
        scope = self.get_scope(dev_name)
        vid, device, _, _ = self.convert_internal_scope(scope, dev_name)
        return self.BUS[vid].get(dev_name, bus)

    def register_has_field(self, reg_name, field_name):
        scope = self.get_scope(reg_name)
        vid, device, register, _ = self.convert_internal_scope(scope, reg_name)
        try:
            reg_def = self.REGISTERS[vid][device][register]
        except KeyError:
            return False
        if 'FIELDS' not in reg_def:
            return False
        return (field_name in reg_def['FIELDS'])

    def get_control_def(self, control_name):
        return self.CONTROLS[control_name]

    def is_control_defined(self, control_name):
        return True if control_name in self.CONTROLS else False

    def is_lock_defined(self, lock_name):
        return lock_name in self.LOCKS.keys()

    def get_lock_desc(self, lock_name):
        return self.LOCKS[lock_name]['desc']

    def get_lock_type(self, lock_name):
        if 'type' in self.LOCKS[lock_name].keys():
            mtype = self.LOCKS[lock_name]['type']
        else:
            mtype = "RW/L"
        return mtype

    def get_lock_list(self):
        return self.LOCKS.keys()

    def get_lockedby(self, lock_name):
        if lock_name in self.LOCKEDBY.keys():
            return self.LOCKEDBY[lock_name]
        else:
            return None

    def get_IO_space(self, io_name):
        scope = self.get_scope(io_name)
        vid, device, io, _ = self.convert_internal_scope(io_name)
        if io in self.Cfg.IO_BARS[vid][device].keys():
            reg = self.Cfg.IO_BARS[io_name]["register"]
            bf = self.Cfg.IO_BARS[io_name]["base_field"]
            return (reg, bf)
        else:
            return (None, None)
