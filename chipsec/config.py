#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2021, Intel Corporation
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

import os
import re
from chipsec.logger import logger
import xml.etree.ElementTree as ET
from chipsec.file import get_main_dir
from chipsec.exceptions import CSConfigError


class Cfg:
    def __init__(self):
        self.BUS           = {}
        self.CONFIG_PCI    = {}
        self.CONTROLS      = {}
        self.IMA_REGISTERS = {}
        self.IO            = {}
        self.IO_BARS       = {}
        self.LOCKS         = {}
        self.LOCKEDBY      = {}
        self.MEMORY_RANGES = {}
        self.MMIO_BARS     = {}
        self.MSGBUS        = {}
        self.MM_MSGBUS     = {}
        self.REGISTERS     = {}
        self.XML_CONFIG_LOADED = False

    def _get_vid_from_filename(self, fname):
        search_string = re.compile(r'cfg.[0-9a-fA-F]+')
        match = search_string.search(fname)
        vid = match.group(0)[4:]
        return vid

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
            logger().log("[*] looking for platform config in '{}'..".format(fxml))
        vid = self._get_vid_from_filename(fxml)
        tree = ET.parse(fxml)
        root = tree.getroot()
        for _cfg in root.iter('configuration'):
            if 'platform' not in _cfg.attrib:
                if logger().DEBUG:
                    logger().log("[*] loading common platform config from '{}'..".format(fxml))
            elif code == _cfg.attrib['platform'].lower():
                if logger().DEBUG:
                    logger().log("[*] loading '{}' platform config from '{}'..".format(code, fxml))
                if 'req_pch' in _cfg.attrib:
                    if 'true' == _cfg.attrib['req_pch'].lower():
                        self.reqs_pch = True
            elif pch_code == _cfg.attrib['platform'].lower():
                if logger().DEBUG:
                    logger().log("[*] loading '{}' PCH config from '{}'..".format(pch_code, fxml))
            else: continue

            if logger().DEBUG:
                logger().log("[*] loading integrated devices/controllers..")
            for _pci in _cfg.iter('pci'):
                for _device in _pci.iter('device'):
                    self._update_bus_name(_device, vid)
                    _name = _device.attrib['name']
                    del _device.attrib['name']
                    _device.attrib['vid'] = vid
                    self.CONFIG_PCI[_name] = _device.attrib
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
                    self.MEMORY_RANGES[_name] = _range.attrib
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
                    self.MM_MSGBUS[_name] = _device.attrib
                    if logger().DEBUG: logger().log("    + {:16}: {}".format(_name, _device.attrib))
                    if 'config' in _device.attrib.keys():
                        self.load_cfg_xml(_device.attrib['config'], _name, vid)

            if logger().DEBUG:
                logger().log("[*] loading msgbus ports..")
            for _msgbus in _cfg.iter('msgbus'):
                for _device in _msgbus.iter('definition'):
                    _name = _device.attrib['name']
                    del _device.attrib['name']
                    self.MSGBUS[_name] = _device.attrib
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
                    self.IO[_name] = _device.attrib
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
                    _definition.attrib['vid'] = vid
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
                    _name = "{}.{}.{}".format(vid, name, _bar.attrib['name'])
                    _bar.attrib['register'] = "{}.{}.{}".format(vid, name, _bar.attrib['register'])
                    del _bar.attrib['name']
                    self.MMIO_BARS[_name] = _bar.attrib
                    if logger().DEBUG:
                        logger().log("    + {:16}: {}".format(_name, _bar.attrib))

            if logger().DEBUG:
                logger().log("[*] loading I/O BARs..")
            for _io in _cfg.iter('io'):
                for _bar in _io.iter('bar'):
                    _name = "{}.{}.{}".format(vid, name, _bar.attrib['name'])
                    _bar.attrib['register'] = "{}.{}.{}".format(vid, name, _bar.attrib['register'])
                    del _bar.attrib['name']
                    self.IO_BARS[_name] = _bar.attrib
                    if logger().DEBUG:
                        logger().log("    + {:16}: {}".format(_name, _bar.attrib))

            if logger().DEBUG:
                logger().log("[*] loading indirect memory accesses definitions..")
            for _indirect in _cfg.iter('indirect'):
                for _ima in _indirect.iter('ima'):
                    _name = "{}.{}.{}".format(vid, name, _ima.attrib['name'])
                    _ima.attrib['index'] = "{}.{}.{}".format(vid, name, _ima.attrib['index'])
                    _ima.attrib['data'] = "{}.{}.{}".format(vid, name, _ima.attrib['data'])
                    del _ima.attrib['name']
                    self.IMA_REGISTERS[_name] = _ima.attrib
                    if logger().DEBUG:
                        logger().log("    + {:16}: {}".format(_name, _ima.attrib))

            if logger().DEBUG:
                logger().log("[*] loading configuration registers..")
            for _registers in _cfg.iter('registers'):
                for _register in _registers.iter('register'):
                    _name = "{}.{}.{}".format(vid, name, _register.attrib['name'])
                    if 'desc' not in _register.attrib: _register.attrib['desc'] = _name
                    del _register.attrib['name']
                    if _register.attrib['type'] in ['pcicfg', 'mmcfg', 'mm_msg_bus']:
                        _register.attrib['device'] = name
                    elif _register.attrib['type'] in ['memory']:
                        _register.attrib['range'] = name
                    elif _register.attrib['type'] in ['mmio']:
                        _register.attrib['bar'] = "{}.{}.{}".format(vid, name, _register.attrib['bar'])
                    if _name in self.REGISTERS and 'FIELDS' in self.REGISTERS[_name]:
                        reg_fields = self.REGISTERS[_name]['FIELDS']
                    else:
                        reg_fields = {}
                    if _register.find('field') is not None:
                        for _field in _register.iter('field'):
                            _field_name = _field.attrib['name']
                            if 'lockedby' in _field.attrib:
                                if _field.attrib['lockedby'].count(".") == 3:
                                    _lockedby = _field.attrib['lockedby']
                                elif _field.attrib['lockedby'].count(".") <= 1:
                                    _lockedby = "{}.{}.{}".format(vid, name, _field.attrib['lockedby'])
                                else:
                                    raise CSConfigError("Invalid LockedBy register {}".format(_field.attrib['lockedby']))
                                if _lockedby in self.LOCKEDBY.keys():
                                    self.LOCKEDBY[_lockedby].append((_name, _field_name))
                                else:
                                    self.LOCKEDBY[_lockedby] = [(_name, _field_name)]
                            del _field.attrib['name']
                            if 'desc' not in _field.attrib: _field.attrib['desc'] = _field_name
                            reg_fields[_field_name] = _field.attrib
                        _register.attrib['FIELDS'] = reg_fields
                    self.REGISTERS[_name] = _register.attrib
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
                    if "name" in _lock.attrib: del _lock.attrib['name']
                    self.LOCKS[_name] = _lock.attrib
                    if logger().DEBUG:
                        logger().log("    + {:16}: {}".format(_name, _lock.attrib))
