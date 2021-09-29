#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2021, Intel Corporation
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
Contains platform identification functions
"""

import sys
import collections
import os
import fnmatch
import re
import xml.etree.ElementTree as ET

from chipsec.helper.oshelper import OsHelper, OsHelperError
from chipsec.hal import cpu, io, iobar, mmio, msgbus, msr, pci, physmem, ucode, igd
from chipsec.hal.pci import PCI_HDR_RID_OFF
from chipsec.exceptions import UnknownChipsetError, DeviceNotFoundError, CSReadError
from chipsec.exceptions import RegisterTypeNotFoundError

from chipsec.logger import logger
from chipsec.defines import is_hex

import chipsec.file

import importlib
import traceback

# DEBUG Flags
QUIET_PCI_ENUM = True
LOAD_COMMON = True
CONSISTENCY_CHECKING = False

class RegisterType:
    PCICFG    = 'pcicfg'
    MMCFG     = 'mmcfg'
    MMIO      = 'mmio'
    MSR       = 'msr'
    PORTIO    = 'io'
    IOBAR     = 'iobar'
    MSGBUS    = 'msgbus'
    MM_MSGBUS = 'mm_msgbus'
    MEMORY    = 'memory'

class Cfg:
    def __init__(self):
        self.CONFIG_PCI    = {}
        self.REGISTERS     = {}
        self.MMIO_BARS     = {}
        self.IO_BARS       = {}
        self.MEMORY_RANGES = {}
        self.CONTROLS      = {}
        self.BUS           = {}
        self.LOCKS         = {}
        self.LOCKEDBY      = {}
        self.XML_CONFIG_LOADED = False


##################################################################################
# Functionality defining current chipset
##################################################################################

CHIPSET_ID_UNKNOWN = 0

CHIPSET_CODE_UNKNOWN = ''

CHIPSET_FAMILY_XEON  = []
CHIPSET_FAMILY_CORE  = []
CHIPSET_FAMILY_ATOM  = []
CHIPSET_FAMILY_QUARK = []


PCH_CODE_PREFIX = 'PCH_'

try:
    from chipsec.custom_chipsets import *
except ImportError:
    pass


def f_xml(self, x):
    XMLFILE_RE = re.compile("^\w+\.xml")
    return ( x.find('common') == -1 and XMLFILE_RE.match(x) )
def map_xmlname(self, x):
    return x.split('.')[0]


class Chipset:

    def __init__(self, helper=None):
        if helper is None:
            self.helper = OsHelper()
        else:
            self.helper = helper

        self.init_xml_configuration()

        self.vid            = 0xFFFF
        self.did            = 0xFFFF
        self.rid            = 0xFF
        self.code           = CHIPSET_CODE_UNKNOWN
        self.longname       = "Unrecognized Platform"
        self.id             = CHIPSET_ID_UNKNOWN
        self.pch_vid        = 0xFFFF
        self.pch_did        = 0xFFFF
        self.pch_rid        = 0xFF
        self.pch_code       = CHIPSET_CODE_UNKNOWN
        self.pch_longname   = 'Unrecognized PCH'
        self.pch_id         = CHIPSET_ID_UNKNOWN
        self.Cfg        = Cfg()

        #
        # Initializing 'basic primitive' HAL components
        # (HAL components directly using native OS helper functionality)
        #
        self.pci        = pci.Pci(self)
        self.mem        = physmem.Memory(self)
        self.msr        = msr.Msr(self)
        self.ucode      = ucode.Ucode(self)
        self.io         = io.PortIO(self)
        self.cpu        = cpu.CPU(self)
        self.msgbus     = msgbus.MsgBus(self)
        self.mmio       = mmio.MMIO(self)
        self.iobar      = iobar.IOBAR(self)
        self.igd        = igd.IGD(self)
        #
        # All HAL components which use above 'basic primitive' HAL components
        # should be instantiated in modules/utilcmd with an instance of chipset
        # Examples:
        # - initializing SPI HAL component in a module or util extension:
        #   self.spi = SPI( self.cs )
        #

    ##################################################################################
    #
    # Initialization
    #
    ##################################################################################
    def detect_platform( self ):
        vid = 0xFFFF
        did = 0xFFFF
        rid = 0xFF
        pch_vid = 0xFFFF
        pch_did = 0xFFFF
        pch_rid = 0xFF
        try:
            vid_did = self.pci.read_dword(0, 0, 0, 0)
            vid = vid_did & 0xFFFF
            did = (vid_did >> 16) & 0xFFFF
            rid = self.pci.read_byte(0, 0, 0, PCI_HDR_RID_OFF)
        except:
            if logger().DEBUG: logger().error("pci.read_dword couldn't read platform VID/DID")
        try:
            vid_did = self.pci.read_dword(0, 31, 0, 0)
            pch_vid = vid_did & 0xFFFF
            pch_did = (vid_did >> 16) & 0xFFFF
            pch_rid = self.pci.read_byte(0, 31, 0, PCI_HDR_RID_OFF)
        except:
            if logger().DEBUG: logger().error("pci.read_dword couldn't read PCH VID/DID")
        return (vid, did, rid, pch_vid, pch_did, pch_rid)

    def get_cpuid(self):
            # Get processor version information
        (eax, ebx, ecx, edx) = self.cpu.cpuid(0x01, 0x00)
        stepping = eax & 0xF
        model = (eax >> 4) & 0xF
        extmodel = (eax >> 16) & 0xF
        family = (eax >> 8) & 0xF
        ptype = (eax >>12) & 0x3
        extfamily = (eax >> 20) & 0xFF
        ret = '{:01X}{:01X}{:01X}{:01X}{:01X}'.format(extmodel, ptype, family, model, stepping)
        if extfamily == 0:
            return ret
        else:
            return '{:02X}{}'.format(extfamily, ret)

    def init( self, platform_code, req_pch_code, start_driver, driver_exists=None, to_file=None, from_file=None ):
        _unknown_platform = False
        self.reqs_pch = False
        self.helper.start(start_driver, driver_exists, to_file, from_file)
        logger().log( '[CHIPSEC] API mode: {}'.format('using OS native API (not using CHIPSEC kernel module)' if self.use_native_api() else 'using CHIPSEC kernel module API') )

        vid, did, rid, pch_vid, pch_did, pch_rid = self.detect_platform()
        # get cpuid only if driver using driver (otherwise it will cause problems)
        if start_driver or self.helper.is_linux():
            cpuid = self.get_cpuid()
        else:
            cpuid = None

        #initialize chipset values to unknown
        _unknown_platform = True
        self.longname   = 'UnknownPlatform'
        self.vid = 0xFFFF
        self.did = 0xFFFF
        self.rid = 0xFF
        #initialize pch values to unknown/default
        _unknown_pch = True
        self.pch_longname = 'Default PCH'
        self.pch_vid = 0xFFFF
        self.pch_did = 0xFFFF
        self.pch_rid = 0xFF

        if platform_code is None:
        #platform code was not passed in try to determine based upon cpu id
            if vid in self.chipset_dictionary and did in self.chipset_dictionary[vid] and len(self.chipset_dictionary[vid][did]) > 1 and cpuid in self.detection_dictionary.keys():
                for item in self.chipset_dictionary[vid][did]:
                    if self.detection_dictionary[cpuid] == item['code']:
                        #matched processor with detection value
                        _unknown_platform = False
                        data_dict       = item
                        self.code       = data_dict['code'].upper()
                        self.longname   = data_dict['longname']
                        self.vid = vid
                        self.did = did
                        self.rid = rid
                        break
            elif vid in self.chipset_dictionary and did in self.chipset_dictionary[vid]:
                _unknown_platform = False
                data_dict       = self.chipset_dictionary[vid][ did ][0]
                self.code       = data_dict['code'].upper()
                self.longname   = data_dict['longname']
                self.vid = vid
                self.did = did
                self.rid = rid
            elif cpuid in self.detection_dictionary.keys():
                _unknown_platform = False
                self.code       = self.detection_dictionary[cpuid]
                self.longname   = self.detection_dictionary[cpuid]
                self.vid = vid
                self.did = did
                self.rid = rid

        elif platform_code in self.chipset_codes:
            # Check if platform code passed in is valid and override configuration
            _unknown_platform = False
            self.vid = self.chipset_codes[ platform_code ]['vid']
            self.did = self.chipset_codes[ platform_code ]['did']
            self.rid = 0x00
            self.code = platform_code
            self.longname = platform_code
            msg = 'Platform: Actual values: VID = 0x{:04X}, DID = 0x{:04X}, RID = 0x{:02X}'.format(vid, did, rid)
            if cpuid:
                msg += ', CPUID = 0x{}'.format(cpuid)
            logger().log("[CHIPSEC] {}".format(msg))

        if req_pch_code is not None:
            # Check if pch code passed in is valid
            if req_pch_code in self.pch_codes:
                self.pch_vid = self.pch_codes[req_pch_code]['vid']
                self.pch_did = self.pch_codes[req_pch_code]['did']
                self.pch_rid = 0x00
                self.pch_code = req_pch_code
                self.pch_longname = req_pch_code
                _unknown_pch = False
                msg = 'PCH     : Actual values: VID = 0x{:04X}, DID = 0x{:04X}, RID = 0x{:02X}'.format(pch_vid, pch_did, pch_rid)
                logger().log("[CHIPSEC] {}".format(msg))
        elif pch_vid in self.pch_dictionary.keys() and pch_did in self.pch_dictionary[pch_vid].keys():
            #Check if pch did for device 0:31:0 is in configuration
            self.pch_vid = pch_vid
            self.pch_did = pch_did
            self.pch_rid = pch_rid
            pch_list = self.pch_dictionary[self.pch_vid][self.pch_did]
            if len(pch_list) > 1:
                logger().log("[!]       Multiple PCHs contain the same DID. Using first in the list.")
            data_dict           = pch_list[0]
            self.pch_code       = data_dict['code']
            self.pch_longname   = data_dict['longname']
            _unknown_pch = False

        if _unknown_platform:
            msg = 'Unknown Platform: VID = 0x{:04X}, DID = 0x{:04X}, RID = 0x{:02X}'.format(vid, did, rid)
            if start_driver:
                logger().error(msg)
                raise UnknownChipsetError(msg)
            else:
                logger().log("[!]       {}; Using Default.".format(msg))
        if not _unknown_platform: # don't initialize config if platform is unknown
            self.init_cfg()
        if _unknown_pch:
            msg = 'Unknown PCH: VID = 0x{:04X}, DID = 0x{:04X}, RID = 0x{:02X}'.format(pch_vid, pch_did, pch_rid)
            if self.reqs_pch and start_driver:
                logger().error("Chipset requires a supported PCH to be loaded. {}".format(msg))
                raise UnknownChipsetError(msg)
            else:
                logger().log("[!]       {}; Using Default.".format(msg))
        if _unknown_pch or _unknown_platform:
            msg = 'Results from this system may be incorrect.'
            logger().log("[!]            {}".format(msg))

    def destroy( self, start_driver ):
        self.helper.stop( start_driver )

    def get_chipset_code(self):
        return self.code

    def get_pch_code(self):
        return self.pch_code

    def get_chipset_name(self, id):
        return self.longname

    def get_pch_name(self, id):
        return self.pch_longname

    def print_chipset(self):
        logger().log("[*] Platform: {}\n          VID: {:04X}\n          DID: {:04X}\n          RID: {:02X}".format(self.longname, self.vid, self.did, self.rid))

    def print_pch(self):
        logger().log("[*] PCH     : {}\n          VID: {:04X}\n          DID: {:04X}\n          RID: {:02X}".format(self.pch_longname, self.pch_vid, self.pch_did, self.pch_rid))

    def is_core(self):
        return  self.get_chipset_code() in CHIPSET_FAMILY_CORE

    def is_server(self):
        return  self.get_chipset_code() in CHIPSET_FAMILY_XEON

    def is_atom(self):
        return self.get_chipset_code() in CHIPSET_FAMILY_ATOM

    def use_native_api(self):
        return self.helper.use_native_api()

    def print_supported_chipsets(self):
        logger().log( "\nSupported platforms:\n" )
        logger().log( "VID     | DID     | Name           | Code   | Long Name" )
        logger().log( "-------------------------------------------------------------------------------------" )
        for _vid in sorted(self.chipset_dictionary.keys()):
            for _did in sorted(self.chipset_dictionary[_vid]):
                for item in self.chipset_dictionary[_vid][_did]:
                    logger().log( " {:-#06x} | {:-#06x} | {:14} | {:6} | {:40}".format(_vid, _did, item['name'], item['code'].lower(), item['longname']) )

    ##################################################################################
    #
    # Loading platform configuration from XML files in chipsec/cfg/
    #
    ##################################################################################

    def init_xml_configuration(self):
        # CAVEAT: this method may be called before command-line flags have been
        # parsed. In that case, logger().DEBUG will be False even if `-d` is
        # used. Switch it to True in logger.py directly if you need to debug
        # this function.
        self.pch_dictionary = dict()
        self.chipset_dictionary = dict()
        self.device_dictionary = dict()
        self.chipset_codes = {}
        self.pch_codes = {}
        self.device_code = []
        self.load_list = []
        self.detection_dictionary = dict()

        # find VID
        _cfg_path = os.path.join( chipsec.file.get_main_dir(), 'chipsec', 'cfg' )
        VID = [f for f in os.listdir(_cfg_path) if os.path.isdir(os.path.join(_cfg_path, f)) and is_hex(f) ]
        # create dictionaries
        for vid in VID:
            self.chipset_dictionary[int(vid, 16)] = collections.defaultdict(list)
            self.pch_dictionary[int(vid, 16)] = collections.defaultdict(list)
            self.device_dictionary[int(vid, 16)] = collections.defaultdict(list)
            for fxml in os.listdir(os.path.join(_cfg_path, vid)):
                if logger().DEBUG: logger().log( "[*] looking for platform config in '{}'..".format(fxml) )
                tree = ET.parse( os.path.join(_cfg_path, vid, fxml) )
                root = tree.getroot()
                for _cfg in root.iter('configuration'):
                    if 'platform' not in _cfg.attrib:
                        if logger().DEBUG: logger().log( "[*] found common platform config '{}'..".format(fxml) )
                        self.load_list.append(fxml)
                        continue
                    elif _cfg.attrib['platform'].lower().startswith('pch'):
                        if logger().DEBUG: logger().log( "[*] found PCH config at '{}'..".format(fxml) )
                        if not _cfg.attrib['platform'].upper() in self.pch_codes.keys():
                            self.pch_codes[_cfg.attrib['platform'].upper()] = {}
                            self.pch_codes[_cfg.attrib['platform'].upper()]['vid'] = int(vid, 16)
                        mdict = self.pch_dictionary[int(vid, 16)]
                        cdict = self.pch_codes[_cfg.attrib['platform'].upper()]
                    elif _cfg.attrib['platform'].upper():
                        if logger().DEBUG: logger().log("[*] found platform config from '{}'..".format(fxml))
                        if not _cfg.attrib['platform'].upper() in self.chipset_codes.keys():
                            self.chipset_codes[_cfg.attrib['platform'].upper()] = {}
                            self.chipset_codes[_cfg.attrib['platform'].upper()]['vid'] = int(vid, 16)
                        mdict = self.chipset_dictionary[int(vid, 16)]
                        cdict = self.chipset_codes[_cfg.attrib['platform'].upper()]
                    else:
                        continue
                    if logger().DEBUG: logger().log( "[*] Populating configuration dictionary.." )
                    for _info in _cfg.iter('info'):
                        if 'family' in _info.attrib:
                            if _info.attrib['family'].lower() == "core":
                                CHIPSET_FAMILY_CORE.append(_cfg.attrib['platform'].upper())
                            if _info.attrib['family'].lower() == "atom":
                                CHIPSET_FAMILY_ATOM.append(_cfg.attrib['platform'].upper())
                            if _info.attrib['family'].lower() == "xeon":
                                CHIPSET_FAMILY_XEON.append(_cfg.attrib['platform'].upper())
                            if _info.attrib['family'].lower() == "quark":
                                CHIPSET_FAMILY_QUARK.append(_cfg.attrib['platform'].upper())
                        if 'detection_value' in _info.attrib:
                            for dv in list(_info.attrib['detection_value'].split(',')):
                                if dv[-1].upper() == 'X':
                                    rdv = int(dv[:-1], 16) << 4   #  Assume valid hex value with last nibble removed
                                    for rdv_value in range( rdv, rdv+0x10 ):
                                        self.detection_dictionary[format(rdv_value,'X')] = _cfg.attrib['platform'].upper()
                                elif '-' in dv:
                                    rdv = dv.split('-')
                                    for rdv_value in range( int(rdv[0],16), int(rdv[1],16)+1 ): #  Assume valid hex values
                                        self.detection_dictionary[format(rdv_value,'X')] = _cfg.attrib['platform'].upper()
                                else:
                                    self.detection_dictionary[dv.strip().upper()] = _cfg.attrib['platform'].upper()
                        if _info.iter('sku'):
                            _det = ""
                            _did = ""
                            for _sku in _info.iter('sku'):
                                _did = int(_sku.attrib['did'], 16)
                                del _sku.attrib['did']
                                mdict[_did].append(_sku.attrib)
                                if "detection_value" in _sku.attrib.keys():
                                    _det = _sku.attrib['detection_value']
                            if _did == "":
                                if logger().DEBUG:
                                    logger().warn("No SKU found in configuration")
                            cdict['did'] = _did
                            cdict['detection_value'] = _det
            for cc in self.chipset_codes:
                globals()["CHIPSET_CODE_{}".format(cc.upper())] = cc.upper()
            for pc in self.pch_codes:
                globals()["PCH_CODE_{}".format(pc[4:].upper())] = pc.upper()


    def load_xml_configuration( self ):
        # Create a sorted config file list (xml only)
        _cfg_files = []
        _cfg_path = os.path.join( chipsec.file.get_main_dir(), 'chipsec/cfg' )
        for root, subdirs, files in os.walk(_cfg_path):
            _cfg_files.extend([os.path.join(root, x) for x in files if fnmatch.fnmatch(x, '*.xml')])
        _cfg_files.sort()
        if logger().DEBUG:
            logger().log("[*] Configuration Files:")
            for _xml in _cfg_files:
                logger().log("[*] - {}".format(_xml))

        # Locate common (chipsec/cfg/common*.xml) configuration XML files.
        loaded_files = []
        if LOAD_COMMON:
            for _xml in _cfg_files:
                if fnmatch.fnmatch(os.path.basename(_xml), 'common*.xml'):
                    loaded_files.append(_xml)

        # Locate configuration files from all other XML files recursively (if any) excluding other platform configuration files.
            platform_files = []
            for plat in [c.lower() for c in self.chipset_codes]:
                platform_files.extend([x for x in _cfg_files if fnmatch.fnmatch(os.path.basename(x), '{}*.xml'.format(plat)) or os.path.basename(x).startswith(PCH_CODE_PREFIX.lower())])
            loaded_files.extend([x for x in _cfg_files if x not in loaded_files and x not in platform_files])

        # Locate platform specific (chipsec/cfg/<code>*.xml) configuration XML files.
        if self.code and CHIPSET_CODE_UNKNOWN != self.code:
            for _xml in _cfg_files:
                if fnmatch.fnmatch(os.path.basename(_xml), '{}*.xml'.format(self.code.lower())):
                    loaded_files.append(_xml)

        # Locate PCH specific (chipsec/cfg/pch_<code>*.xml) configuration XML files.
        if self.pch_code and CHIPSET_CODE_UNKNOWN != self.pch_code:
            for _xml in _cfg_files:
                if fnmatch.fnmatch(os.path.basename(_xml), '{}*.xml'.format(self.pch_code.lower())):
                    loaded_files.append(_xml)

        # Load all configuration files for this platform.
        if logger().DEBUG: logger().log("[*] Loading Configuration Files:")
        for _xml in loaded_files:
            self.init_cfg_xml(_xml, self.code.lower(), self.pch_code.lower())

        # Load Bus numbers for this platform.
        if logger().DEBUG: logger().log("[*] Discovering Bus Configuration:")
        self.init_cfg_bus()

        self.Cfg.XML_CONFIG_LOADED = True


    def init_cfg_xml(self, fxml, code, pch_code):
        if not os.path.exists( fxml ): return
        if logger().DEBUG: logger().log( "[*] looking for platform config in '{}'..".format(fxml) )
        tree = ET.parse( fxml )
        root = tree.getroot()
        for _cfg in root.iter('configuration'):
            if 'platform' not in _cfg.attrib:
                if logger().DEBUG: logger().log( "[*] loading common platform config from '{}'..".format(fxml) )
            elif code == _cfg.attrib['platform'].lower():
                if logger().DEBUG: logger().log( "[*] loading '{}' platform config from '{}'..".format(code, fxml) )
                if 'req_pch' in _cfg.attrib:
                    if 'true' == _cfg.attrib['req_pch'].lower():
                        self.reqs_pch = True
            elif pch_code == _cfg.attrib['platform'].lower():
                if logger().DEBUG: logger().log("[*] loading '{}' PCH config from '{}'..".format(pch_code, fxml))
            else: continue

            if logger().DEBUG: logger().log( "[*] loading integrated devices/controllers.." )
            for _pci in _cfg.iter('pci'):
                for _device in _pci.iter('device'):
                    _name = _device.attrib['name']
                    del _device.attrib['name']
                    if 'undef' in _device.attrib:
                        if _name in self.Cfg.CONFIG_PCI:
                            if logger().DEBUG: logger().log("    - {:16}: {}".format(_name, _device.attrib['undef']))
                            self.Cfg.CONFIG_PCI.pop(_name, None)
                        continue
                    self.Cfg.CONFIG_PCI[ _name ] = _device.attrib
                    if logger().DEBUG: logger().log( "    + {:16}: {}".format(_name, _device.attrib) )
            if logger().DEBUG: logger().log( "[*] loading MMIO BARs.." )
            for _mmio in _cfg.iter('mmio'):
                for _bar in _mmio.iter('bar'):
                    _name = _bar.attrib['name']
                    del _bar.attrib['name']
                    if 'undef' in _bar.attrib:
                        if _name in self.Cfg.MMIO_BARS:
                            if logger().DEBUG: logger().log("    - {:16}: {}".format(_name, _bar.attrib['undef']))
                            self.Cfg.MMIO_BARS.pop(_name, None)
                        continue
                    self.Cfg.MMIO_BARS[ _name ] = _bar.attrib
                    if logger().DEBUG: logger().log( "    + {:16}: {}".format(_name, _bar.attrib) )
            if logger().DEBUG: logger().log( "[*] loading I/O BARs.." )
            for _io in _cfg.iter('io'):
                for _bar in _io.iter('bar'):
                    _name = _bar.attrib['name']
                    del _bar.attrib['name']
                    if 'undef' in _bar.attrib:
                        if _name in self.Cfg.IO_BARS:
                            if logger().DEBUG: logger().log("    - {:16}: {}".format(_name, _bar.attrib['undef']))
                            self.Cfg.IO_BARS.pop(_name, None)
                        continue
                    self.Cfg.IO_BARS[ _name ] = _bar.attrib
                    if logger().DEBUG: logger().log( "    + {:16}: {}".format(_name, _bar.attrib) )
            if logger().DEBUG: logger().log( "[*] loading memory ranges.." )
            for _memory in _cfg.iter('memory'):
                for _range in _memory.iter('range'):
                    _name = _range.attrib['name']
                    del _range.attrib['name']
                    if 'undef' in _range.attrib:
                        if _name in self.Cfg.MEMORY_RANGES:
                            if logger().DEBUG: logger().log("    - {:16}: {}".format(_name, _range.attrib['undef']))
                            self.Cfg.MEMORY_RANGES.pop(_name, None)
                        continue
                    self.Cfg.MEMORY_RANGES[ _name ] = _range.attrib
                    if logger().DEBUG: logger().log( "    + {:16}: {}".format(_name, _range.attrib) )
            if logger().DEBUG: logger().log( "[*] loading configuration registers.." )
            for _registers in _cfg.iter('registers'):
                for _register in _registers.iter('register'):
                    _name = _register.attrib['name']
                    del _register.attrib['name']
                    if 'undef' in _register.attrib:
                        if _name in self.Cfg.REGISTERS:
                            if logger().DEBUG: logger().log("    - {:16}: {}".format(_name, _register.attrib['undef']))
                            self.Cfg.REGISTERS.pop(_name, None)
                        continue
                    if 'size' not in _register.attrib: _register.attrib['size'] = "0x4"
                    if 'desc' not in _register.attrib: _register.attrib['desc'] = ''
                    reg_fields = {}
                    if _register.find('field') is not None:
                        for _field in _register.iter('field'):
                            _field_name = _field.attrib['name']
                            if 'lockedby' in _field.attrib:
                                _lockedby = _field.attrib['lockedby']
                                if _lockedby in self.Cfg.LOCKEDBY.keys():
                                    self.Cfg.LOCKEDBY[_lockedby].append((_name, _field_name))
                                else:
                                    self.Cfg.LOCKEDBY[_lockedby] = [(_name, _field_name)]
                            del _field.attrib['name']
                            if 'desc' not in _field.attrib: _field.attrib['desc'] = ''
                            reg_fields[ _field_name ] = _field.attrib
                        _register.attrib['FIELDS'] = reg_fields
                    self.Cfg.REGISTERS[ _name ] = _register.attrib
                    if logger().DEBUG: logger().log( "    + {:16}: {}".format(_name, _register.attrib) )
            if logger().DEBUG: logger().log( "[*] loading controls.." )
            for _controls in _cfg.iter('controls'):
                for _control in _controls.iter('control'):
                    _name = _control.attrib['name']
                    del _control.attrib['name']
                    if 'undef' in _control.attrib:
                        if _name in self.Cfg.CONTROLS:
                            if logger().DEBUG: logger().log("    - {:16}: {}".format(_name, _control.attrib['undef']))
                            self.Cfg.CONTROLS.pop(_name, None)
                        continue
                    self.Cfg.CONTROLS[ _name ] = _control.attrib
                    if logger().DEBUG: logger().log( "    + {:16}: {}".format(_name, _control.attrib) )
            if logger().DEBUG: logger().log("[*] loading locks..")
            for _locks in _cfg.iter('locks'):
                for _lock in _locks.iter('lock'):
                    _name = _lock.attrib['name']
                    del _lock.attrib['name']
                    if 'undef' in _lock.attrib:
                        if _name in self.Cfg.LOCKS:
                            if logger().DEBUG: logger().log("    - {:16}: {}".format(_name, _control.attrib['undef']))
                            self.Cfg.LOCKS.pop(_name, None)
                        continue
                    self.Cfg.LOCKS[_name] = _lock.attrib
                    if logger().DEBUG: logger().log("    + {:16}: {}".format(_name, _lock.attrib))

    def init_cfg_bus( self ):
        if logger().DEBUG: logger().log( '[*] Loading device buses..' )
        if QUIET_PCI_ENUM:
            old_hal_state = logger().HAL
            logger().HAL = False
        try:
            enum_devices = self.pci.enumerate_devices()
        except:
            if logger().DEBUG: logger().log('[*] Unable to enumerate PCI devices.')
            enum_devices = []
        if QUIET_PCI_ENUM:
            logger().HAL = old_hal_state

        # store entries dev_fun_vid_did = [list of bus entries]
        for enum_dev in enum_devices:
            cfg_str = "{:0>2X}_{:0>2X}_{:04X}_{:04X}".format(*enum_dev[1:5])
            if cfg_str in self.Cfg.BUS.keys():
                self.Cfg.BUS[cfg_str].append(enum_dev[0])
            else:
                self.Cfg.BUS[cfg_str] = [enum_dev[0]]

        # convert entries with matching configuration file names
        for config_device in self.Cfg.CONFIG_PCI:
            device_data = self.Cfg.CONFIG_PCI[config_device]
            xml_vid  = device_data.get( 'vid', None )
            xml_did  = device_data.get( 'did', None )
            # if the vid and did are present within the configuration file attempt to replace generic name with configuration name
            if xml_vid and xml_did:
                did_list = []
                # gather list of device id: device id may have single entry, multiple entries, end in "X", or specified by a range "-"
                for tdid in xml_did.split(','):
                    if tdid[-1].upper() == "X":
                        tndid = int(tdid[:-1], 16) << 4
                        for rdv_value in range(tndid, tndid+0x10):
                            did_list.append(rdv_value)
                    elif '-' in tdid:
                        rdv = tdid.split('-')
                        for rdv_value in range(int(rdv[0], 16), int(rdv[1], 16) + 1):
                            did_list.append(rdv_value)
                    else:
                        did_list.append(int(tdid, 16))
                # If there is a match between the configuration entry and generic entry, replace the name with the configuration entry
                for tdid in did_list:
                    cfg_str = "{:0>2}_{:0>2}_{:s}_{:04X}".format(device_data['dev'][2:] if len(device_data['dev']) > 2 else device_data['dev'], device_data['fun'], device_data['vid'][2:], tdid)
                    if cfg_str in self.Cfg.BUS.keys():
                        self.Cfg.BUS[config_device] = self.Cfg.BUS.pop(cfg_str)
                        if logger().DEBUG: logger().log(' + {:16s}: VID 0x{:s} - DID 0x{:04X} -> Bus {:s}'.format(config_device, device_data['vid'][2:], tdid, ','.join('0x{:02X}'.format(i) for i in self.Cfg.BUS[config_device])))
                        break

    #
    # Load chipsec/cfg/<code>.py configuration file for platform <code>
    #
    def init_cfg(self):
        if self.code and '' != self.code:
            try:
                module_path = 'chipsec.cfg.' + self.code
                module = importlib.import_module( module_path )
                logger().log_good( "imported platform specific configuration: chipsec.cfg.{}".format(self.code) )
                self.Cfg = getattr( module, self.code )()
            except ImportError as msg:
                if logger().DEBUG: logger().log( "[*] Couldn't import chipsec.cfg.{}\n{}".format( self.code, str(msg) ) )

        #
        # Initialize platform configuration from XML files
        #
        try:
            self.load_xml_configuration()
        except:
            if logger().DEBUG: logger().log_bad(traceback.format_exc())
            pass


    ##################################################################################
    #
    # Functions which access configuration of integrated PCI devices (interfaces, controllers)
    # by device name (defined in XML configuration files)
    #
    ##################################################################################

    def get_device_BDF( self, device_name ):
        device = self.Cfg.CONFIG_PCI[ device_name ]
        if device is None or device == {}: raise DeviceNotFoundError ('DeviceNotFound: {}'.format(device_name))
        b = int(device['bus'], 16)
        d = int(device['dev'], 16)
        f = int(device['fun'], 16)
        return (b, d, f)

    def get_DeviceVendorID( self, device_name ):
        (b, d, f) = self.get_device_BDF( device_name )
        return self.pci.get_DIDVID( b, d, f )

    def is_device_enabled( self, device_name ):
        if self.is_device_defined( device_name ):
            (b, d, f) = self.get_device_BDF( device_name )
            return self.pci.is_enabled( b, d, f )
        return False

    def is_register_device_enabled( self, reg_name, bus=None ):
        if reg_name in self.Cfg.REGISTERS:
            reg = self.get_register_def(reg_name)
            rtype = reg['type']
            if (rtype == RegisterType.MMCFG) or (rtype == RegisterType.PCICFG):
                if bus is not None:
                    b = bus
                else:
                    b = int(reg['bus'], 16)
                d = int(reg['dev'], 16)
                f = int(reg['fun'], 16)
                return self.pci.is_enabled( b, d, f )
            elif (rtype == RegisterType.MMIO):
                bar_name = reg['bar']
                return self.mmio.is_MMIO_BAR_enabled(bar_name, bus)
        return False

    def switch_device_def( self, target_dev, source_dev ):
        (b, d, f) = self.get_device_BDF( source_dev )
        self.Cfg.CONFIG_PCI[ target_dev ]['bus'] = str(b)
        self.Cfg.CONFIG_PCI[ target_dev ]['dev'] = str(d)
        self.Cfg.CONFIG_PCI[ target_dev ]['fun'] = str(f)

##################################################################################
#
# Main functionality to read/write configuration registers
# based on their XML configuration
#
# is_register_defined
#   checks if register is defined in the XML config
# is_device_defined
#   checks if device is defined in the XML config
# get_register_bus/get_device_bus
#   returns list of buses device/register was discovered on
# read_register/write_register
#   reads/writes configuration register (by name)
# read_register_all/write_register_all/write_register_all_single
#   reads/writes all configuration register instances (by name)
# get_register_field (set_register_field)
#   reads/writes the value of the field (by name) of configuration register (by register value)
# get_register_field_all (set_register_field_all)
#   reads/writes the value of the field (by name) of all configuration register instances (by register value)
# read_register_field (write_register_field)
#   reads/writes the value of the field (by name) of configuration register (by register name)
# read_register_field_all (write_register_field_all)
#   reads/writes the value of the field (by name) of all configuration register instances (by register name)
# register_has_field
#   checks if the register has specific field
# register_has_all_fields
#   Checks if the register as all fields specified in list
# print_register
#   prints configuration register
# print_register_all
#   prints all configuration register instances
# get_control/set_control
#   reads/writes some control field (by name)
# is_all_value
#   checks if all elements in a list equal a given value
# register_is_msr
#   Returns True if register is type 'msr'
# register_is_pci
#   Returns True if register is type 'pcicfg' or 'mmcfg'
#
##################################################################################


    def is_register_defined(self, reg_name):
        try:
            return (self.Cfg.REGISTERS[reg_name] is not None)
        except KeyError:
            return False

    def is_device_defined(self, dev_name):
        if self.Cfg.CONFIG_PCI.get( dev_name, None ) is None:
            return False
        else:
            return True

    def get_register_def(self, reg_name):
        reg_def = self.Cfg.REGISTERS[reg_name]
        if "device" in reg_def:
            dev_name = reg_def["device"]
            if reg_def["type"] == "pcicfg" or reg_def["type"] == "mmcfg":
                if dev_name in self.Cfg.CONFIG_PCI:
                    dev = self.Cfg.CONFIG_PCI[dev_name]
                    reg_def['bus'] = dev['bus']
                    reg_def['dev'] = dev['dev']
                    reg_def['fun'] = dev['fun']
            elif reg_def["type"] == "memory":
                if dev_name in self.Cfg.MEMORY_RANGES:
                    dev = self.Cfg.MEMORY_RANGES[dev_name]
                    reg_def['address'] = dev['address']
                    reg_def['access'] = dev['access']
                else:
                    logger().error("Memory device {} not found".format(dev_name))
        return reg_def

    def get_register_bus(self, reg_name):
        device = self.Cfg.REGISTERS[reg_name].get('device', '')
        if not device:
            if logger().DEBUG:
                logger().warn( "No device found for '{}'".format(reg_name) )
            if 'bus' in self.Cfg.REGISTERS[reg_name]:
                return [int(self.Cfg.REGISTERS[reg_name]['bus'], 16)]
            else:
                return None
        return self.get_device_bus(device)

    def get_device_bus(self, dev_name):
        return self.Cfg.BUS.get(dev_name, None)

    def read_register(self, reg_name, cpu_thread=0, bus=None, do_check=True):
        reg = self.get_register_def(reg_name)
        rtype = reg['type']
        reg_value = 0
        if RegisterType.PCICFG == rtype or RegisterType.MMCFG == rtype:
            if bus is not None:
                b = bus
            else:
                b = int(reg['bus'], 16)
            d = int(reg['dev'], 16)
            f = int(reg['fun'], 16)
            o = int(reg['offset'], 16)
            size = int(reg['size'], 16)
            if do_check and CONSISTENCY_CHECKING:
                if self.pci.get_DIDVID(b, d, f) == (0xFFFF, 0xFFFF):
                    raise CSReadError("PCI Device is not available ({}:{}.{})".format(b, d, f))
            if RegisterType.PCICFG == rtype:
                if   1 == size: reg_value = self.pci.read_byte ( b, d, f, o )
                elif 2 == size: reg_value = self.pci.read_word ( b, d, f, o )
                elif 4 == size: reg_value = self.pci.read_dword( b, d, f, o )
                elif 8 == size: reg_value = (self.pci.read_dword( b, d, f, o +4 ) << 32) | self.pci.read_dword(b, d, f, o)
            elif RegisterType.MMCFG == rtype:
                reg_value = self.mmio.read_mmcfg_reg(b, d, f, o, size)
        elif RegisterType.MMIO == rtype:
            _bus = bus
            if self.mmio.get_MMIO_BAR_base_address(reg['bar'], _bus)[0] != 0:
                reg_value = self.mmio.read_MMIO_BAR_reg(reg['bar'], int(reg['offset'], 16), int(reg['size'], 16), _bus)
            else:
                raise CSReadError("MMIO Bar ({}) base address is 0".format(reg['bar']))
        elif RegisterType.MSR == rtype:
            (eax, edx) = self.msr.read_msr( cpu_thread, int(reg['msr'], 16) )
            reg_value = (edx << 32) | eax
        elif RegisterType.PORTIO == rtype:
            port = int(reg['port'], 16)
            size = int(reg['size'], 16)
            reg_value = self.io._read_port( port, size )
        elif RegisterType.IOBAR == rtype:
            if self.iobar.get_IO_BAR_base_address(reg['bar'])[0] != 0:
                reg_value = self.iobar.read_IO_BAR_reg( reg['bar'], int(reg['offset'], 16), int(reg['size'], 16) )
            else:
                raise CSReadError("IO Bar ({}) base address is 0".format(reg['bar']))
        elif RegisterType.MSGBUS == rtype:
            reg_value = self.msgbus.msgbus_reg_read( int(reg['port'], 16), int(reg['offset'], 16) )
        elif RegisterType.MM_MSGBUS == rtype:
            reg_value = self.msgbus.mm_msgbus_reg_read(int(reg['port'], 16), int(reg['offset'], 16))
        elif RegisterType.MEMORY == rtype:
            if reg['access'] == 'dram':
                reg_value= self.mem.read_physical_mem(int(reg['address'], 16), int(reg['size'], 16))
            elif reg['access'] == 'mmio':
                reg_value = self.mmio.read_MMIO_reg(int(reg['address'], 16), int(reg['offset'], 16), int(reg['size'], 16))
        else:
            raise RegisterTypeNotFoundError("Register type not found: {}".format(rtype))

        return reg_value

    def read_register_all(self, reg_name, cpu_thread=0):
        values = []
        bus_data = self.get_register_bus(reg_name)
        reg = self.get_register_def(reg_name)
        rtype = reg['type']
        if RegisterType.MSR == rtype:
            topology = self.cpu.get_cpu_topology()
            if 'scope' in reg.keys() and reg['scope'] == "packages":
                packages = topology['packages']
                threads_to_use = [packages[p][0] for p in packages]
            elif 'scope' in reg.keys() and reg['scope'] == "cores":
                cores = topology['cores']
                threads_to_use = [cores[p][0] for p in cores]
            else: # Default to threads
                threads_to_use = range(self.helper.get_threads_count())
            for t in threads_to_use:
                values.append(self.read_register(reg_name, t))
        elif rtype in [RegisterType.MMCFG, RegisterType.PCICFG, RegisterType.MMIO]:
            if bus_data:
                for bus in bus_data:
                    values.append(self.read_register(reg_name, cpu_thread, bus))
        else:
            values.append(self.read_register(reg_name, cpu_thread))
        return values

    def write_register(self, reg_name, reg_value, cpu_thread=0, bus=None):
        reg = self.get_register_def(reg_name)
        rtype = reg['type']
        if RegisterType.PCICFG == rtype or RegisterType.MMCFG == rtype:
            if bus is not None:
                b = bus
            else:
                b = int(reg['bus'], 16)
            d = int(reg['dev'], 16)
            f = int(reg['fun'], 16)
            o = int(reg['offset'], 16)
            size = int(reg['size'], 16)
            if RegisterType.PCICFG == rtype:
                if   1 == size: self.pci.write_byte( b, d, f, o, reg_value )
                elif 2 == size: self.pci.write_word( b, d, f, o, reg_value )
                elif 4 == size: self.pci.write_dword( b, d, f, o, reg_value )
                elif 8 == size:
                    self.pci.write_dword( b, d, f, o, (reg_value & 0xFFFFFFFF) )
                    self.pci.write_dword( b, d, f, o + 4, (reg_value>>32 & 0xFFFFFFFF) )
            elif RegisterType.MMCFG == rtype:
                self.mmio.write_mmcfg_reg(b, d, f, o, size, reg_value )
        elif RegisterType.MMIO == rtype:
            self.mmio.write_MMIO_BAR_reg(reg['bar'], int(reg['offset'], 16), reg_value, int(reg['size'], 16), bus)
        elif RegisterType.MSR == rtype:
            eax = (reg_value & 0xFFFFFFFF)
            edx = ((reg_value >> 32) & 0xFFFFFFFF)
            self.msr.write_msr( cpu_thread, int(reg['msr'], 16), eax, edx )
        elif RegisterType.PORTIO == rtype:
            port = int(reg['port'], 16)
            size = int(reg['size'], 16)
            self.io._write_port( port, reg_value, size )
        elif RegisterType.IOBAR == rtype:
            self.iobar.write_IO_BAR_reg( reg['bar'], int(reg['offset'], 16), int(reg['size'], 16), reg_value )
        elif RegisterType.MSGBUS == rtype:
            self.msgbus.msgbus_reg_write( int(reg['port'], 16), int(reg['offset'], 16), reg_value )
        elif RegisterType.MM_MSGBUS == rtype:
            self.msgbus.mm_msgbus_reg_write(int(reg['port'], 16), int(reg['offset'], 16), reg_value)
        elif RegisterType.MEMORY == rtype:
            if reg['access'] == 'dram':
                self.mem.write_physical_mem(int(reg['address'], 16), int(reg['size'], 16), reg_value)
            elif reg['access'] == 'mmio':
                self.mmio.write_MMIO_reg(int(reg['address'], 16), int(reg['offset'], 16), reg_value, int(reg['size'], 16))
        else:
            raise RegisterTypeNotFoundError("Register type not found: {}".format(rtype))
        return True

    def write_register_all(self, reg_name, reg_values, cpu_thread=0):
        reg = self.get_register_def(reg_name)
        rtype = reg['type']
        bus_data = self.get_register_bus(reg_name)
        ret = False
        if RegisterType.MSR == rtype:
            topology = self.cpu.get_cpu_topology()
            if 'scope' in reg.keys() and reg['scope'] == "packages":
                packages = topology['packages']
                threads_to_use = [packages[p][0] for p in packages]
            elif 'scope' in reg.keys() and reg['scope'] == "cores":
                cores = topology['cores']
                threads_to_use = [cores[p][0] for p in cores]
            else: # Default to threads
                threads_to_use = range(self.helper.get_threads_count())
            if len(reg_values) == len(threads_to_use):
                value = 0
                for t in threads_to_use:
                    self.write_register(reg_name, reg_values[value], t)
                    value += 1
                ret = True
        elif rtype in [RegisterType.MMCFG, RegisterType.PCICFG, RegisterType.MMIO] and bus_data:
            values = len(bus_data)
            if len(reg_values) == values:
                for index in range(values):
                    self.write_register(reg_name, reg_values[index], cpu_thread, bus_data[index])
                ret = True
        else:
            if len(reg_values) == 1:
                self.write_register(reg_name, reg_values[0])
                ret = True
        if not ret and logger().DEBUG:
            logger().log("[write_register_all] There is a mismatch in the number of register values and registers to write")
        return ret

    def write_register_all_single(self, reg_name, reg_value, cpu_thread=0):
        reg = self.get_register_def(reg_name)
        rtype = reg['type']
        bus_data = self.get_register_bus(reg_name)
        if RegisterType.MSR == rtype:
            topology = self.cpu.get_cpu_topology()
            if 'scope' in reg.keys() and reg['scope'] == "packages":
                packages = topology['packages']
                threads_to_use = [packages[p][0] for p in packages]
            elif 'scope' in reg.keys() and reg['scope'] == "cores":
                cores = topology['cores']
                threads_to_use = [cores[p][0] for p in cores]
            else: # Default to threads
                threads_to_use = range(self.helper.get_threads_count())
            for t in threads_to_use:
                self.write_register(reg_name, reg_value, t)
        elif rtype in [RegisterType.MMCFG, RegisterType.PCICFG, RegisterType.MMIO] and bus_data:
            for bus in bus_data:
                self.write_register(reg_name, reg_value, cpu_thread, bus)
        else:
            self.write_register(reg_name, reg_value)
        return True

    def read_register_dict( self, reg_name):
        reg_value = self.read_register(reg_name)
        reg_def = self.get_register_def(reg_name)
        result = reg_def
        result['value'] = reg_value
        for f in reg_def['FIELDS']:
            result['FIELDS'][f]['bit'] = field_bit = int(reg_def['FIELDS'][f]['bit'])
            result['FIELDS'][f]['size'] = field_size = int(reg_def['FIELDS'][f]['size'])
            field_mask = 0
            for i in range(field_size):
                field_mask = (field_mask << 1) | 1
            result['FIELDS'][f]['value'] = (reg_value >> field_bit) & field_mask
        return result

    def get_register_field_mask(self, reg_name, reg_field=None,
                                preserve_field_position=False):
        reg_def = self.get_register_def(reg_name)
        if reg_field is not None:
            field_attrs = reg_def['FIELDS'][reg_field]
            mask_start = int(field_attrs['bit'])
            mask = (1 << int(field_attrs['size'])) - 1
        else:
            mask_start = 0
            mask = (1 << (int(reg_def['size'], 16) * 8)) - 1
        if preserve_field_position:
            return mask << mask_start
        else:
            return mask

    def get_register_field(self, reg_name, reg_value, field_name,
                           preserve_field_position=False):
        field_attrs = self.get_register_def(reg_name)['FIELDS'][field_name]
        field_bit   = int(field_attrs['bit'])
        field_mask  = (1 << int(field_attrs['size'])) - 1
        if preserve_field_position: return reg_value & (field_mask << field_bit)
        else:                       return (reg_value >> field_bit) & field_mask

    def get_register_field_all(self, reg_name, reg_values, field_name, preserve_field_position=False):
        values = []
        for reg_value in reg_values:
            values.append( self.get_register_field( reg_name, reg_value, field_name, preserve_field_position) )
        return values

    def set_register_field(self, reg_name, reg_value, field_name,
                           field_value, preserve_field_position=False):
        field_attrs = self.get_register_def(reg_name)['FIELDS'][field_name]
        field_bit   = int(field_attrs['bit'])
        field_mask  = (1 << int(field_attrs['size'])) - 1
        reg_value  &= ~(field_mask << field_bit) # keep other fields
        if preserve_field_position: reg_value |= (field_value & (field_mask << field_bit))
        else:                       reg_value |= ((field_value & field_mask) << field_bit)
        return reg_value

    def set_register_field_all(self, reg_name, reg_values, field_name, field_value, preserve_field_position=False):
        values = []
        for reg_value in reg_values:
            values.append( self.set_register_field( reg_name, reg_value, field_name, field_value, preserve_field_position) )
        return values

    def read_register_field( self, reg_name, field_name, preserve_field_position=False, cpu_thread=0, bus=None ):
        reg_value = self.read_register(reg_name, cpu_thread, bus)
        return self.get_register_field(reg_name, reg_value, field_name, preserve_field_position)

    def read_register_field_all(self, reg_name, field_name, preserve_field_position=False, cpu_thread=0):
        reg_values = self.read_register_all(reg_name, cpu_thread)
        return self.get_register_field_all(reg_name, reg_values, field_name, preserve_field_position)

    def write_register_field( self, reg_name, field_name, field_value, preserve_field_position=False, cpu_thread=0 ):
        try:
            reg_value = self.read_register(reg_name, cpu_thread)
            reg_value_new = self.set_register_field(reg_name, reg_value, field_name, field_value, preserve_field_position)
            ret = self.write_register(reg_name, reg_value_new, cpu_thread)
        except:
            ret = None
        return ret

    def write_register_field_all(self, reg_name, field_name, field_value, preserve_field_position=False, cpu_thread=0):
        reg_values = self.read_register_all(reg_name, cpu_thread)
        reg_values_new = self.set_register_field_all(reg_name, reg_values, field_name, field_value, preserve_field_position)
        return self.write_register_all(reg_name, reg_values_new, cpu_thread)

    def register_has_field( self, reg_name, field_name ):
        try:
            reg_def = self.get_register_def(reg_name)
        except KeyError:
            return False
        if 'FIELDS' not in reg_def:
            return False
        return (field_name in reg_def['FIELDS'])

    def register_has_all_fields(self, reg_name, field_list):
        ret = True
        for field in field_list:
            ret = ret and self.register_has_field(reg_name, field)
            if not ret:
                break
        return ret

    def _register_fields_str(self, reg_def, reg_val):
        reg_fields_str = ''
        if 'FIELDS' in reg_def:
            reg_fields_str += '\n'
            # sort fields by their bit position in the register
            sorted_fields = sorted( reg_def['FIELDS'].items(), key=lambda field: int(field[1]['bit']) )
            for f in sorted_fields:
                field_attrs = f[1]
                field_bit = int(field_attrs['bit'])
                field_size = int(field_attrs['size'])
                field_mask = 0
                for i in range(field_size):
                    field_mask = (field_mask << 1) | 1
                field_value = (reg_val >> field_bit) & field_mask
                field_desc = (' << ' + field_attrs['desc'] + ' ') if (field_attrs['desc'] != '') else ''
                reg_fields_str += ("    [{:02d}] {:16} = {:X}{}\n".format(field_bit, f[0], field_value, field_desc))

        if '' != reg_fields_str: reg_fields_str = reg_fields_str[:-1]
        return reg_fields_str

    def print_register(self, reg_name, reg_val, bus=None, cpu_thread=0):
        reg = self.get_register_def(reg_name)
        rtype = reg['type']
        reg_str = ''
        reg_val_str = "0x{:0{width}X}".format(reg_val, width=(int(reg['size'], 16) *2))
        if RegisterType.PCICFG == rtype or RegisterType.MMCFG == rtype:
            if bus is not None:
                b = bus
            else:
                b = int(reg['bus'], 16)
            d = int(reg['dev'], 16)
            f = int(reg['fun'], 16)
            o = int(reg['offset'], 16)
            mmcfg_off_str =  ''
            if RegisterType.MMCFG == rtype:
                mmcfg_off_str += ", MMCFG + 0x{:X}".format((b *32 *8 + d *8 + f) * 0x1000 + o)
            reg_str = "[*] {} = {} << {} (b:d.f {:02d}:{:02d}.{:d} + 0x{:X}{})".format(reg_name, reg_val_str, reg['desc'], b, d, f, o, mmcfg_off_str)
        elif RegisterType.MMIO == rtype:
            reg_str = "[*] {} = {} << {} ({} + 0x{:X})".format(reg_name, reg_val_str, reg['desc'], reg['bar'], int(reg['offset'], 16))
        elif RegisterType.MSR == rtype:
            reg_str = "[*] {} = {} << {} (MSR 0x{:X} Thread 0x{:X})".format(reg_name, reg_val_str, reg['desc'], int(reg['msr'], 16), cpu_thread)
        elif RegisterType.PORTIO == rtype:
            reg_str = "[*] {} = {} << {} (I/O port 0x{:X})".format(reg_name, reg_val_str, reg['desc'], int(reg['port'], 16))
        elif RegisterType.IOBAR == rtype:
            reg_str = "[*] {} = {} << {} (I/O {} + 0x{:X})".format(reg_name, reg_val_str, reg['desc'], reg['bar'], int(reg['offset'], 16))
        elif RegisterType.MSGBUS == rtype or RegisterType.MM_MSGBUS == rtype:
            reg_str = "[*] {} = {} << {} (msgbus port 0x{:X}, off 0x{:X})".format(reg_name, reg_val_str, reg['desc'], int(reg['port'], 16), int(reg['offset'], 16))
        else:
            reg_str = "[*] {} = {} << {}".format(reg_name, reg_val_str, reg['desc'])

        reg_str += self._register_fields_str(reg, reg_val)
        logger().log( reg_str )
        return reg_str

    def print_register_all(self, reg_name, cpu_thread=0):
        reg_str = ''
        bus_data = self.get_register_bus( reg_name )
        reg = self.get_register_def(reg_name)
        rtype = reg['type']
        if RegisterType.MSR == rtype:
            topology = self.cpu.get_cpu_topology()
            if 'scope' in reg.keys() and reg['scope'] == "packages":
                packages = topology['packages']
                threads_to_use = [packages[p][0] for p in packages]
            elif 'scope' in reg.keys() and reg['scope'] == "cores":
                cores = topology['cores']
                threads_to_use = [cores[p][0] for p in cores]
            else: # Default to threads
                threads_to_use = range(self.helper.get_threads_count())
            for t in threads_to_use:
                reg_val = self.read_register(reg_name, t)
                reg_str += self.print_register(reg_name, reg_val, cpu_thread=t)
        elif rtype in [RegisterType.MMCFG, RegisterType.PCICFG, RegisterType.MMIO]:
            if bus_data:
                for bus in bus_data:
                    reg_val = self.read_register(reg_name, cpu_thread, bus)
                    reg_str += self.print_register(reg_name, reg_val, bus)
        else:
            reg_val = self.read_register(reg_name, cpu_thread)
            reg_str = self.print_register(reg_name, reg_val)
        return reg_str

    def get_control(self, control_name, cpu_thread=0, with_print=False):
        control = self.Cfg.CONTROLS[ control_name ]
        reg     = control['register']
        field   = control['field']
        reg_data = self.read_register(reg, cpu_thread)
        if logger().VERBOSE or with_print:
            self.print_register(reg, reg_data)
        return self.get_register_field(reg, reg_data, field)

    def set_control(self, control_name, control_value, cpu_thread=0):
        control = self.Cfg.CONTROLS[control_name]
        reg     = control['register']
        field   = control['field']
        return self.write_register_field(reg, field, control_value, cpu_thread)

    def is_control_defined(self, control_name):
        try:
            return (self.Cfg.CONTROLS[ control_name ] is not None)
        except KeyError:
            return False

    def register_is_msr(self, reg_name):
        if self.is_register_defined(reg_name):
            if self.Cfg.REGISTERS[reg_name]['type'].lower() == 'msr':
                return True
        return False

    def register_is_pci(self, reg_name):
        if self.is_register_defined(reg_name):
            reg_def = self.Cfg.REGISTERS[reg_name]
            if (reg_def['type'].lower() == 'pcicfg') or (reg_def['type'].lower() == 'mmcfg'):
                return True
        return False

    def get_lock(self, lock_name, cpu_thread=0, with_print=False, bus=None):
        lock = self.Cfg.LOCKS[lock_name]
        reg     = lock['register']
        field   = lock['field']
        if bus is None:
            reg_data = self.read_register_all(reg, cpu_thread)
        else:
            reg_data = self.read_register(reg, cpu_thread, bus)
            reg_data = [reg_data]
        if logger().VERBOSE or with_print:
            if reg_data:
                for rd in reg_data:
                    self.print_register(reg, rd)
            else:
                self.logger.log("Register has no data")
        if reg_data:
            return self.get_register_field_all(reg, reg_data, field)
        return reg_data

    def set_lock(self, lock_name, lock_value, cpu_thread=0, bus=None):
        lock = self.Cfg.LOCKS[lock_name]
        reg     = lock['register']
        field   = lock['field']
        if bus is None:
            reg_data = self.read_register_all(reg, cpu_thread)
            reg_data = self.set_register_field_all(reg, reg_data, field, lock_value)
            return self.write_register_all(reg, reg_data, cpu_thread)
        else:
            reg_data = self.read_register(reg, cpu_thread, bus)
            reg_data = self.set_register_field(reg, reg_data, field, lock_value)
            return self.write_register(reg, reg_data, cpu_thread, bus)

    def is_lock_defined(self, lock_name):
        return lock_name in self.Cfg.LOCKS.keys()

    def get_locked_value(self, lock_name):
        if logger().DEBUG:
            logger().log('Retrieve value for lock {}'.format(lock_name))
        return int(self.Cfg.LOCKS[lock_name]['value'], 16)

    def get_lock_desc(self, lock_name):
        return self.Cfg.LOCKS[lock_name]['desc']

    def get_lock_type(self, lock_name):
        if 'type' in self.Cfg.LOCKS[lock_name].keys():
            mtype = self.Cfg.LOCKS[lock_name]['type']
        else:
            mtype = "RW/L"
        return mtype

    def get_lock_list(self):
        return self.Cfg.LOCKS.keys()

    def get_lock_mask(self, lock_name):
        lock = self.Cfg.LOCKS[lock_name]
        reg     = lock['register']
        field   = lock['field']
        return(self.get_register_field_mask(reg,field))

    def get_lockedby(self, lock_name):
        if lock_name in self.Cfg.LOCKEDBY.keys():
            return self.Cfg.LOCKEDBY[lock_name]
        else:
            return None

    def is_all_value(self, reg_values, value):
        return all(n == value for n in reg_values)

    def get_IO_space(self, io_name):
        if io_name in self.Cfg.IO_BARS.keys():
            reg = self.Cfg.IO_BARS[io_name]["register"]
            bf = self.Cfg.IO_BARS[io_name]["base_field"]
            return (reg, bf)
        else:
            return None, None


_chipset = None

def cs():
    global _chipset
    from chipsec.helper.oshelper import helper
    if _chipset is None:
        _chipset = Chipset(helper())
    return _chipset
