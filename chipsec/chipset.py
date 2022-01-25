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
Contains platform identification functions
"""

import collections
import os
import xml.etree.ElementTree as ET

from chipsec.helper.oshelper import OsHelper
from chipsec.hal import cpu, cpuid, io, iobar, mmio, msgbus, msr, pci, physmem, ucode
from chipsec.exceptions import UnknownChipsetError, CSReadError, RegisterTypeNotFoundError

from chipsec.logger import logger
from chipsec.defines import is_hex

from chipsec.config import Cfg

import chipsec.file

# DEBUG Flags
QUIET_PCI_ENUM = True
CONSISTENCY_CHECKING = True


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


##################################################################################
# Functionality defining current chipset
##################################################################################

CHIPSET_ID_UNKNOWN = 0

CHIPSET_CODE_UNKNOWN = ''

CHIPSET_FAMILY = {}


class Chipset:

    def __init__(self, helper=None):
        # Initialize configuration and scope
        self.Cfg = Cfg()
        self.logger = logger()
        self.scope = None
        self.pch_dictionary = dict()
        self.chipset_dictionary = dict()
        self.device_dictionary = dict()
        self.chipset_codes = {}
        self.pch_codes = {}
        self.device_code = []
        self.load_list = []

        # Initialize CPU and PCH artifacts
        self.vid = 0xFFFF
        self.did = 0xFFFF
        self.rid = 0xFF
        self.code = CHIPSET_CODE_UNKNOWN
        self.longname = "Unrecognized Platform"
        self.pch_vid = 0xFFFF
        self.pch_did = 0xFFFF
        self.pch_rid = 0xFF
        self.pch_code = CHIPSET_CODE_UNKNOWN
        self.pch_longname = 'Unrecognized PCH'
        self.reqs_pch = False

        # Initialize HAL artifacts
        self.cpu = None
        self.io = None
        self.iobar = None
        self.mem = None
        self.mmio = None
        self.msgbus = None
        self.msr = None
        self.pci = None

        # Initialize the Helper
        if helper is None:
            self.helper = OsHelper()
        else:
            self.helper = helper

    ##################################################################################
    #
    # Initialization
    #
    ##################################################################################
    def get_cpuid(self):
        # Get processor version information
        _cpuid = cpuid.CpuID(self)
        (eax, _, _, _) = _cpuid.cpuid(0x01, 0x00)
        stepping = eax & 0xF
        model = (eax >> 4) & 0xF
        extmodel = (eax >> 16) & 0xF
        family = (eax >> 8) & 0xF
        ptype = (eax >> 12) & 0x3
        extfamily = (eax >> 20) & 0xFF
        ret = '{:01X}{:01X}{:01X}{:01X}{:01X}'.format(extmodel, ptype, family, model, stepping)
        if extfamily == 0:
            return ret
        else:
            return '{:02X}{}'.format(extfamily, ret)

    def init(self, platform_code, req_pch_code, start_driver=True, driver_exists=None, to_file=None, from_file=None):
        # Start Helper
        self.helper.start(start_driver, driver_exists, to_file, from_file)

        # Gather CPUID and enumerate pci devices
        self.init_cfg_bus()
        try:
            self.cpuid = self.get_cpuid()
        except Exception:
            self.cpuid = None

        self.init_xml_configuration(platform_code, req_pch_code)
        if self.code == CHIPSET_CODE_UNKNOWN:
            raise UnknownChipsetError('Did not identify CPU')
        if self.req_pch is True and self.pch_code == CHIPSET_CODE_UNKNOWN:
            raise UnknownChipsetError('Did not identify PCH')

        self.load_xml_configuration()

        self.cpu = cpu.CPU(self)
        self.io = io.PortIO(self)
        self.iobar = iobar.IOBAR(self)
        self.mem = physmem.Memory(self)
        self.mmio = mmio.MMIO(self)
        self.msgbus = msgbus.MsgBus(self)
        self.msr = msr.Msr(self)
        self.pci = pci.Pci(self)

    def destroy(self, start_driver):
        self.helper.stop(start_driver)

    def get_chipset_code(self):
        return self.code

    def get_pch_code(self):
        return self.pch_code

    def get_chipset_name(self, id):
        return self.longname

    def get_pch_name(self, id):
        return self.pch_longname

    def print_chipset(self):
        self.logger.log("[*] Platform: {}\n          VID: {:04X}\n          DID: {:04X}\n          RID: {:02X}".format(self.longname, self.vid, self.did, self.rid))

    def print_pch(self):
        self.logger.log("[*] PCH     : {}\n          VID: {:04X}\n          DID: {:04X}\n          RID: {:02X}".format(self.pch_longname, self.pch_vid, self.pch_did, self.pch_rid))

    def is_core(self):
        return self.get_chipset_code() in CHIPSET_FAMILY["core"]

    def is_server(self):
        return self.get_chipset_code() in CHIPSET_FAMILY["xeon"]

    def is_atom(self):
        return self.get_chipset_code() in CHIPSET_FAMILY["atom"]

    def print_supported_chipsets(self):
        self.logger.log("\nSupported platforms:\n")
        self.logger.log(" VID  | DID  | Name           | Code   | Long Name")
        self.logger.log("-------------------------------------------------------------------------------------")
        for _vid in sorted(self.chipset_dictionary.keys()):
            for _did in sorted(self.chipset_dictionary[_vid]):
                for item in self.chipset_dictionary[_vid][_did]:
                    self.logger.log(" {:4} | {:4} | {:14} | {:6} | {:40}".format(_vid, _did, item['name'], item['code'].lower(), item['longname'][:40]))

    ##################################################################################
    #
    # Loading platform configuration from XML files in chipsec/cfg/
    #
    ##################################################################################

    # def init_xml_configuration(self):
    def init_xml_configuration(self, platform_code, pch_code):
        # find VID
        _cfg_path = os.path.join(chipsec.file.get_main_dir(), 'chipsec', 'cfg')
        VID = [f for f in os.listdir(_cfg_path) if os.path.isdir(os.path.join(_cfg_path, f)) and is_hex(f)]
        # create dictionaries
        for vid in VID:
            self.logger.log_debug("[*] Entering directory '{}'..".format(os.path.join(_cfg_path, vid)))
            self.chipset_dictionary[vid] = collections.defaultdict(list)
            self.pch_dictionary[vid] = collections.defaultdict(list)
            self.device_dictionary[vid] = collections.defaultdict(list)
            for fxml in os.listdir(os.path.join(_cfg_path, vid)):
                if os.path.isdir(os.path.join(_cfg_path, vid, fxml)):
                    continue
                self.logger.log_debug("[*] looking for platform config in '{}'..".format(fxml))
                tree = ET.parse(os.path.join(_cfg_path, vid, fxml))
                root = tree.getroot()
                for _cfg in root.iter('configuration'):
                    platform = ""
                    req_pch = False
                    if 'platform' not in _cfg.attrib:
                        self.logger.log_debug("[*] found Device config at '{}'..".format(fxml))
                        if vid not in self.device_dictionary.keys():
                            self.device_dictionary[vid] = {}
                        mdict = self.device_dictionary[vid]
                        platform_type = "device"
                    elif _cfg.attrib['platform'].lower().startswith('pch'):
                        self.logger.log_debug("[*] found PCH config at '{}'..".format(fxml))
                        if not _cfg.attrib['platform'].upper() in self.pch_codes.keys():
                            self.pch_codes[_cfg.attrib['platform'].upper()] = {}
                            self.pch_codes[_cfg.attrib['platform'].upper()]['vid'] = vid
                        mdict = self.pch_dictionary[vid]
                        cdict = self.pch_codes[_cfg.attrib['platform'].upper()]
                        platform = _cfg.attrib['platform']
                        platform_type = "pch"
                    elif _cfg.attrib['platform'].upper():
                        self.logger.log_debug("[*] found platform config from '{}'..".format(fxml))
                        if not _cfg.attrib['platform'].upper() in self.chipset_codes.keys():
                            self.chipset_codes[_cfg.attrib['platform'].upper()] = {}
                            self.chipset_codes[_cfg.attrib['platform'].upper()]['vid'] = vid
                        mdict = self.chipset_dictionary[vid]
                        cdict = self.chipset_codes[_cfg.attrib['platform'].upper()]
                        platform = _cfg.attrib['platform']
                        platform_type = "cpu"
                    else:
                        continue
                    if "req_pch" in _cfg.attrib:
                        req_pch = _cfg.attrib['req_pch']
                    self.logger.log_debug("[*] Populating configuration dictionary..")
                    for _info in _cfg.iter('info'):
                        dv_list = []
                        if 'family' in _info.attrib:
                            family = _info.attrib['family'].lower()
                            if family not in CHIPSET_FAMILY:
                                CHIPSET_FAMILY[family] = []
                            CHIPSET_FAMILY[family].append(_cfg.attrib['platform'].upper())
                        if 'detection_value' in _info.attrib:
                            for dv in list(_info.attrib['detection_value'].split(',')):
                                if dv[-1].upper() == 'X':
                                    rdv = int(dv[:-1], 16) << 4   #  Assume valid hex value with last nibble removed
                                    for rdv_value in range(rdv, rdv + 0x10):
                                        dv_list.append(rdv_value)
                                elif '-' in dv:
                                    rdv = dv.split('-')
                                    for rdv_value in range(int(rdv[0], 16), int(rdv[1], 16) + 1):  #  Assume valid hex values
                                        dv_list.append(rdv_value)
                                else:
                                    dv_list.append(dv)
                        if _info.find('sku') is not None:
                            _did = ""
                            for _sku in _info.iter('sku'):
                                _did = _sku.attrib['did'][2:]
                                del _sku.attrib['did']
                                mdict[_did].append(_sku.attrib)
                                if platform_code:
                                    if platform.upper() == platform_code.upper():
                                        self.load_list.append(os.path.join(_cfg_path, vid, fxml))
                                        if _did and self.did is not None:
                                            self.did = int(_did, 16)
                                            self.vid = int(vid, 16)
                                            self.code = platform_code.upper()
                                            self.longname = _sku.attrib['longname']
                                            self.req_pch = req_pch
                                elif platform_type == "cpu":
                                    if self.cpuid in dv_list or (dv_list == [] and vid in self.Cfg.BUS.keys() and _did in self.Cfg.BUS[vid].keys()):
                                        self.load_list.append(os.path.join(_cfg_path, vid, fxml))
                                        self.did = int(_did, 16)
                                        self.vid = int(vid, 16)
                                        self.code = platform.upper()
                                        self.longname = _sku.attrib["longname"]
                                        self.req_pch = req_pch
                                if pch_code:
                                    if platform.upper() == pch_code.upper():
                                        self.load_list.append(os.path.join(_cfg_path, vid, fxml))
                                        self.pch_vid = int(vid, 16)
                                        self.pch_did = int(_did, 16)
                                        self.pch_code = pch_code.upper()
                                        self.pch_longname = _sku.attrib["longname"]
                                elif platform_type == "pch":
                                    if vid in self.Cfg.BUS.keys() and _did in self.Cfg.BUS[vid].keys():
                                        self.load_list.append(os.path.join(_cfg_path, vid, fxml))
                                        self.pch_vid = int(vid, 16)
                                        self.pch_did = int(_did, 16)
                                        self.pch_code = platform.upper()
                                        self.pch_longname = _sku.attrib["longname"]
                                if platform == "":
                                    if _did in self.Cfg.BUS[vid].keys():
                                        self.load_list.append(os.path.join(_cfg_path, vid, fxml))
                            if _did == "":
                                self.logger.log_debug("No SKU found in configuration")
                            else:
                                if not platform == "":
                                    cdict['did'] = _did
            for cc in self.chipset_codes:
                globals()["CHIPSET_CODE_{}".format(cc.upper())] = cc.upper()
            for pc in self.pch_codes:
                globals()["PCH_CODE_{}".format(pc[4:].upper())] = pc.upper()

    def load_xml_configuration(self):
        for _xml in self.load_list:
            self.Cfg.init_cfg_xml(_xml, self.code.lower(), self.pch_code.lower())

    def init_cfg_bus(self):
        _pci = pci.Pci(self)
        self.logger.log_debug('[*] Loading device buses..')
        if QUIET_PCI_ENUM:
            old_log_state = (self.logger.HAL, self.logger.DEBUG, self.logger.VERBOSE)
            self.logger.HAL, self.logger.DEBUG, self.logger.VERBOSE  = (False, False, False)
            self.logger.setlevel()
        try:
            enum_devices = _pci.enumerate_devices()
        except Exception:
            self.logger.log_debug('[*] Unable to enumerate PCI devices.')
            enum_devices = []
        if QUIET_PCI_ENUM:
            self.logger.HAL, self.logger.DEBUG, self.logger.VERBOSE  = old_log_state
            self.logger.setlevel()

        # store entries dev_fun_vid_did = [list of bus entries]
        for b, d, f, vid, did, rid in enum_devices:
            dstr = "{:04X}".format(did)
            vstr = "{:04X}".format(vid)
            cfg_str = "{:0>2X}_{:0>2X}".format(d, f)
            if vstr not in self.Cfg.BUS.keys():
                self.Cfg.BUS[vstr] = {}
            if dstr not in self.Cfg.BUS[vstr].keys():
                self.Cfg.BUS[vstr][dstr] = [b]
            else:
                self.Cfg.BUS[vstr][dstr].append(b)

    ##################################################################################
    #
    # Functions which access configuration of integrated PCI devices (interfaces, controllers)
    # by device name (defined in XML configuration files)
    #
    ##################################################################################

    # def get_DeviceVendorID(self, device_name):
    #     (b, d, f) = self.Cfg.get_device_BDF(device_name)
    #     return self.pci.get_DIDVID(b, d, f)

    def is_device_enabled(self, device_name):
        if self.Cfg.is_device_defined(device_name):
            (b, d, f) = self.Cfg.get_device_BDF(device_name)
            return self.pci.is_enabled(b, d, f)
        return False

    def is_register_device_enabled(self, reg_name, bus=None):
        if reg_name in self.Cfg.REGISTERS:
            reg = self.Cfg.get_register_def(reg_name)
            rtype = reg['type']
            if (rtype == RegisterType.MMCFG) or (rtype == RegisterType.PCICFG):
                if bus is not None:
                    b = bus
                else:
                    b = int(reg['bus'], 16)
                d = int(reg['dev'], 16)
                f = int(reg['fun'], 16)
                return self.pci.is_enabled(b, d, f)
            elif (rtype == RegisterType.MMIO):
                bar_name = reg['bar']
                return self.mmio.is_MMIO_BAR_enabled(bar_name, bus)
        return False

    # def switch_device_def(self, target_dev, source_dev):
    #     (b, d, f) = self.get_device_BDF(source_dev)
    #     self.Cfg.CONFIG_PCI[target_dev]['bus'] = str(b)
    #     self.Cfg.CONFIG_PCI[target_dev]['dev'] = str(d)
    #     self.Cfg.CONFIG_PCI[target_dev]['fun'] = str(f)

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

    def get_scope(self):
        return self.Cfg.get_scope()

    def set_scope(self, scope):
        self.Cfg.set_scope(scope)

    def clear_scope(self):
        self.Cfg.clear_scope()

    def is_register_defined(self, regname):
        return self.Cfg.is_register_defined(regname)

    def is_device_defined(self, dev_name):
        return self.Cfg.is_device_defined(dev_name)

    def get_mmio_def(self, bar_name):
        return self.Cfg.get_mmio_def(bar_name)

    def get_io_def(self, bar_name):
        return self.Cfg.get_io_def(bar_name)

    def get_mem_def(self, range_name):
        return self.Cfg.get_mem_def(range_name)

    def get_register_def(self, reg_name, bus=0):
        return self.Cfg.get_register_def(reg_name, bus)

    def get_register_bus(self, reg_name):
        return self.Cfg.get_register_bus(reg_name)

    def get_device_bus(self, dev_name):
        return self.Cfg.get_device_bus(dev_name)

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
            if 1 == size:
                reg_value = self.pci.read_byte(b, d, f, o)
            elif 2 == size:
                reg_value = self.pci.read_word(b, d, f, o)
            elif 4 == size:
                reg_value = self.pci.read_dword(b, d, f, o)
            elif 8 == size:
                reg_value = (self.pci.read_dword(b, d, f, o + 4) << 32) | self.pci.read_dword(b, d, f, o)
        elif RegisterType.MMCFG == rtype:
            reg_value = self.mmio.read_mmcfg_reg(b, d, f, o, size)
        elif RegisterType.MMIO == rtype:
            _bus = bus
            if self.mmio.get_MMIO_BAR_base_address(reg['bar'], _bus)[0] != 0:
                reg_value = self.mmio.read_MMIO_BAR_reg(reg['bar'], int(reg['offset'], 16), int(reg['size'], 16), _bus)
            else:
                raise CSReadError("MMIO Bar ({}) base address is 0".format(reg['bar']))
        elif RegisterType.MSR == rtype:
            (eax, edx) = self.msr.read_msr(cpu_thread, int(reg['msr'], 16))
            reg_value = (edx << 32) | eax
        elif RegisterType.PORTIO == rtype:
            port = int(reg['port'], 16)
            size = int(reg['size'], 16)
            reg_value = self.io._read_port(port, size)
        elif RegisterType.IOBAR == rtype:
            if self.iobar.get_IO_BAR_base_address(reg['bar'])[0] != 0:
                reg_value = self.iobar.read_IO_BAR_reg(reg['bar'], int(reg['offset'], 16), int(reg['size'], 16))
            else:
                raise CSReadError("IO Bar ({}) base address is 0".format(reg['bar']))
        elif RegisterType.MSGBUS == rtype:
            reg_value = self.msgbus.msgbus_reg_read(int(reg['port'], 16), int(reg['offset'], 16))
        elif RegisterType.MM_MSGBUS == rtype:
            reg_value = self.msgbus.mm_msgbus_reg_read(int(reg['port'], 16), int(reg['offset'], 16))
        elif RegisterType.MEMORY == rtype:
            if reg['access'] == 'dram':
                size = int(reg['size'], 16)
                if 1 == size:
                    reg_value = self.mem.read_physical_mem_byte(int(reg['address'], 16))
                elif 2 == size:
                    reg_value = self.mem.read_physical_mem_word(int(reg['address'], 16))
                elif 4 == size:
                    reg_value = self.mem.read_physical_mem_dword(int(reg['address'], 16))
                elif 8 == size:
                    reg_value = self.mem.read_physical_mem_qword(int(reg['address'], 16))
            elif reg['access'] == 'mmio':
                reg_value = self.mmio.read_MMIO_reg(int(reg['address'], 16), int(reg['offset'], 16), int(reg['size'], 16))
        elif RegisterType.IMA == rtype:
            self.write_register(reg['index'], int(reg['offset'], 16) + int(reg['base'], 16))
            reg_value = self.read_register(reg['data'])
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
            else:  # Default to threads
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
                if 1 == size:
                    self.pci.write_byte(b, d, f, o, reg_value)
                elif 2 == size:
                    self.pci.write_word(b, d, f, o, reg_value)
                elif 4 == size:
                    self.pci.write_dword(b, d, f, o, reg_value)
                elif 8 == size:
                    self.pci.write_dword(b, d, f, o, (reg_value & 0xFFFFFFFF))
                    self.pci.write_dword(b, d, f, o + 4, (reg_value >> 32 & 0xFFFFFFFF))
            elif RegisterType.MMCFG == rtype:
                self.mmio.write_mmcfg_reg(b, d, f, o, size, reg_value)
        elif RegisterType.MMIO == rtype:
            self.mmio.write_MMIO_BAR_reg(reg['bar'], int(reg['offset'], 16), reg_value, int(reg['size'], 16), bus)
        elif RegisterType.MSR == rtype:
            eax = (reg_value & 0xFFFFFFFF)
            edx = ((reg_value >> 32) & 0xFFFFFFFF)
            self.msr.write_msr(cpu_thread, int(reg['msr'], 16), eax, edx)
        elif RegisterType.PORTIO == rtype:
            port = int(reg['port'], 16)
            size = int(reg['size'], 16)
            self.io._write_port(port, reg_value, size)
        elif RegisterType.IOBAR == rtype:
            self.iobar.write_IO_BAR_reg(reg['bar'], int(reg['offset'], 16), int(reg['size'], 16), reg_value)
        elif RegisterType.MSGBUS == rtype:
            self.msgbus.msgbus_reg_write(int(reg['port'], 16), int(reg['offset'], 16), reg_value)
        elif RegisterType.MM_MSGBUS == rtype:
            self.msgbus.mm_msgbus_reg_write(int(reg['port'], 16), int(reg['offset'], 16), reg_value)
        elif RegisterType.MEMORY == rtype:
            if reg['access'] == 'dram':
                self.mem.write_physical_mem(int(reg['address'], 16), int(reg['size'], 16), reg_value)
            elif reg['access'] == 'mmio':
                self.mmio.write_MMIO_reg(int(reg['address'], 16), int(reg['offset'], 16), reg_value, int(reg['size'], 16))
        elif RegisterType.IMA == rtype:
            self.write_register(reg['index'], int(reg['offset'], 16) + int(reg['base'], 16))
            self.write_register(reg['data'], reg_value)
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
            else:  # Default to threads
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
        if not ret:
            self.logger.log_debug("[write_register_all] There is a mismatch in the number of register values and registers to write")
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
            else:  # Default to threads
                threads_to_use = range(self.helper.get_threads_count())
            for t in threads_to_use:
                self.write_register(reg_name, reg_value, t)
        elif rtype in [RegisterType.MMCFG, RegisterType.PCICFG, RegisterType.MMIO] and bus_data:
            for bus in bus_data:
                self.write_register(reg_name, reg_value, cpu_thread, bus)
        else:
            self.write_register(reg_name, reg_value)
        return True

    def read_register_dict(self, reg_name):
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
        field_bit = int(field_attrs['bit'])
        field_mask = (1 << int(field_attrs['size'])) - 1
        if preserve_field_position:
            return reg_value & (field_mask << field_bit)
        else:
            return (reg_value >> field_bit) & field_mask

    def get_register_field_all(self, reg_name, reg_values, field_name, preserve_field_position=False):
        values = []
        for reg_value in reg_values:
            values.append(self.get_register_field(reg_name, reg_value, field_name, preserve_field_position))
        return values

    def set_register_field(self, reg_name, reg_value, field_name,
                           field_value, preserve_field_position=False):
        field_attrs = self.get_register_def(reg_name)['FIELDS'][field_name]
        field_bit = int(field_attrs['bit'])
        field_mask = (1 << int(field_attrs['size'])) - 1
        reg_value &= ~(field_mask << field_bit)  # keep other fields
        if preserve_field_position:
            reg_value |= (field_value & (field_mask << field_bit))
        else:
            reg_value |= ((field_value & field_mask) << field_bit)
        return reg_value

    def set_register_field_all(self, reg_name, reg_values, field_name, field_value, preserve_field_position=False):
        values = []
        for reg_value in reg_values:
            values.append(self.set_register_field(reg_name, reg_value, field_name, field_value, preserve_field_position))
        return values

    def read_register_field(self, reg_name, field_name, preserve_field_position=False, cpu_thread=0, bus=None):
        reg_value = self.read_register(reg_name, cpu_thread, bus)
        return self.get_register_field(reg_name, reg_value, field_name, preserve_field_position)

    def read_register_field_all(self, reg_name, field_name, preserve_field_position=False, cpu_thread=0):
        reg_values = self.read_register_all(reg_name, cpu_thread)
        return self.get_register_field_all(reg_name, reg_values, field_name, preserve_field_position)

    def write_register_field(self, reg_name, field_name, field_value, preserve_field_position=False, cpu_thread=0):
        try:
            reg_value = self.read_register(reg_name, cpu_thread)
            reg_value_new = self.set_register_field(reg_name, reg_value, field_name, field_value, preserve_field_position)
            ret = self.write_register(reg_name, reg_value_new, cpu_thread)
        except Exception:
            ret = None
        return ret

    def write_register_field_all(self, reg_name, field_name, field_value, preserve_field_position=False, cpu_thread=0):
        reg_values = self.read_register_all(reg_name, cpu_thread)
        reg_values_new = self.set_register_field_all(reg_name, reg_values, field_name, field_value, preserve_field_position)
        return self.write_register_all(reg_name, reg_values_new, cpu_thread)

    def register_has_field(self, reg_name, field_name):
        return self.Cfg.register_has_field(reg_name, field_name)

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
            sorted_fields = sorted(reg_def['FIELDS'].items(), key=lambda field: int(field[1]['bit']))
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

        if '' != reg_fields_str:
            reg_fields_str = reg_fields_str[:-1]
        return reg_fields_str

    def print_register(self, reg_name, reg_val, bus=None, cpu_thread=0):
        reg = self.get_register_def(reg_name, bus)
        rtype = reg['type']
        reg_str = ''
        if 'size' in reg:
            reg_val_str = "0x{:0{width}X}".format(reg_val, width=(int(reg['size'], 16) * 2))
        else:
            reg_val_str = "0x{:08X}".format(reg_val)
        if RegisterType.PCICFG == rtype or RegisterType.MMCFG == rtype:
            if bus is not None:
                b = bus
            else:
                b = int(reg['bus'], 16)
            d = int(reg['dev'], 16)
            f = int(reg['fun'], 16)
            o = int(reg['offset'], 16)
            mmcfg_off_str = ''
            if RegisterType.MMCFG == rtype:
                mmcfg_off_str += ", MMCFG + 0x{:X}".format((b * 32 * 8 + d * 8 + f) * 0x1000 + o)
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
        elif RegisterType.IMA == rtype:
            reg_str = "[*] {} = {} << {} (indirect access via {}/{}, base 0x{:X}, off 0x{:X})".format(reg_name, reg_val_str, reg['desc'], reg['index'], reg['data'], int(reg['base'], 16), int(reg['offset'], 16))
        else:
            reg_str = "[*] {} = {} << {}".format(reg_name, reg_val_str, reg['desc'])

        reg_str += self._register_fields_str(reg, reg_val)
        self.logger.log(reg_str)
        return reg_str

    def print_register_all(self, reg_name, cpu_thread=0):
        reg_str = ''
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
            else:  # Default to threads
                threads_to_use = range(self.helper.get_threads_count())
            for t in threads_to_use:
                reg_val = self.read_register(reg_name, t)
                reg_str += self.print_register(reg_name, reg_val, cpu_thread=t)
        elif rtype in [RegisterType.MMCFG, RegisterType.PCICFG, RegisterType.MMIO]:
            if bus_data:
                for bus in bus_data:
                    reg_val = self.read_register(reg_name, cpu_thread, bus)
                    reg_str += self.print_register(reg_name, reg_val, bus)
        elif rtype in [RegisterType.MMCFG, RegisterType.PCICFG, RegisterType.MMIO] and bus_data:
            for bus in bus_data:
                reg_val = self.read_register(reg_name, cpu_thread, bus)
                reg_str += self.print_register(reg_name, reg_val, bus)
        else:
            reg_val = self.read_register(reg_name, cpu_thread)
            reg_str = self.print_register(reg_name, reg_val)
        return reg_str

    def get_control(self, control_name, cpu_thread=0, with_print=False):
        control = self.Cfg.get_control_def(control_name)
        reg = control['register']
        field = control['field']
        reg_data = self.read_register(reg, cpu_thread)
        if self.logger.VERBOSE or with_print:
            self.print_register(reg, reg_data)
        ret = self.get_register_field(reg, reg_data, field)
        return ret

    def set_control(self, control_name, control_value, cpu_thread=0):
        control = self.Cfg.get_control_def(control_name)
        reg = control['register']
        field = control['field']
        return self.write_register_field(reg, field, control_value, cpu_thread)

    def is_control_defined(self, control_name):
        return self.Cfg.is_control_defined(control_name)

    # def register_is_msr(self, reg_name):
    #     if self.is_register_defined(reg_name):
    #         if self.scope is not None:
    #             if not reg_name.startswith(self.scope):
    #                 reg_name = "{}.{}".format(self.scope, reg_name)
    #         if self.Cfg.REGISTERS[reg_name]['type'].lower() == 'msr':
    #             return True
    #     return False

    # def register_is_pci(self, reg_name):
    #     if self.is_register_defined(reg_name):
    #         reg_def = self.Cfg.REGISTERS[reg_name]
    #         if (reg_def['type'].lower() == 'pcicfg') or (reg_def['type'].lower() == 'mmcfg'):
    #             return True
    #     return False

    def get_lock(self, lock_name, cpu_thread=0, with_print=False, bus=None):
        lock = self.Cfg.LOCKS[lock_name]
        reg = lock['register']
        field = lock['field']
        if bus is None:
            reg_data = self.read_register_all(reg, cpu_thread)
        else:
            reg_data = self.read_register(reg, cpu_thread, bus)
            reg_data = [reg_data]
        if self.logger.VERBOSE or with_print:
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
        reg = lock['register']
        field = lock['field']
        if bus is None:
            reg_data = self.read_register_all(reg, cpu_thread)
            reg_data = self.set_register_field_all(reg, reg_data, field, lock_value)
            return self.write_register_all(reg, reg_data, cpu_thread)
        else:
            reg_data = self.read_register(reg, cpu_thread, bus)
            reg_data = self.set_register_field(reg, reg_data, field, lock_value)
            return self.write_register(reg, reg_data, cpu_thread, bus)

    def is_lock_defined(self, lock_name):
        return self.Cfg.is_lock_defined(lock_name)

    def get_locked_value(self, lock_name):
        self.logger.log_debug('Retrieve value for lock {}'.format(lock_name))
        return int(self.Cfg.LOCKS[lock_name]['value'], 16)

    def get_lock_desc(self, lock_name):
        return self.Cfg.get_lock_desc(lock_name)

    def get_lock_type(self, lock_name):
        return self.Cfg.get_lock_type(lock_name)

    def get_lock_list(self):
        return self.Cfg.get_lock_list()

    def get_lock_mask(self, lock_name):
        lock = self.Cfg.LOCKS[lock_name]
        reg = lock['register']
        field = lock['field']
        return(self.get_register_field_mask(reg, field))

    def get_lockedby(self, lock_name):
        return self.Cfg.get_lockedby(lock_name)

    def is_all_value(self, reg_values, value):
        return all(n == value for n in reg_values)

    def get_IO_space(self, io_name):
        return self.Cfg.get_IO_space(io_name)

    def get_REGISTERS_match(self, name):
        return self.Cfg.get_REGISTERS_match(name)


_chipset = None


def cs():
    global _chipset
    from chipsec.helper.oshelper import helper
    if _chipset is None:
        _chipset = Chipset(helper())
    return _chipset
