# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2022, Intel Corporation
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

from chipsec.helper.oshelper import helper as os_helper
from chipsec.helper.basehelper import Helper
from chipsec.helper.nonehelper import NoneHelper
from chipsec.hal import cpu, io, iobar, mmio, msgbus, msr, pci, physmem, ucode, igd, cpuid
from chipsec.hal.pci import PCI_HDR_RID_OFF
from chipsec.exceptions import UnknownChipsetError, DeviceNotFoundError, CSReadError
from chipsec.exceptions import RegisterTypeNotFoundError, OsHelperError

from chipsec.logger import logger
from chipsec.defines import is_hex, is_all_ones, ARCH_VID

from chipsec.config import Cfg, CHIPSET_CODE_UNKNOWN, PROC_FAMILY


# DEBUG Flags
QUIET_PCI_ENUM = True
LOAD_COMMON = True
CONSISTENCY_CHECKING = False


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

PCH_ADDRESS = {
    # Intel: 0:1F.0
    ARCH_VID.INTEL: (0, 0x1F, 0),
    # AMD: 0:14.3
    ARCH_VID.AMD: (0, 0x14, 3)
}


class Chipset:

    def __init__(self):
        self.Cfg = Cfg()
        self.helper = None
        self.os_helper = os_helper()
        self.set_hal_objects()
        self.Cfg.load_parsers()
        self.Cfg.load_platform_info()
        self.using_return_codes = False
    def set_hal_objects(self):
        #
        # Initializing 'basic primitive' HAL components
        # (HAL components directly using native OS helper functionality)
        #
        self.pci = pci.Pci(self)
        self.mem = physmem.Memory(self)
        self.msr = msr.Msr(self)
        self.ucode = ucode.Ucode(self)
        self.io = io.PortIO(self)
        self.cpu = cpu.CPU(self)
        self.msgbus = msgbus.MsgBus(self)
        self.mmio = mmio.MMIO(self)
        self.iobar = iobar.IOBAR(self)
        self.igd = igd.IGD(self)
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
    def get_cpuid(self):
        _cpuid = cpuid.CpuID(self)
        return _cpuid.get_proc_info()

    @classmethod
    def basic_init_with_helper(cls, helper = None):
        _cs = cls()
        _cs.load_helper(helper)
        _cs.start_helper()
        return _cs
    def init(self, platform_code, req_pch_code, helper_name=None, start_helper=True, load_config=True, ignore_platform=False):
        self.reqs_pch = None
        self.load_config = load_config
        _unknown_proc = True
        _unknown_pch = True

        # platform detection

        # get cpuid only if driver using driver (otherwise it will cause problems)
        self.cpuid = None
        if start_helper:
            self.load_helper(helper_name)
            self.start_helper()
            # get cpuid only if using driver (otherwise it will cause problems)
            self.cpuid = self.get_cpuid() 
        else:
            self.load_helper(NoneHelper())
        self.init_cfg_bus()
        if load_config:
            if not ignore_platform:
                self.Cfg.platform_detection(platform_code, req_pch_code, self.cpuid)
                _unknown_proc = self.Cfg.get_chipset_code() is None
                _unknown_pch = self.Cfg.is_pch_req() and self.Cfg.get_pch_code() == CHIPSET_CODE_UNKNOWN

                if _unknown_proc:
                    msg = 'Unknown Platform: VID = 0x{:04X}, DID = 0x{:04X}, RID = 0x{:02X}'.format(self.Cfg.vid, self.Cfg.did, self.Cfg.rid)
                    if start_driver:
                        logger().log_error(msg)
                        raise UnknownChipsetError(msg)
                    else:
                        logger().log("[!]       {}; Using Default.".format(msg))
            if not _unknown_proc:  # Don't initialize config if platform is unknown
                self.Cfg.load_platform_config()
                # Load Bus numbers for this platform.
                if logger().DEBUG:
                    logger().log("[*] Discovering Bus Configuration:")
            if _unknown_pch:
                msg = 'Unknown PCH: VID = 0x{:04X}, DID = 0x{:04X}, RID = 0x{:02X}'.format(self.Cfg.pch_vid, self.Cfg.pch_did, self.Cfg.pch_rid)
                if self.reqs_pch and start_driver:
                    logger().log_error("Chipset requires a supported PCH to be loaded. {}".format(msg))
                    raise UnknownChipsetError(msg)
                else:
                    logger().log("[!]       {}; Using Default.".format(msg))
        if _unknown_pch or _unknown_proc:
            msg = 'Results from this system may be incorrect.'
            logger().log("[!]            {}".format(msg))



    def load_helper(self, helper_name):
        if helper_name:
            if isinstance(helper_name, Helper):
                self.helper = helper_name
            else:
                self.helper = self.os_helper.get_helper(helper_name)
                if self.helper is None:
                    raise OsHelperError(f'Helper named {helper_name} not found in available helpers', 1)
        else:
            self.helper = self.os_helper.get_default_helper()
        self.set_hal_objects()

    def start_helper(self):
        try:
            if not self.helper.create():
                raise OsHelperError("failed to create OS helper", 1)
            if not self.helper.start():
                raise OsHelperError("failed to start OS helper", 1)
        except Exception as msg:
            logger().log_debug(traceback.format_exc())
            error_no = ENXIO
            if hasattr(msg, 'errorcode'):
                error_no = msg.errorcode
            raise OsHelperError("Message: \"{}\"".format(msg), error_no)
        

    def switch_helper(self, helper_name):
        oldName = self.helper.name
        self.destroy_helper()
        self.load_helper(helper_name)
        self.start_helper()
        return oldName

    def destroy_helper(self):
        if not self.helper.stop():
            logger().log_warning("failed to stop OS helper")
        else:
            if not self.helper.delete():
                logger().log_warning("failed to delete OS helper")

    def is_core(self):
        return self.Cfg.get_chipset_code() in PROC_FAMILY["core"]

    def is_server(self):
        return self.Cfg.get_chipset_code() in PROC_FAMILY["xeon"]

    def is_atom(self):
        return self.Cfg.get_chipset_code() in PROC_FAMILY["atom"]

    def is_intel(self) -> bool:
        """Returns true if platform Vendor ID equals Intel VID"""
        return self.is_arch(ARCH_VID.INTEL)

    def is_amd(self) -> bool:
        """Returns true if platform Vendor ID equals AMD VID"""
        return self.is_arch(ARCH_VID.AMD)

    def is_arch(self, *arch_vid: int) -> bool:
        """Check support for multiple architecture VIDs"""
        return self.Cfg.vid in arch_vid

    def init_cfg_bus(self):
        logger().log_debug('[*] Loading device buses..')
        if QUIET_PCI_ENUM:
            old_log_state = (logger().HAL, logger().DEBUG, logger().VERBOSE)
            logger().HAL, logger().DEBUG, logger().VERBOSE = (False, False, False)
            logger().setlevel()
        try:
            enum_devices = self.pci.enumerate_devices()
        except Exception:
            logger().log_debug('[*] Unable to enumerate PCI devices.')
            enum_devices = []
        if QUIET_PCI_ENUM:
            logger().HAL, logger().DEBUG, logger().VERBOSE = old_log_state
            logger().setlevel()
        self.Cfg.set_pci_data(enum_devices)


    ##################################################################################
    #
    # Functions which access configuration of integrated PCI devices (interfaces, controllers)
    # by device name (defined in XML configuration files)
    #
    ##################################################################################

    def get_device_BDF(self, device_name):
        device = self.Cfg.CONFIG_PCI[device_name]
        if device is None or device == {}:
            raise DeviceNotFoundError('DeviceNotFound: {}'.format(device_name))
        b = device['bus']
        d = device['dev']
        f = device['fun']
        return (b, d, f)

    def get_DeviceVendorID(self, device_name):
        (b, d, f) = self.get_device_BDF(device_name)
        return self.pci.get_DIDVID(b, d, f)

    def is_device_enabled(self, device_name):
        if self.is_device_defined(device_name):
            (b, d, f) = self.get_device_BDF(device_name)
            return self.pci.is_enabled(b, d, f)
        return False

    def is_register_device_enabled(self, reg_name, bus=None):
        if reg_name in self.Cfg.REGISTERS:
            reg = self.get_register_def(reg_name)
            rtype = reg['type']
            if (rtype == RegisterType.MMCFG) or (rtype == RegisterType.PCICFG):
                if bus is not None:
                    b = bus
                else:
                    b = reg['bus']
                d = reg['dev']
                f = reg['fun']
                return self.pci.is_enabled(b, d, f)
            elif (rtype == RegisterType.MMIO):
                bar_name = reg['bar']
                return self.mmio.is_MMIO_BAR_enabled(bar_name, bus)
        return False

    def switch_device_def(self, target_dev, source_dev):
        (b, d, f) = self.get_device_BDF(source_dev)
        self.Cfg.CONFIG_PCI[target_dev]['bus'] = str(b)
        self.Cfg.CONFIG_PCI[target_dev]['dev'] = str(d)
        self.Cfg.CONFIG_PCI[target_dev]['fun'] = str(f)

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
        if self.Cfg.CONFIG_PCI.get(dev_name, None) is None:
            return False
        else:
            return True

    def get_register_def(self, reg_name):
        reg_def = self.Cfg.REGISTERS[reg_name]
        if "device" in reg_def:
            dev_name = reg_def["device"]
            if reg_def["type"] in ["pcicfg", "mmcfg"]:
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
                    logger().log_error(f'Memory device {dev_name} not found')
            elif reg_def["type"] == "indirect":
                if dev_name in self.Cfg.IMA_REGISTERS:
                    dev = self.Cfg.IMA_REGISTERS[dev_name]
                    if ('base' in dev):
                        reg_def['base'] = dev['base']
                    else:
                        reg_def['base'] = "0"
                    if (dev['index'] in self.Cfg.REGISTERS):
                        reg_def['index'] = dev['index']
                    else:
                        logger().log_error(f'Index register {dev["index"]} not found')
                    if (dev['data'] in self.Cfg.REGISTERS):
                        reg_def['data'] = dev['data']
                    else:
                        logger().log_error(f'Data register {dev["data"]} not found')
                else:
                    logger().log_error(f'Indirect access device {dev_name} not found')
        return reg_def

    def get_register_bus(self, reg_name):
        device = self.Cfg.REGISTERS[reg_name].get('device', '')
        if not device:
            if logger().DEBUG:
                logger().log_important(f"No device found for '{reg_name}'")
            if 'bus' in self.Cfg.REGISTERS[reg_name]:
                return [self.Cfg.REGISTERS[reg_name]['bus']]
            else:
                return []
        return self.get_device_bus(device)

    def get_device_bus(self, dev_name):
        buses = self.Cfg.BUS.get(dev_name, [])
        if buses:
            if logger().DEBUG:
                logger().log_important(f"Using discovered bus values for device '{dev_name}'")
            return buses
        if 'bus' in self.Cfg.CONFIG_PCI[dev_name]:
            (bus, dev, fun) = self.get_device_BDF(dev_name)
            if self.pci.is_enabled(bus, dev, fun):
                if logger().DEBUG:
                    logger().log_important(f"Using pre-defined bus values for device '{dev_name}'")
                buses = [bus]
            else:
                if logger().DEBUG:
                    logger().log_important(f"Device '{dev_name}' not enabled")
        else:
            if logger().DEBUG:
                logger().log_important(f"No bus value defined for device '{dev_name}'")
        return buses

    def read_register(self, reg_name, cpu_thread=0, bus=None, do_check=True):
        reg = self.get_register_def(reg_name)
        rtype = reg['type']
        reg_value = 0
        if (RegisterType.PCICFG == rtype) or (RegisterType.MMCFG == rtype):
            if bus is not None:
                b = bus
            else:
                b = reg['bus']
            d = reg['dev']
            f = reg['fun']
            o = reg['offset']
            size = reg['size']
            if do_check and CONSISTENCY_CHECKING:
                if self.pci.get_DIDVID(b, d, f) == (0xFFFF, 0xFFFF):
                    raise CSReadError(f'PCI Device is not available ({b}:{d}.{f})')
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
                reg_value = self.mmio.read_MMIO_BAR_reg(reg['bar'], reg['offset'], reg['size'], _bus)
            else:
                raise CSReadError(f'MMIO Bar ({reg["bar"]}) base address is 0')
        elif RegisterType.MSR == rtype:
            (eax, edx) = self.msr.read_msr(cpu_thread, reg['msr'])
            reg_value = (edx << 32) | eax
        elif RegisterType.PORTIO == rtype:
            port = reg['port']
            size = reg['size']
            reg_value = self.io._read_port(port, size)
        elif RegisterType.IOBAR == rtype:
            if self.iobar.get_IO_BAR_base_address(reg['bar'])[0] != 0:
                reg_value = self.iobar.read_IO_BAR_reg(reg['bar'], reg['offset'], reg['size'])
            else:
                raise CSReadError(f'IO Bar ({reg["bar"]}) base address is 0')
        elif RegisterType.MSGBUS == rtype:
            reg_value = self.msgbus.msgbus_reg_read(reg['port'], reg['offset'])
        elif RegisterType.MM_MSGBUS == rtype:
            reg_value = self.msgbus.mm_msgbus_reg_read(reg['port'], reg['offset'])
        elif RegisterType.MEMORY == rtype:
            if reg['access'] == 'dram':
                size = reg['size']
                if 1 == size:
                    reg_value = self.mem.read_physical_mem_byte(reg['address'])
                elif 2 == size:
                    reg_value = self.mem.read_physical_mem_word(reg['address'])
                elif 4 == size:
                    reg_value = self.mem.read_physical_mem_dword(reg['address'])
                elif 8 == size:
                    reg_value = self.mem.read_physical_mem_qword(reg['address'])
            elif reg['access'] == 'mmio':
                reg_value = self.mmio.read_MMIO_reg(reg['address'], reg['offset'], reg['size'])
        elif RegisterType.IMA == rtype:
            self.write_register(reg['index'], reg['offset'] + reg['base'])
            reg_value = self.read_register(reg['data'])
        else:
            raise RegisterTypeNotFoundError(f'Register type not found: {rtype}')

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
        if (RegisterType.PCICFG == rtype) or (RegisterType.MMCFG == rtype):
            if bus is not None:
                b = bus
            else:
                b = reg['bus']
            d = reg['dev']
            f = reg['fun']
            o = reg['offset']
            size = reg['size']
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
            self.mmio.write_MMIO_BAR_reg(reg['bar'], reg['offset'], reg_value, reg['size'], bus)
        elif RegisterType.MSR == rtype:
            eax = (reg_value & 0xFFFFFFFF)
            edx = ((reg_value >> 32) & 0xFFFFFFFF)
            self.msr.write_msr(cpu_thread, reg['msr'], eax, edx)
        elif RegisterType.PORTIO == rtype:
            port = reg['port']
            size = reg['size']
            self.io._write_port(port, reg_value, size)
        elif RegisterType.IOBAR == rtype:
            self.iobar.write_IO_BAR_reg(reg['bar'], reg['offset'], reg['size'], reg_value)
        elif RegisterType.MSGBUS == rtype:
            self.msgbus.msgbus_reg_write(reg['port'], reg['offset'], reg_value)
        elif RegisterType.MM_MSGBUS == rtype:
            self.msgbus.mm_msgbus_reg_write(reg['port'], reg['offset'], reg_value)
        elif RegisterType.MEMORY == rtype:
            if reg['access'] == 'dram':
                self.mem.write_physical_mem(reg['address'], reg['size'], reg_value)
            elif reg['access'] == 'mmio':
                self.mmio.write_MMIO_reg(reg['address'], reg['offset'], reg_value, reg['size'])
        elif RegisterType.IMA == rtype:
            self.write_register(reg['index'], reg['offset'] + reg['base'])
            self.write_register(reg['data'], reg_value)
        else:
            raise RegisterTypeNotFoundError(f'Register type not found: {rtype}')
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
            mask = (1 << (reg_def['size'] * 8)) - 1
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
        except:
            ret = None
        return ret

    def write_register_field_all(self, reg_name, field_name, field_value, preserve_field_position=False, cpu_thread=0):
        reg_values = self.read_register_all(reg_name, cpu_thread)
        reg_values_new = self.set_register_field_all(reg_name, reg_values, field_name, field_value, preserve_field_position)
        return self.write_register_all(reg_name, reg_values_new, cpu_thread)

    def register_has_field(self, reg_name, field_name):
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
            sorted_fields = sorted(reg_def['FIELDS'].items(), key=lambda field: int(field[1]['bit']))
            for f in sorted_fields:
                field_attrs = f[1]
                field_bit = int(field_attrs['bit'])
                field_size = int(field_attrs['size'])
                field_mask = 0
                for i in range(field_size):
                    field_mask = (field_mask << 1) | 1
                field_value = (reg_val >> field_bit) & field_mask
                field_desc = f' << {field_attrs["desc"]} ' if (field_attrs['desc'] != '') else ''
                reg_fields_str += f'    [{field_bit:02d}] {f[0]:16} = {field_value:X}{field_desc}\n'

        if '' != reg_fields_str:
            reg_fields_str = reg_fields_str[:-1]
        return reg_fields_str

    def print_register(self, reg_name, reg_val, bus=None, cpu_thread=0):
        reg = self.get_register_def(reg_name)
        rtype = reg['type']
        reg_str = ''
        reg_width = reg["size"] * 2
        reg_val_str = f'0x{reg_val:0{reg_width:d}X}'
        if RegisterType.PCICFG == rtype or RegisterType.MMCFG == rtype:
            if bus is not None:
                b = bus
            else:
                b = reg['bus']
            d = reg['dev']
            f = reg['fun']
            o = reg['offset']
            mmcfg_off_str = ''
            if RegisterType.MMCFG == rtype:
                mmcfg_off = (b * 32 * 8 + d * 8 + f) * 0x1000 + o
                mmcfg_off_str += f', MMCFG + 0x{mmcfg_off:X}'
            reg_str = f'[*] {reg_name} = {reg_val_str} << {reg["desc"]} (b:d.f {b:02d}:{d:02d}.{f:d} + 0x{o:X}{mmcfg_off_str})'
        elif RegisterType.MMIO == rtype:
            reg_str = f'[*] {reg_name} = {reg_val_str} << {reg["desc"]} ({reg["bar"]} + 0x{reg["offset"]:X})'
        elif RegisterType.MSR == rtype:
            reg_str = f'[*] {reg_name} = {reg_val_str} << {reg["desc"]} (MSR 0x{reg["msr"]:X} Thread 0x{cpu_thread:X})'
        elif RegisterType.PORTIO == rtype:
            reg_str = f'[*] {reg_name} = {reg_val_str} << {reg["desc"]} (I/O port 0x{reg["port"]:X})'
        elif RegisterType.IOBAR == rtype:
            reg_str = f'[*] {reg_name} = {reg_val_str} << {reg["desc"]} (I/O {reg["bar"]} + 0x{reg["offset"]:X})'
        elif RegisterType.MSGBUS == rtype or RegisterType.MM_MSGBUS == rtype:
            reg_str = f'[*] {reg_name} = {reg_val_str} << {reg["desc"]} (msgbus port 0x{reg["port"]:X}, off 0x{reg["offset"]:X})'
        elif RegisterType.IMA == rtype:
            reg_str = f'[*] {reg_name} = {reg_val_str} << {reg["desc"]} (indirect access via {reg["index"]}/{reg["data"]}, base 0x{reg["base"]:X}, off 0x{reg["offset"]:X})'
        else:
            reg_str = f'[*] {reg_name} = {reg_val_str} << {reg["desc"]}'

        reg_str += self._register_fields_str(reg, reg_val)
        logger().log(reg_str)
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
        elif rtype in [RegisterType.MMCFG, RegisterType.PCICFG, RegisterType.MMIO] and bus_data:
            for bus in bus_data:
                reg_val = self.read_register(reg_name, cpu_thread, bus)
                reg_str += self.print_register(reg_name, reg_val, bus)
        else:
            reg_val = self.read_register(reg_name, cpu_thread)
            reg_str = self.print_register(reg_name, reg_val)
        return reg_str

    def get_control(self, control_name, cpu_thread=0, with_print=False):
        control = self.Cfg.CONTROLS[control_name]
        reg = control['register']
        field = control['field']
        reg_data = self.read_register(reg, cpu_thread)
        if logger().VERBOSE or with_print:
            self.print_register(reg, reg_data)
        return self.get_register_field(reg, reg_data, field)

    def set_control(self, control_name, control_value, cpu_thread=0):
        control = self.Cfg.CONTROLS[control_name]
        reg = control['register']
        field = control['field']
        return self.write_register_field(reg, field, control_value, cpu_thread=cpu_thread)

    def is_control_defined(self, control_name):
        try:
            return (self.Cfg.CONTROLS[control_name] is not None)
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
        reg = lock['register']
        field = lock['field']
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
                logger().log("Register has no data")
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
        return lock_name in self.Cfg.LOCKS.keys()

    def get_locked_value(self, lock_name):
        if logger().DEBUG:
            logger().log(f'Retrieve value for lock {lock_name}')
        return self.Cfg.LOCKS[lock_name]['value']

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
        reg = lock['register']
        field = lock['field']
        return self.get_register_field_mask(reg, field)

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

    def is_register_all_ffs(self, reg_name, value):
        if self.register_is_msr(reg_name):
            size = 8
        else:
            size = self.get_register_def(reg_name)['size']
        return is_all_ones(value, size)

    def is_field_all_ones(self, reg_name, field_name, value):
        reg_def = self.get_register_def(reg_name)
        size = reg_def['FIELDS'][field_name]['size']
        return is_all_ones(value, size, 1)

    def is_control_all_ffs(self, control_name, cpu_thread=0, field_only=False):
        if self.is_control_defined(control_name) is None:
            if logger().DEBUG:
                logger().log_error(f"Control '{control_name}' not defined.")
            return True
        control = self.Cfg.CONTROLS[control_name]
        reg_def = control['register']
        reg_data = self.read_register(reg_def, cpu_thread)
        if field_only:
            reg_field = control['field']
            reg_data = self.get_register_field(reg_def, reg_data, reg_field)
            result = self.is_field_all_ones(reg_def, reg_field, reg_data)
        else:
            result = self.is_register_all_ffs(reg_def, reg_data)
        return result


_chipset = None


def cs():
    global _chipset

    if _chipset is None:
        _chipset = Chipset()
    return _chipset
