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
import errno
import traceback
import json
from typing import Tuple, Type, Optional

from chipsec.helper.oshelper import helper as os_helper
from chipsec.helper.basehelper import Helper
from chipsec.helper.nonehelper import NoneHelper
from chipsec.hal.hals import Hals #cpu, io, iobar, mmio, msgbus, msr, pci, physmem, ucode, igd, cpuid, psp
from chipsec.library.options import Options
from chipsec.library.exceptions import UnknownChipsetError, OsHelperError
from chipsec.library.logger import logger
from chipsec.library.defines import ARCH_VID
from chipsec.library.register import Register, RegData
from chipsec.library.lock import Lock
from chipsec.library.control import Control
from chipsec.library.device import Device
from chipsec.library.pci import PCI as pcilib

from chipsec.config import Cfg, CHIPSET_CODE_UNKNOWN, PROC_FAMILY


# DEBUG Flags
QUIET_PCI_ENUM = True
LOAD_COMMON = True


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
        self.options = Options()
        self.logger = logger()
        self.helper = None
        self.os_helper = os_helper()
        self.init_hals_object()

    def init_hals_object(self):
        if hasattr(self, 'hals'):
            delattr(self, 'hals')
        self.hals = Hals(self)


    ##################################################################################
    #
    # Initialization
    #
    ##################################################################################
    def get_cpuid(self):
        return self.hals.CpuID.get_proc_info()

    @classmethod
    def basic_init_with_helper(cls, helper=None):
        _cs = cls()
        _cs.load_helper(helper)
        _cs.start_helper()
        return _cs

    def init(self, platform_code, req_pch_code, helper_name=None, start_helper=True, load_config=True, ignore_platform=False):
        self.using_return_codes = False
        self.consistency_checking = False

        self.lock = Lock(self)
        self.register = Register(self)
        self.control = Control(self)
        self.device = Device(self)
        raise_unknown_platform = False
        msg = []
        self.load_config = load_config
        _unknown_proc = True
        _unknown_pch = True

        # platform detection

        # get cpuid only if driver using driver (otherwise it will cause problems)
        self.cpuid = 0
        if start_helper:
            self.load_helper(helper_name)
            self.start_helper()
            # get cpuid only if using driver (otherwise it will cause problems)
            self.cpuid = self.get_cpuid()
        else:
            self.load_helper(NoneHelper())

        self.Cfg.load_parsers()
        self.Cfg.load_platform_info()

        if load_config:
            self.init_cfg_bus()
            self.init_topology()
            if not ignore_platform:
                self.Cfg.platform_detection(platform_code, req_pch_code, self.cpuid)
                _unknown_proc = not bool(self.Cfg.get_chipset_code())
                if self.Cfg.is_pch_req() is False or self.Cfg.get_pch_code() != CHIPSET_CODE_UNKNOWN:
                    _unknown_pch = False
                if _unknown_proc:
                    msg.append(f'Unknown Platform: VID = 0x{self.Cfg.vid:04X}, DID = 0x{self.Cfg.did:04X}, RID = 0x{self.Cfg.rid:02X}, CPUID = 0x{self.cpuid:X}')
                    if start_helper:
                        self.logger.log_error(msg[-1])
                        raise_unknown_platform = True
                    else:
                        self.logger.log(f'[!]       {msg}; Using Default.')
            if not _unknown_proc:  # Don't initialize config if platform is unknown
                self.Cfg.load_platform_config()
                # Load Bus numbers for this platform.
                if self.logger.DEBUG:
                    self.logger.log("[*] Discovering Bus Configuration:")
            if _unknown_pch:
                msg.append(f'Unknown PCH: VID = 0x{self.Cfg.pch_vid:04X}, DID = 0x{self.Cfg.pch_did:04X}, RID = 0x{self.Cfg.pch_rid:02X}')
                if self.Cfg.is_pch_req() and start_helper:
                    self.logger.log_error(f'Chipset requires a supported PCH to be loaded. {msg[-1]}')
                    raise_unknown_platform = True
                else:
                    self.logger.log(f'[!]       {msg[-1]}; Using Default.')
        if start_helper and ((self.logger.VERBOSE) or (load_config and (_unknown_pch or _unknown_proc))):
            pcilib.print_pci_devices(self.hals.Pci.enumerate_devices())
        if _unknown_pch or _unknown_proc:
            msg.append('Results from this system may be incorrect.')
            self.logger.log(f'[!]            {msg[-1]}')
        if raise_unknown_platform:
            raise UnknownChipsetError('\n'.join(msg))

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
        self.init_hals_object()

    def start_helper(self):
        try:
            if not self.helper.create():
                raise OsHelperError("failed to create OS helper", 1)
            if not self.helper.start():
                raise OsHelperError("failed to start OS helper", 1)
        except Exception as msg:
            self.logger.log_debug(traceback.format_exc())
            error_no = errno.ENXIO
            if hasattr(msg, 'errorcode'):
                error_no = msg.errorcode
            raise OsHelperError(f'Message: "{msg}"', error_no)

    def switch_helper(self, helper_name):
        oldName = self.helper.name
        self.destroy_helper()
        self.load_helper(helper_name)
        self.start_helper()
        return oldName

    def destroy_helper(self):
        if not self.helper.stop():
            self.logger.log_warning("failed to stop OS helper")
        else:
            if not self.helper.delete():
                self.logger.log_warning("failed to delete OS helper")

    def is_core(self):
        return self._check_proc_family("core")

    def is_server(self):
        return self._check_proc_family("xeon")

    def is_atom(self):
        return self._check_proc_family("atom")

    def _check_proc_family(self, proctype: str) -> bool:
        return self.Cfg.get_chipset_code() in PROC_FAMILY[proctype] if proctype in PROC_FAMILY else False

    def is_intel(self) -> bool:
        """Returns true if platform Vendor ID equals Intel VID"""
        return self.is_arch(ARCH_VID.INTEL)

    def is_amd(self) -> bool:
        """Returns true if platform Vendor ID equals AMD VID"""
        return self.is_arch(ARCH_VID.AMD)

    def is_arch(self, *arch_vid: int) -> bool:
        """Check support for multiple architecture VIDs"""
        return self.Cfg.vid in arch_vid

    def init_cfg_bus(self) -> None:
        enum_devices = {}
        self.logger.log_debug('[*] Loading device buses..')
        if QUIET_PCI_ENUM:
            old_log_state = self.save_log_state()
            self.set_log_state((False, False, False))
        reuse_scan = self.options.get_section_data('PCI_Enum', 'reuse_platform_detection', None)
        if reuse_scan:
            try:
                enum_devices_filename = self.options.get_section_data('PCI_Enum', 'enum_devices_filename', None)
                enum_devices = json.load(open(enum_devices_filename))
            except:
                self.logger.log_debug('[*] Unable to load cached PCI configuration.')
        if not enum_devices:
            try:
                enum_devices = self.hals.Pci.enumerate_devices()
                if reuse_scan:
                    json.dump(enum_devices, open(enum_devices_filename, 'w'))
            except Exception:
                self.logger.log_debug('[*] Unable to enumerate PCI devices.')
                enum_devices = []
        if QUIET_PCI_ENUM:
            self.set_log_state(old_log_state)
        self.Cfg.set_pci_data(enum_devices)

    def set_log_state(self, log_state: Tuple[bool, bool, bool]) -> None:
        self.logger.HAL, self.logger.DEBUG, self.logger.VERBOSE = log_state
        self.logger.setlevel()

    def save_log_state(self) -> Tuple[bool, bool, bool]:
        old_log_state = (self.logger.HAL, self.logger.DEBUG, self.logger.VERBOSE)
        return old_log_state
    
    def init_topology(self):
        self.logger.log_debug('[*] Gathering CPU Topology..')
        topology = self.hals.CPU.get_cpu_topology()
        self.Cfg.set_topology(topology)

    def is_all_value(self, regdata: Type[RegData], value: int, mask: Optional[int] = None) -> bool:
        if mask is None:
            return all(n.value == value for n in regdata)
        else:
            newvalue = value & mask
            return all((n.value & mask) == newvalue for n in regdata)

    def is_any_value(self, regdata: Type[RegData], value: int, mask: Optional[int] = None) -> bool:
        if mask is None:
            return any(n.value == value for n in regdata)
        else:
            newvalue = value & mask
            return any((n.value & mask) == newvalue for n in regdata)

    #####
    # Scoping functions
    #####
    def set_scope(self, scope):
        self.Cfg.set_scope(scope)

    def clear_scope(self):
        self.Cfg.clear_scope()

    def init_topology(self):
        self.logger.log_debug('[*] Gathering CPU Topology..')
        topology = self.hals.CPU.get_cpu_topology()
        self.Cfg.set_topology(topology)

    def is_all_value(self, regdata: Type[RegData], value: int, mask: Optional[int] = None) -> bool:
        if mask is None:
            return all(n.value == value for n in regdata)
        else:
            newvalue = value & mask
            return all((n.value & mask) == newvalue for n in regdata)

    def is_any_value(self, regdata: Type[RegData], value: int, mask: Optional[int] = None) -> bool:
        if mask is None:
            return any(n.value == value for n in regdata)
        else:
            newvalue = value & mask
            return any((n.value & mask) == newvalue for n in regdata)

    #####
    # Scoping functions
    #####
    def set_scope(self, scope):
        self.Cfg.set_scope(scope)

    def clear_scope(self):
        self.Cfg.clear_scope()

    def is_all_value(self, regdata: Type[RegData], value: int, mask: Optional[int] = None) -> bool:
        if mask is None:
            return all(n.value == value for n in regdata)
        else:
            newvalue = value & mask
            return all((n.value & mask) == newvalue for n in regdata)

    def is_any_value(self, regdata: Type[RegData], value: int, mask: Optional[int] = None) -> bool:
        if mask is None:
            return any(n.value == value for n in regdata)
        else:
            newvalue = value & mask
            return any((n.value & mask) == newvalue for n in regdata)

    #####
    # Scoping functions
    #####
    def set_scope(self, scope):
        self.Cfg.set_scope(scope)

    def clear_scope(self):
        self.Cfg.clear_scope()

_chipset = None


def cs() -> Chipset:
    global _chipset

    if _chipset is None:
        _chipset = Chipset()
    return _chipset
