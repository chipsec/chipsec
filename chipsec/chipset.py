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
from chipsec.hal.hals import Hals  # Hardware abstraction layer
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


# ###############################################################################
# Functionality defining current chipset
# ###############################################################################

PCH_ADDRESS = {
    # Intel: 0:1F.0
    ARCH_VID.INTEL: (0, 0x1F, 0),
    # AMD: 0:14.3
    ARCH_VID.AMD: (0, 0x14, 3)
}


class Chipset:
    """Main chipset detection and configuration management class.

    This class provides the core functionality for platform identification,
    hardware abstraction layer management, and configuration parsing.
    """

    def __init__(self):
        """Initialize the chipset object with default configuration."""
        self.Cfg = Cfg()
        self.options = Options()
        self.logger = logger()
        self.helper = None
        self.os_helper = os_helper()
        self.init_hals_object()

    def init_hals_object(self):
        """Initialize or reinitialize the hardware abstraction layer."""
        if hasattr(self, 'hals'):
            delattr(self, 'hals')
        self.hals = Hals(self)

    # ###########################################################################
    # Initialization
    # ###########################################################################

    def get_cpuid(self):
        """Get CPU identification information."""
        return self.hals.cpuid.get_proc_info()

    def get_mfgid(self) -> str:
        """Get CPU manufacturer identification."""
        return self.hals.cpuid.get_mfgid()

    @classmethod
    def basic_init_with_helper(cls, helper=None):
        """Create and initialize a chipset instance with a specific helper.

        Args:
            helper: The helper instance to use for hardware access

        Returns:
            Initialized Chipset instance
        """
        _cs = cls()
        _cs.load_helper(helper)
        _cs.start_helper()
        return _cs

    def init(self, platform_code, req_pch_code, helper_name=None, start_helper=True,
             load_config=True, ignore_platform=False):
        """Initialize the chipset with platform detection and configuration.

        Args:
            platform_code: Platform code to force detection
            req_pch_code: PCH code to force detection
            helper_name: Name of helper to use for hardware access
            start_helper: Whether to start the helper immediately
            load_config: Whether to load platform configuration
            ignore_platform: Whether to skip platform detection

        Raises:
            UnknownChipsetError: If platform cannot be detected
        """
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

        # Platform detection
        cpuid = 0
        if start_helper:
            self.load_helper(helper_name)
            self.start_helper()
            # Get CPUID only if using driver (otherwise it will cause problems)
            cpuid = self.get_cpuid()
            mfgid = self.get_mfgid()
            self.Cfg.set_cpuid(cpuid)
            self.Cfg.set_mfgid(mfgid)
        else:
            self.load_helper(NoneHelper())

        self.Cfg.load_parsers()
        self.Cfg.load_platform_info()

        if load_config:
            self.init_cfg_bus()
            self.init_topology()
            if not ignore_platform:
                self.Cfg.platform_detection(platform_code, req_pch_code, cpuid)
                _unknown_proc = not bool(self.Cfg.get_chipset_code())
                pch_req_condition = (self.Cfg.is_pch_req() is False or
                                     self.Cfg.get_pch_code() != CHIPSET_CODE_UNKNOWN)
                if pch_req_condition:
                    _unknown_pch = False
                if _unknown_proc:
                    platform_msg = (f'Unknown Platform: VID = 0x{self.Cfg.vid:04X}, '
                                    f'DID = 0x{self.Cfg.did:04X}, RID = 0x{self.Cfg.rid:02X}, '
                                    f'CPUID = 0x{cpuid:X}')
                    msg.append(platform_msg)
                    if start_helper:
                        self.logger.log_error(msg[-1])
                        raise_unknown_platform = True
                    else:
                        self.logger.log(f'[!]       {msg}; Using Default.')
            # Don't initialize config if platform is unknown
            if not _unknown_proc:
                self.Cfg.load_platform_config()
                # Load Bus numbers for this platform.
                if self.logger.DEBUG:
                    self.logger.log("[*] Discovering Bus Configuration:")
            if _unknown_pch:
                pch_msg = (f'Unknown PCH: VID = 0x{self.Cfg.pch_vid:04X}, DID = 0x{self.Cfg.pch_did:04X}, '
                           f'RID = 0x{self.Cfg.pch_rid:02X}')
                msg.append(pch_msg)
                if self.Cfg.is_pch_req() and start_helper:
                    error_msg = f'Chipset requires a supported PCH to be loaded. {msg[-1]}'
                    self.logger.log_error(error_msg)
                    raise_unknown_platform = True
                else:
                    self.logger.log(f'[!]       {msg[-1]}; Using Default.')

        verbose_condition = (start_helper and ((self.logger.VERBOSE) or
                                               (load_config and (_unknown_pch or _unknown_proc))))
        if verbose_condition:
            pcilib.print_pci_devices(self.hals.pci.enumerate_devices())
        if _unknown_pch or _unknown_proc:
            msg.append('Results from this system may be incorrect.')
            self.logger.log(f'[!]            {msg[-1]}')
        if raise_unknown_platform:
            raise UnknownChipsetError('\n'.join(msg))

    def load_helper(self, helper_name):
        """Load and initialize a hardware helper.

        Args:
            helper_name: Name or instance of the helper to load

        Raises:
            OsHelperError: If the specified helper cannot be found or loaded
        """
        if helper_name:
            if isinstance(helper_name, Helper):
                self.helper = helper_name
            else:
                self.helper = self.os_helper.get_helper(helper_name)
                if self.helper is None:
                    error_msg = f'Helper named {helper_name} not found in available helpers'
                    raise OsHelperError(error_msg, 1)
        else:
            self.helper = self.os_helper.get_default_helper()
        self.init_hals_object()

    def start_helper(self):
        """Start the hardware helper.

        Raises:
            OsHelperError: If the helper fails to start
        """
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
        """Switch to a different hardware helper.

        Args:
            helper_name: Name of the new helper to switch to

        Returns:
            str: Name of the previous helper
        """
        oldName = self.helper.name
        self.destroy_helper()
        self.load_helper(helper_name)
        self.start_helper()
        return oldName

    def destroy_helper(self):
        """Clean up and destroy the current hardware helper."""
        if not self.helper.stop():
            self.logger.log_warning("failed to stop OS helper")
        else:
            if not self.helper.delete():
                self.logger.log_warning("failed to delete OS helper")

    def is_core(self):
        """Check if platform is Core processor family."""
        return self._check_proc_family("core")

    def is_server(self):
        """Check if platform is Xeon server processor family."""
        return self._check_proc_family("xeon")

    def is_atom(self):
        """Check if platform is Atom processor family."""
        return self._check_proc_family("atom")

    def _check_proc_family(self, proctype: str) -> bool:
        """Check if current platform belongs to specified processor family.

        Args:
            proctype: Processor family type to check

        Returns:
            bool: True if platform belongs to the specified family
        """
        if proctype not in PROC_FAMILY:
            return False
        return self.Cfg.get_chipset_code() in PROC_FAMILY[proctype]

    def is_intel(self) -> bool:
        """Returns true if platform Vendor ID equals Intel VID."""
        return self.is_arch(ARCH_VID.INTEL)

    def is_amd(self) -> bool:
        """Returns true if platform Vendor ID equals AMD VID."""
        return self.is_arch(ARCH_VID.AMD)

    def is_arch(self, *arch_vid: int) -> bool:
        """Check support for multiple architecture VIDs.

        Args:
            *arch_vid: Variable number of architecture VIDs to check

        Returns:
            bool: True if platform VID matches any of the provided VIDs
        """
        return self.Cfg.vid in arch_vid

    def init_cfg_bus(self) -> None:
        """Initialize PCI bus configuration by enumerating devices."""
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
            except (IOError, json.JSONDecodeError):
                self.logger.log_debug('[*] Unable to load cached PCI configuration.')
        if not enum_devices:
            try:
                enum_devices = self.hals.pci.enumerate_devices()
                if reuse_scan:
                    json.dump(enum_devices, open(enum_devices_filename, 'w'))
            except Exception:
                self.logger.log_debug('[*] Unable to enumerate PCI devices.')
                enum_devices = []
        if QUIET_PCI_ENUM:
            self.set_log_state(old_log_state)
        self.Cfg.set_pci_data(enum_devices)

    def set_log_state(self, log_state: Tuple[bool, bool, bool]) -> None:
        """Set logger state for HAL, DEBUG, and VERBOSE flags."""
        self.logger.HAL, self.logger.DEBUG, self.logger.VERBOSE = log_state
        self.logger.setlevel()

    def save_log_state(self) -> Tuple[bool, bool, bool]:
        """Save current logger state."""
        return (self.logger.HAL, self.logger.DEBUG, self.logger.VERBOSE)

    def init_topology(self):
        """Initialize CPU topology information."""
        self.logger.log_debug('[*] Gathering CPU Topology..')
        topology = self.hals.cpu.get_cpu_topology()
        self.Cfg.set_topology(topology)

    def is_all_value(self, regdata: Type[RegData], value: int, mask: Optional[int] = None) -> bool:
        """Check if all register data values match the specified value.

        Args:
            regdata: Register data to check
            value: Value to compare against
            mask: Optional mask to apply before comparison

        Returns:
            bool: True if all values match
        """
        if mask is None:
            return all(n.value == value for n in regdata)
        else:
            newvalue = value & mask
            return all((n.value & mask) == newvalue for n in regdata)

    def is_any_value(self, regdata: Type[RegData], value: int, mask: Optional[int] = None) -> bool:
        """Check if any register data values match the specified value.

        Args:
            regdata: Register data to check
            value: Value to compare against
            mask: Optional mask to apply before comparison

        Returns:
            bool: True if any values match
        """
        if mask is None:
            return any(n.value == value for n in regdata)
        else:
            newvalue = value & mask
            return any((n.value & mask) == newvalue for n in regdata)

    # ###########################################################################
    # Scoping functions
    # ###########################################################################

    def set_scope(self, scope):
        """Set the current scope for register access."""
        self.Cfg.set_scope(scope)

    def clear_scope(self):
        """Clear the current scope for register access."""
        self.Cfg.clear_scope()


# ###############################################################################
# Global chipset management
# ###############################################################################

_chipset = None


def clear_cs():
    """Clear the global chipset instance."""
    global _chipset
    _chipset = None


def cs() -> Chipset:
    """Get or create the global chipset instance.

    Returns:
        Chipset: The global chipset instance
    """
    global _chipset
    if _chipset is None:
        _chipset = Chipset()
    return _chipset
