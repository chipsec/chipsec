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
from typing import Dict, Tuple, Optional

from chipsec.helper.oshelper import helper as os_helper
from chipsec.helper.basehelper import Helper
from chipsec.helper.nonehelper import NoneHelper
from chipsec.hal.common.smbios import SMBIOS, SMBIOS_BIOS_INFO_ENTRY_ID, SMBIOS_SYSTEM_INFO_ENTRY_ID
from chipsec.hal.hals import Hals  # Hardware abstraction layer
from chipsec.library.options import Options
from chipsec.library.exceptions import UnknownChipsetError, OsHelperError
from chipsec.library.logger import logger
from chipsec.library.defines import ARCH_VID
from chipsec.library.register import Register
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


# Mapping from architecture VID to CPUID manufacturer string. Used to seed
# Cfg.mfgid when running without a helper, so HAL dispatch (which keys off
# mfgid) still selects the correct architecture-specific HALs.
_MFGID_BY_VID = {
    ARCH_VID.INTEL: 'GenuineIntel',
    ARCH_VID.AMD: 'AuthenticAMD',
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
        self._firmware_info: Optional[Dict[str, Optional[str]]] = None

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
        # The unknown flags only carry meaning when detection actually ran
        detection_performed = load_config and not ignore_platform

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

        self.Cfg.load()

        if load_config:
            self.init_cfg_bus()
            if start_helper:
                self.init_topology()
            else:
                # Seed a minimal topology so config parsers that reference CPU
                # (e.g. MSR scope handling) don't fail when running without a helper.
                self.Cfg.set_topology({'threads': 1, 'cores': {0: [0]}, 'packages': {0: [0]}})
                self.Cfg.set_mfgid(_MFGID_BY_VID.get(self.Cfg.vid, 'GenuineIntel'))
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
                        self.logger.log(f'[!]       {platform_msg}. No matching CPU configuration was found in '
                                        f'chipsec/cfg, so no platform configuration will be loaded and no registers '
                                        f'will be defined. Use -p <platform_code> to select a specific platform.')
            # Don't initialize config if platform is unknown
            if not _unknown_proc:
                self.Cfg.load_platform_config()
                # Load Bus numbers for this platform.
                if self.logger.DEBUG:
                    self.logger.log("[*] Discovering Bus Configuration:")
            if _unknown_pch and detection_performed:
                pch_msg = (f'Unknown PCH: VID = 0x{self.Cfg.pch_vid:04X}, DID = 0x{self.Cfg.pch_did:04X}, '
                           f'RID = 0x{self.Cfg.pch_rid:02X}')
                msg.append(pch_msg)
                if self.Cfg.is_pch_req() and start_helper:
                    error_msg = f'Chipset requires a supported PCH to be loaded. {msg[-1]}'
                    self.logger.log_error(error_msg)
                    raise_unknown_platform = True
                else:
                    self.logger.log(f'[!]       {pch_msg}. No matching PCH configuration was found in chipsec/cfg, '
                                    f'so PCH registers will not be defined. '
                                    f'Use --pch <pch_code> to select a specific PCH.')

        verbose_condition = (start_helper and ((self.logger.VERBOSE) or
                                               (detection_performed and (_unknown_pch or _unknown_proc))))
        if verbose_condition:
            pcilib.print_pci_devices(self.hals.pci.enumerate_devices(refresh=False))
        if detection_performed and (_unknown_pch or _unknown_proc):
            unknown_parts = ', '.join(p for p, unknown in (('CPU', _unknown_proc), ('PCH', _unknown_pch)) if unknown)
            msg.append(f'Unrecognized {unknown_parts}: register definitions may not match this system, '
                       f'so module results should not be trusted.')
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
            self.logger.log_warning(f'Failed to stop OS helper "{self.helper.name}". '
                                    f'The CHIPSEC driver/service may still be loaded on this system.')
        else:
            if not self.helper.delete():
                self.logger.log_warning(f'Failed to unload/delete OS helper "{self.helper.name}". '
                                        f'The CHIPSEC driver may need to be removed manually.')

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
        enum_devices_filename = None
        if reuse_scan:
            enum_devices_filename = self.options.get_section_data('PCI_Enum', 'enum_devices_filename', None)
            if not enum_devices_filename:
                self.logger.log_debug('[*] PCI_Enum.reuse_platform_detection is enabled but '
                                      'PCI_Enum.enum_devices_filename is not set. Falling back to a live PCI scan.')
                reuse_scan = False
        if reuse_scan:
            try:
                with open(enum_devices_filename) as enum_devices_file:
                    enum_devices = json.load(enum_devices_file)
            except (OSError, ValueError) as cache_err:
                self.logger.log_debug(f'[*] Unable to load cached PCI configuration from '
                                      f'"{enum_devices_filename}" ({cache_err}). Falling back to a live PCI scan.')
        if not enum_devices:
            try:
                enum_devices = self.hals.pci.enumerate_devices()
                if reuse_scan:
                    with open(enum_devices_filename, 'w') as enum_devices_file:
                        json.dump(enum_devices, enum_devices_file)
            except Exception as enum_err:
                self.logger.log_debug(f'[*] PCI device enumeration failed ({type(enum_err).__name__}: {enum_err}). '
                                      f'Platform detection and bus discovery will be incomplete.')
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

    # ###########################################################################
    # Scoping functions
    # ###########################################################################

    def set_scope(self, scope):
        """Set the current scope for register access."""
        self.Cfg.set_scope(scope)

    def clear_scope(self):
        """Clear the current scope for register access."""
        self.Cfg.clear_scope()

    def _get_helper_firmware_info(self) -> Dict[str, Optional[str]]:
        if self.helper is None:
            return {'vendor': None, 'product': None, 'version': None, 'type': None}
        return {
            'vendor': self.helper.firmware_vendor(),
            'product': self.helper.firmware_product(),
            'version': self.helper.firmware_version(),
            'type': self.helper.firmware_type()
        }

    def _get_smbios_string(self, string_index: int, strings) -> Optional[str]:
        if string_index == 0 or strings is None or string_index > len(strings):
            return None
        value = strings[string_index - 1].strip()
        return value or None

    def _get_driver_firmware_info(self) -> Dict[str, Optional[str]]:
        info = {'vendor': None, 'product': None, 'version': None, 'type': None}
        try:
            smbios = SMBIOS(self)
            if not smbios.find_smbios_table():
                return info

            bios_entries = smbios.get_decoded_structs(SMBIOS_BIOS_INFO_ENTRY_ID)
            if bios_entries:
                bios_info = bios_entries[0]
                info['vendor'] = self._get_smbios_string(bios_info.vendor_str, bios_info.strings)
                info['version'] = self._get_smbios_string(bios_info.version_str, bios_info.strings)

            system_entries = smbios.get_decoded_structs(SMBIOS_SYSTEM_INFO_ENTRY_ID)
            if system_entries:
                system_info = system_entries[0]
                info['product'] = self._get_smbios_string(system_info.product_str, system_info.strings)
        except Exception as err:
            self.logger.log_hal(f'[chipset] Unable to read firmware info from SMBIOS. Error: {err}')

        try:
            found, _, ect, _ = self.hals.uefi.find_EFI_Configuration_Table()
            info['type'] = 'UEFI' if found and ect is not None else 'BIOS'
        except Exception:
            pass

        return info

    def _get_firmware_info(self) -> Dict[str, Optional[str]]:
        if self._firmware_info is not None:
            return self._firmware_info

        helper_info = self._get_helper_firmware_info()
        if self.helper is not None and getattr(self.helper, 'driver_loaded', False):
            info = self._get_driver_firmware_info()
            for key, value in helper_info.items():
                if info[key] is None:
                    info[key] = value
        else:
            info = helper_info

        self._firmware_info = info
        return info

    def firmware_vendor(self) -> Optional[str]:
        return self._get_firmware_info()['vendor']

    def firmware_product(self) -> Optional[str]:
        return self._get_firmware_info()['product']

    def firmware_version(self) -> Optional[str]:
        return self._get_firmware_info()['version']

    def firmware_type(self) -> Optional[str]:
        return self._get_firmware_info()['type']


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
