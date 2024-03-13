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
from typing import Tuple

from chipsec.helper.oshelper import helper as os_helper
from chipsec.helper.basehelper import Helper
from chipsec.helper.nonehelper import NoneHelper
from chipsec.hal import cpu, io, iobar, mmio, msgbus, msr, pci, physmem, ucode, igd, cpuid
from chipsec.library.exceptions import UnknownChipsetError, OsHelperError

from chipsec.library.logger import logger
from chipsec.library.defines import ARCH_VID
from chipsec.library.register import Register
from chipsec.library.lock import Lock
from chipsec.library.control import Control
from chipsec.library.device import Device

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
        self.helper = None
        self.os_helper = os_helper()
        self.set_hal_objects()
        self.Cfg.load_parsers()
        self.Cfg.load_platform_info()
        self.using_return_codes = False
        self.consistency_checking = False
        self.lock = Lock(self)
        self.register = Register(self)
        self.control = Control(self)
        self.device = Device(self)

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
                _unknown_proc = not bool(self.Cfg.get_chipset_code())
                if self.Cfg.is_pch_req() == False or self.Cfg.get_pch_code() != CHIPSET_CODE_UNKNOWN:
                    _unknown_pch = False
                if _unknown_proc:
                    msg = f'Unknown Platform: VID = 0x{self.Cfg.vid:04X}, DID = 0x{self.Cfg.did:04X}, RID = 0x{self.Cfg.rid:02X}, CPUID = 0x{self.cpuid:X}'
                    if start_helper:
                        logger().log_error(msg)
                        raise UnknownChipsetError(msg)
                    else:
                        logger().log(f'[!]       {msg}; Using Default.')
            if not _unknown_proc:  # Don't initialize config if platform is unknown
                self.Cfg.load_platform_config()
                # Load Bus numbers for this platform.
                if logger().DEBUG:
                    logger().log("[*] Discovering Bus Configuration:")
            if _unknown_pch:
                msg = f'Unknown PCH: VID = 0x{self.Cfg.pch_vid:04X}, DID = 0x{self.Cfg.pch_did:04X}, RID = 0x{self.Cfg.pch_rid:02X}'
                if self.Cfg.is_pch_req() and start_helper:
                    logger().log_error(f'Chipset requires a supported PCH to be loaded. {msg}')
                    raise UnknownChipsetError(msg)
                else:
                    logger().log(f'[!]       {msg}; Using Default.')
        if start_helper and ((logger().VERBOSE) or (load_config and (_unknown_pch or _unknown_proc))):
            pci.print_pci_devices(self.pci.enumerate_devices())
        if _unknown_pch or _unknown_proc:
            msg = 'Results from this system may be incorrect.'
            logger().log(f'[!]            {msg}')

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

    def init_cfg_bus(self) -> None:
        logger().log_debug('[*] Loading device buses..')
        old_log_state = (False, False, False)
        if QUIET_PCI_ENUM:
            old_log_state = self.save_log_state()
            self.set_log_state((False, False, False))
        try:
            enum_devices = self.pci.enumerate_devices()
        except Exception:
            logger().log_debug('[*] Unable to enumerate PCI devices.')
            enum_devices = []
        if QUIET_PCI_ENUM:
            self.set_log_state(old_log_state)
        self.Cfg.set_pci_data(enum_devices)

    def set_log_state(self, log_state: Tuple[bool, bool, bool]) -> None:
        logger().HAL, logger().DEBUG, logger().VERBOSE = log_state
        logger().setlevel()

    def save_log_state(self) -> Tuple[bool, bool, bool]:
        old_log_state = (logger().HAL, logger().DEBUG, logger().VERBOSE)
        return old_log_state

_chipset = None

def cs():
    global _chipset

    if _chipset is None:
        _chipset = Chipset()
    return _chipset
