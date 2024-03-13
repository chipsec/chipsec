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


from chipsec.library.logger import logger
from typing import List, Optional, Tuple, Union
from chipsec.library.exceptions import CSFirstNotFoundError, CSBusNotFoundError, DeviceNotFoundError
##################################################################################
#
# Functions which access configuration of integrated PCI devices (interfaces, controllers)
# by device name (defined in XML configuration files)
#
##################################################################################


class Device:
    def __init__(self, cs) -> None:
        self.cs = cs

    def get_first_bus(self, device: dict) -> int:
        '''Retrieves first value in bus list for PCI device'''
        if 'bus' in device:
            return self.get_first(device['bus'])
        raise CSBusNotFoundError()

    def get_first(self, a_list: Union[list, int]) -> int:
        '''Returns received integer or first item from recieved list'''
        if type(a_list) is int:
            return a_list
        if type(a_list) is list:
            return a_list[0]
        raise CSFirstNotFoundError()

    def get_BDF(self, device_name: str) -> Tuple[int, int, int]:
        '''Retrieves bus, device, and function values from PCI device'''
        device = self.cs.Cfg.CONFIG_PCI[device_name]
        if device is None or device == {}:
            raise DeviceNotFoundError(f'DeviceNotFound: {device_name}')
        b = self.get_first_bus(device)
        d = device['dev']
        f = device['fun']
        return (b, d, f)

    def get_VendorID(self, device_name: str) -> Tuple[int, int]:
        '''Retrieves device ID and vendor ID from the PCI device'''
        (b, d, f) = self.get_BDF(device_name)
        return self.cs.pci.get_DIDVID(b, d, f)

    def is_enabled(self, device_name: str) -> bool:
        '''Checks if PCI device is enabled'''
        if self.is_defined(device_name):
            (b, d, f) = self.get_BDF(device_name)
            return self.cs.pci.is_enabled(b, d, f)
        return False

    def is_defined(self, device_name: str) -> bool:
        '''Checks if device is defined in the XML config'''
        if self.cs.Cfg.CONFIG_PCI.get(device_name, None) is None:
            return False
        else:
            return True

    def get_bus(self, device_name: str) -> List[int]:
        '''Retrieves bus value(s) from PCI device'''
        buses = self.cs.Cfg.BUS.get(device_name, [])
        if buses:
            if logger().DEBUG:
                logger().log_important(f"Using discovered bus values for device '{device_name}'")
            return buses
        if device_name in self.cs.Cfg.CONFIG_PCI and 'bus' in self.cs.Cfg.CONFIG_PCI[device_name]:
            (bus, dev, fun) = self.get_BDF(device_name)
            if self.cs.pci.is_enabled(bus, dev, fun):
                if logger().DEBUG:
                    logger().log_important(f"Using pre-defined bus values for device '{device_name}'")
                buses = [bus]
            else:
                if logger().DEBUG:
                    logger().log_important(f"Device '{device_name}' not enabled")
        else:
            if logger().DEBUG:
                logger().log_important(f"No bus value defined for device '{device_name}'")
        return buses

    def switch_def(self, target_device: str, source_device: str) -> None:
        '''Changes bus, device, and function values of PCI device'''
        (b, d, f) = self.get_BDF(source_device)
        self.cs.Cfg.CONFIG_PCI[target_device]['bus'] = b
        self.cs.Cfg.CONFIG_PCI[target_device]['dev'] = d
        self.cs.Cfg.CONFIG_PCI[target_device]['fun'] = f

    def get_IO_space(self, io_name: str) -> Tuple[Optional[int], Optional[int]]:
        '''Retrieves BAR values for given IO range'''
        if io_name in self.cs.Cfg.IO_BARS.keys():
            reg = self.cs.Cfg.IO_BARS[io_name]["register"]
            bf = self.cs.Cfg.IO_BARS[io_name]["base_field"]
            return (reg, bf)
        else:
            return None, None
