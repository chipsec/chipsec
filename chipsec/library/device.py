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

"""
Device interface module.

This module provides functionality to access and manage device configurations
in the CHIPSEC framework, including PCI devices and I/O spaces.
"""

from typing import Any, List, Optional, Tuple
from chipsec.cfg.parsers.ip.pci_device import PCIConfig


class Device:
    """
    Device interface for platform device definitions.

    Provides methods to access and query device configurations,
    particularly PCI devices and I/O space configurations.
    """

    def __init__(self, cs: Any) -> None:
        """
        Initialize the Device interface.

        Args:
            cs: Chipset interface object
        """
        self.cs = cs

    def get_instance_by_name(self, device_name: str,
                             instance: Any) -> Optional[PCIConfig]:
        """
        Get a specific device instance by name and instance identifier.

        Args:
            device_name: Name of the device
            instance: Instance identifier to retrieve

        Returns:
            Device instance if found, None otherwise
        """
        devlist = self.get_list_by_name(device_name)
        for dev in devlist:
            if instance in dev.instances:
                return dev.instances[instance]
        return None

    def get_list_by_name(self, device_name: str) -> List[Any]:
        """
        Get list of device objects by name.

        Args:
            device_name: Name of the device to retrieve objects for

        Returns:
            List of device objects matching the name
        """
        devices = self.cs.Cfg.get_objlist(device_name)
        objlist = []
        [objlist.extend(ip.obj) for ip in devices]
        return objlist 

    def is_defined(self, device_name: str) -> bool:
        """
        Check if a device is defined in the configuration.

        Args:
            device_name: Name of the device to check

        Returns:
            True if device is defined, False otherwise
        """
        return len(self.get_list_by_name(device_name)) > 0

    def get_bus(self, device_name: str) -> List[int]:
        """
        Retrieve bus value(s) from PCI device instances.

        Args:
            device_name: Name of the PCI device

        Returns:
            List of bus numbers for all instances of the device
        """
        dev_list = self.get_list_by_name(device_name)
        buses = []
        for dev in dev_list:
            for instance_key in dev.instances.keys():
                buses.append(dev.instances[instance_key].bus)
        return buses

    def get_IO_space(self, io_name: str) -> Tuple[Optional[str],
                                                  Optional[str]]:
        """
        Retrieve BAR values for given I/O range.

        Args:
            io_name: Name of the I/O space

        Returns:
            Tuple of (register_name, base_field_name) if found,
            (None, None) otherwise
        """
        if io_name in self.cs.Cfg.IO_BARS:
            reg = self.cs.Cfg.IO_BARS[io_name].get('register')
            bf = self.cs.Cfg.IO_BARS[io_name].get('base_field')
            return (reg, bf)
        else:
            return (None, None)
