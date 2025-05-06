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


from typing import List, Optional, Tuple
from chipsec.cfg.parsers.ip.pci_device import PCIConfig


class Device:
    def __init__(self, cs) -> None:
        self.cs = cs

    def get_instance_by_name(self, device_name: str, instance) -> PCIConfig:
        devlist = self.get_list_by_name(device_name)
        for dev in devlist:
            if instance in dev.instances:
                return dev.instances[instance]
        return None
        
    def get_list_by_name(self, device_name: str):
        devices = self.cs.Cfg.get_objlist(device_name)
        return [ip.obj for ip in devices]

    def is_defined(self, device_name: str) -> bool:
        """Checks if device is defined in the XML config"""
        return self.get_list_by_name(device_name) is not None

    def get_bus(self, device_name: str) -> List[int]:
        """Retrieves bus value(s) from PCI device"""
        dev_list = self.get_list_by_name(device_name)
        buses = []
        for dev in dev_list:
            for instance_key in dev.instances.keys():
                buses.append(dev.instances[instance_key].bus)
        return buses

    def get_IO_space(self, io_name: str) -> Tuple[Optional[int], Optional[int]]:
        """Retrieves BAR values for given IO range"""
        if io_name in self.cs.Cfg.IO_BARS.keys():
            reg = self.cs.Cfg.IO_BARS[io_name]['register']
            bf = self.cs.Cfg.IO_BARS[io_name]['base_field']
            return (reg, bf)
        else:
            return None, None
