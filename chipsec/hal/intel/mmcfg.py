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
Access to MMIO (Memory Mapped IO) BARs and Memory-Mapped PCI Configuration Space (MMCFG)

usage:
    Access Memory Mapped Config Space:

    >>> get_MMCFG_base_address(cs)
    >>> read_mmcfg_reg(cs, 0, 0, 0, 0x10, 4)
    >>> read_mmcfg_reg(cs, 0, 0, 0, 0x10, 4, 0xFFFFFFFF)
"""

from chipsec.hal import hal_base
from chipsec.library.bits import get_bits
from chipsec.library.pci import VSECEntry, ECEntry
from chipsec.library.exceptions import CSReadError
from typing import List, Tuple, Optional

PCI_PCIEXBAR_REG_LENGTH = {0: 2,  # 256MB
                           1: 1,  # 128MB
                           2: 0,  # 64MB
                           3: 3,  # 512MB
                           4: 4,  # 1GB
                           5: 5,  # 2GB
                           6: 6}  # 4GB

PCI_PCIEBAR_REG_MASK = 0x7FFC000000


class MMCFG(hal_base.HALBase):

    def __init__(self, cs):
        super(MMCFG, self).__init__(cs)
        self.base_list = []
        if self.cs.is_server():
            self.PCIEXBAR = "8086.MEMMAP_VTD.PCIEXBAR"
            self.MmioCfgBaseAddr = "8086.MEMMAP_VTD.MmioCfgBaseAddr"
            self.MMCFG = "8086.MEMMAP_VTD.MMCFG"
        else:
            self.PCIEXBAR = "8086.HOSTCTL.PCIEXBAR"
            self.MmioCfgBaseAddr = "8086.HOSTCTL.MmioCfgBaseAddr"
            self.MMCFG = "8086.HOSTCTL.MMCFG"

    ##################################################################################
    # Access to Memory Mapped PCIe Configuration Space
    ##################################################################################

    def populate_base_list(self) -> None:
        bar = self.cs.register.mmio.get_def(self.MMCFG)
        for instance in bar.instances:
            self.base_list.append(instance)

    def get_MMCFG_base_address(self, bus: int) -> Tuple[int, int]:
        """
        Get the base address of the Memory Mapped PCIe Configuration Space (MMCFG) for a given bus.
        """
        if not self.base_list:
            self.populate_base_list()
        base_instance = self._find_base_instance(bus)
        bar_base, bar_size = self._get_bar_base_and_size(base_instance)
        bar_base = self._adjust_bar_base_for_length(bar_base, base_instance)
        bar_size = self._adjust_bar_size_for_bus_range(bar_size, base_instance)
        self.logger.log_hal(f"[mmcfg] Memory Mapped CFG Base: 0x{bar_base:016X}")
        return bar_base, bar_size

    def _find_base_instance(self, bus: int) -> Optional['PCIObj']:
        """
        Find the base bus for the given bus number.
        :param bus: The bus number to find the base for.
        :return: The base bus object.
        """
        base_instance = None
        for _instance in self.base_list:
            if _instance is None or _instance.bus is None:
                continue
            if bus >= _instance.bus:
                base_instance = _instance
            else:
                break
        if base_instance is None:
            raise CSReadError(f"[mmcfg] Unable to find active bus with MMCFG defined for bus {bus}")
        return base_instance

    def _get_bar_base_and_size(self, base_instance: 'PCIObj') -> Tuple[int, int]:
        """
        Get the base address and size of the BAR for the given base bus.
        :param base_bus: The base bus object.
        :return: A tuple containing the base address and size of the BAR.
        """
        bar = self.cs.register.mmio.get_def(self.MMCFG)
        bar_base, bar_size = bar.get_base(base_instance)
        if not bar_base:
            bar_base, bar_size = self.cs.hals.mmio.get_MMIO_BAR_base_address(self.MMCFG, base_instance)
        return bar_base, bar_size

    def _adjust_bar_base_for_length(self, bar_base: int, base_instance: 'PCIObj') -> int:
        """
        Adjust the base address of the BAR for the given base bus based on the length field.
        :param bar_base: The base address of the BAR.
        :param base_bus: The base bus object.
        :return: The adjusted base address of the BAR.
        """
        if self.cs.register.has_field(self.MmioCfgBaseAddr, "LENGTH") and not self.cs.is_server():
            bar_obj = self.cs.register.get_instance_by_name(self.PCIEXBAR, base_instance)
            reg_len = bar_obj.get_field("LENGTH")
            bar_base &= PCI_PCIEBAR_REG_MASK << PCI_PCIEXBAR_REG_LENGTH[reg_len]
        return bar_base

    def _adjust_bar_size_for_bus_range(self, bar_size: int, base_instance: 'PCIObj') -> int:
        """
        Adjust the size of the BAR for the given base bus based on the bus range field.
        :param bar_size: The size of the BAR.
        :param base_bus: The base bus object.
        :return: The adjusted size of the BAR.
        """
        if self.cs.register.has_field(self.MmioCfgBaseAddr, "BusRange"):
            bar_obj = self.cs.register.get_instance_by_name(self.MmioCfgBaseAddr, base_instance)
            num_buses = bar_obj.get_field("BusRange")
            if num_buses <= 8:
                bar_size = 2**20 * 2**num_buses
            else:
                self.logger.log_hal(f"[mmcfg] Unexpected MmioCfgBaseAddr bus range: 0x{num_buses:X}")
        return bar_size

    def read_mmcfg_reg(self, bus: int, dev: int, fun: int, off: int, size: int) -> int:
        """
        Read a register from the Memory Mapped PCIe Configuration Space (MMCFG).
        :param bus: The bus number of the device.
        :param dev: The device number of the device.
        :param fun: The function number of the device.
        :param off: The offset of the register to read.
        :param size: The size of the register to read (1, 2, or 4 bytes).
        :return: The value read from the register.
        """
        pciexbar, pciexbar_sz = self.get_MMCFG_base_address(bus)
        pciexbar_off = (bus * 32 * 8 + dev * 8 + fun) * 0x1000 + off
        value = self.cs.hals.mmio.read_MMIO_reg(pciexbar, pciexbar_off, size, pciexbar_sz)
        self.logger.log_hal(f"[mmcfg] Reading MMCFG register at bus {bus}, device {dev}, function {fun}, offset 0x{off:X}")
        self.logger.log_hal("[mmcfg] reading {:02d}:{:02d}.{:d} + 0x{:02X} (MMCFG + 0x{:08X}): 0x{:08X}".format(
            bus, dev, fun, off, pciexbar_off, value))
        if 1 == size:
            return (value & 0xFF)
        elif 2 == size:
            return (value & 0xFFFF)
        return value

    def write_mmcfg_reg(self, bus: int, dev: int, fun: int, off: int, size: int, value: int) -> bool:
        """
        Write a register to the Memory Mapped PCIe Configuration Space (MMCFG).
        :param bus: The bus number of the device.
        :param dev: The device number of the device.
        :param fun: The function number of the device.
        :param off: The offset of the register to write.
        :param size: The size of the register to write (1, 2, or 4 bytes).
        :param value: The value to write to the register.
        :return: True if the write was successful, False otherwise.
        """
        pciexbar, pciexbar_sz = self.get_MMCFG_base_address(bus)
        pciexbar_off = (bus * 32 * 8 + dev * 8 + fun) * 0x1000 + off
        if size == 1:
            mask = 0xFF
        elif size == 2:
            mask = 0xFFFF
        else:
            mask = 0xFFFFFFFF
        self.cs.hals.mmio.write_MMIO_reg(pciexbar, pciexbar_off, (value & mask), size)
        self.logger.log_hal(f"[mmcfg] Writing value 0x{value:X} to MMCFG register at bus {bus}, device {dev}, function {fun}, offset 0x{off:X}")
        self.logger.log_hal("[mmcfg] writing {:02d}:{:02d}.{:d} + 0x{:02X} (MMCFG + 0x{:08X}): 0x{:08X}".format(
            bus, dev, fun, off, pciexbar_off, value))
        return True

    def get_extended_capabilities(self, bus: int, dev: int, fun: int) -> List[ECEntry]:
        """
        Get the extended capabilities for a given device.
        :param bus: The bus number of the device.
        :param dev: The device number of the device.
        :param fun: The function number of the device.
        :return: A list of extended capability entries.
        """
        retcap = []
        off = 0x100
        while off and off != 0xFFF:
            try:
                cap = self.read_mmcfg_reg(bus, dev, fun, off, 4)
                retcap.append(ECEntry(bus, dev, fun, off, cap))
                off = get_bits(cap, 20, 12)
            except Exception as e:
                self.logger.log_hal(f"[mmcfg] Error reading extended capability at offset 0x{off:X}: {e}")
                break
        if not retcap:
            self.logger.log_hal(f"[mmcfg] No extended capabilities found for {bus}:{dev}.{fun}")
        return retcap

    def get_vsec(self, bus: int, dev: int, fun: int, ecoff: int) -> VSECEntry:
        """
        Get the VSEC (Vendor Specific Extended Capability) entry for a given device.
        :param bus: The bus number of the device.
        :param dev: The device number of the device.
        :param fun: The function number of the device.
        :param ecoff: The offset of the VSEC entry.
        :return: The VSEC entry.
        """
        off = ecoff + 4
        vsec = self.read_mmcfg_reg(bus, dev, fun, off, 4)
        return VSECEntry(vsec)


haldata = {"arch": [hal_base.HALBase.MfgIds.Intel], 'name': {'mmcfg': "MMCFG"}}
