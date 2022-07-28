# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2020, Intel Corporation
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
Simple PCIe device Memory-Mapped I/O (MMIO) and I/O ranges VMM emulation fuzzer

Usage:
    ``chipsec_main -m tools.vmm.pcie_fuzz [-a <bus> <dev> <fun>]``

    - ``<bus>`` : Bus # to fuzz (in hex)
    - ``<dev>`` : Device # to fuzz (in hex)
    - ``<fun>`` : Function # to fuzz (in hex)

Where:
    - ``[]``: optional line

Examples:
    >>> chipsec_main.py -i -m tools.vmm.pcie_fuzz
    >>> chipsec_main.py -i -m tools.vmm.pcie_fuzz -l log.txt
    >>> chipsec_main.py -i -m tools.vmm.pcie_fuzz -a 0 1f 0

Additional options set within the module:
    - ``IO_FUZZ``       : Set to fuzz IO BARs
    - ``CALC_BAR_SIZE`` : Set to calculate BAR sizes
    - ``TIMEOUT``       : Timeout between memory writes (seconds)
    - ``ACTIVE_RANGE``  : Set to fuzz MMIO BAR in Active range
    - ``BIT_FLIP``      : Set to fuzz using bit flips
    - ``_EXCLUDE_BAR``  : BARs to exclude (list)

.. note::
    - Returns a Warning by default
    - System may be in an unknown state, further evaluation may be needed

.. important::
    - This module is designed to run in a VM environment
    - Behavior on physical HW is undefined

"""

import time
import random

from chipsec.module_common import BaseModule, ModuleResult
from chipsec.hal.pci import print_pci_devices


#################################################################
# Fuzzing configuration
#################################################################
#
IO_FUZZ = 0
CALC_BAR_SIZE = 1
TIMEOUT = 1
ACTIVE_RANGE = 0
BIT_FLIP = 1

_EXCLUDE_BAR = []


class pcie_fuzz(BaseModule):

    def fuzz_io_bar(self, bar, size=0x100):
        port_off = 0
        # Issue 8/16/32-bit I/O requests with various values to all I/O ports (aligned and unaligned)
        for port_off in range(size):
            port_value = self.cs.io.read_port_byte(bar + port_off)
            self.cs.io.write_port_byte(bar + port_off, port_value)
            self.cs.io.write_port_byte(bar + port_off, ~port_value & 0xFF)
            self.cs.io.write_port_byte(bar + port_off, 0xFF)
            self.cs.io.write_port_byte(bar + port_off, 0x00)
            self.cs.io.write_port_word(bar + port_off, 0xFFFF)
            self.cs.io.write_port_word(bar + port_off, 0x0000)
            self.cs.io.write_port_dword(bar + port_off, 0xFFFFFFFF)
            self.cs.io.write_port_dword(bar + port_off, 0x00000000)

    def fuzz_offset(self, bar, reg_off, reg_value, is64bit):
        self.cs.mmio.write_MMIO_reg(bar, reg_off, reg_value)  # same value
        self.cs.mmio.write_MMIO_reg(bar, reg_off, ~reg_value & 0xFFFFFFFF)
        self.cs.mmio.write_MMIO_reg(bar, reg_off, 0xFFFFFFFF)
        self.cs.mmio.write_MMIO_reg(bar, reg_off, 0x5A5A5A5A)
        self.cs.mmio.write_MMIO_reg(bar, reg_off, 0x00000000)

    def fuzz_unaligned(self, bar, reg_off, is64bit):
        dummy = self.cs.mmio.read_MMIO_reg(bar, reg_off + 1)
        # @TODO: crosses the reg boundary
        self.cs.mem.write_physical_mem_word(bar + reg_off + 1, 0xFFFF)
        self.cs.mem.write_physical_mem_byte(bar + reg_off + 1, 0xFF)

    def fuzz_mmio_bar(self, bar, is64bit, size=0x1000):
        self.logger.log("[*] Fuzzing MMIO BAR 0x{:016X}, size = 0x{:X}..".format(bar, size))
        reg_off = 0
        # Issue aligned 32-bit MMIO requests with various values to all MMIO registers
        for reg_off in range(0, size, 4):
            reg_value = self.cs.mmio.read_MMIO_reg(bar, reg_off)
            self.fuzz_offset(bar, reg_off, reg_value, is64bit)
            self.fuzz_unaligned(bar, reg_off, is64bit)
            # restore the original value
            self.cs.mmio.write_MMIO_reg(bar, reg_off, reg_value)

    def fuzz_mmio_bar_random(self, bar, is64bit, size=0x1000):
        self.logger.log("[*] Fuzzing MMIO BAR in random mode 0x{:016X}, size = 0x{:X}..".format(bar, size))
        reg_off = 0
        while 1:
            rand = random.randint(0, size / 4 - 1)
            self.fuzz_offset(bar, reg_off, rand * 4, is64bit)
            self.fuzz_offset(bar, reg_off, rand * 4 + 1, is64bit)
            self.fuzz_unaligned(bar, rand * 4, is64bit)

    def fuzz_mmio_bar_in_active_range(self, bar, is64bit, list):
        self.logger.log("[*] Fuzzing MMIO BAR in Active range 0x{:016X}, size of range = 0x{:X}..".format(bar, len(list)))
        for reg_off in list:
            rand = random.randint(0, 255)
            self.fuzz_offset(bar, reg_off, rand, is64bit)
            self.fuzz_unaligned(bar, reg_off, is64bit)

    def fuzz_mmio_bar_in_active_range_random(self, bar, is64bit, list):
        self.logger.log("[*] Fuzzing MMIO BAR in Active range 0x{:016X} in random mode, size of range = 0x{:X}..".format(bar, len(list)))
        reg_off = 0
        self.fuzz_unaligned(bar, reg_off, is64bit)
        while 1:
            rand = random.randint(0, len(list) - 1)
            self.fuzz_offset(bar, reg_off, list[rand], is64bit)

    def fuzz_mmio_bar_in_active_range_bit_flip(self, bar, is64bit, list):
        self.logger.log("[*] Fuzzing (bit flipping) MMIO BAR in Active range 0x{:016X}, size of range = 0x{:X}..".format(bar, len(list)))
        reg_off = 0
        while 1:
            rand_index = random.randint(0, len(list) - 1)
            reg_value = self.cs.mmio.read_MMIO_reg(bar, list[rand_index])

            rand_offset = random.randint(0, 32)
            if (1 << rand_offset) & reg_value:
                reg_value = ~(1 << rand_offset) & 0xffffffff & reg_value
            else:
                reg_value = reg_value | (1 << rand_offset)

            self.cs.mmio.write_MMIO_reg(bar, reg_off, reg_value)

    def find_active_range(self, bar, size):
        self.logger.log("[*] Determine MMIO BAR Active range 0x{:016X}, size  0x{:X}..".format(bar, size))
        one = self.cs.mem.read_physical_mem(bar, size)
        time.sleep(TIMEOUT)
        two = self.cs.mem.read_physical_mem(bar, size)
        diff_index = []
        for i in range(len(one) // 4 - 1):
            j = 4 * i
            if (one[j] != two[j]) or (one[j + 1] != two[j + 1]) or (one[j + 2] != two[j + 2]) or (one[j + 3] != two[j + 3]):
                diff_index.append(j)
        return diff_index

    def fuzz_pcie_device(self, b, d, f):
        self.logger.log("[*] Discovering MMIO and I/O BARs of the device..")
        device_bars = self.cs.pci.get_device_bars(b, d, f, bCalcSize=CALC_BAR_SIZE)
        for (bar, isMMIO, is64bit, bar_off, bar_reg, size) in device_bars:
            if bar not in _EXCLUDE_BAR:
                # Fuzzing MMIO registers of the PCIe device
                if isMMIO:
                    self.logger.log("[*] + 0x{:02X} ({:X}): MMIO BAR at 0x{:016X} (64-bit? {:d}) with size: 0x{:08X}. Fuzzing..".format(bar_off, bar_reg, bar, is64bit, size))
                    if ACTIVE_RANGE and (size > 0x1000):
                        list = []
                        list = self.find_active_range(bar, size)
                        if len(list) > 0:
                            if BIT_FLIP:
                                self.fuzz_mmio_bar_in_active_range_bit_flip(bar, is64bit, list)
                            else:
                                self.fuzz_mmio_bar_in_active_range(bar, is64bit, list)
                    else:
                        if size >= 0x2000000:
                            size = 0x2000000
                        self.fuzz_mmio_bar(bar, is64bit, size)
                # Fuzzing I/O registers of the PCIe device
                else:
                    if IO_FUZZ:
                        self.logger.log("[*] + 0x{:02X}: I/O BAR at 0x{:08X}. Fuzzing..".format(bar_off, bar))
                        self.fuzz_io_bar(bar)

    def run(self, module_argv):
        self.logger.start_test("PCIe device fuzzer (pass-through devices)")

        pcie_devices = []
        if len(module_argv) > 2:
            _bus = int(module_argv[0], 16)
            _dev = int(module_argv[1], 16)
            _fun = int(module_argv[2], 16)
            pcie_devices.append((_bus, _dev, _fun, 0, 0))
        else:
            self.logger.log("[*] Enumerating available PCIe devices..")
            pcie_devices = self.cs.pci.enumerate_devices()

        self.logger.log("[*] About to fuzz the following PCIe devices..")
        print_pci_devices(pcie_devices)

        for (b, d, f, _, _) in pcie_devices:
            self.logger.log("[+] Fuzzing device {:02X}:{:02X}.{:X}".format(b, d, f))
            self.fuzz_pcie_device(b, d, f)

        self.logger.log_information('Module completed')
        self.logger.log_warning('System may be in an unknown state, further evaluation may be needed.')
        self.res = ModuleResult.WARNING
        return self.res
