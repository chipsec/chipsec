# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2017-2021, Intel Security
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
# Authors:
#   Yuriy Bulygin
#   Alex Bazhaniuk
#


"""
Experimental module that may help checking SMM firmware for MMIO BAR hijacking
vulnerabilities described in the following presentation:

`BARing the System: New vulnerabilities in Coreboot & UEFI based systems <https://web.archive.org/web/20170702042016/http://www.intelsecurity.com/advanced-threat-research/content/data/REConBrussels2017_BARing_the_system.pdf>`_ by Intel Advanced Threat Research team at RECon Brussels 2017

Usage:
    ``chipsec_main -m tools.smm.rogue_mmio_bar [-a <smi_start:smi_end>,<b:d.f>]``

    - ``smi_start:smi_end``: range of SMI codes (written to IO port 0xB2)
    - ``b:d.f``: PCIe bus/device/function in b:d.f format (in hex)

Example:
    >>> chipsec_main.py -m tools.smm.rogue_mmio_bar -a 0x00:0x80
    >>> chipsec_main.py -m tools.smm.rogue_mmio_bar -a 0x00:0xFF,0:1C.0

.. NOTE::
    Look for 'changes found' messages for items that should be further investigated.

.. WARNING::
    When running this test, system may freeze, reboot, etc. This is not unexpected behavior and not generally considered a failure.

"""

from chipsec.module_common import BaseModule
from chipsec.library.returncode import ModuleResult
from chipsec.library.defines import BOUNDARY_4GB
from chipsec.library.file import write_file
from chipsec.hal.pci import PCI_HDR_BAR_STEP, PCI_HDR_BAR_BASE_MASK_MMIO64, PCI_HDR_BAR_CFGBITS_MASK
from chipsec.hal.interrupts import Interrupts

#################################################################
# Testing configuration
#################################################################

FLUSH_OUTPUT_AFTER_SMI = False

_FILL_VALUE_QWORD = 0x0000000000000000
_MEM_FILL_VALUE = b"\xFF"
MAX_MMIO_RANGE_SIZE = 0x10000  # 0x400000

SMI_CODE_LIMIT = 0x0
SMI_DATA_LIMIT = 0xF
SMI_FUNC_LIMIT = 0xF


def DIFF(s, t, sz):
    return [pos for pos in range(sz) if s[pos] != t[pos]]


class rogue_mmio_bar(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self._interrupts = Interrupts(self.cs)

        # SMI code to be written to I/O port 0xB2
        self.smic_start = 0x00
        self.smic_end = SMI_CODE_LIMIT
        # SMI data to be written to I/O port 0xB3
        self.smid_start = 0x00
        self.smid_end = SMI_DATA_LIMIT
        # SMI handler "function" often supplied in ECX register
        self.smif_start = 0x00
        self.smif_end = SMI_FUNC_LIMIT
        # SMM communication buffer often supplied in EBX register
        self.comm = 0x00

        self.reloc_mmio = None

    def smi_mmio_range_fuzz(self, thread_id, b, d, f, bar_off, is64bit, bar, new_bar, base, size):

        # copy all registers from MMIO range to new location in memory
        # we do that once rather than before every SMI since we return after first change detected
        self.logger.log(f'[*] copying BAR 0x{base:X} > 0x{self.reloc_mmio:X}')
        try:
            orig_mmio = self.copy_bar(base, self.reloc_mmio, size)
        except Exception as e:
            self.logger.log_failed('Unable to copy bar. Skipping.')
            self.logger.log_verbose(str(e))
            if self.cs.os_helper.is_windows():
                self.logger.log_important('Try running in Linux for better coverage.')
            return False
        
        if self.logger.VERBOSE:
            self.cs.mmio.dump_MMIO(base, size)
            write_file('mmio_mem.orig', orig_mmio)

        for smi_code in range(self.smic_start, self.smic_end + 1):
            for smi_data in range(self.smid_start, self.smid_end + 1):
                for ecx in range(self.smif_start, self.smif_end + 1):
                    self.logger.log(f'> SMI# {smi_code:02X}: data {smi_data:02X}, func (ECX) {ecx:X}')
                    if FLUSH_OUTPUT_AFTER_SMI:
                        self.logger.flush()

                    # point MMIO range to new location (relocate MMIO range)
                    self.logger.log(f'  relocating BAR 0x{bar:X}')
                    if not self.modify_bar(b, d, f, bar_off, is64bit, bar, new_bar):
                        continue

                    # generate SW SMI
                    self._interrupts.send_SW_SMI(thread_id, smi_code, smi_data, _FILL_VALUE_QWORD, self.comm, ecx, _FILL_VALUE_QWORD, _FILL_VALUE_QWORD, _FILL_VALUE_QWORD)

                    # restore original location of MMIO range
                    self.restore_bar(b, d, f, bar_off, is64bit, bar)
                    self.logger.log(f'  restored BAR with 0x{bar:X}')

                    # check the contents at the address range used to relocate MMIO BAR
                    buf = self.cs.mem.read_physical_mem(self.reloc_mmio, size)
                    diff = DIFF(orig_mmio, buf, size)
                    self.logger.log("  checking relocated MMIO")
                    if len(diff) > 0:
                        self.logger.log_important(f'changes found at 0x{self.reloc_mmio:X} +{diff}')
                        if self.logger.VERBOSE:
                            write_file('mmio_mem.new', buf)
                        return True
        return False

    def copy_bar(self, bar_base, bar_base_mem, size):
        for off in range(0, size, 4):
            r = self.cs.mem.read_physical_mem_dword(bar_base + off)
            self.cs.mem.write_physical_mem_dword(bar_base_mem + off, r)
        return self.cs.mem.read_physical_mem(bar_base_mem, size)

    def modify_bar(self, b, d, f, off, is64bit, bar, new_bar):
        # Modify MMIO BAR address
        if is64bit:
            self.cs.pci.write_dword(b, d, f, off + PCI_HDR_BAR_STEP, ((new_bar >> 32) & 0xFFFFFFFF))
        self.cs.pci.write_dword(b, d, f, off, (new_bar & 0xFFFFFFFF))
        # Check that the MMIO BAR has been modified correctly. Restore original and skip if not
        l = self.cs.pci.read_dword(b, d, f, off)
        if l != (new_bar & 0xFFFFFFFF):
            self.restore_bar(b, d, f, off, is64bit, bar)
            self.logger.log(f'  skipping ({l:X} != {new_bar:X})')
            return False
        self.logger.log(f'  new BAR: 0x{l:X}')
        return True

    def restore_bar(self, b, d, f, off, is64bit, bar):
        if is64bit:
            self.cs.pci.write_dword(b, d, f, off + PCI_HDR_BAR_STEP, ((bar >> 32) & 0xFFFFFFFF))
        self.cs.pci.write_dword(b, d, f, off, (bar & 0xFFFFFFFF))
        return True

    def run(self, module_argv):
        self.logger.start_test("Experimental tool to help checking for SMM MMIO BAR issues")

        pcie_devices = []

        if len(module_argv) > 0:
            smic_arr = module_argv[0].split(':')
            self.smic_start = int(smic_arr[0], 16)
            self.smic_end = int(smic_arr[1], 16)

        if len(module_argv) > 1:
            try:
                b, df = module_argv[1].split(':')
                d, f = df.split('.')
                pcie_devices = [(int(b, 16), int(d, 16), int(f, 16), 0, 0)]
            except:
                self.logger.log_error("Incorrect b:d.f format\nUsage:\nchipsec_main -m tools.smm.rogue_mmio_bar [-a <smi_start:smi_end>,<b:d.f>]")
        else:
            self.logger.log("[*] Discovering PCIe devices..")
            pcie_devices = self.cs.pci.enumerate_devices()

        self.logger.log("[*] Testing MMIO of PCIe devices:")
        for (b, d, f, _, _, _) in pcie_devices:
            self.logger.log(f'    {b:02X}:{d:02X}.{f:X}')

        # allocate a page or SMM communication buffer (often supplied in EBX register)
        _, self.comm = self.cs.mem.alloc_physical_mem(0x1000, BOUNDARY_4GB - 1)
        #self.cs.mem.write_physical_mem( self.comm, 0x1000, chr(0)*0x1000 )

        # allocate range in physical memory (should cover all MMIO ranges including GTTMMADR)
        bsz = 2 * MAX_MMIO_RANGE_SIZE
        (va, pa) = self.cs.mem.alloc_physical_mem(bsz, BOUNDARY_4GB - 1)
        self.logger.log(f'[*] Allocated memory range : 0x{pa:016X} (0x{bsz:X} bytes)')
        self.cs.mem.write_physical_mem(pa, bsz, _MEM_FILL_VALUE * bsz)
        # align at the MAX_MMIO_RANGE_SIZE boundary within allocated range
        self.reloc_mmio = pa & (~(MAX_MMIO_RANGE_SIZE - 1))
        if self.reloc_mmio < pa:
            self.reloc_mmio += MAX_MMIO_RANGE_SIZE
        self.logger.log(f'[*] MMIO relocation address: 0x{self.reloc_mmio:016X}\n')

        for (b, d, f, vid, did, _) in pcie_devices:
            self.logger.log(f'[*] Enumerating device {b:02X}:{d:02X}.{f:X} MMIO BARs..')
            device_bars = self.cs.pci.get_device_bars(b, d, f, True)
            for (base, isMMIO, is64bit, bar_off, bar, size) in device_bars:
                if isMMIO and size <= MAX_MMIO_RANGE_SIZE:
                    self.logger.flush()
                    self.logger.log(f'[*] Found MMIO BAR +0x{bar_off:02X} (base 0x{base:016X}, size 0x{size:X})')
                    new_bar = ((self.reloc_mmio & PCI_HDR_BAR_BASE_MASK_MMIO64) | (bar & PCI_HDR_BAR_CFGBITS_MASK))
                    if self.smi_mmio_range_fuzz(0, b, d, f, bar_off, is64bit, bar, new_bar, base, size):
                        self.result.setStatusBit(self.result.status.RESTORE)
                        return self.result.getReturnCode(ModuleResult.FAILED)

        self.result.setStatusBit(self.result.status.SUCCESS)
        return self.result.getReturnCode(ModuleResult.PASSED)