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
VMM specific functionality
1. Hypervisor hypercall interfaces
2. Second-level Address Translation (SLAT)
3. VirtIO devices
4. ...

"""

import struct

from typing import AnyStr, Dict, List, Optional, Tuple
from chipsec.library.logger import logger, pretty_print_hex_buffer
import chipsec.hal.pcidb


class VMM:

    def __init__(self, cs):
        self.cs = cs
        self.helper = cs.helper
        self.output = ''
        (self.membuf0_va, self.membuf0_pa) = (0, 0)
        (self.membuf1_va, self.membuf1_pa) = (0, 0)

        chipsec.hal.pcidb.VENDORS[VIRTIO_VID] = VIRTIO_VENDOR_NAME
        chipsec.hal.pcidb.DEVICES[VIRTIO_VID] = VIRTIO_DEVICES

    def __del__(self):
        if self.membuf0_va != 0:
            (self.membuf0_va, self.membuf0_pa) = (0, 0)
            (self.membuf1_va, self.membuf1_pa) = (0, 0)

    def init(self) -> None:
        (self.membuf0_va, self.membuf0_pa) = self.cs.mem.alloc_physical_mem(0x2000, 0xFFFFFFFFFFFFFFFF)
        (self.membuf1_va, self.membuf1_pa) = (self.membuf0_va + 0x1000, self.membuf0_pa + 0x1000)
        if self.membuf0_va == 0:
            logger().log("[vmm] Could not allocate memory!")
            raise Exception("[vmm] Could not allocate memory!")

    # Generic hypercall interface

    def hypercall(self, rax: int, rbx: int, rcx: int, rdx: int, rdi: int, rsi: int, r8: int = 0, r9: int = 0, r10: int = 0, r11: int = 0, xmm_buffer: int = 0) -> int:
        return self.helper.hypercall(rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer)

    # Hypervisor-specific hypercall interfaces

    def hypercall64_five_args(self, vector: int, arg1: int = 0, arg2: int = 0, arg3: int = 0, arg4: int = 0, arg5: int = 0) -> int:
        return self.helper.hypercall(0, arg3, arg5, 0, arg4, 0, vector, 0, arg1, arg2)

    def hypercall64_memory_based(self, hypervisor_input_value: int, parameters: AnyStr, size: int = 0) -> int:
        self.cs.mem.write_physical_mem(self.membuf0_pa, len(parameters[:0x1000]), parameters[:0x1000])
        regs = self.helper.hypercall(hypervisor_input_value & ~0x00010000, self.membuf0_pa, self.membuf1_pa)
        self.output = self.helper.read_phys_mem(self.membuf1_pa, size) if size > 0 else ''
        return regs

    def hypercall64_fast(self, hypervisor_input_value: int, param0: int = 0, param1: int = 0) -> int:
        return self.helper.hypercall(hypervisor_input_value | 0x00010000, param0, param1)

    def hypercall64_extended_fast(self, hypervisor_input_value: int, parameter_block: bytes) -> int:
        (param0, param1, xmm_regs) = struct.unpack('<QQ96s', parameter_block)
        self.cs.mem.write_physical_mem(self.membuf0_pa, 0x60, xmm_regs)
        return self.helper.hypercall(hypervisor_input_value | 0x00010000, param0, param1, 0, 0, 0, 0, 0, 0, 0, self.membuf0_va)

    #
    # Dump EPT page tables at specified physical base (EPT pointer)
    #
    def dump_EPT_page_tables(self, eptp: str, pt_fname: Optional[str] = None) -> None:
        _orig_logname = logger().LOG_FILE_NAME
        paging_ept = chipsec.hal.paging.c_extended_page_tables(self.cs)
        logger().log_hal(f'[vmm] Dumping EPT paging hierarchy at EPTP 0x{eptp:08X}...')
        if pt_fname is None:
            pt_fname = (f'ept_{eptp:08X}')
        logger().set_log_file(pt_fname, False)
        paging_ept.read_pt_and_show_status(pt_fname, 'EPT', eptp)
        logger().set_log_file(_orig_logname, False)
        if paging_ept.failure:
            logger().log_error('Could not dump EPT page tables')


################################################################################
#
# VirtIO functions
#
################################################################################

VIRTIO_VID: int = 0x1AF4
VIRTIO_VENDOR_NAME: str = 'Red Hat, Inc.'
VIRTIO_VENDORS: List[int] = [VIRTIO_VID]
VIRTIO_DEVICES: Dict[int, str] = {
    0x1000: 'VirtIO Network',
    0x1001: 'VirtIO Block',
    0x1002: 'VirtIO Baloon',
    0x1003: 'VirtIO Console',
    0x1004: 'VirtIO SCSI',
    0x1005: 'VirtIO RNG',
    0x1009: 'VirtIO filesystem',
    0x1041: 'VirtIO network (1.0)',
    0x1042: 'VirtIO block (1.0)',
    0x1043: 'VirtIO console (1.0)',
    0x1044: 'VirtIO RNG (1.0)',
    0x1045: 'VirtIO memory balloon (1.0)',
    0x1046: 'VirtIO SCSI (1.0)',
    0x1049: 'VirtIO filesystem (1.0)',
    0x1050: 'VirtIO GPU (1.0)',
    0x1052: 'VirtIO input (1.0)',
    0x1110: 'VirtIO Inter-VM shared memory'
}


def get_virtio_devices(devices: List[Tuple[int, int, int, int, int]]) -> List[Tuple[int, int, int, int, int]]:
    virtio_devices = []
    for (b, d, f, vid, did) in devices:
        if vid in VIRTIO_VENDORS:
            virtio_devices.append((b, d, f, vid, did))
    return virtio_devices


class VirtIO_Device:

    def __init__(self, cs, b, d, f):
        self.cs = cs
        self.bus = b
        self.dev = d
        self.fun = f

    def dump_device(self) -> None:
        logger().log(f"\n[vmm] VirtIO device {self.bus:02X}:{self.dev:02X}.{self.fun:01X}")
        dev_cfg = self.cs.pci.dump_pci_config(self.bus, self.dev, self.fun)
        pretty_print_hex_buffer(dev_cfg)
        bars = self.cs.pci.get_device_bars(self.bus, self.dev, self.fun)
        for (bar, isMMIO, _, _, _, size) in bars:
            if isMMIO:
                self.cs.mmio.dump_MMIO(bar, size)
            else:
                self.cs.io.dump_IO(bar, size, 4)
