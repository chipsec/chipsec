#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2015, Intel Corporation
# 
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#

"""
QEMU VirtIO info tool

 Usage:
   ``chipsec_main.py -i -m tools.vmm.virtio``
   ``chipsec_main.py -i -m tools.vmm.virtio -a 0:6.0``
"""

import re
from chipsec.module_common import *
from chipsec.hal.pci       import *
from chipsec.hal.mmio      import *

VENDORS[0x1AF4] = 'Red Hat, Inc.'
DEVICES[0x1AF4] = {
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

VIRTIO_VENDORS = [0x1AF4]

class VirtIO_MMIO_Device(BaseModule):

    def __init__(self, b, d, f):
        BaseModule.__init__(self)
        self.bus = b
        self.dev = d
        self.fun = f

    def get_bars(self):
        return [self.cs.pci.read_dword(self.bus, self.dev, self.fun, x) for x in xrange(0x10, 0x28, 4)]

    def print_virtio_device(self):
        self.logger.log("")
        self.logger.log("VirtIO Device %02x:%02x.%01x" % (self.bus, self.dev, self.fun))
        bars = self.get_bars()
        for i in xrange(len(bars)):
            if bars[i] in [0x0, 0xFFFFFFFF]: continue
            if bars[i] & 0x1 == 0:
                base = bars[i] & 0xFFFFFFF0
                data = struct.unpack("<1024L", self.cs.mem.read_physical_mem(base, 0x1000))
            else:
                base = bars[i] & 0xFFFFFFFC
                data = [self.cs.io.read_port_dword(x) for x in xrange(base, base + 0x100, 4)]
            self.logger.log("  BAR%d: 0x%08x (assuming size is 4096 bytes)" % (i, base))
            for x in xrange(len(data)):
                if data[x] in [0x0, 0xFFFFFFFF]: continue
                self.logger.log("    BAR + 0x%04x: 0x%08x" % (x * 4, data[x]))
        return

class VirtIO(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def get_virtio_devices(self, devices):
        virtio_devices = []
        for (b, d, f, vid, did) in devices:
            if vid in VIRTIO_VENDORS:
                virtio_devices.append((b, d, f, vid, did))
        return virtio_devices
        
    def run(self, module_argv):
        self.logger.start_test("QEMU VirtIO info tool")

        pcie_dev = []
        if len(module_argv) >= 1:
            match = re.search(r"^([0-9a-f]{1,2}):([0-1]?[0-9a-f]{1})\.([0-7]{1})$", module_argv[0])
            if match:
                _bus = int(match.group(1), 16) & 0xFF
                _dev = int(match.group(2), 16) & 0x1F
                _fun = int(match.group(3), 16) & 0x07 
                vid  = self.cs.pci.read_word(_bus, _dev, _fun, 0)
                did  = self.cs.pci.read_word(_bus, _dev, _fun, 2)
                dev  = (_bus, _dev, _fun, vid, did)
                pcie_dev = [dev]
                virt_dev = [dev]
            else:
                self.logger.log("ERROR: Invalid B:D.F (%s)" % module_argv[0])
                return ModuleResult.ERROR
        else:
            self.logger.log("Enumerating available PCI devices..")
            pcie_dev = self.cs.pci.enumerate_devices()
            virt_dev = self.get_virtio_devices(pcie_dev)

        self.logger.log("PCI devices:")
        print_pci_devices(virt_dev)

        for (b, d, f, vid, did) in virt_dev:
            dev = VirtIO_MMIO_Device(b, d, f)
            dev.print_virtio_device()

        return ModuleResult.PASSED
