# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2022, Intel Corporation

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# Contact information:
# chipsec@intel.com

from chipsec.lib.pcidb import VENDORS, DEVICES
from chipsec.logger import logger


def get_vendor_name_by_vid(vid):
    if vid in VENDORS:
        return VENDORS[vid]
    return ''


def get_device_name_by_didvid(vid, did):
    if vid in DEVICES:
        if did in DEVICES[vid]:
            return DEVICES[vid][did]
    return ''


def print_pci_devices(_devices):
    logger().log("BDF     | VID:DID:RID   | Vendor                       | Device")
    logger().log("-------------------------------------------------------------------------")
    for (b, d, f, vid, did, rid) in _devices:
        vendor_name = get_vendor_name_by_vid(vid)
        device_name = get_device_name_by_didvid(vid, did)
        logger().log("{:02X}:{:02X}.{:X} | {:04X}:{:04X}{:02X} | {:28} | {}".format(b, d, f, vid, did, rid, vendor_name, device_name))


def print_pci_XROMs(_xroms):
    if len(_xroms) == 0:
        return
    logger().log("BDF     | VID:DID   | XROM base | XROM size | en ")
    logger().log("-------------------------------------------------")
    for xrom in _xroms:
        logger().log("{:02X}:{:02X}.{:X} | {:04X}:{:04X} | {:08X}  | {:08X}  | {:d}".format(xrom.bus, xrom.dev, xrom.fun, xrom.vid, xrom.did, xrom.base, xrom.size, xrom.en))
