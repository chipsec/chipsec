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
>>> chipsec_util spd detect
>>> chipsec_util spd dump [device_addr]
>>> chipsec_util spd read <device_addr> <offset>
>>> chipsec_util spd write <device_addr> <offset> <byte_val>

Examples:

>>> chipsec_util spd detect
>>> chipsec_util spd dump DIMM0
>>> chipsec_util spd dump 0xA0
>>> chipsec_util spd read DIMM2 0x0
>>> chipsec_util spd read 0xA0 0x0
>>> chipsec_util spd write 0xA0 0x0 0xAA
"""

from chipsec.command import BaseCommand, toLoad
from chipsec.hal import smbus, spd
from argparse import ArgumentParser


class SPDCommand(BaseCommand):

    def requirements(self) -> toLoad:
        return toLoad.All

    def parse_arguments(self) -> None:
        parser = ArgumentParser(usage=__doc__)
        subparsers = parser.add_subparsers()

        parser_detect = subparsers.add_parser('detect')
        parser_detect.set_defaults(func=self.spd_detect)

        parser_dump = subparsers.add_parser('dump')
        parser_dump.add_argument('dev', type=str, nargs='?', default=None, help="Device")
        parser_dump.set_defaults(func=self.spd_dump)

        parser_read = subparsers.add_parser('read')
        parser_read.add_argument('dev', type=str, help="Device Address")
        parser_read.add_argument('off', type=lambda x: int(x, 16), nargs='?', default=None, help="Offset (hex)")
        parser_read.set_defaults(func=self.spd_read)

        parser_write = subparsers.add_parser('write')
        parser_write.add_argument('dev', type=str, help="Device Address")
        parser_write.add_argument('off', type=lambda x: int(x, 16), help="Offset (hex)")
        parser_write.add_argument('val', type=lambda x: int(x, 16), help="Byte Value (hex)")
        parser_write.set_defaults(func=self.spd_write)

        parser.parse_args(self.argv, namespace=self)

    def spd_detect(self):
        self.logger.log("[CHIPSEC] Searching for DIMMs with SPD...")
        _dimms = self._spd.detect()
        if _dimms is not None:
            self.logger.log("Detected the following SPD devices:")
            for _dimm in _dimms:
                self.logger.log("{}: 0x{:02X}".format(spd.SPD_DIMMS[_dimm], _dimm))
        else:
            self.logger.log("Unable to detect SPD devices.")

    def spd_dump(self):
        if self.dev is not None:
            _dev = self.dev.upper()
            self.dev_addr = spd.SPD_DIMM_ADDRESSES[_dev] if _dev in spd.SPD_DIMM_ADDRESSES else int(self.dev, 16)
            if not self._spd.isSPDPresent(self.dev_addr):
                self.logger.log("[CHIPSEC] SPD for DIMM 0x{:X} is not found".format(self.dev_addr))
                return
            self._spd.decode(self.dev_addr)
        else:
            _dimms = self._spd.detect()
            for _dimm in _dimms:
                self._spd.decode(_dimm)

    def spd_read(self):
        _dev = self.dev.upper()
        self.dev_addr = spd.SPD_DIMM_ADDRESSES[_dev] if _dev in spd.SPD_DIMM_ADDRESSES else int(self.dev, 16)
        if not self._spd.isSPDPresent(self.dev_addr):
            self.logger.log("[CHIPSEC] SPD for DIMM 0x{:X} is not found".format(self.dev_addr))
            return

        val = self._spd.read_byte(self.off, self.dev_addr)
        self.logger.log("[CHIPSEC] SPD read: offset 0x{:X} = 0x{:X}".format(self.off, val))

    def spd_write(self):
        _dev = self.dev.upper()
        self.dev_addr = spd.SPD_DIMM_ADDRESSES[_dev] if _dev in spd.SPD_DIMM_ADDRESSES else int(self.dev, 16)
        if not self._spd.isSPDPresent(self.dev_addr):
            self.logger.log("[CHIPSEC] SPD for DIMM 0x{:X} is not found".format(self.dev_addr))
            return

        self.logger.log("[CHIPSEC] SPD write: offset 0x{:X} = 0x{:X}".format(self.off, self.val))
        self._spd.write_byte(self.off, self.val, self.dev_addr)

    def run(self):
        try:
            _smbus = smbus.SMBus(self.cs)
            self._spd = spd.SPD(_smbus)
        except BaseException as msg:
            self.logger.log_error(msg)
            return
        if not _smbus.is_SMBus_supported():
            self.logger.log("[CHIPSEC] SMBus controller is not supported")
            return
        self.dev_addr = spd.SPD_SMBUS_ADDRESS
        self.func()


commands = {'spd': SPDCommand}
