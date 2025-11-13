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
SMBus chipsec utility

Usage:

>>> chipsec_util smbus read <device_addr> <offset> [size] [--OnSemi] [flags]
>>> chipsec_util smbus read_block <device_addr> <offset> [flags]
>>> chipsec_util smbus write <device_addr> <offset> <byte_val> [size] [--OnSemi] [flags]
>>> chipsec_util smbus process_call <device_addr> <offset> <byte_val> [flags]
>>> chipsec_util smbus scan [<start> [<stop>]] [flags]
>>> chipsec_util smbus dump <device_addr> [<start> [<stop>]] [flags]

flags = --addr8b, --mmio, --i2c

Examples:

>>> chipsec_util smbus read 0xA0 0x0 0x100
"""
from time import sleep
from argparse import ArgumentParser

from chipsec.command import BaseCommand, toLoad
from chipsec.library.logger import print_buffer, pretty_print_hex_buffer
# from chipsec.hal.common.smbus import SMBus


class SMBusCommand(BaseCommand):

    def parse_arguments(self):
        parser = ArgumentParser(prog='chipsec_util smbus', usage=__doc__)

        parser_opts = ArgumentParser(add_help=False)
        parser_opts.add_argument('--addr8b', dest='is_addr_8b', help='use 8-bit addressing', action='store_true')
        parser_opts.add_argument('--mmio', dest='is_mmio',
                                 help='use MMIO address bar to access SMBUS controller', action='store_true')
        parser_opts.add_argument('--i2c', dest='is_i2c', help='use i2c command routines', action='store_true')

        parser_dev = ArgumentParser(add_help=False)
        parser_dev.add_argument('dev_addr', type=lambda x: int(x, 0), help='SMBus destination address')

        parser_offset = ArgumentParser(add_help=False)
        parser_offset.add_argument('offset', type=lambda x: int(x, 0), help='offset')

        parser_start = ArgumentParser(add_help=False)
        parser_start.add_argument('r_min', metavar='start', type=lambda x: int(x, 0),
                                  nargs='?', help='Start of range')
        parser_start.add_argument('r_max', metavar='stop', type=lambda x: int(x, 0),
                                  nargs='?', help='End of range')

        parser_OnSemi = ArgumentParser(add_help=False)
        parser_OnSemi.add_argument('--OnSemi', dest='is_OnSemi', help='use OnSemi command routines', action='store_true')
        parser_size = ArgumentParser(add_help=False)
        parser_size.add_argument('size', metavar='size', type=lambda x: int(x, 0), help='Size of data to read/write')

        parser_write_data = ArgumentParser(add_help=False)
        parser_write_data.add_argument('write_data', type=lambda x: int(x, 0), help='Value to write')

        subparsers = parser.add_subparsers()

        # read
        parser_read = subparsers.add_parser('read', parents=[parser_opts, parser_dev, parser_offset, parser_size, parser_OnSemi], help='Read data from SMBus Address')
        parser_read.set_defaults(func=self.read, command='read')

        # readblock
        parser_read = subparsers.add_parser('readblock', parents=[parser_opts, parser_dev, parser_offset], help='Read block of data from SMBus Address')
        parser_read.set_defaults(func=self.readblock, command='readblock')

        # write
        parser_write = subparsers.add_parser('write', parents=[parser_opts, parser_dev, parser_offset, parser_write_data, parser_size, parser_OnSemi], help='Write data to SMBus Address')
        parser_write.set_defaults(func=self.write, command='write')

        # process_call
        parser_process_call = subparsers.add_parser('process_call', parents=[parser_opts, parser_dev, parser_offset, parser_write_data])
        parser_process_call.set_defaults(func=self.process_call, command='process_call')

        # scan
        parser_scan = subparsers.add_parser('scan', parents=[parser_opts, parser_start], help='Scan a range of device addresses')
        parser_scan.set_defaults(func=self.scan, command='scan', s_min=0x00, s_max=0x7F)

        # dump
        parser_dump = subparsers.add_parser('dump', parents=[parser_opts, parser_dev, parser_start], help='Dump a device address')
        parser_dump.set_defaults(func=self.dump_dev, command='dump', r_min=0x00, r_max=0xFF)

        parser.parse_args(self.argv, namespace=self)

    def requirements(self):
        return toLoad.All

    def pretty_print_buffer(self, arr, length=16):
        """Prints the buffer (bytes, bytearray) in a grid"""
        _str = ['    _']
        for n in range(length):
            _str += [f'{n:02X}__']
        for n in range(0, len(arr), 2):
            if n % (length * 2) == 0:
                _str += [f'\n{n // 2:02X} | ']
            _str += [f'{arr[n]:s}{arr[n + 1]:s}  ']
        self.logger.log(''.join(_str))

    def scan(self):
        self.logger.log_heading(f'Scanning range 0x{self.s_min:02X} - 0x{self.s_max:02X}')
        forward_list = self.scan_range(self.s_min, self.s_max)
        reverse_list = self.scan_range(self.s_min, self.s_max, True)
        inter_list = list(set(forward_list).union(reverse_list))
        # verify entries within list
        final_list = []
        for entry in inter_list:
            if entry in self.scan_range(entry, entry):
                final_list.append(entry)
                sleep(1)
        buf = ''
        for x in range(0, self.s_max + 1):
            if x in final_list:
                buf += f'{x:02x}'
            elif x < self.s_min:
                buf += '  '
            else:
                buf += '--'
        self.pretty_print_buffer(buf)

    def scan_range(self, fmin, fmax, reverse=False):
        res_dec = []
        if reverse:
            devs = range(fmax, fmin - 1, -1)
        else:
            devs = range(fmin, fmax + 1)
        devs = [0x52]
        for dev_addr in devs:
            self.logger.log_verbose(f'Scanning device {dev_addr:x}')
            if self.is_i2c:
                res = self.i2c_fixed_read_1(dev_addr)
                if res:
                    res_dec.append(dev_addr)
                    continue
                res = self.i2c_fixed_read_2(dev_addr)
                if res:
                    res_dec.append(dev_addr)
                    continue
                res = self.OnSemi_i2c_read(dev_addr, 0x00)
                if res:
                    res_dec.append(dev_addr)
                    continue
                res = self.i2c_fixed_write(dev_addr)
                if res:
                    res_dec.append(dev_addr)
                    self.logger.log_verbose('device found')
            else:
                if ((dev_addr >= 0x30) and (dev_addr <= 0x37)) or ((dev_addr >= 0x50) and (dev_addr <= 0x57)):
                    res = self._smbus.read_byte(dev_addr, 0)
                else:
                    res = self._smbus.quick_write(dev_addr)
                if res:
                    res_dec.append(dev_addr)
                    self.logger.log_verbose('device found')
        return res_dec

    def dump_dev(self):
        self.logger.log_heading(f'dump dev 0x{self.dev_addr:02X} range 0x{self.r_min:02X} - 0x{self.r_max:02X}')
        res = self._read_range(self.r_min, max(self.r_max - self.r_min, 0))
        if res is not False:
            self.logger.log_verbose(f'Read success for device: 0x{self.dev_addr:X}')
            pretty_print_hex_buffer(bytearray(i if i is not None else 0 for i in res))
            return True
        return res

    def OnSemi_i2c_read(self, target_address, i2c_register_offset):
        user_read_reg = 0x01
        result = self._smbus.process_call(target_address, 0x00, i2c_register_offset, user_read_reg)
        if result is not False:
            self.logger.log_verbose(f'OnSemi read success for device: {hex(target_address)}')
            return [result[0]]
        return False

    def i2c_fixed_read_1(self, target_address):
        res = self._smbus.read_byte(target_address, 0)
        if res is not False:
            self.logger.log_debug(f'read1 success for device: {hex(target_address)}')
            return [res[0]]
        return False

    def i2c_fixed_read_2(self, target_address):
        result = self._smbus.process_call(target_address, 0x00, 0x00, 0x00)
        if result is not False:
            self.logger.log_debug(f'read2 success for device: {hex(target_address)}')
            return [result[0]]
        return False

    def i2c_fixed_write(self, target_address):
        result = self._smbus.write_byte(target_address, 0x00, 0x00)
        if result is not False:
            self.logger.log_debug(f'fixed write success for device: {hex(target_address)}')
            return True
        return False

    def read(self):
        if self.is_OnSemi:
            user_read_reg = 0x01
            res = self._smbus.process_call(self.dev_addr, 0x00, self.offset, user_read_reg)
        else:
            res = self._read_range(self.offset, self.size)
        if not any(result is None for result in res):
            self.logger.log_verbose(f'Read success for device: 0x{self.dev_addr:X}')
            if self.logger.VERBOSE:
                print_buffer([chr(i) for i in res])
            return res
        return False

    def readblock(self):
        res = self._smbus.read_block(self.dev_addr, self.offset)
        if not any(result is None for result in res):
            self.logger.log_verbose(f'Read success for device: 0x{self.dev_addr:X}')
            if self.logger.VERBOSE:
                print_buffer([chr(i) for i in res])
            return res
        return False

    def _read_range(self, offset, msize):
        res = []
        read_size = 32
        while msize:
            if msize > 32 and read_size == 32:
                lres = self._smbus.read_block(self.dev_addr, offset)
                if not lres:
                    read_size = 2
                    continue
            elif msize > 2 and read_size > 1:
                lres = self._smbus.read_word(self.dev_addr, offset)
                read_size = 2
                if not lres:
                    read_size = 1
                    continue
            else:
                lres = self._smbus.read_byte(self.dev_addr, offset)
                read_size = 1
            if lres is False:
                lres = [None]
            msize -= read_size
            res += lres
            offset += read_size
        return res

    def write(self):
        if self.is_OnSemi:
            user_write_reg = 0x2
            res = self._smbus.write_word(self.dev_addr, user_write_reg, self.write_data, self.offset)
        else:
            res = self._write_range()
        if res is not False:
            self.logger.log_verbose(f'Write success for device: 0x{self.dev_addr:X}')
            return True
        return res

    def _write_range(self):
        msize = self.size
        offset = self.offset
        value = self.write_data
        write_size = 2
        while msize:
            if msize > 2 and write_size == 2:
                valueH = (value & 0xFF00) >> 8
                valueL = (value & 0xFF)
                lres = self._smbus.write_word(self.dev_addr, offset, valueH, valueL)
                if not lres:
                    write_size = 1
                    continue
            else:
                lres = self._smbus.write_byte(self.dev_addr, offset, value)
            msize -= write_size
            offset += write_size
            value >>= (8 * write_size)
            if lres is False:
                break
        return lres

    def process_call(self):
        val_h = (self.write_data & 0xFF00) >> 16
        val_l = self.write_data & 0xFF
        res = self._smbus.process_call(self.dev_addr, self.offset, val_h, val_l)
        if res is not False:
            self.logger.log_verbose(f'Process Call success for device: 0x{self.dev_addr:X}')
            print_buffer([chr(i) for i in res])
            return True
        return res

    def configure(self):
        if self.is_mmio:
            self._smbus = self.cs.hals.smbusmmio
        else:
            self._smbus = self.cs.hals.smbus
        self._smbus.set_i2c_mode(self.is_i2c)
        self._smbus.enable()
        return True

    def run(self):
        if not self.configure():
            return False

        if not self._smbus.is_SMBus_supported():
            self.logger.log_verbose('[CHIPSEC] SMBus controller is not supported')
            return

        if self.logger.VERBOSE:
            self._smbus.display_SMBus_info()

        if self.is_addr_8b:
            self.dev_addr = self.dev_addr >> 1
            self.logger.log_hal(f'8-bit address mode enabled. Shifted address to: 0x{self.dev_addr:02X}')

        result = self.func()
        if isinstance(result, list):
            self.logger.log(f'"{self.command}" command result: [ 0x' + ' 0x'.join(f"{x:02X}" for x in result) + ' ]')
        elif isinstance(result, bool):
            if result:
                self.logger.log_good(f'command "{self.command}" succeeded')
            else:
                self.logger.log_bad(f'command "{self.command}" failed')
        return

commands = {'smbus': SMBusCommand}
