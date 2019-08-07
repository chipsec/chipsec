#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2019, Intel Corporation
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
The vmem command provides direct access to read and write virtual memory.
"""

import os
import chipsec_util

import chipsec.defines
from chipsec.logger     import print_buffer
from chipsec.command    import BaseCommand
from chipsec.hal	    import virtmem

# Virtual Memory
class VMemCommand(BaseCommand):
    """
    >>> chipsec_util vmem <op> <physical_address> <length> [value|buffer_file]
    >>>
    >>> <physical_address> : 64-bit physical address
    >>> <op>               : read|readval|write|writeval|allocate|pagedump|search|getphys
    >>> <length>           : byte|word|dword or length of the buffer from <buffer_file>
    >>> <value>            : byte, word or dword value to be written to memory at <physical_address>
    >>> <buffer_file>      : file with the contents to be written to memory at <physical_address>

    Examples:

    >>> chipsec_util vmem <op>     <virtual_address>  <length> [value|file]                      
    >>> chipsec_util vmem readval  0xFED40000         dword
    >>> chipsec_util vmem read     0x41E              0x20     buffer.bin
    >>> chipsec_util vmem writeval 0xA0000            dword    0x9090CCCC
    >>> chipsec_util vmem write    0x100000000        0x1000   buffer.bin
    >>> chipsec_util vmem write    0x100000000        0x10     000102030405060708090A0B0C0D0E0F
    >>> chipsec_util vmem allocate                    0x1000
    >>> chipsec_util vmem search   0xF0000            0x10000  _SM_  
    >>> chipsec_util vmem getphys  0xFED00000                       
    """


    def requires_driver(self):
        # No driver required when printing the util documentation
        if len(self.argv) < 3:
            return False
        return True

    def run(self):
        try:
            _vmem = virtmem.VirtMemory(self.cs)
        except:
            return

        size = 0x100

        if len(self.argv) < 3:
            print (VMemCommand.__doc__)
            return

        op = self.argv[2]

        if 'allocate'   == op and 4 == len(self.argv):
            size = int(self.argv[3],16)
            (va, pa) = _vmem.alloc_virtual_mem( size )
            self.logger.log( '[CHIPSEC] Allocated {:X} bytes of virtual memory: VA = 0x{:016X}, PA = 0x{:016X}'.format(size, va, pa) )

        elif 'search' == op and len(self.argv) > 5:
            virt_address = int(self.argv[3],16)
            size         = int(self.argv[4],16)
                      
            buffer = _vmem.read_virtual_mem( virt_address, size )
            buffer = chipsec.defines.bytestostring(buffer)
            offset = buffer.find(self.argv[5])

            if offset != -1:
                self.logger.log( '[CHIPSEC] search buffer from memory: VA = 0x{:016X}, len = 0x{:X}, target address= 0x{:X}..'.format(virt_address, size, virt_address + offset) )
            else:
                self.logger.log( '[CHIPSEC] search buffer from memory: VA = 0x{:016X}, len = 0x{:X}, can not find the target in the searched range..'.format(virt_address, size) )

        elif 'read'     == op:
            virt_address = int(self.argv[3],16)
            size         = int(self.argv[4],16) if len(self.argv) > 4 else 0x100
            self.logger.log( '[CHIPSEC] reading buffer from memory: VA = 0x{:016X}, len = 0x{:X}..'.format(virt_address, size) )
            buffer = _vmem.read_virtual_mem( virt_address, size )
            if len(self.argv) > 5:
                buf_file = self.argv[5]
                chipsec.file.write_file( buf_file, buffer )
                self.logger.log( "[CHIPSEC] written 0x{:X} bytes to '{}'".format(len(buffer), buf_file) )
            else:
                print_buffer( chipsec.defines.bytestostring(buffer) )

        elif 'readval'  == op:
            virt_address = int(self.argv[3],16)
            width        = 0x4
            if len(self.argv) > 4: 
                width = chipsec_util.get_option_width(self.argv[4]) if chipsec_util.is_option_valid_width(self.argv[4]) else int(self.argv[4],16)
            self.logger.log( '[CHIPSEC] reading {:X}-byte value from VA 0x{:016X}..'.format(width, virt_address) )
            if   0x1 == width: value = _vmem.read_virtual_mem_byte ( virt_address )
            elif 0x2 == width: value = _vmem.read_virtual_mem_word ( virt_address )
            elif 0x4 == width: value = _vmem.read_virtual_mem_dword( virt_address )
            self.logger.log( '[CHIPSEC] value = 0x{:X}'.format(value) )

        elif 'write'    == op:
            virt_address = int(self.argv[3],16)
            if len(self.argv) > 4: 
                size = int(self.argv[4],16)
            else:
                self.logger.error( "must specify <length> argument in 'mem write'" )
                return
            if len(self.argv) > 5:
                buf_file = self.argv[5]
                if not os.path.exists( buf_file ):
                    #buffer = buf_file.decode('hex')
                    try:
                      buffer = bytearray.fromhex(buf_file)
                    except ValueError as e:
                        self.logger.error( "incorrect <value> specified: '{}'".format(buf_file) )
                        self.logger.error( str(e) )
                        return
                    self.logger.log( "[CHIPSEC] read 0x{:X} hex bytes from command-line: {}'".format(len(buffer), buf_file) )
                else:
                    buffer = chipsec.file.read_file( buf_file )
                    self.logger.log( "[CHIPSEC] read 0x{:X} bytes from file '{}'".format(len(buffer), buf_file) )

                if len(buffer) < size:
                    self.logger.error( "number of bytes read (0x{:X}) is less than the specified <length> (0x{:X})".format(len(buffer),size) )
                    return

                self.logger.log( '[CHIPSEC] writing buffer to memory: VA = 0x{:016X}, len = 0x{:X}..'.format(virt_address, size) )
                _vmem.write_virtual_mem( virt_address, size, buffer )
            else:
                self.logger.error( "must specify <buffer>|<file> argument in 'mem write'" )
                return

        elif 'writeval' == op:
            virt_address = int(self.argv[3],16)
            if len(self.argv) > 4: 
                width = chipsec_util.get_option_width(self.argv[4]) if chipsec_util.is_option_valid_width(self.argv[4]) else int(self.argv[4],16)
            else:
                self.logger.error( "must specify <length> argument in 'mem writeval' as one of {}".format(chipsec_util.CMD_OPTS_WIDTH) )
                return
            if len(self.argv) > 5: 
                value = int(self.argv[5],16)
            else:
                self.logger.error( "must specify <value> argument in 'mem writeval'" )
                return

            self.logger.log( '[CHIPSEC] writing {:X}-byte value 0x{:X} to VA 0x{:016X}..'.format(width, value, virt_address) )
            if   0x1 == width: _vmem.write_virtual_mem_byte ( virt_address, value )
            elif 0x2 == width: _vmem.write_virtual_mem_word ( virt_address, value )
            elif 0x4 == width: _vmem.write_virtual_mem_dword( virt_address, value )

        elif 'getphys' == op:
            virt_address = int(self.argv[3],16)
            pa = _vmem.va2pa( virt_address )
            if pa is not None:
                self.logger.log( '[CHIPSEC] Allocated {:X} bytes of virtual memory: VA = 0x{:016X}, PA = 0x{:016X}'.format(size, virt_address, pa) )
            
        else:
                print (VMemCommand.__doc__)
                return

commands = { 'vmem': VMemCommand }

