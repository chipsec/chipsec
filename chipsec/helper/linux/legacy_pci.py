# Copyright (c) 2020 Intel Corporation
# SPDX-License-Identifier: GPL-2.0-only
#
# This file incorporates work covered by the following copyright and
# permission notice:
#
# Copyright (c) 2014 Anders Høst
# Copyright (c) 2018 Anders Høst
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


import mmap

from ctypes import cdll, c_ubyte, CFUNCTYPE, c_uint32, c_uint16, c_void_p, addressof

IN_PORT = [
    0x55,  # push   %rbp
    0x48,
    0x89,
    0xE5,  # mov    %rsp,%rbp
    0x89,
    0xF8,  # mov    %edi,%eax
    0x66,
    0x89,
    0x45,
    0xEC,  # mov    %ax,-0x14(%rbp)
    0x0F,
    0xB7,
    0x45,
    0xEC,  # movzwl -0x14(%rbp),%eax
    0x89,
    0xC2,  # mov    %eax,%edx
    0xED,  # in     (%dx),%eax
    0x89,
    0x45,
    0xFC,  # mov    %eax,-0x4(%rbp)
    0x8B,
    0x45,
    0xFC,  # mov    -0x4(%rbp),%eax
    0x5D,  # pop    %rbp
    0xC3,  # retq
]


OUT_PORT = [
    0x55,  # push   %rbp
    0x48,
    0x89,
    0xE5,  # mov    %rsp,%rbp
    0x89,
    0x7D,
    0xFC,  # mov    %edi,-0x4(%rbp)
    0x89,
    0xF0,  # mov    %esi,%eax
    0x66,
    0x89,
    0x45,
    0xF8,  # mov    %ax,-0x8(%rbp)
    0x8B,
    0x45,
    0xFC,  # mov    -0x4(%rbp),%eax
    0x0F,
    0xB7,
    0x55,
    0xF8,  # movzwl -0x8(%rbp),%edx
    0xEF,  # out    %eax,(%dx)
    0x90,  # nop
    0x5D,  # pop    %rbp
    0xC3,  # retq
]


class PORTS(object):
    def __init__(self):
        clib = cdll.LoadLibrary("libc.so.6")
        clib.iopl(3)

        opc = IN_PORT
        size = len(opc)
        code = (c_ubyte * size)(*opc)
        self.addr = mmap.mmap(
            -1, mmap.PAGESIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC
        )
        self.addr.write(bytes(code))
        in_func_type = CFUNCTYPE(c_uint32, c_uint16)
        self.in_fp = c_void_p.from_buffer(self.addr)
        self.inl_ptr = in_func_type(addressof(self.in_fp))

        opc = OUT_PORT
        size = len(opc)
        code = (c_ubyte * size)(*opc)
        self.addr = mmap.mmap(
            -1, mmap.PAGESIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC
        )
        self.addr.write(bytes(code))
        out_func_type = CFUNCTYPE(None, c_uint32, c_uint16)
        self.out_fp = c_void_p.from_buffer(self.addr)
        self.outl_ptr = out_func_type(addressof(self.out_fp))

    def inl(self, port):
        x = self.inl_ptr(port)
        return x

    def outl(self, value, port):
        self.outl_ptr(value, port)


class LEGACY_PCI(object):
    def __init__(self):
        self.ports = PORTS()

    def read_pci_config(self, bus, dev, func, offset):
        self.ports.outl(
            0x80000000 | (bus << 16) | (dev << 11) | (func << 8) | offset, 0xCF8
        )
        v = self.ports.inl(0xCFC)
        return v

    def write_pci_config(self, bus, dev, func, offset, value):
        self.ports.outl(
            0x80000000 | (bus << 16) | (dev << 11) | (func << 8) | offset, 0xCF8
        )
        self.ports.outl(value, 0xCFC)
