# -*- coding: utf-8 -*-
# # Copyright (c) 2020 Intel Corporation
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
from ctypes import CDLL, CFUNCTYPE, addressof, c_uint16, c_uint32, c_void_p, get_errno
from typing import Callable

from chipsec.library.exceptions import OsHelperError

IN_PORT = bytes((
    0x55,                   # push   %rbp
    0x48, 0x89, 0xe5,       # mov    %rsp,%rbp
    0x89, 0xf8,             # mov    %edi,%eax
    0x66, 0x89, 0x45, 0xec,  # mov    %ax,-0x14(%rbp)
    0x0f, 0xb7, 0x45, 0xec,  # movzwl -0x14(%rbp),%eax
    0x89, 0xc2,             # mov    %eax,%edx
    0xed,                   # in     (%dx),%eax
    0x89, 0x45, 0xfc,       # mov    %eax,-0x4(%rbp)
    0x8b, 0x45, 0xfc,       # mov    -0x4(%rbp),%eax
    0x5d,                   # pop    %rbp
    0xc3,                   # retq
))


OUT_PORT = bytes((
    0x55,                   # push   %rbp
    0x48, 0x89, 0xe5,       # mov    %rsp,%rbp
    0x89, 0x7d, 0xfc,       # mov    %edi,-0x4(%rbp)
    0x89, 0xf0,             # mov    %esi,%eax
    0x66, 0x89, 0x45, 0xf8,  # mov    %ax,-0x8(%rbp)
    0x8b, 0x45, 0xfc,       # mov    -0x4(%rbp),%eax
    0x0f, 0xb7, 0x55, 0xf8,  # movzwl -0x8(%rbp),%edx
    0xef,                   # out    %eax,(%dx)
    0x90,                   # nop
    0x5d,                   # pop    %rbp
    0xc3,                   # retq
))


class Ports:
    # Use a unique Ports instance, to avoid allocating memory mappings every time it is used
    instance = None

    def __init__(self) -> None:
        clib = CDLL("libc.so.6", use_errno=True)
        if clib.iopl(3) == -1:
            raise OsHelperError("Unable to use I/O ports using iopl", get_errno())

        self.inl_addr = mmap.mmap(-1, mmap.PAGESIZE, flags=mmap.MAP_PRIVATE, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        self.inl_addr.write(IN_PORT)
        in_func_type = CFUNCTYPE(c_uint32, c_uint16)
        in_fp = c_void_p.from_buffer(self.inl_addr)
        self.inl_ptr: Callable[[int], int] = in_func_type(addressof(in_fp))

        self.outl_addr = mmap.mmap(-1, mmap.PAGESIZE, flags=mmap.MAP_PRIVATE, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        self.outl_addr.write(OUT_PORT)
        out_func_type = CFUNCTYPE(None, c_uint32, c_uint16)
        out_fp = c_void_p.from_buffer(self.outl_addr)
        self.outl_ptr: Callable[[int, int], None] = out_func_type(addressof(out_fp))

    @classmethod
    def get_instance(cls) -> "Ports":
        if cls.instance is None:
            cls.instance = cls()
        return cls.instance

    def inl(self, port: int) -> int:
        x = self.inl_ptr(port)
        return x

    def outl(self, value: int, port: int) -> None:
        self.outl_ptr(value, port)


class LegacyPci:
    @staticmethod
    def read_pci_config(bus: int, dev: int, func: int, offset: int) -> int:
        ports = Ports.get_instance()
        ports.outl(0x80000000 | (bus << 16) | (dev << 11) | (func << 8) | offset, 0xcf8)
        v = ports.inl(0xcfc)
        return v

    @staticmethod
    def write_pci_config(bus: int, dev: int, func: int, offset: int, value: int) -> None:
        ports = Ports.get_instance()
        ports.outl(0x80000000 | (bus << 16) | (dev << 11) | (func << 8) | offset, 0xcf8)
        ports.outl(value, 0xcfc)
