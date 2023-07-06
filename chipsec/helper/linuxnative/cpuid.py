# -*- coding: utf-8 -*-
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
import platform
from ctypes import CFUNCTYPE, POINTER, Structure, addressof, c_uint32, c_void_p, sizeof
from typing import Callable, Generator, Tuple

# Posix x86_64:
# Three first call registers : RDI, RSI, RDX
# Volatile registers         : RAX, RCX, RDX, RSI, RDI, R8-11

# cdecl 32 bit:
# Three first call registers : Stack (%esp)
# Volatile registers         : EAX, ECX, EDX

_POSIX_64_OPC = bytes((
    0x53,                    # push   %rbx
    0x89, 0xf0,              # mov    %esi,%eax
    0x89, 0xd1,              # mov    %edx,%ecx
    0x0f, 0xa2,              # cpuid
    0x89, 0x07,              # mov    %eax,(%rdi)
    0x89, 0x5f, 0x04,        # mov    %ebx,0x4(%rdi)
    0x89, 0x4f, 0x08,        # mov    %ecx,0x8(%rdi)
    0x89, 0x57, 0x0c,        # mov    %edx,0xc(%rdi)
    0x5b,                    # pop    %rbx
    0xc3                     # retq
))

_CDECL_32_OPC = bytes((
    0x53,                    # push   %ebx
    0x57,                    # push   %edi
    0x8b, 0x7c, 0x24, 0x0c,  # mov    0xc(%esp),%edi
    0x8b, 0x44, 0x24, 0x10,  # mov    0x10(%esp),%eax
    0x8b, 0x4c, 0x24, 0x14,  # mov    0x14(%esp),%ecx
    0x0f, 0xa2,              # cpuid
    0x89, 0x07,              # mov    %eax,(%edi)
    0x89, 0x5f, 0x04,        # mov    %ebx,0x4(%edi)
    0x89, 0x4f, 0x08,        # mov    %ecx,0x8(%edi)
    0x89, 0x57, 0x0c,        # mov    %edx,0xc(%edi)
    0x5f,                    # pop    %edi
    0x5b,                    # pop    %ebx
    0xc3                     # ret
))

is_64bit = sizeof(c_void_p) == 8


class CPUID_struct(Structure):
    _fields_ = [(r, c_uint32) for r in ("eax", "ebx", "ecx", "edx")]


class CPUID:
    def __init__(self) -> None:
        if platform.machine() not in ("AMD64", "x86_64", "x86", "i686"):
            raise SystemError("Only available for x86")

        code: bytes = _POSIX_64_OPC if is_64bit else _CDECL_32_OPC
        self.addr = mmap.mmap(-1, mmap.PAGESIZE, flags=mmap.MAP_PRIVATE, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        self.addr.write(code)

        func_type = CFUNCTYPE(None, POINTER(CPUID_struct), c_uint32, c_uint32)
        self.fp = c_void_p.from_buffer(self.addr)
        self.func_ptr: Callable[[CPUID_struct, int, int], None] = func_type(addressof(self.fp))

    def __call__(self, eax: int, ecx: int = 0) -> Tuple[int, int, int, int]:
        struct = CPUID_struct()
        self.func_ptr(struct, eax, ecx)
        return struct.eax, struct.ebx, struct.ecx, struct.edx

    def __del__(self) -> None:
        del self.fp
        self.addr.close()


if __name__ == "__main__":
    def valid_inputs() -> Generator[Tuple[int, Tuple[int, int, int, int]], None, None]:
        cpuid = CPUID()
        for eax in (0x0, 0x80000000):
            highest, _, _, _ = cpuid(eax)
            while eax <= highest:
                regs = cpuid(eax)
                yield (eax, regs)
                eax += 1

    print(" ".join(x.ljust(8) for x in ("CPUID", "A", "B", "C", "D")).strip())
    for eax, regs in valid_inputs():
        print("%08x" % eax, " ".join("%08x" % reg for reg in regs))
