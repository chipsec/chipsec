#
# Copyright 2016 Google Inc. All Rights Reserved.
# Authors: Thiebaud Weksteen (tweksteen@gmail.com)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.text

.globl _WritePCIByte
.globl _WritePCIWord
.globl _WritePCIDword
.globl _ReadPCIByte
.globl _ReadPCIWord
.globl _ReadPCIDword
.globl _ReadCR0
.globl _ReadCR2
.globl _ReadCR3
.globl _ReadCR4
.globl _ReadCR8
.globl _WriteCR0
.globl _WriteCR2
.globl _WriteCR3
.globl _WriteCR4
.globl _WriteCR8

#------------------------------------------------------------------------------
#  void
#  WritePCIByte (
#    unsigned int	pci_reg          // rdi
#    unsigned short	cfg_data_port    // rsi
#    unsigned char	byte_value       // rdx
#    )
#------------------------------------------------------------------------------
_WritePCIByte:
    push %rax
    push %rsi
    push %rdx

    cli
    movq %rdi, %rax  # pci_reg
    movw $0x0CF8, %dx
    out %eax, %dx

    pop %rax         # byte_value
    pop %rdx         # cfg_data_port
    out %al, %dx
    sti

    pop %rax
    ret

#------------------------------------------------------------------------------
#  void
#  WritePCIWord (
#    unsigned int	pci_reg          // rdi
#    unsigned short	cfg_data_port    // rsi
#    unsigned short	word_value       // rdx
#    )
#------------------------------------------------------------------------------
_WritePCIWord:
    push %rax
    push %rsi
    push %rdx

    cli
    movq %rdi, %rax  # pci_reg
    movw $0x0CF8, %dx
    out %eax, %dx

    pop %rax         # byte_value
    pop %rdx         # cfg_data_port
    out %ax, %dx
    sti

    pop %rax
    ret

#------------------------------------------------------------------------------
#  void
#  WritePCIDword (
#    unsigned int	pci_reg          // rdi
#    unsigned short	cfg_data_port    // rsi
#    unsigned int	dword_value      // rdx
#    )
#------------------------------------------------------------------------------
_WritePCIDword:
    push %rax
    push %rsi
    push %rdx

    cli
    movq %rdi, %rax  # pci_reg
    movw $0x0CF8, %dx
    out %eax, %dx

    pop %rax         # byte_value
    pop %rdx         # cfg_data_port
    out %eax, %dx
    sti

    pop %rax
    ret

#------------------------------------------------------------------------------
#  unsigned char
#  ReadPCIByte (
#    unsigned int	pci_reg          // rdi
#    unsigned short	cfg_data_port    // rsi
#    )
#------------------------------------------------------------------------------
_ReadPCIByte:

    cli
    movq %rdi, %rax  # pci_reg
    movw $0x0CF8, %dx
    out %eax, %dx

    xor %rax, %rax
    movq %rsi, %rdx  # cfg_data_port
    in  %dx, %al
    sti

    ret

#------------------------------------------------------------------------------
#  unsigned short
#  ReadPCIWord (
#    unsigned int	pci_reg          // rdi
#    unsigned short	cfg_data_port    // rsi
#    )
#------------------------------------------------------------------------------
_ReadPCIWord:

    cli
    movq %rdi, %rax  # pci_reg
    movw $0x0CF8, %dx
    out %eax, %dx

    xor %rax, %rax
    movq %rsi, %rdx  # cfg_data_port
    in  %dx, %ax
    sti

    ret

#------------------------------------------------------------------------------
#  unsigned int
#  ReadPCIDword (
#    unsigned int	pci_reg          // rdi
#    unsigned short	cfg_data_port    // rsi
#    )
#------------------------------------------------------------------------------
_ReadPCIDword:

    cli
    movq %rdi, %rax  # pci_reg
    movw $0x0CF8, %dx
    out %eax, %dx

    xor %rax, %rax
    movq %rsi, %rdx  # cfg_data_port
    in  %dx, %eax
    sti

    ret

#------------------------------------------------------------------------------
# Read and Write Control Registers
#
# unsigned int ReadCR##()
# void WriteCR##(unsigned long value) //rdi
#------------------------------------------------------------------------------

_ReadCR0:
    xor %rax, %rax
    movq %cr0, %rax
    ret

_ReadCR2:
    xor %rax, %rax
    movq %cr2, %rax
    ret

_ReadCR3:
    xor %rax, %rax
    movq %cr3, %rax
    ret

_ReadCR4:
    xor %rax, %rax
    movq %cr4, %rax
    ret

_ReadCR8:
    xor %rax, %rax
    movq %cr8, %rax
    ret

_WriteCR0:
    movq %rdi, %cr0
    ret

_WriteCR2:
    movq %rdi, %cr2
    ret

_WriteCR3:
    movq %rdi, %cr3
    ret

_WriteCR4:
    movq %rdi, %cr4
    ret

_WriteCR8:
    movq %rdi, %cr8
    ret



