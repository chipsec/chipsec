#
# Copyright 2016 Google Inc. All Rights Reserved.
# Authors: Thiebaud Weksteen (tweksteen@gmail.com)
# Copyright (c) 2010-2015, Intel Corporation
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
.globl _ReadPortByte
.globl _ReadPortWord
.globl _ReadPortDword
.globl _WritePortByte
.globl _WritePortWord
.globl _WritePortDword
.globl _ReadMSR
.globl _WriteMSR
.globl _chipCPUID
.globl _SWSMI
.globl _hypercall
.globl _hypercall_page
.globl _store_idtr
.globl _store_gdtr
.globl _store_ldtr
.globl _load_idtr
.globl _load_gdtr
.globl _load_ldtr
.globl _load_gdt

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

#------------------------------------------------------------------------------
#  unsigned int
#  ReadPortByte (
#    unsigned short	io_port    // rdi
#    )
#------------------------------------------------------------------------------
_ReadPortByte:
    xor %rax, %rax
    mov %rdi, %rdx
    in  %dx, %al

    ret

#------------------------------------------------------------------------------
#  unsigned int
#  ReadPortWord (
#    unsigned short	io_port    // rdi
#    )
#------------------------------------------------------------------------------
_ReadPortWord:
    xor %rax, %rax
    mov %rdi, %rdx
    in  %dx, %ax

    ret

#------------------------------------------------------------------------------
#  unsigned int
#  ReadPortDword (
#    unsigned short	io_port    // rdi
#    )
#------------------------------------------------------------------------------
_ReadPortDword:
    xor %rax, %rax
    mov %rdi, %rdx
    in  %dx, %eax

    ret

#------------------------------------------------------------------------------
#  unsigned int
#  WritePortByte (
#    unsigned char  value      // rdi
#    unsigned short	io_port    // rsi
#    )
#------------------------------------------------------------------------------
_WritePortByte:
    xor %rax, %rax
    mov %rdi, %rax
    mov %rsi, %rdx
    out %al, %dx

    ret

#------------------------------------------------------------------------------
#  unsigned int
#  WritePortWord (
#    unsigned short value      // rdi
#    unsigned short	io_port    // rsi
#    )
#------------------------------------------------------------------------------
_WritePortWord:
    xor %rax, %rax
    mov %rdi, %rax
    mov %rsi, %rdx
    out %ax, %dx

    ret

#------------------------------------------------------------------------------
#  unsigned int
#  WritePortDword (
#    unsigned int  value      // rdi
#    unsigned short	io_port    // rsi
#    )
#------------------------------------------------------------------------------
_WritePortDword:
    mov %rdi, %rax
    mov %rsi, %rdx
    out %eax, %dx

    ret

#------------------------------------------------------------------------------
#  void
#  RDMSR (
#    unsigned long   msr_num   // rdi
#    unsigned * long msr_lo        // rsi
#    unsigned * long msr_hi        // rdx
#    )
#------------------------------------------------------------------------------
_ReadMSR:
    //msr_add goes in rcx
    mov %rdi, %rcx
    //mov store pointers in r10 and r11
    mov %rsi, %r10
    mov %rdx, %r11
    //call rdmsr
    rdmsr
    //Write msr results in edx:eax
    mov %rax, (%r10)
    mov %rdx, (%r11)

    ret

#------------------------------------------------------------------------------
#  void
#  WriteMSR (
#    unsigned long   msr_num   // rdi
#    unsigned long msr_lo      // rsi
#    unsigned long msr_hi      // rdx
#    )
#------------------------------------------------------------------------------
_WriteMSR:
    //msr_add goes in rcx
    mov %rdi, %rcx
    //msr_lo -> rax msr_hi -> rdx
    mov %rsi, %rax
    //call wrmsr
    wrmsr

    ret

#------------------------------------------------------------------------------
#  void
#  CPUID (
#    unsigned long   struct_cpuid   // rdi
#    )
#------------------------------------------------------------------------------
_chipCPUID:
    xchg (%rdi),     %rax
    xchg 0x8(%rdi),  %rbx
    xchg 0x10(%rdi), %rcx
    xchg 0x18(%rdi), %rdx
    cpuid
    xchg %rax, (%rdi)
    xchg %rbx, 0x8(%rdi)
    xchg %rcx, 0x10(%rdi)
    xchg %rdx, 0x18(%rdi)

    ret

#------------------------------------------------------------------------------
#  void
#  SWSMI (
#    unsigned long   struct_swsmi   // rdi
#    )
#------------------------------------------------------------------------------
_SWSMI:
    mov  %rdi, %r10
    xchg %rax, (%r10)
    xchg %rbx, 0x10(%r10)
    xchg %rcx, 0x18(%r10)
    xchg %rdx, 0x20(%r10)
    xchg %rsi, 0x28(%r10)
    xchg %rdi, 0x30(%r10)
    out  %ax, $0x0B2h
    xchg %rax, 0x8(%r10)
    xchg %rbx, 0x10(%r10)
    xchg %rcx, 0x18(%r10)
    xchg %rdx, 0x20(%r10)
    xchg %rsi, 0x28(%r10)
    xchg %rdi, 0x30(%r10)

    ret

#------------------------------------------------------------------------------
#   uint64_t
#   hypercall(
#     uint64_t rdi  //rdi
#     uint64_t rsi  //rsi
#     uint64_t rdx  //rdx
#     uint64_t rcx  //rcx
#     uint64_t r8   //r8
#     uint64_t r9   //r9
#     uint64_t rax  //sp + 10h
#     uint64_t rbx  //sp + 18h
#     uint64_t r10  //sp + 20h
#     uint64_t r11  //sp + 28h
#     uint64_t xmm_buff  //sp + 30h
#     uint64_t hypercall_page  // sp + 38h
#   )
#------------------------------------------------------------------------------
_hypercall:
    push   %rbp
    mov     %rsp, %rbp
    push   %rbx
    mov    0x30(%rbp), %rax
    test   %rax, %rax
    jz     hypercall_skip_xmm
    pinsrq $0x0, (%rax), %xmm0
    pinsrq $0x1, 0x8(%rax), %xmm0
    pinsrq $0x0, 0x10(%rax), %xmm1
    pinsrq $0x1, 0x18(%rax), %xmm1
    pinsrq $0x0, 0x20(%rax), %xmm2
    pinsrq $0x1, 0x28(%rax), %xmm2
    pinsrq $0x0, 0x30(%rax), %xmm3
    pinsrq $0x1, 0x38(%rax), %xmm3
    pinsrq $0x0, 0x40(%rax), %xmm4
    pinsrq $0x1, 0x48(%rax), %xmm4
    pinsrq $0x0, 0x50(%rax), %xmm5
    pinsrq $0x1, 0x58(%rax), %xmm5
  hypercall_skip_xmm:
    mov    0x10(%rbp), %rax
    mov    0x18(%rbp), %rbx
    mov    0x20(%rbp), %r10
    mov    0x28(%rbp), %r11
    call   *0x38(%rbp)
    pop    %rbx
    pop    %rbp
    ret

#------------------------------------------------------------------------------
#   uint64_t
#   hypercall_page()
#------------------------------------------------------------------------------
_hypercall_page:
    vmcall
    ret

#------------------------------------------------------------------------------
#  void
#  store_idtr(
#   unsigned char * address //rdi
#   );
#------------------------------------------------------------------------------
_store_idtr:
    sidt (%rdi)
    ret

#------------------------------------------------------------------------------
#  void
#  store_gdtr(
#   unsigned char * address //rdi
#   );
#------------------------------------------------------------------------------
_store_gdtr:
    sgdt (%rdi)
    ret

#------------------------------------------------------------------------------
#  void
#store_ldtr(
#   unsigned char * address //rdi
#   );
#------------------------------------------------------------------------------
_store_ldtr:
    sldt (%rdi)
    ret

#------------------------------------------------------------------------------
#  void
#  load_idtr(
#   unsigned char * address //rdi
#   );
#------------------------------------------------------------------------------
_load_idtr:
    lidt (%rdi)
    ret

#------------------------------------------------------------------------------
#  void
#  load_gdtr(
#   unsigned char * address //rdi
#   );
#------------------------------------------------------------------------------
_load_gdtr:
    lgdt (%rdi)
    ret

#------------------------------------------------------------------------------
#  void
#  load_ldtr(
#   unsigned char * address //rdi
#   );
#------------------------------------------------------------------------------
_load_ldtr:
    lldt (%rdi)
    ret

#------------------------------------------------------------------------------
#  void
#  load_gdt(
#   unsigned char * address //rdi
#   );
#------------------------------------------------------------------------------
_load_gdt:
    sgdt (%rdi)
    lgdt (%rdi)
    ret
