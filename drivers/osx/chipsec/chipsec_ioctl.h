//
// Copyright 2012, 2016 Google Inc. All Rights Reserved.
// Authors: Johannes Stüttgen (johannes.stuettgen@gmail.com)
//          Thiebaud Weksteen (tweksteen@gmail.com)
//
// Copyright (c) 2010-2015, Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef _CHIPSEC_IOCTLS_H_
#define _CHIPSEC_IOCTLS_H_

#include <stdint.h>

#define CHIPSEC_NONE                    0x0
#define CHIPSEC_RDPCI                   0x1
#define CHIPSEC_WRPCI                   0x2
#define CHIPSEC_RDMMIO                  0x3
#define CHIPSEC_WRMMIO                  0x4
#define CHIPSEC_RDCR                    0x5
#define CHIPSEC_WRCR                    0x6
#define CHIPSEC_RDIO                    0x7
#define CHIPSEC_WRIO                    0x8
#define CHIPSEC_CPUID                   0x9
#define CHIPSEC_RDMSR                   0xa
#define CHIPSEC_WRMSR                   0xb
#define CHIPSEC_SWSMI                   0xc
#define CHIPSEC_HYPERCALL               0xd
#define CHIPSEC_MSGBUS_SEND_MESSAGE     0xe
#define CHIPSEC_CPU_DESCRIPTOR_TABLE    0xf
#define CHIPSEC_ALLOC_PHYSMEM           0x10
#define CHIPSEC_LOAD_UCODE_PATCH        0x11


typedef struct _pci_msg_t {
    uint8_t  bus;
    uint8_t  device;
    uint8_t  function;
    uint16_t offset;
    uint8_t  length; // 1, 2 or 4
    uint32_t value;
} pci_msg_t;

typedef struct _mmio_msg_t {
    uint64_t addr;
    uint64_t value;
    uint8_t length; // 1, 2, 4 or 8
} mmio_msg_t;

typedef struct _cr_msg_t {
    int  register_number; // 0, 2, 3, 4 or 8
    unsigned long value;
} cr_msg_t;

typedef struct _io_msg_t {
    uint64_t port;
    uint64_t size;
    uint64_t value;
} io_msg_t;

typedef struct _msr_msg_t {
    uint64_t msr_num;
    uint64_t msr_lo;
    uint64_t msr_hi;
} msr_msg_t;

typedef struct _cpuid_msg_t {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
} cpuid_msg_t;

typedef struct _swsmi_msg_t {
    uint64_t code_data;
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
} swsmi_msg_t;

typedef struct _hypercall_msg_t {
    uint64_t rcx;
    uint64_t rdx;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t rax;
    uint64_t rbx;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t xmm_buffer;
    uint64_t hypercall_page;
} hypercall_msg_t;

typedef struct _msgbus_msg_t {
    uint64_t direction;
    uint64_t mcr;
    uint64_t mcrx;
    uint64_t mdr;
    uint64_t mdr_out;
} msgbus_msg_t;

typedef struct _cpudes_msg_t {
    uint64_t cpu_thread_id;
    uint64_t des_table_code;
    uint64_t limit;
    uint64_t base_hi;
    uint64_t base_lo;
    uint64_t pa_hi;
    uint64_t pa_lo;
} cpudes_msg_t;

typedef struct _alloc_pmem_msg_t {
    uint64_t num_bytes;
    uint64_t max_addr;
    uint64_t virt_addr;
    uint64_t phys_addr;
} alloc_pmem_msg_t;

#define CHIPSEC_IOCTL_BASE 'p'

#define CHIPSEC_IOC_RDPCI                _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_RDPCI,                   pci_msg_t)
#define CHIPSEC_IOC_WRPCI                _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_WRPCI,                   pci_msg_t)
#define CHIPSEC_IOC_RDMMIO               _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_RDMMIO,                  mmio_msg_t)
#define CHIPSEC_IOC_WRMMIO               _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_WRMMIO,                  mmio_msg_t)
#define CHIPSEC_IOC_RDCR                 _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_RDCR,                    cr_msg_t)
#define CHIPSEC_IOC_WRCR                 _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_WRCR,                    cr_msg_t)
#define CHIPSEC_IOC_RDIO                 _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_RDIO,                    io_msg_t)
#define CHIPSEC_IOC_WRIO                 _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_WRIO,                    io_msg_t)
#define CHIPSEC_IOC_CPUID                _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_CPUID,                   cpuid_msg_t)
#define CHIPSEC_IOC_RDMSR                _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_RDMSR,                   msr_msg_t)
#define CHIPSEC_IOC_WRMSR                _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_WRMSR,                   msr_msg_t)
#define CHIPSEC_IOC_SWSMI                _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_SWSMI,                   swsmi_msg_t)
#define CHIPSEC_IOC_HYPERCALL            _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_HYPERCALL,               hypercall_msg_t)
#define CHIPSEC_IOC_MSGBUS_SEND_MESSAGE  _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_MSGBUS_SEND_MESSAGE,     msgbus_msg_t)
#define CHIPSEC_IOC_CPU_DESCRIPTOR_TABLE _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_CPU_DESCRIPTOR_TABLE,    cpudes_msg_t)
#define CHIPSEC_IOC_ALLOC_PHYSMEM        _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_ALLOC_PHYSMEM,           alloc_pmem_msg_t)


#endif  // _CHIPSEC_IOCTLS_H_
