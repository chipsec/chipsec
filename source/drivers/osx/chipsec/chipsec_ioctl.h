//
// Copyright 2012, 2016 Google Inc. All Rights Reserved.
// Authors: Johannes Stüttgen (johannes.stuettgen@gmail.com)
//          Thiebaud Weksteen (tweksteen@gmail.com)
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

#define CHIPSEC_NONE    0
#define CHIPSEC_RDPCI   1
#define CHIPSEC_WRPCI   2
#define CHIPSEC_RDMMIO  3
#define CHIPSEC_WRMMIO  4
#define CHIPSEC_RDCR    5
#define CHIPSEC_WRCR    6

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

#define CHIPSEC_IOCTL_BASE 'p'

#define CHIPSEC_IOC_RDPCI   _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_RDPCI,   pci_msg_t)
#define CHIPSEC_IOC_WRPCI   _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_WRPCI,   pci_msg_t)
#define CHIPSEC_IOC_RDMMIO  _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_RDMMIO,  mmio_msg_t)
#define CHIPSEC_IOC_WRMMIO  _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_WRMMIO,  mmio_msg_t)
#define CHIPSEC_IOC_RDCR    _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_RDCR,    cr_msg_t)
#define CHIPSEC_IOC_WRCR    _IOWR(CHIPSEC_IOCTL_BASE, CHIPSEC_WRCR,    cr_msg_t)



#endif  // _CHIPSEC_IOCTLS_H_
