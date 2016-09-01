//
// Copyright 2012, 2016 Google Inc. All Rights Reserved.
// Authors: Thiebaud Weksteen (tweksteen@gmail.com)
//   (pmem) Johannes Stüttgen (johannes.stuettgen@gmail.com)
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

#ifndef _CHIPSEC_H_
#define _CHIPSEC_H_

// ioctl commands for this driver
#include "chipsec_ioctl.h"
// variable length function arguments for the logging functions
// sysctl and general kernel tools
#include <libkern/OSMalloc.h>
#include <sys/systm.h>
// Character device dependencies
#include <miscfs/devfs/devfs.h>
#include <sys/conf.h>
// IOKit memory interface
#include <IOKit/IOMemoryDescriptor.h>

// Read as many bytes as requested in uio->resid (starting from uio->offset)
// and copy them to the userspace buffer in the uio.
static kern_return_t pmem_read(dev_t dev, struct uio *uio, __unused int rw);

// Read directly from physical memory.
static kern_return_t pmem_read_memory(struct uio *uio);

// Will read as many bytes as possible from physical memory,
// stopping at page boundaries or invalid regions like memory-mapped I/O.
static uint64_t pmem_partial_read(struct uio *uio, addr64_t addr,
                                  uint64_t requested_bytes);

// User-mode interface to obtain the binary memory map
static kern_return_t pmem_ioctl(dev_t dev, u_long cmd, caddr_t data, int flag,
                                struct proc *p);

// Debug logging, only active in debug build.
static void pmem_log(const char *fmt, ...);

// Error logging, always active.
static void pmem_error(const char *fmt, ...);


// Try to free all resources.
static int pmem_cleanup(int error);


// Declare c calling conventions for the linker to find these symbols
extern "C" {
    kern_return_t chipsec_start(kmod_info_t * ki, void *d);
    kern_return_t chipsec_stop(kmod_info_t *ki, void *d);
}

#endif  // _CHIPSEC_H_
