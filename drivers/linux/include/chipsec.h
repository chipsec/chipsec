/*
CHIPSEC: Platform Security Assessment Framework
Copyright (c) 2010-2019, Intel Corporation

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; Version 2.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

Contact information:
chipsec@intel.com
*/
#ifndef CHIPSEC_H
#define CHIPSEC_H

#define MSR_IA32_BIOS_UPDT_TRIG 0x79
#define MSR_IA32_BIOS_SIGN_ID   0x8b

#define IOCTL_NUM 'C'

#define IOCTL_BASE                     _IO(IOCTL_NUM, 0)
#define IOCTL_RDIO                     _IOWR(IOCTL_NUM, 0x1, int*)
#define IOCTL_WRIO                     _IOWR(IOCTL_NUM, 0x2, int*)
#define IOCTL_RDPCI                    _IOWR(IOCTL_NUM, 0x3, int*)
#define IOCTL_WRPCI                    _IOWR(IOCTL_NUM, 0x4, int*)
#define IOCTL_RDMSR                    _IOWR(IOCTL_NUM, 0x5, int*) 
#define IOCTL_WRMSR                    _IOWR(IOCTL_NUM, 0x6, int*) 
#define IOCTL_CPUID                    _IOWR(IOCTL_NUM, 0x7, int*) 
#define IOCTL_GET_CPU_DESCRIPTOR_TABLE _IOWR(IOCTL_NUM, 0x8, int*)
#define IOCTL_HYPERCALL                _IOWR(IOCTL_NUM, 0x9, int*)
#define IOCTL_SWSMI                    _IOWR(IOCTL_NUM, 0xA, int*)
#define IOCTL_LOAD_UCODE_PATCH         _IOWR(IOCTL_NUM, 0xB, int*)
#define IOCTL_ALLOC_PHYSMEM            _IOWR(IOCTL_NUM, 0xC, int*)
#define IOCTL_GET_EFIVAR               _IOWR(IOCTL_NUM, 0xD, int*)
#define IOCTL_SET_EFIVAR               _IOWR(IOCTL_NUM, 0xE, int*)       
#define IOCTL_RDCR                     _IOWR(IOCTL_NUM, 0x10, int*) 
#define IOCTL_WRCR                     _IOWR(IOCTL_NUM, 0x11, int*) 
#define IOCTL_RDMMIO                   _IOWR(IOCTL_NUM, 0x12, int*)
#define IOCTL_WRMMIO                   _IOWR(IOCTL_NUM, 0x13, int*)
#define IOCTL_VA2PA                    _IOWR(IOCTL_NUM, 0x14, int*)
#define IOCTL_MSGBUS_SEND_MESSAGE      _IOWR(IOCTL_NUM, 0x15, int*)
#define IOCTL_FREE_PHYSMEM             _IOWR(IOCTL_NUM, 0x16, int*)
#define IOCTL_SWSMI_TIMED              _IOWR(IOCTL_NUM, 0x17, int*)

//
// SoC IOSF Message Bus constants
//
#define MSGBUS_BUS  0x0
#define MSGBUS_DEV  0x0
#define MSGBUS_FUN  0x0

#define MCR         0xD0
#define MDR         0xD4
#define MCRX        0xD8

#define MSGBUS_MDR_IN_MASK  0x1
#define MSGBUS_MDR_OUT_MASK 0x2


/// if defined debug is enabled
#define DEBUG
#ifdef DEBUG 
/// Macro for debug print
#define dbgprint(format, args...) \
	do {            \
		printk(KERN_DEBUG "%s %s %d: "format"\n", program_name, __FUNCTION__, __LINE__, ## args);\
	} while ( 0 )
#else
#define dbgprint(format, args...) do {} while( 0 );
#endif
#endif	

#ifdef __x86_64__
typedef u64 physaddr_t;
#else
typedef __u32 physaddr_t;
#endif

typedef enum {
  CPU_DT_CODE_IDTR = 0x0,
  CPU_DT_CODE_GDTR = 0x1,
  CPU_DT_CODE_LDTR = 0x2,
} DTR_CODE;

#pragma pack(1)
typedef union {
   struct {
       uint32_t low;
       int32_t high;
   } u;
   physaddr_t quadpart;
} PHYSICAL_ADDRESS;
#pragma pack()

#pragma pack(1)
typedef struct _DESCRIPTOR_TABLE_RECORD {
  uint16_t    limit;
  physaddr_t base;
} DESCRIPTOR_TABLE_RECORD, *PDESCRIPTOR_TABLE_RECORD;
#pragma pack()
