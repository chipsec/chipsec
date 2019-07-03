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
#ifndef CPU_H
#define CPU_H

//#ifndef _WIN64 TODO: remove
#if 0
#define _eflags( eflags ) __asm \
          {                             \
            __asm push eax		\
            __asm pushfd                \
            __asm pop eax		\
            __asm mov eflags, eax	\
            __asm pop eax               \
          }
#endif

#if defined(_M_AMD64)
typedef UINT64 CPU_REG_TYPE;
typedef UINT64 UINTN;
#elif defined(_M_IX86)
typedef unsigned long CPU_REG_TYPE;
typedef UINT32 UINTN;
#else
#error "Architecture not supported"
#endif

typedef struct _swsmi_msg_t {
    UINTN code_data;
    UINTN rax;
    UINTN rbx;
    UINTN rcx;
    UINTN rdx;
    UINTN rsi;
    UINTN rdi;
} swsmi_msg_t;

extern CPU_REG_TYPE ReadCR0();
extern CPU_REG_TYPE ReadCR2();
extern CPU_REG_TYPE ReadCR3();
extern CPU_REG_TYPE ReadCR4();
#if defined(_M_AMD64)
extern CPU_REG_TYPE ReadCR8();
#endif
extern void   WriteCR0( CPU_REG_TYPE cr_val );
extern void   WriteCR2( CPU_REG_TYPE cr_val );
extern void   WriteCR3( CPU_REG_TYPE cr_val );
extern void   WriteCR4( CPU_REG_TYPE cr_val );
#if defined(_M_AMD64)
extern void   WriteCR8( CPU_REG_TYPE cr_val );
#endif

/*
 * External Assembly Functions
 */
// -- Access to CPU MSRs
extern void _rdmsr( UINT32 msr_num, UINT32* msr_lo, UINT32* msr_hi );
extern void _wrmsr( UINT32 msr_num, UINT32 msr_lo, UINT32 msr_hi );
// -- Access to PCI CFG space
extern void   WritePCIByte ( UINT32 pci_reg, UINT16 cfg_data_port, UINT8  byte_value );
extern void   WritePCIWord ( UINT32 pci_reg, UINT16 cfg_data_port, UINT16 word_value );
extern void   WritePCIDword( UINT32 pci_reg, UINT16 cfg_data_port, UINT32 dword_value );
extern UINT8  ReadPCIByte  ( UINT32 pci_reg, UINT16 cfg_data_port );
extern UINT16 ReadPCIWord  ( UINT32 pci_reg, UINT16 cfg_data_port );
extern UINT32 ReadPCIDword ( UINT32 pci_reg, UINT16 cfg_data_port );
// -- Access to Port I/O
extern UINT32 ReadPortDword ( UINT16 port_num );
extern UINT16 ReadPortWord  ( UINT16 port_num );
extern UINT8  ReadPortByte  ( UINT16 port_num );
extern void   WritePortDword( UINT32 out_value, UINT16 port_num );
extern void   WritePortWord ( UINT16 out_value, UINT16 port_num );
extern void   WritePortByte ( UINT8  out_value, UINT16 port_num );
// -- Access to CPU Descriptor tables
extern void _store_idtr( void* desc_address );
extern void _load_idtr ( void* desc_address );
extern void _store_gdtr( void* desc_address );
extern void _store_ldtr( void* desc_address );
// -- Interrupts
extern void _swsmi( swsmi_msg_t* sw_smi );
// -- Hypercalls
extern CPU_REG_TYPE hypercall (
    CPU_REG_TYPE rcx_val,
    CPU_REG_TYPE rdx_val,
    CPU_REG_TYPE r8_val,
    CPU_REG_TYPE r9_val,
    CPU_REG_TYPE r10_val,
    CPU_REG_TYPE r11_val,
    CPU_REG_TYPE rax_val,
    CPU_REG_TYPE rbx_val,
    CPU_REG_TYPE rdi_val,
    CPU_REG_TYPE rsi_val,
    CPU_REG_TYPE xmm_buffer,
    void*  hypercall_page
);
extern CPU_REG_TYPE hypercall_page(void);

// --
// -- MSR definitions
// --
#define MSR_IA32_BIOS_UPDT_TRIG 0x79
#define MSR_IA32_BIOS_SIGN_ID   0x8b


// -- CPU Descriptor tables
typedef enum {
  CPU_DT_CODE_IDTR = 0x0,
  CPU_DT_CODE_GDTR = 0x1,
  CPU_DT_CODE_LDTR = 0x2,
} DTR_CODE;

#pragma pack(1)
typedef struct _DESCRIPTOR_TABLE_RECORD {
  UINT16    limit;
  //UINT32    base_hi;
  //UINT32    base_lo;
  ULONG_PTR base;
} DESCRIPTOR_TABLE_RECORD, *PDESCRIPTOR_TABLE_RECORD;
#pragma pack()

#endif	// CPU_H
