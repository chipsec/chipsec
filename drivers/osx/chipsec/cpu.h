//
// Copyright 2016 Google Inc. All Rights Reserved.
// Author: Thiebaud Weksteen (tweksteen@gmail.com)
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

#ifndef _CPU_H
#define _CPU_H

extern "C" {
    
    
typedef struct _descriptor_table_record{
    uint16_t limit;
    uint64_t base;
} descriptor_table_record;

void WritePCIByte(uint32_t pci_reg,  uint16_t data_port, uint8_t  byte_value);
void WritePCIWord(uint32_t pci_reg,  uint16_t data_port, uint16_t word_value);
void WritePCIDword(uint32_t pci_reg, uint16_t data_port, uint32_t dword_value);

uint8_t  ReadPCIByte(uint32_t pci_reg,  uint16_t data_port);
uint16_t ReadPCIWord(uint32_t pci_reg,  uint16_t data_port);
uint32_t ReadPCIDword(uint32_t pci_reg, uint16_t data_port);

unsigned long ReadCR0(void);
unsigned long ReadCR2(void);
unsigned long ReadCR3(void);
unsigned long ReadCR4(void);
unsigned long ReadCR8(void);

void WriteCR0(unsigned long);
void WriteCR2(unsigned long);
void WriteCR3(unsigned long);
void WriteCR4(unsigned long);
void WriteCR8(unsigned long);
    
uint8_t  ReadPortByte  (uint16_t data_port);
uint16_t ReadPortWord  (uint16_t data_port);
uint32_t ReadPortDword (uint16_t data_port);
    
void WritePortByte  (uint8_t  byte_value,  uint16_t data_port);
void WritePortWord  (uint16_t word_value,  uint16_t data_port);
void WritePortDword (uint32_t dword_value, uint16_t data_port);

void ReadMSR(uint64_t msr_num, uint64_t* msr_lo, uint64_t* msr_hi);
void WriteMSR(uint64_t msr_num, uint64_t msr_lo, uint64_t msr_hi);
    
void chipCPUID(cpuid_msg_t *cpuid_regs);
    
void SWSMI(swsmi_msg_t *swsmi_regs);
    
uint64_t hypercall(uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx, uint64_t r8, uint64_t r9, uint64_t rax, uint64_t rbx, uint64_t r10, uint64_t r11, uint64_t xmm_buff, uint64_t hypercall_page);
uint64_t hypercall_page();
    
void store_idtr ( descriptor_table_record * address);
void store_gdtr ( descriptor_table_record * address);
void store_ldtr ( descriptor_table_record * address);
void load_idtr  ( descriptor_table_record * address);
void load_gdtr  ( descriptor_table_record * address);
void load_ldtr  ( descriptor_table_record * address);
void load_gdt   ( descriptor_table_record * address);

}
#endif /* _CPU_H */
