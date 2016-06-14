//
// Copyright 2016 Google Inc. All Rights Reserved.
// Author: Thiebaud Weksteen (tweksteen@gmail.com)
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

void WritePCIByte(uint32_t pci_reg,  uint16_t data_port, uint8_t  byte_value);
void WritePCIWord(uint32_t pci_reg,  uint16_t data_port, uint16_t word_value);
void WritePCIDword(uint32_t pci_reg, uint16_t data_port, uint32_t dword_value);

uint8_t  ReadPCIByte(uint32_t pci_reg,  uint16_t data_port);
uint16_t ReadPCIWord(uint32_t pci_reg,  uint16_t data_port);
uint32_t ReadPCIDword(uint32_t pci_reg, uint16_t data_port);

unsigned int ReadCR0(void);
unsigned int ReadCR2(void);
unsigned int ReadCR3(void);
unsigned int ReadCR4(void);
unsigned int ReadCR8(void);

void WriteCR0(unsigned int);
void WriteCR2(unsigned int);
void WriteCR3(unsigned int);
void WriteCR4(unsigned int);
void WriteCR8(unsigned int);
    
}
#endif /* _CPU_H */
