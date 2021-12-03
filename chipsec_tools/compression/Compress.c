/** CHIPSEC: Platform Security Assessment Framework
Copyright (c) 2019, Intel Corporation
 
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

This file incorporates work covered by the following copyright and permission notice
**/

/** @file
Compression routine. The compression algorithm is a mixture of LZ77 and Huffman
coding. LZ77 transforms the source data into a sequence of Original Characters
and Pointers to repeated strings. This sequence is further divided into Blocks
and Huffman codings are applied to each Block.

Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Compress.h"

EFI_STATUS
Pack (
  IN      VOID    *Source,
  IN      UINT32  SrcSize,
     OUT  VOID    **Destination,
     OUT  UINT32  *DstSize,
  IN      UINTN   Algorithm
  )
{
  EFI_STATUS    Status;

  Status  = EFI_SUCCESS;

  *Destination = (VOID *)malloc(SrcSize);
  if (*Destination == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  switch (Algorithm) {
  case 0:
    memcpy(*Destination, Source, SrcSize);
    return Status;
    break;
  case 1:
    Status = EfiCompress(Source, SrcSize, *Destination, DstSize);
    if (Status == EFI_BUFFER_TOO_SMALL){
        free(*Destination);
        *Destination = (VOID *)malloc(*DstSize);
        if (*Destination == NULL) {
          Status = EFI_OUT_OF_RESOURCES;
        }
        else{
          Status = EfiCompress(Source, SrcSize, *Destination, DstSize);
        }
    }
    break;
  case 2:
    Status = TianoCompress(Source, SrcSize, *Destination, DstSize);
    if (Status == EFI_BUFFER_TOO_SMALL){
        free(*Destination);
        *Destination = (VOID *)malloc(*DstSize);
        if (*Destination == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        }
        else{
        Status = TianoCompress(Source, SrcSize, *Destination, DstSize);
        }
    }
    break;
  default:
    Status = EFI_INVALID_PARAMETER;
  }

  if (EFI_ERROR (Status)) {
    return EFI_OUT_OF_RESOURCES;
  }

  return Status;
}

