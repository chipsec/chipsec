/** @file
Header file for compression routine

Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _EFI_DECOMPRESS_H
#define _EFI_DECOMPRESS_H

#include <Common/UefiBaseTypes.h>

EFI_STATUS
EfiGetInfo (
  IN      VOID    *Source,
  IN      UINT32  SrcSize,
  OUT     UINT32  *DstSize,
  OUT     UINT32  *ScratchSize
  );
/**

Routine Description:

  The implementation Efi Decompress GetInfo().

Arguments:

  Source      - The source buffer containing the compressed data.
  SrcSize     - The size of source buffer
  DstSize     - The size of destination buffer.
  ScratchSize - The size of scratch buffer.

Returns:

  EFI_SUCCESS           - The size of destination buffer and the size of scratch buffer are successfully retrieved.
  EFI_INVALID_PARAMETER - The source data is corrupted

**/

EFI_STATUS
EfiDecompress (
  IN      VOID    *Source,
  IN      UINT32  SrcSize,
  IN OUT  VOID    *Destination,
  IN      UINT32  DstSize,
  IN OUT  VOID    *Scratch,
  IN      UINT32  ScratchSize
  );
/**

Routine Description:

  The implementation of Efi Decompress().

Arguments:

  Source      - The source buffer containing the compressed data.
  SrcSize     - The size of source buffer
  Destination - The destination buffer to store the decompressed data
  DstSize     - The size of destination buffer.
  Scratch     - The buffer used internally by the decompress routine. This  buffer is needed to store intermediate data.
  ScratchSize - The size of scratch buffer.

Returns:

  EFI_SUCCESS           - Decompression is successful
  EFI_INVALID_PARAMETER - The source data is corrupted

**/

EFI_STATUS
TianoGetInfo (
  IN      VOID    *Source,
  IN      UINT32  SrcSize,
  OUT     UINT32  *DstSize,
  OUT     UINT32  *ScratchSize
  );
/**

Routine Description:

  The implementation Tiano Decompress GetInfo().

Arguments:

  Source      - The source buffer containing the compressed data.
  SrcSize     - The size of source buffer
  DstSize     - The size of destination buffer.
  ScratchSize - The size of scratch buffer.

Returns:

  EFI_SUCCESS           - The size of destination buffer and the size of scratch buffer are successfully retrieved.
  EFI_INVALID_PARAMETER - The source data is corrupted

**/

EFI_STATUS
TianoDecompress (
  IN      VOID    *Source,
  IN      UINT32  SrcSize,
  IN OUT  VOID    *Destination,
  IN      UINT32  DstSize,
  IN OUT  VOID    *Scratch,
  IN      UINT32  ScratchSize
  );
/**

Routine Description:

  The implementation of Tiano Decompress().

Arguments:

  Source      - The source buffer containing the compressed data.
  SrcSize     - The size of source buffer
  Destination - The destination buffer to store the decompressed data
  DstSize     - The size of destination buffer.
  Scratch     - The buffer used internally by the decompress routine. This  buffer is needed to store intermediate data.
  ScratchSize - The size of scratch buffer.

Returns:

  EFI_SUCCESS           - Decompression is successful
  EFI_INVALID_PARAMETER - The source data is corrupted

**/

typedef
EFI_STATUS
(*GETINFO_FUNCTION) (
  IN      VOID    *Source,
  IN      UINT32  SrcSize,
  OUT     UINT32  *DstSize,
  OUT     UINT32  *ScratchSize
  );

typedef
EFI_STATUS
(*DECOMPRESS_FUNCTION) (
  IN      VOID    *Source,
  IN      UINT32  SrcSize,
  IN OUT  VOID    *Destination,
  IN      UINT32  DstSize,
  IN OUT  VOID    *Scratch,
  IN      UINT32  ScratchSize
  );

EFI_STATUS
Extract (
  IN      VOID    *Source,
  IN      UINT32  SrcSize,
     OUT  VOID    **Destination,
     OUT  UINT32  *DstSize,
  IN      UINTN   Algorithm
  );

#endif
