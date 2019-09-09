/** @file
Header file for helper functions useful for parsing INF files.

Copyright (c) 2004 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _EFI_PARSE_INF_H
#define _EFI_PARSE_INF_H

#include <stdio.h>
#include <stdlib.h>
#include <Common/UefiBaseTypes.h>
#include <MemoryFile.h>

#ifdef __cplusplus
extern "C" {
#endif
//
// Functions declarations
//
CHAR8 *
ReadLine (
  IN MEMORY_FILE    *InputFile,
  IN OUT CHAR8      *InputBuffer,
  IN UINTN          MaxLength
  )
;

/*++

Routine Description:

  This function reads a line, stripping any comments.
  The function reads a string from the input stream argument and stores it in
  the input string. ReadLine reads characters from the current file position
  to and including the first newline character, to the end of the stream, or
  until the number of characters read is equal to MaxLength - 1, whichever
  comes first.  The newline character, if read, is replaced with a \0.

Arguments:

  InputFile     Memory file image.
  InputBuffer   Buffer to read into, must be MaxLength size.
  MaxLength     The maximum size of the input buffer.

Returns:

  NULL if error or EOF
  InputBuffer otherwise

--*/
BOOLEAN
FindSection (
  IN MEMORY_FILE    *InputFile,
  IN CHAR8          *Section
  )
;

/*++

Routine Description:

  This function parses a file from the beginning to find a section.
  The section string may be anywhere within a line.

Arguments:

  InputFile     Memory file image.
  Section       Section to search for

Returns:

  FALSE if error or EOF
  TRUE if section found

--*/
EFI_STATUS
FindToken (
  IN MEMORY_FILE    *InputFile,
  IN CHAR8          *Section,
  IN CHAR8          *Token,
  IN UINTN          Instance,
  OUT CHAR8         *Value
  )
;

/*++

Routine Description:

  Finds a token value given the section and token to search for.

Arguments:

  InputFile Memory file image.
  Section   The section to search for, a string within [].
  Token     The token to search for, e.g. EFI_PEIM_RECOVERY, followed by an = in the INF file.
  Instance  The instance of the token to search for.  Zero is the first instance.
  Value     The string that holds the value following the =.  Must be MAX_LONG_FILE_PATH in size.

Returns:

  EFI_SUCCESS             Value found.
  EFI_ABORTED             Format error detected in INF file.
  EFI_INVALID_PARAMETER   Input argument was null.
  EFI_LOAD_ERROR          Error reading from the file.
  EFI_NOT_FOUND           Section/Token/Value not found.

--*/
EFI_STATUS
StringToGuid (
  IN CHAR8        *AsciiGuidBuffer,
  OUT EFI_GUID    *GuidBuffer
  )
;

/*++

Routine Description:

  Converts a string to an EFI_GUID.  The string must be in the
  xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx format.

Arguments:

  GuidBuffer      - pointer to destination Guid
  AsciiGuidBuffer - pointer to ascii string

Returns:

  EFI_ABORTED    Could not convert the string
  EFI_SUCCESS    The string was successfully converted

--*/
EFI_STATUS
AsciiStringToUint64 (
  IN CONST CHAR8  *AsciiString,
  IN BOOLEAN      IsHex,
  OUT UINT64      *ReturnValue
  )
;

/*++

Routine Description:

  Converts a null terminated ascii string that represents a number into a
  UINT64 value.  A hex number may be preceded by a 0x, but may not be
  succeeded by an h.  A number without 0x or 0X is considered to be base 10
  unless the IsHex input is true.

Arguments:

  AsciiString   The string to convert.
  IsHex         Force the string to be treated as a hex number.
  ReturnValue   The return value.

Returns:

  EFI_SUCCESS   Number successfully converted.
  EFI_ABORTED   Invalid character encountered.

--*/
CHAR8 *
ReadLineInStream (
  IN FILE       *InputFile,
  IN OUT CHAR8  *InputBuffer
  )
;

/*++

Routine Description:

  This function reads a line, stripping any comments.

Arguments:

  InputFile     Stream pointer.
  InputBuffer   Buffer to read into, must be MAX_LONG_FILE_PATH size.

Returns:

  NULL if error or EOF
  InputBuffer otherwise

--*/
BOOLEAN
FindSectionInStream (
  IN FILE       *InputFile,
  IN CHAR8      *Section
  )
;

/*++

Routine Description:

  This function parses a stream file from the beginning to find a section.
  The section string may be anywhere within a line.

Arguments:

  InputFile     Stream pointer.
  Section       Section to search for

Returns:

  FALSE if error or EOF
  TRUE if section found

--*/

#ifdef __cplusplus
}
#endif

#endif
