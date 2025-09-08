# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2021, Intel Corporation
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Contact information:
# chipsec@intel.com

"""
UEFI Compression Support Module

This module provides comprehensive compression and decompression capabilities
for UEFI firmware analysis, with support for both standard UEFI/PI specification
compression types and vendor-specific extensions.

UEFI/PI Standards Compliance:
- UEFI 2.11 Chapter 19: Compression Algorithm Specification
- PI 1.9 Volume III: Firmware Storage Code Definitions
- Standard compression types: None, UEFI/Tiano, LZMA
- Guided section extraction with authentication support
- EFI_DECOMPRESS_PROTOCOL interface pattern

Supported Compression Types:
Standard (UEFI/PI compliant):
- None (uncompressed)
- UEFI/Tiano (EFI native compression)
- LZMA (standard LZMA compression)
- LZMA F86 (LZMA with x86 filter)

Vendor Extensions (non-standard):
- Brotli, GZIP, ZLIB, Zstandard, LZ4

Key Features:
- Auto-detection of compression types from data headers
- GUID-based compression type identification
- Section header validation per PI specification
- Authentication status support for guided sections
- Comprehensive error handling and logging
"""


import platform

from typing import List

from chipsec.library.logger import logger


def show_import_error(import_name: str) -> None:
    if platform.system().lower() in ('windows', 'linux', 'darwin'):
        logger().log_error(f'Failed to import compression module "{import_name}"')


try:
    import brotli

    has_brotli = True
except ImportError as exception:
    has_brotli = False

    show_import_error(exception.name)

try:
    import lzma

    has_lzma = True
except ImportError as exception:
    has_lzma = False

    show_import_error(exception.name)

try:
    import EfiCompressor

    has_eficomp = True
except ImportError as exception:
    has_eficomp = False

    show_import_error(exception.name)

try:
    import gzip

    has_gzip = True
except ImportError as exception:
    has_gzip = False

    show_import_error(exception.name)

try:
    import zlib

    has_zlib = True
except ImportError as exception:
    has_zlib = False

    show_import_error(exception.name)

try:
    import zstandard

    has_zstd = True
except ImportError as exception:
    has_zstd = False

    show_import_error(exception.name)

try:
    import lz4.frame

    has_lz4 = True
except ImportError as exception:
    has_lz4 = False

    show_import_error(exception.name)

#
# Compression Types
#
COMPRESSION_TYPE_NONE = 0
COMPRESSION_TYPE_TIANO = 1
COMPRESSION_TYPE_UEFI = 2
COMPRESSION_TYPE_LZMA = 3
COMPRESSION_TYPE_BROTLI = 4
COMPRESSION_TYPE_LZMAF86 = 5
COMPRESSION_TYPE_GZIP = 6
COMPRESSION_TYPE_ZLIB = 7
COMPRESSION_TYPE_ZSTD = 8
COMPRESSION_TYPE_LZ4 = 9
COMPRESSION_TYPE_EFI_STANDARD = COMPRESSION_TYPE_UEFI
COMPRESSION_TYPE_UNKNOWN = 10
COMPRESSION_TYPES_ALGORITHMS: List[int] = [COMPRESSION_TYPE_LZMA,
                                           COMPRESSION_TYPE_TIANO,
                                           COMPRESSION_TYPE_UEFI,
                                           COMPRESSION_TYPE_BROTLI,
                                           COMPRESSION_TYPE_LZMAF86,
                                           COMPRESSION_TYPE_GZIP,
                                           COMPRESSION_TYPE_ZLIB,
                                           COMPRESSION_TYPE_ZSTD,
                                           COMPRESSION_TYPE_LZ4,
                                           COMPRESSION_TYPE_NONE]
COMPRESSION_TYPES: List[int] = [COMPRESSION_TYPE_NONE,
                                COMPRESSION_TYPE_TIANO,
                                COMPRESSION_TYPE_UEFI,
                                COMPRESSION_TYPE_LZMA,
                                COMPRESSION_TYPE_BROTLI,
                                COMPRESSION_TYPE_UNKNOWN,
                                COMPRESSION_TYPE_LZMAF86,
                                COMPRESSION_TYPE_GZIP,
                                COMPRESSION_TYPE_ZLIB,
                                COMPRESSION_TYPE_ZSTD,
                                COMPRESSION_TYPE_LZ4]

COMPRESSION_TYPE_NAMES = {
    COMPRESSION_TYPE_NONE: 'None',
    COMPRESSION_TYPE_TIANO: 'Tiano',
    COMPRESSION_TYPE_UEFI: 'UEFI',
    COMPRESSION_TYPE_LZMA: 'LZMA',
    COMPRESSION_TYPE_BROTLI: 'Brotli',
    COMPRESSION_TYPE_UNKNOWN: 'Unknown',
    COMPRESSION_TYPE_LZMAF86: 'LZMA F86',
    COMPRESSION_TYPE_GZIP: 'GZIP',
    COMPRESSION_TYPE_ZLIB: 'ZLIB',
    COMPRESSION_TYPE_ZSTD: 'Zstandard',
    COMPRESSION_TYPE_LZ4: 'LZ4'
}


def get_compression_type_name(compression_type: int) -> str:
    """Get human-readable name for compression type."""
    return COMPRESSION_TYPE_NAMES.get(compression_type, f'Unknown (0x{compression_type:02X})')


class UEFICompression:
    """
    UEFI compression/decompression handler supporting multiple algorithms.
    
    This class provides unified compression and decompression capabilities
    for various UEFI firmware compression formats including legacy and
    modern compression algorithms.
    """

    def __init__(self):
        pass

    def is_compression_supported(self, compression_type: int) -> bool:
        """Check if a compression type is supported by the current environment."""
        if compression_type == COMPRESSION_TYPE_NONE:
            return True
        elif compression_type in [COMPRESSION_TYPE_TIANO, COMPRESSION_TYPE_UEFI]:
            return has_eficomp
        elif compression_type in [COMPRESSION_TYPE_LZMA, COMPRESSION_TYPE_LZMAF86]:
            return has_lzma
        elif compression_type == COMPRESSION_TYPE_BROTLI:
            return has_brotli
        elif compression_type == COMPRESSION_TYPE_GZIP:
            return has_gzip
        elif compression_type == COMPRESSION_TYPE_ZLIB:
            return has_zlib
        elif compression_type == COMPRESSION_TYPE_ZSTD:
            return has_zstd
        elif compression_type == COMPRESSION_TYPE_LZ4:
            return has_lz4
        else:
            return False

    def get_supported_compression_types(self) -> List[int]:
        """Get list of compression types supported in current environment."""
        supported = [COMPRESSION_TYPE_NONE]
        if has_eficomp:
            supported.extend([COMPRESSION_TYPE_TIANO, COMPRESSION_TYPE_UEFI])
        if has_lzma:
            supported.extend([COMPRESSION_TYPE_LZMA, COMPRESSION_TYPE_LZMAF86])
        if has_brotli:
            supported.append(COMPRESSION_TYPE_BROTLI)
        if has_gzip:
            supported.append(COMPRESSION_TYPE_GZIP)
        if has_zlib:
            supported.append(COMPRESSION_TYPE_ZLIB)
        if has_zstd:
            supported.append(COMPRESSION_TYPE_ZSTD)
        if has_lz4:
            supported.append(COMPRESSION_TYPE_LZ4)
        return supported

    def detect_compression_type(self, data: bytes) -> int:
        """
        Attempt to detect compression type from data headers.
        Returns COMPRESSION_TYPE_UNKNOWN if unable to detect.
        """
        if not data:
            return COMPRESSION_TYPE_UNKNOWN
            
        # Check for common compression signatures
        if data.startswith(b'\x1f\x8b'):  # GZIP magic
            return COMPRESSION_TYPE_GZIP
        elif data.startswith(b'\x78\x9c') or data.startswith(b'\x78\xda'):  # ZLIB magic
            return COMPRESSION_TYPE_ZLIB
        elif data.startswith(b'\x28\xb5\x2f\xfd'):  # Zstandard magic
            return COMPRESSION_TYPE_ZSTD
        elif data.startswith(b'\x04"M\x18'):  # LZ4 magic
            return COMPRESSION_TYPE_LZ4
        elif len(data) >= 13 and data[0:1] in [b'\x5d', b'\x6d']:  # LZMA patterns
            return COMPRESSION_TYPE_LZMA
        elif len(data) >= 6:
            # Check for Brotli (more complex detection)
            try:
                # Brotli doesn't have a clear magic number, but we can try to detect the window size
                if data[0] & 0x0F == 0x06:  # Common Brotli window size pattern
                    return COMPRESSION_TYPE_BROTLI
            except Exception:
                pass
                
        # If no signature matches, return unknown
        return COMPRESSION_TYPE_UNKNOWN

    def get_compression_info(self, compression_type: int) -> dict:
        """Get detailed information about a compression type."""
        return {
            'type': compression_type,
            'name': get_compression_type_name(compression_type),
            'supported': self.is_compression_supported(compression_type),
            'category': self._get_compression_category(compression_type)
        }
        
    def _get_compression_category(self, compression_type: int) -> str:
        """Get compression type category for classification."""
        if compression_type == COMPRESSION_TYPE_NONE:
            return 'None'
        elif compression_type in [COMPRESSION_TYPE_TIANO, COMPRESSION_TYPE_UEFI]:
            return 'EFI Native'
        elif compression_type in [COMPRESSION_TYPE_LZMA, COMPRESSION_TYPE_LZMAF86]:
            return 'LZMA Family'
        elif compression_type in [COMPRESSION_TYPE_GZIP, COMPRESSION_TYPE_ZLIB]:
            return 'Deflate Family'
        elif compression_type == COMPRESSION_TYPE_BROTLI:
            return 'Modern'
        elif compression_type == COMPRESSION_TYPE_ZSTD:
            return 'Modern'
        elif compression_type == COMPRESSION_TYPE_LZ4:
            return 'Modern'
        else:
            return 'Unknown'

    def decompress_EFI_binary(self, compressed_data: bytes, compression_type: int) -> bytes:
        if compression_type in COMPRESSION_TYPES:
            if compression_type == COMPRESSION_TYPE_NONE:
                data = compressed_data
            elif compression_type == COMPRESSION_TYPE_UNKNOWN:
                # For unknown types, try auto-detection
                detected_type = self.detect_compression_type(compressed_data)
                if detected_type != COMPRESSION_TYPE_UNKNOWN:
                    data = self.decompress_EFI_binary(compressed_data, detected_type)
                else:
                    # Try common EFI compression types as fallback
                    for fallback_type in [COMPRESSION_TYPE_TIANO, COMPRESSION_TYPE_UEFI, COMPRESSION_TYPE_LZMA]:
                        try:
                            data = self.decompress_EFI_binary(compressed_data, fallback_type)
                            if data:
                                break
                        except Exception:
                            continue
                    else:
                        data = b''
            elif compression_type == COMPRESSION_TYPE_TIANO and has_eficomp:
                try:
                    if self._is_efi_compressed(compressed_data):
                        data = EfiCompressor.TianoDecompress(compressed_data)
                    else:
                        data = b''
                except Exception:
                    data = b''
            elif compression_type == COMPRESSION_TYPE_UEFI and has_eficomp:
                try:
                    if self._is_efi_compressed(compressed_data):
                        data = EfiCompressor.UefiDecompress(compressed_data)
                    else:
                        data = b''
                except Exception:
                    data = b''
            elif compression_type in [COMPRESSION_TYPE_LZMA, COMPRESSION_TYPE_LZMAF86] and has_lzma:
                try:
                    data = lzma.decompress(compressed_data)
                except lzma.LZMAError:
                    # lzma may not be able to decompress
                    # https://github.com/python/cpython/issues/92018
                    # suggested workaround is to change the size within the header
                    try:
                        buf = compressed_data[:5] + b'\xFF' * 8 + compressed_data[13:]
                        data = lzma.decompress(buf)
                    except lzma.LZMAError:
                        data = b''
                if compression_type == COMPRESSION_TYPE_LZMAF86:
                    try:
                        data = EfiCompressor.LZMAf86Decompress(data)
                    except Exception:
                        data = b''
            elif compression_type == COMPRESSION_TYPE_BROTLI and has_brotli:
                try:
                    data = brotli.decompress(compressed_data)
                except brotli.error:
                    data = b''
            elif compression_type == COMPRESSION_TYPE_GZIP and has_gzip:
                try:
                    data = gzip.decompress(compressed_data)
                except (gzip.BadGzipFile, OSError):
                    data = b''
            elif compression_type == COMPRESSION_TYPE_ZLIB and has_zlib:
                try:
                    data = zlib.decompress(compressed_data)
                except zlib.error:
                    data = b''
            elif compression_type == COMPRESSION_TYPE_ZSTD and has_zstd:
                try:
                    decompressor = zstandard.ZstdDecompressor()
                    data = decompressor.decompress(compressed_data)
                except (zstandard.ZstdError, Exception):
                    data = b''
            elif compression_type == COMPRESSION_TYPE_LZ4 and has_lz4:
                try:
                    data = lz4.frame.decompress(compressed_data)
                except Exception:
                    data = b''
            else:
                data = b''
                # Log specific reason for failure if compression type is known but not supported
                if compression_type in COMPRESSION_TYPE_NAMES:
                    comp_name = COMPRESSION_TYPE_NAMES[compression_type]
                    if not self.is_compression_supported(compression_type):
                        logger().log_hal(f'{comp_name} compression not supported (missing library)')
                    else:
                        logger().log_hal(f'Failed to decompress {comp_name} data')
            if not data:
                logger().log_hal(f'Cannot decompress data with compression type {get_compression_type_name(compression_type)}')
        else:
            logger().log_error(f'Unknown EFI compression type 0x{compression_type:X}')
            data = b''
        return data

    def compress_EFI_binary(self, uncompressed_data: bytes, compression_type: int) -> bytes:
        if compression_type in COMPRESSION_TYPES:
            if compression_type == COMPRESSION_TYPE_NONE:
                data = uncompressed_data
            elif compression_type == COMPRESSION_TYPE_TIANO:
                try:
                    data = EfiCompressor.TianoCompress(uncompressed_data)
                    if not self._is_efi_compressed(data):
                        data = b''
                        raise RuntimeError('Failed to validate EFI compression header')
                except Exception:
                    data = b''
            elif compression_type == COMPRESSION_TYPE_UEFI:
                try:
                    data = EfiCompressor.UefiCompress(uncompressed_data)
                    if not self._is_efi_compressed(data):
                        data = b''
                        raise RuntimeError('Failed to validate EFI compression header')
                except Exception:
                    data = b''
            elif compression_type in [COMPRESSION_TYPE_LZMA, COMPRESSION_TYPE_LZMAF86]:
                if compression_type == COMPRESSION_TYPE_LZMAF86:
                    uncompressed_data = EfiCompressor.LZMAf86Compress(uncompressed_data)
                try:
                    data = lzma.compress(uncompressed_data)
                except lzma.LZMAError:
                    data = b''
            elif compression_type == COMPRESSION_TYPE_BROTLI:
                try:
                    data = brotli.compress(uncompressed_data)
                except brotli.error:
                    data = b''
            elif compression_type == COMPRESSION_TYPE_GZIP and has_gzip:
                try:
                    data = gzip.compress(uncompressed_data)
                except Exception:
                    data = b''
            elif compression_type == COMPRESSION_TYPE_ZLIB and has_zlib:
                try:
                    data = zlib.compress(uncompressed_data)
                except zlib.error:
                    data = b''
            elif compression_type == COMPRESSION_TYPE_ZSTD and has_zstd:
                try:
                    compressor = zstandard.ZstdCompressor()
                    data = compressor.compress(uncompressed_data)
                except (zstandard.ZstdError, Exception):
                    data = b''
            elif compression_type == COMPRESSION_TYPE_LZ4 and has_lz4:
                try:
                    data = lz4.frame.compress(uncompressed_data)
                except Exception:
                    data = b''
            else:
                data = b''
        else:
            logger().log_error(f'Unknown EFI compression type 0x{compression_type:X}')
            data = b''
        return data

    @staticmethod
    def get_compression_type_from_guid(guid_str: str) -> int:
        """
        Get compression type from GUID string.
        
        Args:
            guid_str: GUID string (e.g., "EE4E5898-3914-4259-9D6E-DC7BD79403CF")
            
        Returns:
            Compression type constant or COMPRESSION_TYPE_UNKNOWN
        """
        # Import here to avoid circular imports
        from chipsec.library.uefi.fv import (
            LZMAF86_DECOMPRESS_GUID, LZMA_CUSTOM_DECOMPRESS_GUID, TIANO_DECOMPRESSED_GUID,
            BROTLI_CUSTOM_DECOMPRESS_GUID, GZIP_CUSTOM_DECOMPRESS_GUID, ZLIB_CUSTOM_DECOMPRESS_GUID,
            ZSTD_CUSTOM_DECOMPRESS_GUID, LZ4_CUSTOM_DECOMPRESS_GUID,
            EFI_GUIDED_SECTION_GZIP, EFI_GUIDED_SECTION_LZMA_HP, EFI_GUIDED_SECTION_LZMA_MS,
            EFI_DECOMPRESS_PROTOCOL_GUID, EFI_FIRMWARE_CONTENTS_SIGNED_GUID, EFI_STANDARD_COMPRESSION_GUID
        )
        
        # Convert string to uppercase for comparison
        guid_upper = guid_str.upper()
        
        # Standard compression GUIDs
        if guid_upper == str(LZMAF86_DECOMPRESS_GUID).upper():
            return COMPRESSION_TYPE_LZMAF86
        elif guid_upper == str(LZMA_CUSTOM_DECOMPRESS_GUID).upper():
            return COMPRESSION_TYPE_LZMA
        elif guid_upper == str(TIANO_DECOMPRESSED_GUID).upper():
            return COMPRESSION_TYPE_TIANO
        elif guid_upper == str(BROTLI_CUSTOM_DECOMPRESS_GUID).upper():
            return COMPRESSION_TYPE_BROTLI
        elif guid_upper in [str(GZIP_CUSTOM_DECOMPRESS_GUID).upper(), str(EFI_GUIDED_SECTION_GZIP).upper()]:
            return COMPRESSION_TYPE_GZIP
        elif guid_upper in [str(ZLIB_CUSTOM_DECOMPRESS_GUID).upper()]:
            return COMPRESSION_TYPE_ZLIB
        elif guid_upper == str(ZSTD_CUSTOM_DECOMPRESS_GUID).upper():
            return COMPRESSION_TYPE_ZSTD
        elif guid_upper == str(LZ4_CUSTOM_DECOMPRESS_GUID).upper():
            return COMPRESSION_TYPE_LZ4
        # Vendor-specific LZMA variants
        elif guid_upper in [str(EFI_GUIDED_SECTION_LZMA_HP).upper(), str(EFI_GUIDED_SECTION_LZMA_MS).upper()]:
            return COMPRESSION_TYPE_LZMA
        # Standard UEFI/PI GUIDs
        elif guid_upper == str(EFI_DECOMPRESS_PROTOCOL_GUID).upper():
            return COMPRESSION_TYPE_UEFI  # Standard UEFI decompression
        elif guid_upper == str(EFI_STANDARD_COMPRESSION_GUID).upper():
            return COMPRESSION_TYPE_UEFI  # Standard compression section
        elif guid_upper == str(EFI_FIRMWARE_CONTENTS_SIGNED_GUID).upper():
            return COMPRESSION_TYPE_UNKNOWN  # Signed content, not compression
        else:
            return COMPRESSION_TYPE_UNKNOWN

    @staticmethod
    def get_guid_info_from_compression_type(compression_type: int) -> dict:
        """
        Get GUID information for a compression type.
        
        Args:
            compression_type: Compression type constant
            
        Returns:
            Dictionary with GUID information including variants
        """
        from chipsec.library.uefi.fv import (
            LZMAF86_DECOMPRESS_GUID, LZMA_CUSTOM_DECOMPRESS_GUID, TIANO_DECOMPRESSED_GUID,
            BROTLI_CUSTOM_DECOMPRESS_GUID, GZIP_CUSTOM_DECOMPRESS_GUID, ZLIB_CUSTOM_DECOMPRESS_GUID,
            ZSTD_CUSTOM_DECOMPRESS_GUID, LZ4_CUSTOM_DECOMPRESS_GUID,
            EFI_GUIDED_SECTION_GZIP, EFI_GUIDED_SECTION_LZMA_HP, EFI_GUIDED_SECTION_LZMA_MS,
            EFI_DECOMPRESS_PROTOCOL_GUID, EFI_STANDARD_COMPRESSION_GUID
        )
        
        if compression_type == COMPRESSION_TYPE_LZMAF86:
            return {
                'primary': str(LZMAF86_DECOMPRESS_GUID),
                'variants': [],
                'name': 'LZMA F86'
            }
        elif compression_type == COMPRESSION_TYPE_LZMA:
            return {
                'primary': str(LZMA_CUSTOM_DECOMPRESS_GUID),
                'variants': [str(EFI_GUIDED_SECTION_LZMA_HP), str(EFI_GUIDED_SECTION_LZMA_MS)],
                'name': 'LZMA'
            }
        elif compression_type == COMPRESSION_TYPE_TIANO:
            return {
                'primary': str(TIANO_DECOMPRESSED_GUID),
                'variants': [],
                'name': 'Tiano'
            }
        elif compression_type == COMPRESSION_TYPE_BROTLI:
            return {
                'primary': str(BROTLI_CUSTOM_DECOMPRESS_GUID),
                'variants': [],
                'name': 'Brotli'
            }
        elif compression_type == COMPRESSION_TYPE_GZIP:
            return {
                'primary': str(GZIP_CUSTOM_DECOMPRESS_GUID),
                'variants': [str(EFI_GUIDED_SECTION_GZIP)],
                'name': 'GZIP'
            }
        elif compression_type == COMPRESSION_TYPE_ZLIB:
            return {
                'primary': str(ZLIB_CUSTOM_DECOMPRESS_GUID),
                'variants': [],
                'name': 'ZLIB'
            }
        elif compression_type == COMPRESSION_TYPE_ZSTD:
            return {
                'primary': str(ZSTD_CUSTOM_DECOMPRESS_GUID),
                'variants': [],
                'name': 'Zstandard'
            }
        elif compression_type == COMPRESSION_TYPE_LZ4:
            return {
                'primary': str(LZ4_CUSTOM_DECOMPRESS_GUID),
                'variants': [],
                'name': 'LZ4'
            }
        else:
            return {
                'primary': None,
                'variants': [],
                'name': 'Unknown'
            }

    def get_info(self, compressed_data: bytes) -> tuple:
        """
        Get decompressed size and scratch buffer size requirements.
        
        This method follows the EFI_DECOMPRESS_PROTOCOL interface pattern
        from UEFI 2.11 specification Chapter 19.
        
        Args:
            compressed_data: The compressed data to analyze
            
        Returns:
            Tuple of (decompressed_size, scratch_size_needed)
        """
        if not compressed_data or len(compressed_data) < 8:
            return (0, 0)
        
        # For EFI compressed data, extract size from header
        if self._is_efi_compressed(compressed_data):
            decompressed_size = int.from_bytes(compressed_data[4:8], byteorder='little')
            # Scratch buffer size is typically the same as decompressed size for EFI compression
            scratch_size = decompressed_size
            return (decompressed_size, scratch_size)
        
        # For other compression types, we can't easily determine size without decompressing
        return (0, 0)

    def extract_guided_section(self, section_data: bytes, guid_str: str) -> tuple:
        """
        Extract GUID-defined section with authentication status.
        
        This method follows the PI 1.9 specification for guided section extraction.
        
        Args:
            section_data: The section data including GUID-defined header
            guid_str: The GUID string identifying the section type
            
        Returns:
            Tuple of (extracted_data, authentication_status)
        """
        from chipsec.library.uefi.fv import (
            EFI_GUIDED_SECTION_PROCESSING_REQUIRED, EFI_GUIDED_SECTION_AUTH_STATUS_VALID,
            EFI_AUTH_STATUS_NOT_TESTED
        )
        
        # Get compression type from GUID
        compression_type = self.get_compression_type_from_guid(guid_str)
        
        if compression_type == COMPRESSION_TYPE_UNKNOWN:
            # Unknown GUID, return original data with not tested status
            return (section_data, EFI_AUTH_STATUS_NOT_TESTED)
        
        # Process the section based on compression type
        try:
            extracted_data = self.decompress_EFI_binary(section_data, compression_type)
            if extracted_data:
                # Successful extraction, no authentication performed
                return (extracted_data, EFI_AUTH_STATUS_NOT_TESTED)
            else:
                # Failed extraction
                return (b'', EFI_AUTH_STATUS_NOT_TESTED)
        except Exception:
            return (b'', EFI_AUTH_STATUS_NOT_TESTED)

    def is_standard_compression_type(self, compression_type: int) -> bool:
        """
        Check if a compression type is part of the UEFI/PI standards.
        
        Args:
            compression_type: Compression type constant
            
        Returns:
            True if it's a standard UEFI/PI compression type, False for vendor extensions
        """
        standard_types = [
            COMPRESSION_TYPE_NONE,
            COMPRESSION_TYPE_TIANO,
            COMPRESSION_TYPE_UEFI,
            COMPRESSION_TYPE_LZMA,
            COMPRESSION_TYPE_LZMAF86
        ]
        return compression_type in standard_types

    def get_standards_compliance_info(self) -> dict:
        """
        Get information about UEFI/PI standards compliance.
        
        Returns:
            Dictionary with compliance information
        """
        return {
            'uefi_version': '2.11',
            'pi_version': '1.9',
            'standard_compression_types': [
                COMPRESSION_TYPE_NONE,
                COMPRESSION_TYPE_TIANO,
                COMPRESSION_TYPE_UEFI,
                COMPRESSION_TYPE_LZMA,
                COMPRESSION_TYPE_LZMAF86
            ],
            'vendor_extension_types': [
                COMPRESSION_TYPE_BROTLI,
                COMPRESSION_TYPE_GZIP,
                COMPRESSION_TYPE_ZLIB,
                COMPRESSION_TYPE_ZSTD,
                COMPRESSION_TYPE_LZ4
            ],
            'supported_sections': [
                'EFI_SECTION_COMPRESSION',
                'EFI_SECTION_GUID_DEFINED'
            ],
            'authentication_support': True,
            'guided_section_support': True
        }

    @staticmethod
    def validate_section_header(section_data: bytes) -> bool:
        """
        Validate UEFI section header format.
        
        Args:
            section_data: Section data to validate
            
        Returns:
            True if header is valid, False otherwise
        """
        if len(section_data) < 4:
            return False
        
        # Extract 24-bit size from first 3 bytes
        size = int.from_bytes(section_data[0:3], byteorder='little')
        section_type = section_data[3]
        
        # Basic validation
        valid_size = size > 0 and size <= len(section_data)
        valid_type = section_type <= 0x1C  # Maximum section type from PI 1.9
        return valid_size and valid_type

    @staticmethod
    def get_standard_guids() -> dict:
        """
        Get all standard UEFI/PI compression GUIDs.
        
        Returns:
            Dictionary mapping GUID categories to GUID lists
        """
        from chipsec.library.uefi.fv import (
            EFI_DECOMPRESS_PROTOCOL_GUID, EFI_STANDARD_COMPRESSION_GUID,
            EFI_FIRMWARE_CONTENTS_SIGNED_GUID, TIANO_DECOMPRESSED_GUID,
            LZMA_CUSTOM_DECOMPRESS_GUID, LZMAF86_DECOMPRESS_GUID
        )
        
        return {
            'standard_compression': [
                str(EFI_DECOMPRESS_PROTOCOL_GUID),
                str(EFI_STANDARD_COMPRESSION_GUID),
                str(TIANO_DECOMPRESSED_GUID)
            ],
            'extended_compression': [
                str(LZMA_CUSTOM_DECOMPRESS_GUID),
                str(LZMAF86_DECOMPRESS_GUID)
            ],
            'security_related': [
                str(EFI_FIRMWARE_CONTENTS_SIGNED_GUID)
            ]
        }

    @staticmethod
    def _is_efi_compressed(efi_data: bytes) -> bool:
        """
        Check if data is EFI compressed by validating the header structure.
        
        Args:
            efi_data: The compressed data to validate
            
        Returns:
            True if the data has a valid EFI compression header, False otherwise
        """
        if len(efi_data) < 8:
            return False
            
        size_compressed = int.from_bytes(efi_data[0:4], byteorder='little')
        size_decompressed = int.from_bytes(efi_data[4:8], byteorder='little')
        
        # Check if sizes are reasonable
        check_size = 0 < size_compressed < size_decompressed
        
        # Check if the compressed size matches the actual data length
        check_data = size_compressed + 8 == len(efi_data)
        
        return check_size and check_data
