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


import platform

from typing import List, Any

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
COMPRESSION_TYPE_EFI_STANDARD = 5
COMPRESSION_TYPE_UNKNOWN = 6
COMPRESSION_TYPE_LZMAF86 = 7
COMPRESSION_TYPE_GZIP = 8
COMPRESSION_TYPE_ZLIB = 9
COMPRESSION_TYPE_ZSTD = 10
COMPRESSION_TYPE_LZ4 = 11
COMPRESSION_TYPES_ALGORITHMS: List[int] = [COMPRESSION_TYPE_LZMA,
                                           COMPRESSION_TYPE_TIANO,
                                           COMPRESSION_TYPE_UEFI,
                                           COMPRESSION_TYPE_BROTLI,
                                           COMPRESSION_TYPE_LZMAF86,
                                           COMPRESSION_TYPE_GZIP,
                                           COMPRESSION_TYPE_ZLIB,
                                           COMPRESSION_TYPE_ZSTD,
                                           COMPRESSION_TYPE_LZ4,
                                           COMPRESSION_TYPE_NONE, ]
COMPRESSION_TYPES: List[int] = [COMPRESSION_TYPE_NONE,
                                COMPRESSION_TYPE_TIANO,
                                COMPRESSION_TYPE_UEFI,
                                COMPRESSION_TYPE_LZMA,
                                COMPRESSION_TYPE_BROTLI,
                                COMPRESSION_TYPE_EFI_STANDARD,
                                COMPRESSION_TYPE_UNKNOWN,
                                COMPRESSION_TYPE_LZMAF86,
                                COMPRESSION_TYPE_GZIP,
                                COMPRESSION_TYPE_ZLIB,
                                COMPRESSION_TYPE_ZSTD,
                                COMPRESSION_TYPE_LZ4, ]

COMPRESSION_TYPE_NAMES = {
    COMPRESSION_TYPE_NONE: 'None',
    COMPRESSION_TYPE_TIANO: 'Tiano',
    COMPRESSION_TYPE_UEFI: 'UEFI',
    COMPRESSION_TYPE_LZMA: 'LZMA',
    COMPRESSION_TYPE_BROTLI: 'Brotli',
    COMPRESSION_TYPE_EFI_STANDARD: 'EFI Standard',
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
    decompression_oder_type1: List[int] = [COMPRESSION_TYPE_TIANO, COMPRESSION_TYPE_UEFI]
    decompression_oder_type2: List[int] = [COMPRESSION_TYPE_TIANO,
                                           COMPRESSION_TYPE_UEFI,
                                           COMPRESSION_TYPE_LZMA,
                                           COMPRESSION_TYPE_BROTLI,
                                           COMPRESSION_TYPE_GZIP,
                                           COMPRESSION_TYPE_ZLIB,
                                           COMPRESSION_TYPE_ZSTD,
                                           COMPRESSION_TYPE_LZ4, ]

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

    def rotate_list(self, rot_list: List[Any], n: int) -> List[Any]:
        return rot_list[n:] + rot_list[:n]

    def decompress_EFI_binary(self, compressed_data: bytes, compression_type: int) -> bytes:
        if compression_type in COMPRESSION_TYPES:
            if compression_type == COMPRESSION_TYPE_UNKNOWN:
                data = self.unknown_decompress(compressed_data)
            elif compression_type == COMPRESSION_TYPE_EFI_STANDARD:
                data = self.unknown_efi_decompress(compressed_data)
            elif compression_type == COMPRESSION_TYPE_NONE:
                data = compressed_data
            elif compression_type == COMPRESSION_TYPE_TIANO and has_eficomp:
                try:
                    data = EfiCompressor.TianoDecompress(compressed_data)
                except Exception:
                    data = b''
            elif compression_type == COMPRESSION_TYPE_UEFI and has_eficomp:
                try:
                    data = EfiCompressor.UefiDecompress(compressed_data)
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

    def unknown_decompress(self, compressed_data: bytes) -> bytes:
        res = b''
        failed_times = 0
        for CompressionType in self.decompression_oder_type2:
            res = self.decompress_EFI_binary(compressed_data, CompressionType)
            if res:
                self.rotate_list(self.decompression_oder_type2, failed_times)
                break
            else:
                failed_times += 1
        return res

    def unknown_efi_decompress(self, compressed_data: bytes) -> bytes:
        res = b''
        failed_times = 0
        for CompressionType in self.decompression_oder_type1:
            res = self.decompress_EFI_binary(compressed_data, CompressionType)
            if res:
                self.rotate_list(self.decompression_oder_type1, failed_times)
                break
            else:
                failed_times += 1
        return res

    def compress_EFI_binary(self, uncompressed_data: bytes, compression_type: int) -> bytes:
        if compression_type in COMPRESSION_TYPES:
            if compression_type == COMPRESSION_TYPE_NONE:
                data = uncompressed_data
            elif compression_type == COMPRESSION_TYPE_TIANO:
                try:
                    data = EfiCompressor.TianoCompress(uncompressed_data)
                except Exception:
                    data = b''
            elif compression_type == COMPRESSION_TYPE_UEFI:
                try:
                    data = EfiCompressor.UefiCompress(uncompressed_data)
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
