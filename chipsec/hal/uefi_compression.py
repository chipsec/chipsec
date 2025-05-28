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


import importlib
import platform
import struct
from typing import Dict, Final, List

from chipsec.hal.uefi_fv import EFI_SECTION_ZLIB_AMD_HEADER_FORMAT, EFI_SECTION_ZLIB_AMD_HEADER_LENGTH
from chipsec.library.logger import logger

modules: Dict[str, bool] = {}

for module_name in ['brotli', 'EfiCompressor', 'gzip', 'lzma', 'zlib']:
    try:
        globals()[module_name] = importlib.import_module(module_name)

        modules[module_name] = True
    except ModuleNotFoundError as import_error:
        modules[module_name] = False

        if platform.system().lower() in ['windows', 'linux', 'darwin']:
            logger().log_error(f'Failed to import compression module "{import_error.name}"')

COMPRESSION_TYPE_NONE: Final[int] = 0
COMPRESSION_TYPE_TIANO: Final[int] = 1
COMPRESSION_TYPE_UEFI: Final[int] = 2
COMPRESSION_TYPE_LZMA: Final[int] = 3
COMPRESSION_TYPE_BROTLI: Final[int] = 4
COMPRESSION_TYPE_EFI_STANDARD: Final[int] = 5
COMPRESSION_TYPE_UNKNOWN: Final[int] = 6
COMPRESSION_TYPE_LZMAF86: Final[int] = 7
COMPRESSION_TYPE_ZLIB_AMD: Final[int] = 8
COMPRESSION_TYPE_GZIP: Final[int] = 9

COMPRESSION_TYPES_ALGORITHMS: Final[List[int]] = [
    COMPRESSION_TYPE_LZMA,
    COMPRESSION_TYPE_TIANO,
    COMPRESSION_TYPE_UEFI,
    COMPRESSION_TYPE_LZMAF86,
    COMPRESSION_TYPE_ZLIB_AMD,
    COMPRESSION_TYPE_GZIP,
    COMPRESSION_TYPE_BROTLI,
    COMPRESSION_TYPE_NONE
]

COMPRESSION_TYPES: Final[List[int]] = [
    COMPRESSION_TYPE_BROTLI,
    COMPRESSION_TYPE_EFI_STANDARD,
    COMPRESSION_TYPE_GZIP,
    COMPRESSION_TYPE_LZMA,
    COMPRESSION_TYPE_LZMAF86,
    COMPRESSION_TYPE_NONE,
    COMPRESSION_TYPE_TIANO,
    COMPRESSION_TYPE_UEFI,
    COMPRESSION_TYPE_UNKNOWN,
    COMPRESSION_TYPE_ZLIB_AMD
]

COMPRESSION_TYPES_UNKNOWN_EFI: Final[List[int]] = [
    COMPRESSION_TYPE_TIANO,
    COMPRESSION_TYPE_UEFI
]

COMPRESSION_TYPES_UNKNOWN_ALL: Final[List[int]] = [
    COMPRESSION_TYPE_TIANO,
    COMPRESSION_TYPE_UEFI,
    COMPRESSION_TYPE_LZMA,
    COMPRESSION_TYPE_ZLIB_AMD,
    COMPRESSION_TYPE_GZIP,
    COMPRESSION_TYPE_BROTLI
]

# noinspection PyUnresolvedReferences
class UefiCompression:
    """ UEFI Compression """

    @staticmethod
    def _is_efi_compressed(efi_data: bytes) -> bool:
        """ Check if data is EFI compressed """

        size_compressed: int = int.from_bytes(efi_data[0:4], byteorder='little')

        size_decompressed: int = int.from_bytes(efi_data[4:8], byteorder='little')

        check_size: bool = 0 < size_compressed < size_decompressed

        check_data: bool = size_compressed + 8 == len(efi_data)

        return check_size and check_data

    def decompress_efi_binary(self, compressed_data: bytes, compression_type: int) -> bytes:
        """ Decompress EFI data """

        data: bytes = b''

        if compression_type not in COMPRESSION_TYPES:
            logger().log_error(f'Unknown EFI compression type 0x{compression_type:X}')

            return data

        if compression_type == COMPRESSION_TYPE_UNKNOWN:
            data = self._decompress_unknown(compressed_data, COMPRESSION_TYPES_UNKNOWN_ALL)
        elif compression_type == COMPRESSION_TYPE_EFI_STANDARD:
            data = self._decompress_unknown(compressed_data, COMPRESSION_TYPES_UNKNOWN_EFI)
        elif compression_type == COMPRESSION_TYPE_NONE:
            data = compressed_data
        elif compression_type == COMPRESSION_TYPE_TIANO and modules['EfiCompressor'] and self._is_efi_compressed(compressed_data):
            try:
                data = EfiCompressor.TianoDecompress(compressed_data)
            except Exception as error:
                logger().log_hal(f'Cannot decompress TIANO data: {error}')
        elif compression_type == COMPRESSION_TYPE_UEFI and modules['EfiCompressor'] and self._is_efi_compressed(compressed_data):
            try:
                data = EfiCompressor.UefiDecompress(compressed_data)
            except Exception as error:
                logger().log_hal(f'Cannot decompress UEFI data: {error}')
        elif compression_type in [COMPRESSION_TYPE_LZMA, COMPRESSION_TYPE_LZMAF86] and modules['lzma']:
            try:
                data = lzma.decompress(compressed_data)
            except lzma.LZMAError as error:
                logger().log_debug(f'Cannot decompress LZMA data: {error}')

                # If lzma fails, patch the size within the header
                # https://github.com/python/cpython/issues/92018
                try:
                    data = lzma.decompress(compressed_data[:0x5] + b'\xFF' * 0x8 + compressed_data[0xD:])
                except lzma.LZMAError as error_fallback:
                    logger().log_hal(f'Cannot decompress LZMA data: {error_fallback}')

            if compression_type == COMPRESSION_TYPE_LZMAF86:
                try:
                    if modules['EfiCompressor']:
                        data = EfiCompressor.LZMAf86Decompress(data)
                    else:
                        data = b''
                except Exception as error:
                    logger().log_hal(f'Cannot decompress LZMAF86 data: {error}')

                    data = b''
        elif compression_type == COMPRESSION_TYPE_ZLIB_AMD and modules['zlib']:
            try:
                compressed_size: int = struct.unpack_from(EFI_SECTION_ZLIB_AMD_HEADER_FORMAT, compressed_data)[0]

                if compressed_size + EFI_SECTION_ZLIB_AMD_HEADER_LENGTH == len(compressed_data):
                    data = zlib.decompress(compressed_data[EFI_SECTION_ZLIB_AMD_HEADER_LENGTH:])
            except Exception as error:
                logger().log_hal(f'Cannot decompress ZLIB AMD data: {error}')
        elif compression_type == COMPRESSION_TYPE_GZIP and modules['gzip']:
            try:
                data = gzip.decompress(compressed_data)
            except Exception as error:
                logger().log_hal(f'Cannot decompress GZIP data: {error}')
        elif compression_type == COMPRESSION_TYPE_BROTLI and modules['brotli']:
            try:
                data = brotli.decompress(compressed_data)
            except Exception as error:
                logger().log_hal(f'Cannot decompress BROTLI data: {error}')

        if not data:
            logger().log_hal(f'Failed to decompress EFI data of type 0x{compression_type:X}')

        return data

    def _decompress_unknown(self, compressed_data: bytes, compression_types: List[int]) -> bytes:
        """ Attempt to decompress unknown EFI data """

        data: bytes = b''

        for compression_type in compression_types:
            data = self.decompress_efi_binary(compressed_data, compression_type)

            if data:
                break

        return data

    def compress_efi_binary(self, uncompressed_data: bytes, compression_type: int) -> bytes:
        """ Compress EFI data """

        data: bytes = b''

        if compression_type not in COMPRESSION_TYPES:
            logger().log_error(f'Unknown EFI compression type 0x{compression_type:X}')

            return data

        if compression_type == COMPRESSION_TYPE_NONE:
            data = uncompressed_data
        elif compression_type == COMPRESSION_TYPE_TIANO and modules['EfiCompressor']:
            try:
                data = EfiCompressor.TianoCompress(uncompressed_data)

                if not self._is_efi_compressed(data):
                    data = b''

                    raise RuntimeError('Failed to validate EFI compression header')
            except Exception as error:
                logger().log_hal(f'Cannot compress TIANO data: {error}')
        elif compression_type == COMPRESSION_TYPE_UEFI and modules['EfiCompressor']:
            try:
                data = EfiCompressor.UefiCompress(uncompressed_data)

                if not self._is_efi_compressed(data):
                    data = b''

                    raise RuntimeError('Failed to validate EFI compression header')
            except Exception as error:
                logger().log_hal(f'Cannot compress UEFI data: {error}')
        elif compression_type == COMPRESSION_TYPE_LZMA and modules['lzma']:
            try:
                data = lzma.compress(uncompressed_data)
            except lzma.LZMAError as error:
                logger().log_hal(f'Cannot compress LZMA data: {error}')
        elif compression_type == COMPRESSION_TYPE_LZMAF86 and modules['EfiCompressor'] and modules['lzma']:
            try:
                data = lzma.compress(EfiCompressor.LZMAf86Compress(uncompressed_data))
            except lzma.LZMAError as error:
                logger().log_hal(f'Cannot compress LZMAF86 data: {error}')
        elif compression_type == COMPRESSION_TYPE_ZLIB_AMD and modules['zlib']:
            try:
                compressed_data: bytes = zlib.compress(uncompressed_data)
                amd_header_data: bytes = struct.pack(EFI_SECTION_ZLIB_AMD_HEADER_FORMAT, len(compressed_data))

                data = amd_header_data + compressed_data
            except zlib.error as error:
                logger().log_hal(f'Cannot compress ZLIB AMD data: {error}')
        elif compression_type == COMPRESSION_TYPE_GZIP and modules['gzip']:
            try:
                data = gzip.compress(uncompressed_data)
            except gzip.BadGzipFile as error:
                logger().log_hal(f'Cannot compress GZIP data: {error}')
        elif compression_type == COMPRESSION_TYPE_BROTLI and modules['brotli']:
            try:
                data = brotli.compress(uncompressed_data)
            except brotli.error as error:
                logger().log_hal(f'Cannot compress BROTLI data: {error}')

        return data
