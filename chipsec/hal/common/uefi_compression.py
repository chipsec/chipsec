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
COMPRESSION_TYPES_ALGORITHMS: List[int] = [COMPRESSION_TYPE_LZMA,
                                           COMPRESSION_TYPE_TIANO,
                                           COMPRESSION_TYPE_UEFI,
                                           COMPRESSION_TYPE_BROTLI,
                                           COMPRESSION_TYPE_LZMAF86,
                                           COMPRESSION_TYPE_NONE, ]
COMPRESSION_TYPES: List[int] = [COMPRESSION_TYPE_NONE,
                                COMPRESSION_TYPE_TIANO,
                                COMPRESSION_TYPE_UEFI,
                                COMPRESSION_TYPE_LZMA,
                                COMPRESSION_TYPE_BROTLI,
                                COMPRESSION_TYPE_EFI_STANDARD,
                                COMPRESSION_TYPE_UNKNOWN,
                                COMPRESSION_TYPE_LZMAF86, ]


class UEFICompression:
    decompression_oder_type1: List[int] = [COMPRESSION_TYPE_TIANO, COMPRESSION_TYPE_UEFI]
    decompression_oder_type2: List[int] = [COMPRESSION_TYPE_TIANO,
                                           COMPRESSION_TYPE_UEFI,
                                           COMPRESSION_TYPE_LZMA,
                                           COMPRESSION_TYPE_BROTLI, ]

    def __init__(self):
        pass

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
                    except Exception as msg:
                        data = b''
            elif compression_type == COMPRESSION_TYPE_BROTLI and has_brotli:
                try:
                    data = brotli.decompress(compressed_data)
                except brotli.error:
                    data = b''
            else:
                data = b''
            if not data:
                logger().log_hal(f'Cannot decompress data with {compression_type}')
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
            else:
                data = b''
        else:
            logger().log_error(f'Unknown EFI compression type 0x{compression_type:X}')
            data = b''
        return data
