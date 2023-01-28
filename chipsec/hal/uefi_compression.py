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


try:
    import brotli
    has_brotli = True
except ImportError:
    has_brotli = False
import lzma
try:
    import EfiCompressor
    has_eficomp = True
except ImportError:
    has_eficomp = False

from chipsec.logger import logger

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
COMPRESSION_TYPES_ALGORITHMS = [COMPRESSION_TYPE_LZMA,
                                COMPRESSION_TYPE_TIANO,
                                COMPRESSION_TYPE_UEFI,
                                COMPRESSION_TYPE_BROTLI,
                                COMPRESSION_TYPE_NONE, ]
COMPRESSION_TYPES = [COMPRESSION_TYPE_NONE,
                     COMPRESSION_TYPE_TIANO,
                     COMPRESSION_TYPE_UEFI,
                     COMPRESSION_TYPE_LZMA,
                     COMPRESSION_TYPE_BROTLI,
                     COMPRESSION_TYPE_EFI_STANDARD,
                     COMPRESSION_TYPE_UNKNOWN, ]


class UEFICompression:
    decompression_oder_type1 = [COMPRESSION_TYPE_TIANO, COMPRESSION_TYPE_UEFI]
    decompression_oder_type2 = [COMPRESSION_TYPE_TIANO,
                                COMPRESSION_TYPE_UEFI,
                                COMPRESSION_TYPE_LZMA,
                                COMPRESSION_TYPE_BROTLI, ]

    def __init__(self):
        pass

    def rotate_list(self, list, n):
        return list[n:] + list[:n]

    def decompress_EFI_binary(self, compressed_data, compression_type):
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
                    data = None
            elif compression_type == COMPRESSION_TYPE_UEFI and has_eficomp:
                try:
                    data = EfiCompressor.UefiDecompress(compressed_data)
                except Exception:
                    data = None
            elif compression_type == COMPRESSION_TYPE_LZMA:
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
                        data = None
            elif compression_type == COMPRESSION_TYPE_BROTLI and has_brotli:
                try:
                    data = brotli.decompress(compressed_data)
                except brotli.error:
                    data = None
            else:
                data = None
            if logger().HAL and data is None:
                logger().log("Cannot decompress data with {}".format(compression_type))
        else:
            logger().log_error('Unknown EFI compression type 0x{:X}'.format(compression_type))
            data = None
        return data

    def unknown_decompress(self, compressed_data):
        res = None
        failed_times = 0
        for CompressionType in self.decompression_oder_type2:
            res = self.decompress_EFI_binary(compressed_data, CompressionType)
            if res is not None:
                self.rotate_list(self.decompression_oder_type2, failed_times)
                break
            else:
                failed_times += 1
        return res

    def unknown_efi_decompress(self, compressed_data):
        res = None
        failed_times = 0
        for CompressionType in self.decompression_oder_type1:
            res = self.decompress_EFI_binary(compressed_data, CompressionType)
            if res is not None:
                self.rotate_list(self.decompression_oder_type1, failed_times)
                break
            else:
                failed_times += 1
        return res

    def compress_EFI_binary(self, uncompressed_data, compression_type):
        if compression_type in COMPRESSION_TYPES:
            if compression_type == COMPRESSION_TYPE_NONE:
                data = uncompressed_data
            elif compression_type == COMPRESSION_TYPE_TIANO:
                try:
                    data = EfiCompressor.TianoCompress(uncompressed_data)
                except Exception:
                    data = None
            elif compression_type == COMPRESSION_TYPE_UEFI:
                try:
                    data = EfiCompressor.UefiCompress(uncompressed_data)
                except Exception:
                    data = None
            elif compression_type == COMPRESSION_TYPE_LZMA:
                try:
                    data = lzma.compress(uncompressed_data)
                except lzma.LZMAError:
                    data = None
            elif compression_type == COMPRESSION_TYPE_BROTLI:
                try:
                    data = brotli.compress(uncompressed_data)
                except brotli.error:
                    data = None
            else:
                data = None
        else:
            logger().log_error('Unknown EFI compression type 0x{:X}'.format(compression_type))
            data = None
        return data
