#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2021, Intel Corporation
#
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#

import brotli
import lzma
import EfiCompressor

from chipsec.defines import COMPRESSION_TYPES, COMPRESSION_TYPE_TIANO, COMPRESSION_TYPE_UEFI, COMPRESSION_TYPE_EFI_STANDARD
from chipsec.defines import COMPRESSION_TYPE_LZMA, COMPRESSION_TYPE_BROTLI, COMPRESSION_TYPE_NONE, COMPRESSION_TYPE_UNKNOWN
#from chipsec.hal.hal_base import HALBase
from chipsec.logger import logger
#from chipsec_tools.compression.tianocomress import Decompress as TianoDecompress
#from chipsec_tools.compression.tianocomress import TianoError


class UEFICompression:
    decompression_oder_type1 = [COMPRESSION_TYPE_TIANO, COMPRESSION_TYPE_UEFI]
    decompression_oder_type2 = [COMPRESSION_TYPE_TIANO, COMPRESSION_TYPE_UEFI, COMPRESSION_TYPE_LZMA, COMPRESSION_TYPE_BROTLI]

    def __init__(self):
        pass

    #def decompress_EFI_binary(self, compressed_name, uncompressed_name, compression_type):
    def decompress_EFI_binary(self, compressed_data, compression_type):
        if compression_type in COMPRESSION_TYPES:
            if compression_type == COMPRESSION_TYPE_UNKNOWN:
                data = self.unknown_decompress(compressed_data)
            elif compression_type == COMPRESSION_TYPE_EFI_STANDARD:
                data = self.unknown_efi_decompress(compressed_data)
            elif compression_type == COMPRESSION_TYPE_NONE:
                data = compressed_data
            elif compression_type == COMPRESSION_TYPE_TIANO:
                try:
                    data = EfiCompressor.TianoDecompress(compressed_data)
                    # data = TianoDecompress().Decompress(compressed_data, Version=1)
                except Exception:
                    data = None
            elif compression_type == COMPRESSION_TYPE_UEFI:
                try:
                    data = EfiCompressor.UefiDecompress(compressed_data)
                    # data = TianoDecompress().Decompress(compressed_data, Version=2)
                except Exception:
                    data = None
            elif compression_type == COMPRESSION_TYPE_LZMA:
                try:
                    data = lzma.decompress(compressed_data)
                except lzma.LZMAError:
                    data = None
            elif compression_type == COMPRESSION_TYPE_BROTLI:
                try:
                    data = brotli.decompress(compressed_data)
                except brotli.error:
                    data = None
            if logger().HAL and data is None:
                logger().error("Cannot decompress data with {}".format(compression_type))

        else:
            logger().error('Unknown EFI compression type 0x{:X}'.format(compression_type))
            data = None
        return data

    def unknown_decompress(self, compressed_data):
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
        failed_times = 0
        for CompressionType in self.decompression_oder_type1:
            res = self.decompress_file(compressed_data, CompressionType)
            if res is not None:
                self.rotate_list(self.decompression_oder_type1, failed_times)
                break
            else:
                failed_times += 1
        return res

    #def compress_EFI_binary(self, uncompressed_name, compressed_name, compression_type):
    def compress_EFI_binary(self, uncompressed_data, compression_type):
        if compression_type in COMPRESSION_TYPES:
            if compression_type == COMPRESSION_TYPE_NONE:
                data = uncompressed_data
            elif compression_type == COMPRESSION_TYPE_TIANO:
                try:
                    data = EfiCompressor.TianoCompress(compressed_data)
                    # data = TianoDecompress().Decompress(compressed_data, Version=1)
                except Exception:
                    data = None
            elif compression_type == COMPRESSION_TYPE_UEFI:
                try:
                    data = EfiCompressor.UefiCompress(compressed_data)
                    # data = TianoDecompress().Decompress(compressed_data, Version=2)
                except Exception:
                    data = None
            elif compression_type == COMPRESSION_TYPE_LZMA:
                try:
                    data = lzma.compress(compressed_data)
                except lzma.LZMAError:
                    data = None
            elif compression_type == COMPRESSION_TYPE_BROTLI:
                try:
                    data = brotli.compress(compressed_data)
                except brotli.error:
                    data = None
            else:
                data = None
        else:
            logger().error('Unknown EFI compression type 0x{:X}'.format(compression_type))
            data = None
        return data

    
    #Compress binary file
    
    def compress_file(self, FileName, OutputFileName, CompressionType):
        if CompressionType not in [i for i in COMPRESSION_TYPES]:
            #return False
            data = None
        encode_str = " -e -o {} ".format(OutputFileName)
        if CompressionType == COMPRESSION_TYPE_NONE:
            shutil.copyfile(FileName, OutputFileName)
            return True
        elif CompressionType == COMPRESSION_TYPE_TIANO:
            encode_str = TIANO + encode_str
        elif CompressionType == COMPRESSION_TYPE_UEFI:
            encode_str = EFI + encode_str + "--uefi "
        elif CompressionType == COMPRESSION_TYPE_LZMA:
            encode_str = LZMA + encode_str
        elif CompressionType == COMPRESSION_TYPE_BROTLI:
            encode_str = BROTLI + encode_str
        encode_str += FileName
        data = subprocess.check_output(encode_str, shell=True)
        if not data == 0 and logger().VERBOSE:
            logger().error("Cannot compress file({})".format(FileName))
            return False
        return True
