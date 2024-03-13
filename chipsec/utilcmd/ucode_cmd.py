# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
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
#

"""
>>> chipsec_util ucode id|load|decode [ucode_update_file (in .PDB or .BIN format)] [cpu_id]

Examples:

>>> chipsec_util ucode id
>>> chipsec_util ucode load ucode.bin 0
>>> chipsec_util ucode decode ucode.pdb
"""

from chipsec.command import BaseCommand, toLoad
from chipsec.library.file import read_file
from chipsec.hal.ucode import dump_ucode_update_header
from argparse import ArgumentParser

# ###################################################################
#
# Microcode patches
#
# ###################################################################


class UCodeCommand(BaseCommand):

    def requirements(self) -> toLoad:
        return toLoad.Driver

    def parse_arguments(self) -> None:
        parser = ArgumentParser(usage=__doc__)
        subparsers = parser.add_subparsers()
        parser_id = subparsers.add_parser('id')
        parser_id.add_argument('cpu_thread_id', nargs='?', type=lambda x: int(x, 16), default=None, help='CPU ID (hex)')
        parser_id.set_defaults(func=self.ucode_id)

        parser_load = subparsers.add_parser('load')
        parser_load.add_argument('ucode_filename', type=str, help='ucode file name (.PDB or .BIN format)')
        parser_load.add_argument('cpu_thread_id', nargs='?', type=lambda x: int(x, 16), default=None, help='CPU ID (hex)')
        parser_load.set_defaults(func=self.ucode_load)

        parser_decode = subparsers.add_parser('decode')
        parser_decode.add_argument('ucode_filename', type=str, help='ucode file name (.PDB format)')
        parser.parse_args(self.argv, namespace=self)

    def ucode_id(self):
        if self.cpu_thread_id is None:
            for tid in range(self.cs.msr.get_cpu_thread_count()):
                ucode_update_id = self.cs.ucode.ucode_update_id(tid)
                self.logger.log("[CHIPSEC] CPU{:d}: Microcode update ID = 0x{:08X}".format(tid, ucode_update_id))
        else:
            ucode_update_id = self.cs.ucode.ucode_update_id(self.cpu_thread_id)
            self.logger.log("[CHIPSEC] CPU{:d}: Microcode update ID = 0x{:08X}".format(self.cpu_thread_id, ucode_update_id))

    def ucode_load(self):
        if self.cpu_thread_id is None:
            self.logger.log("[CHIPSEC] Loading Microcode update on all cores from '{}'".format(self.ucode_filename))
            self.cs.ucode.update_ucode_all_cpus(self.ucode_filename)
        else:
            self.logger.log("[CHIPSEC] Loading Microcode update on CPU{:d} from '{}'".format(self.cpu_thread_id, self.ucode_filename))
            self.cs.ucode.update_ucode(self.cpu_thread_id, self.ucode_filename)

    def ucode_decode(self):
        if (not self.ucode_filename.endswith('.pdb')):
            self.logger.log("[CHIPSEC] Ucode update file is not PDB file: '{}'".format(self.ucode_filename))
            return
        pdb_ucode_buffer = read_file(self.ucode_filename)
        self.logger.log("[CHIPSEC] Decoding Microcode Update header of PDB file: '{}'".format(self.ucode_filename))
        dump_ucode_update_header(pdb_ucode_buffer)


commands = {'ucode': UCodeCommand}
