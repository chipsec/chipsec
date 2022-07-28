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
The msr command allows direct access to read and write MSRs.

>>> chipsec_util msr <msr> [eax] [edx] [cpu_id]

Examples:

>>> chipsec_util msr 0x3A
>>> chipsec_util msr 0x3A 0
>>> chipsec_util msr 0x8B 0x0 0x0 0
"""

from chipsec.command import BaseCommand
from chipsec.hal.msr import Msr
from argparse import ArgumentParser


# CPU Model Specific Registers
class MSRCommand(BaseCommand):

    def requires_driver(self):
        parser = ArgumentParser(prog='chipsec_util msr', usage=__doc__)
        parser.add_argument('msr_addr', type=lambda x: int(x, 16), metavar='<msr>', help='MSR address (hex)')
        parser.add_argument('msr_input1', type=lambda x: int(x, 16), metavar='MSR Value', nargs='?', default=None, help='EAX (hex)')
        parser.add_argument('msr_input2', type=lambda x: int(x, 16), metavar='MSR Value', nargs='?', default=None, help='EDX (hex)')
        parser.add_argument('cpu_id', type=lambda x: int(x, 16), metavar='CPU ID', nargs='?', default=None, help='CPU ID (hex)')
        parser.parse_args(self.argv[2:], namespace=self)
        return True

    def run(self):
        if self.msr_input1 is None:
            for tid in range(self.cs.msr.get_cpu_thread_count()):
                (eax, edx) = self.cs.msr.read_msr(tid, self.msr_addr)
                val64 = ((edx << 32) | eax)
                self.logger.log("[CHIPSEC] CPU{:d}: RDMSR( 0x{:x} ) = {:016X} (EAX={:08X}, EDX={:08X})".format(tid, self.msr_addr, val64, eax, edx))
        elif self.msr_input2 is None:
            cpu_thread_id = self.msr_input1
            (eax, edx) = self.cs.msr.read_msr(cpu_thread_id, self.msr_addr)
            val64 = ((edx << 32) | eax)
            self.logger.log("[CHIPSEC] CPU{:d}: RDMSR( 0x{:x} ) = {:016X} (EAX={:08X}, EDX={:08X})".format(cpu_thread_id, self.msr_addr, val64, eax, edx))
        else:
            eax = self.msr_input1
            edx = self.msr_input2
            val64 = ((edx << 32) | eax)
            if self.cpu_id is None:
                self.logger.log("[CHIPSEC] All CPUs: WRMSR( 0x{:x} ) = {:016X}".format(self.msr_addr, val64))
                for tid in range(self.cs.msr.get_cpu_thread_count()):
                    self.cs.msr.write_msr(tid, self.msr_addr, eax, edx)
            else:
                cpu_thread_id = self.cpu_id
                self.logger.log("[CHIPSEC] CPU{:d}: WRMSR( 0x{:x} ) = {:016X}".format(cpu_thread_id, self.msr_addr, val64))
                self.cs.msr.write_msr(cpu_thread_id, self.msr_addr, eax, edx)


commands = {'msr': MSRCommand}
