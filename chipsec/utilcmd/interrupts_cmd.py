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
SMI command:

>>> chipsec_util smi count
>>> chipsec_util smi send <thread_id> <SMI_code> <SMI_data> [RAX] [RBX] [RCX] [RDX] [RSI] [RDI]
>>> chipsec_util smi smmc <RT_code_start> <RT_code_end> <GUID> <payload_loc> <payload_file|payload_string> [port]

Examples:

>>> chipsec_util smi count
>>> chipsec_util smi send 0x0 0xDE 0x0
>>> chipsec_util smi send 0x0 0xDE 0x0 0xAAAAAAAAAAAAAAAA ..
>>> chipsec_util smi smmc 0x79dfe000 0x79efdfff ed32d533-99e6-4209-9cc02d72cdd998a7 0x79dfaaaa payload.bin

NMI command:

>>> chipsec_util nmi

Examples:

>>> chipsec_util nmi
"""

import os

from chipsec.command import BaseCommand, toLoad
from chipsec.hal.interrupts import Interrupts
from chipsec.hal.uefi_common import EFI_ERROR_STR
from argparse import ArgumentParser


# ###################################################################
#
# CPU Interrupts
#
# ###################################################################


class SMICommand(BaseCommand):
    """
    >>> chipsec_util smi count
    >>> chipsec_util smi send <thread_id> <SMI_code> <SMI_data> [RAX] [RBX] [RCX] [RDX] [RSI] [RDI]
    >>> chipsec_util smi smmc <RT_code_start> <RT_code_end> <GUID> <payload_loc> <payload_file|payload_string> [port]

    Examples:

    >>> chipsec_util smi count
    >>> chipsec_util smi send 0x0 0xDE 0x0
    >>> chipsec_util smi send 0x0 0xDE 0x0 0xAAAAAAAAAAAAAAAA ..
    >>> chipsec_util smi smmc 0x79dfe000 0x79efdfff ed32d533-99e6-4209-9cc02d72cdd998a7 0x79dfaaaa payload.bin
    """

    def requirements(self) -> toLoad:
        return toLoad.All

    def parse_arguments(self) -> None:
        parser = ArgumentParser(prog='chipsec_util smi', usage=SMICommand.__doc__)
        subparsers = parser.add_subparsers()

        parser_count = subparsers.add_parser('count')
        parser_count.set_defaults(func=self.smi_count)

        parser_send = subparsers.add_parser('send')
        parser_send.add_argument('thread_id', type=lambda x: int(x, 16), help='Thread ID (hex)')
        parser_send.add_argument('SMI_code_port_value', type=lambda x: int(x, 16), help='SMI Code (hex)')
        parser_send.add_argument('SMI_data_port_value', type=lambda x: int(x, 16), help='SMI Data (hex)')
        parser_send.add_argument('_rax', type=lambda x: int(x, 16), nargs='?', default=None, help='RAX (hex)')
        parser_send.add_argument('_rbx', type=lambda x: int(x, 16), nargs='?', default=0, help='RBX (hex) [default=0]')
        parser_send.add_argument('_rcx', type=lambda x: int(x, 16), nargs='?', default=0, help='RCX (hex) [default=0]')
        parser_send.add_argument('_rdx', type=lambda x: int(x, 16), nargs='?', default=0, help='RDX (hex) [default=0]')
        parser_send.add_argument('_rsi', type=lambda x: int(x, 16), nargs='?', default=0, help='RSI (hex) [default=0]')
        parser_send.add_argument('_rdi', type=lambda x: int(x, 16), nargs='?', default=0, help='RDI (hex) [default=0]')
        parser_send.set_defaults(func=self.smi_send)

        parser_smmc = subparsers.add_parser('smmc')
        parser_smmc.add_argument('RTC_start', type=lambda x: int(x, 16), help='RTC Code Start (hex)')
        parser_smmc.add_argument('RTC_end', type=lambda x: int(x, 16), help='RT Code End (hex)')
        parser_smmc.add_argument('guid', type=str, help='GUID')
        parser_smmc.add_argument('payload_loc', type=lambda x: int(x, 16), help='Payload Location (hex)')
        parser_smmc.add_argument('payload', type=str, help='Payload')
        parser_smmc.add_argument('port', type=lambda x: int(x, 16), nargs='?', default=0x0, help='Port (hex) [default=0]')
        parser_smmc.set_defaults(func=self.smi_smmc)

        parser.parse_args(self.argv, namespace=self)

    def smi_count(self) -> None:
        self.logger.log("[CHIPSEC] SMI count:")
        for tid in range(self.cs.msr.get_cpu_thread_count()):
            smi_cnt = self.cs.register.read_field('MSR_SMI_COUNT', 'Count', cpu_thread=tid)
            self.logger.log(f'  CPU{tid:d}: {smi_cnt:d}')

    def smi_smmc(self) -> None:
        if os.path.isfile(self.payload):
            with open(self.payload, 'rb') as f:
                self.payload = f.read()

        self.logger.log(f'Searching for \'smmc\' in range 0x{self.RTC_start:x}-0x{self.RTC_end:x}')
        # scan for SMM_CORE_PRIVATE_DATA smmc signature
        smmc_loc = self.interrupts.find_smmc(self.RTC_start, self.RTC_end)
        if (smmc_loc == 0):
            self.logger.log(" Couldn't find smmc signature")
            return
        self.logger.log(f'Found \'smmc\' structure at 0x{smmc_loc:x}')

        ReturnStatus = self.interrupts.send_smmc_SMI(smmc_loc, self.guid, self.payload, self.payload_loc, CommandPort=self.port)
        # TODO Translate ReturnStatus to EFI_STATUS enum
        self.logger.log(f'ReturnStatus: 0x{ReturnStatus:x} ({EFI_ERROR_STR(ReturnStatus)})')

    def smi_send(self) -> None:
        self.logger.log(f'[CHIPSEC] Sending SW SMI (code: 0x{self.SMI_code_port_value:02X}, data: 0x{self.SMI_data_port_value:02X})..')
        if self._rax is None:
            self.interrupts.send_SMI_APMC(self.SMI_code_port_value, self.SMI_data_port_value)
        else:
            self.logger.log(f'          RAX: 0x{self._rax:016X} (AX will be overridden with values of SW SMI ports B2/B3)')
            self.logger.log(f'          RBX: 0x{self._rbx:016X}')
            self.logger.log(f'          RCX: 0x{self._rcx:016X}')
            self.logger.log(f'          RDX: 0x{self._rdx:016X} (DX will be overridden with 0x00B2)')
            self.logger.log(f'          RSI: 0x{self._rsi:016X}')
            self.logger.log(f'          RDI: 0x{self._rdi:016X}')
            ret = self.interrupts.send_SW_SMI(self.thread_id, self.SMI_code_port_value, self.SMI_data_port_value, self._rax, self._rbx, self._rcx, self._rdx, self._rsi, self._rdi)
            if not ret is None:
                self.logger.log("Return values")
                self.logger.log(f'          RAX: {ret[1]:16X}')
                self.logger.log(f'          RBX: {ret[2]:16X}')
                self.logger.log(f'          RCX: {ret[3]:16X}')
                self.logger.log(f'          RDX: {ret[4]:16X}')
                self.logger.log(f'          RSI: {ret[5]:16X}')
                self.logger.log(f'          RDI: {ret[6]:16X}')

    def run(self) -> None:
        try:
            self.interrupts = Interrupts(self.cs)
        except RuntimeError as msg:
            self.logger.log(msg)
            return

        self.func()


class NMICommand(BaseCommand):
    """
    >>> chipsec_util nmi

    Examples:

    >>> chipsec_util nmi
    """

    def requirements(self) -> toLoad:
        return toLoad.All

    def parse_arguments(self) -> None:
        return

    def run(self) -> None:
        try:
            interrupts = Interrupts(self.cs)
        except RuntimeError as msg:
            self.logger.log(msg)
            return

        self.logger.log("[CHIPSEC] Sending NMI#...")
        interrupts.send_NMI()


commands = {'smi': SMICommand, 'nmi': NMICommand}
