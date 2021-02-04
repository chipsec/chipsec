#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2015, Intel Corporation
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


import time

from chipsec.command        import BaseCommand
from chipsec.hal.interrupts import Interrupts
from argparse               import ArgumentParser
import os


# ###################################################################
#
# CPU Interrupts
#
# ###################################################################



class SMICommand(BaseCommand):
    """
    >>> chipsec_util smi count
    >>> chipsec_util smi apmc <SMI_code> <SMI_data>
    >>> chipsec_util smi sw <thread_id> <SMI_code> <SMI_data> [RAX] [RBX] [RCX] [RDX] [RSI] [RDI]
    >>> chipsec_util smi smmc <RT_code_start> <RT_code_end> <GUID> <payload_loc> <payload_file|payload_string>

    Examples:

    >>> chipsec_util smi count
    >>> chipsec_util smi apmc 0x0 0xDE 0x0
    >>> chipsec_util smi sw 0x0 0xDE 0x0 0xAAAAAAAAAAAAAAAA ..
    >>> chipsec_util smi smmc 0x79dfe000 0x79efdfff ed32d533-99e6-4209-9cc02d72cdd998a7 0x79dfaaaa payload.bin
    """
    
    def count_smi(self):
        self.logger.log( "[CHIPSEC] SMI count:" )
        for tid in range(self.cs.msr.get_cpu_thread_count()):
            smi_cnt = self.cs.read_register_field('MSR_SMI_COUNT', 'Count', cpu_thread=tid)
            self.logger.log( "  CPU{:d}: {:d}".format(tid, smi_cnt) )
    
    def smmc_smi(self):
        if os.path.isfile(self.payload):
            f = open(self.payload, 'rb')
            payload = f.read()
            f.close()
        else:
            payload = self.payload

        self.logger.log("Searching for \'smmc\' in range 0x{:x}-0x{:x}".format(RTC_start, RTC_end))
        # scan for SMM_CORE_PRIVATE_DATA smmc signature
        smmc_loc = interrupts.find_smmc(self.rtc_start, self.rtc_end)
        if smmc_loc == 0:
            self.logger.log(" Couldn't find smmc signature")
            return
        self.logger.log("Found \'smmc\' structure at 0x{:x}".format(smmc_loc))

        ReturnStatus = interrupts.send_smmc_SMI(smmc_loc, self.guid, payload, self.payload_loc)
        #TODO Translate ReturnStatus to EFI_STATUS enum
        self.logger.log("ReturnStatus: {:x}".format(ReturnStatus))
    
    def apmc_smi(self):
        self.logger.log( "[CHIPSEC] Sending SW SMI (code: 0x{:02X}, data: 0x{:02X})..".format(self.smi_code_port_value, self._data_port_value) )
        interrupts.send_SMI_APMC( self.smi_code_port_value, self.smi_data_port_value )

    def sw_smi(self):
        self.logger.log( "[CHIPSEC] Sending SW SMI (code: 0x{:02X}, data: 0x{:02X})..".format(self.smi_code_port_value, self._data_port_value) )
        self.logger.log( "          RAX: 0x{:016X} (AX will be overwridden with values of SW SMI ports B2/B3)".format(_rax) )
        self.logger.log( "          RBX: 0x{:016X}".format(_rbx) )
        self.logger.log( "          RCX: 0x{:016X}".format(_rcx) )
        self.logger.log( "          RDX: 0x{:016X} (DX will be overwridden with 0x00B2)".format(_rdx) )
        self.logger.log( "          RSI: 0x{:016X}".format(_rsi) )
        self.logger.log( "          RDI: 0x{:016X}".format(_rdi) )
        ret = interrupts.send_SW_SMI( thread_id, SMI_code_port_value, SMI_data_port_value, _rax, _rbx, _rcx, _rdx, _rsi, _rdi )
        if not ret is None:
            self.logger.log( "Return values")
            self.logger.log( "          RAX: {:16X}".format(ret[1]) )
            self.logger.log( "          RBX: {:16X}".format(ret[2]) )
            self.logger.log( "          RCX: {:16X}".format(ret[3]) )
            self.logger.log( "          RDX: {:16X}".format(ret[4]) )
            self.logger.log( "          RSI: {:16X}".format(ret[5]) )
            self.logger.log( "          RDI: {:16X}".format(ret[6]) )

    def requires_driver(self):
        parser = ArgumentParser( prog='chipsec_util smi', usage=SMICommand.__doc__ )
        
        subparsers = parser.add_subparsers()
        parser_count = subparsers.add_parser('count')
        parser_count.set_defaults(func=self.count_smi)

        parser_smmc = subparsers.add_parser('smmc')
        parser_smmc.add_argument('rtc_start', type=lambda x: int(x,16), help='RTC Start (hex)')
        parser_smmc.add_argument('rtc_end', type=lambda x: int(x,16), help='RTC End (hex)')
        parser_smmc.add_argument('guid', type=str, help='Guid')
        parser_smmc.add_argument('payload_loc', type=lambda x: int(x,16), help='Payload Location (hex)')
        parser_smmc.add_argument('payload', type=str, help='payload')
        parser_smmc.set_defaults(func=self.smmc_smi)

        parser_apmc = subparsers.add_parser('apmc')
        parser_apmc.add_argument('smi_code_port_value', type=lambda x: int(x,16), help='SMI Code Port Value (hex)')
        parser_apmc.add_argument('smi_data_port_value', type=lambda x: int(x,16), help='SMI Data Port Value (hex)')
        parser_apmc.set_defaults(func=self.apmc_smi)

        parser_sw = subparsers.add_parser('sw')
        parser_sw.add_argument('thread_id', type=lambda x: int(x,16), help='Thread Id (hex)')
        parser_sw.add_argument('smi_code_port_value', type=lambda x: int(x,16), help='SMI Code Port Value (hex)')
        parser_sw.add_argument('smi_data_port_value', type=lambda x: int(x,16), help='SMI Data Port Value (hex)')
        parser_sw.add_argument('rax', type=lambda x: int(x,16), help='RAX (hex)')
        parser_sw.add_argument('rbx', type=lambda x: int(x,16), help='RBX (hex)')
        parser_sw.add_argument('rcx', type=lambda x: int(x,16), help='RCX (hex)')
        parser_sw.add_argument('rdx', type=lambda x: int(x,16), help='RDX (hex)')
        parser_sw.add_argument('rsi', type=lambda x: int(x,16), help='RSI (hex)')
        parser_sw.add_argument('rdi', type=lambda x: int(x,16), help='RDI (hex)')
        parser_sw.set_defaults(func=self.sw_smi)

        parser.parse_args(self.argv[2:], namespace=self)
        if hasattr(self, 'func'):
            return True
        return False

    def run(self):

        try:
            interrupts = Interrupts( self.cs )
        except RuntimeError as msg:
            print (msg)
            return

        t = time.time()

        self.func()

        self.logger.log( "[CHIPSEC] (smi) time elapsed {:.3f}".format(time.time() -t) )


class NMICommand(BaseCommand):
    """
    >>> chipsec_util nmi

    Examples:

    >>> chipsec_util nmi
    """
    def requires_driver(self):
        return True

    def run(self):
        try:
            interrupts = Interrupts( self.cs )
        except RuntimeError as msg:
            print (msg)
            return

        t = time.time()
        self.logger.log( "[CHIPSEC] Sending NMI#.." )
        interrupts.send_NMI()
        self.logger.log( "[CHIPSEC] (nmi) time elapsed {:.3f}".format(time.time() -t) )

commands = { 'smi': SMICommand, 'nmi': NMICommand }
