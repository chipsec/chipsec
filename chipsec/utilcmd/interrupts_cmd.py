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
import os


# ###################################################################
#
# CPU Interrupts
#
# ###################################################################



class SMICommand(BaseCommand):
    """
    >>> chipsec_util smi count
    >>> chipsec_util smi <thread_id> <SMI_code> <SMI_data> [RAX] [RBX] [RCX] [RDX] [RSI] [RDI]
    >>> chipsec_util smi smmc <RT_code_start> <RT_code_end> <GUID> <payload_loc> <payload_file|payload_string>

    Examples:

    >>> chipsec_util smi count
    >>> chipsec_util smi 0x0 0xDE 0x0
    >>> chipsec_util smi 0x0 0xDE 0x0 0xAAAAAAAAAAAAAAAA ..
    >>> chipsec_util.py smi smmc 0x79dfe000 0x79efdfff ed32d533-99e6-4209-9cc02d72cdd998a7 0x79dfaaaa payload.bin
    """
    def requires_driver(self):
        # No driver required when printing the util documentation
        if len(self.argv) < 3:
            return False
        return True

    def run(self):
        if len(self.argv) < 3:
            print (SMICommand.__doc__)
            return

        try:
            interrupts = Interrupts( self.cs )
        except RuntimeError as msg:
            print (msg)
            return

        op = self.argv[2]
        t = time.time()

        if 'count' == op:
            self.logger.log( "[CHIPSEC] SMI count:" )
            for tid in range(self.cs.msr.get_cpu_thread_count()):
                smi_cnt = self.cs.read_register_field('MSR_SMI_COUNT', 'Count', cpu_thread=tid)
                self.logger.log( "  CPU{:d}: {:d}".format(tid,smi_cnt) )
        elif 'smmc' == op:
            if len(self.argv) < 8:
                print (SMICommand.__doc__)
                return

            RTC_start = int(self.argv[3],16)
            RTC_end = int(self.argv[4],16)
            guid = self.argv[5]
            payload_loc = int(self.argv[6],16)
            payload = self.argv[7]
            if os.path.isfile(payload):
                f = open(payload,'rb')
                payload = f.read()
                f.close()

            self.logger.log("Searching for \'smmc\' in range 0x{:x}-0x{:x}".format(RTC_start,RTC_end))
            # scan for SMM_CORE_PRIVATE_DATA smmc signature
            smmc_loc = interrupts.find_smmc(RTC_start,RTC_end)
            if smmc_loc == 0:
                self.logger.log(" Couldn't find smmc signature")
                return
            self.logger.log("Found \'smmc\' structure at 0x{:x}".format(smmc_loc))

            ReturnStatus = interrupts.send_smmc_SMI(smmc_loc,guid,payload,payload_loc)
            #TODO Translate ReturnStatus to EFI_STATUS enum
            self.logger.log("ReturnStatus: {:x}".format(ReturnStatus))
        else:
            SMI_data_port_value = 0x0
            if len(self.argv) > 4:
                thread_id           = int(self.argv[2],16)
                SMI_code_port_value = int(self.argv[3],16)
                SMI_data_port_value = int(self.argv[4],16)
                self.logger.log( "[CHIPSEC] Sending SW SMI (code: 0x{:02X}, data: 0x{:02X})..".format(SMI_code_port_value, SMI_data_port_value) )
                if 5 == len(self.argv):
                    interrupts.send_SMI_APMC( SMI_code_port_value, SMI_data_port_value )
                elif 11 == len(self.argv):
                    _rax = int(self.argv[5],16)
                    _rbx = int(self.argv[6],16)
                    _rcx = int(self.argv[7],16)
                    _rdx = int(self.argv[8],16)
                    _rsi = int(self.argv[9],16)
                    _rdi = int(self.argv[10],16)
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
                else: print (SMICommand.__doc__)
            else:
                self.logger.error( "unknown command-line option '{:32}'".format(op) )
                print (SMICommand.__doc__)
                return

        self.logger.log( "[CHIPSEC] (smi) time elapsed {:.3f}".format(time.time()-t) )


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
        self.logger.log( "[CHIPSEC] (nmi) time elapsed {:.3f}".format(time.time()-t) )

commands = { 'smi': SMICommand, 'nmi': NMICommand }
