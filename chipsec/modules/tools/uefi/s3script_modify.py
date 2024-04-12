# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2020, Intel Corporation
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
This module will attempt to modify the S3 Boot Script on the platform. Doing this could cause the platform to malfunction. Use with care!

Usage:
    Replacing existing opcode::

        chipsec_main.py -m tools.uefi.s3script_modify -a replace_op,<reg_opcode>,<address>,<value>
            <reg_opcode> = pci_wr|mmio_wr|io_wr|pci_rw|mmio_rw|io_rw

        chipsec_main.py -m tools.uefi.s3script_modify -a replace_op,mem[,<address>,<value>]

        chipsec_main.py -m tools.uefi.s3script_modify -a replace_op,dispatch``

        chipsec_main.py -m tools.uefi.s3script_modify -a replace_op,dispatch_ep``


    Adding new opcode::

        chipsec_main.py -m tools.uefi.s3script_modify -a add_op,<reg_opcode>,<address>,<value>,<width>
            <reg_opcode> = pci_wr|mmio_wr|io_wr

        chipsec_main.py -m tools.uefi.s3script_modify -a add_op,dispatch[,<entrypoint>]

Examples:

>>> chipsec_main.py -m tools.uefi.s3script_modify -a replace_op,<reg_opcode>,<address>,<value>
>>>   <reg_opcode> = pci_wr|mmio_wr|io_wr|pci_rw|mmio_rw|io_rw

The option will look for a script opcode that writes to PCI config, MMIO or I/O registers and modify the opcode to write the given value to the register with the given address.

After executing this, if the system is vulnerable to boot script modification, the hardware configuration will have changed according to given <reg_opcode>.

>>> chipsec_main.py -m tools.uefi.s3script_modify -a replace_op,mem

The option will look for a script opcode that writes to memory and modify the opcode to write the given value to the given address.

By default this test will allocate memory and write write ``0xB007B007`` that location.

After executing this, if the system is vulnerable to boot script modification, you should find the given value in the allocated memory location.

>>> chipsec_main.py -m tools.uefi.s3script_modify -a replace_op,dispatch

The option will look for a dispatch opcode in the script and modify the opcode to point to a different entry point. The new entry point will contain a HLT instruction.

After executing this, if the system is vulnerable to boot script modification, the system should hang on resume from S3.

>>> chipsec_main.py -m tools.uefi.s3script_modify -a replace_op,dispatch_ep

The option will look for a dispatch opcode in the script and will modify memory at the entry point for that opcode. The modified instructions will contain a HLT instruction.

After executing this, if the system is vulnerable to dispatch opcode entry point modification, the system should hang on resume from S3.

>>> chipsec_main.py -m tools.uefi.s3script_modify -a add_op,<reg_opcode>,<address>,<value>,<width>
>>>   <reg_opcode> = pci_wr|mmio_wr|io_wr

The option will add a new opcode which writes to PCI config, MMIO or I/O registers with specified values.

>>> chipsec_main.py -m tools.uefi.s3script_modify -a add_op,dispatch

The option will add a new DISPATCH opcode to the script with entry point to either existing or newly allocated memory.

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

import struct

from chipsec.module_common import BaseModule
from chipsec.library.returncode import ModuleResult
from chipsec.library.logger import print_buffer_bytes
from chipsec.hal.uefi import UEFI
from chipsec.hal.uefi_common import S3BootScriptOpcode, script_width_values, script_width_formats, op_io_pci_mem, op_dispatch
from chipsec.hal.uefi_platform import encode_s3bootscript_entry, id_s3bootscript_type, create_s3bootscript_entry_buffer

########################################################################################################
#
# Main module functionality
#
########################################################################################################

cmd2opcode = {
    'pci_wr': S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE,
    'mmio_wr': S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE,
    'io_wr': S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_WRITE_OPCODE,
    'pci_rw': S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE,
    'mmio_rw': S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE,
    'io_rw': S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE
}

dispatch_opcode = S3BootScriptOpcode.EFI_BOOT_SCRIPT_DISPATCH_OPCODE
terminate_opcode = S3BootScriptOpcode.EFI_BOOT_SCRIPT_TERMINATE_OPCODE

write_opcodes = [
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE,
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE,
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_WRITE_OPCODE
]


class s3script_modify(BaseModule):

    DISPATCH_ENTRYPOINT_INSTR = '\x90\x90\xF4\xF4'

    def __init__(self):
        BaseModule.__init__(self)
        self.result.url = 'https://chipsec.github.io/modules/chipsec.modules.tools.uefi.s3script_modify.html'
        self.logger.HAL = True
        self._uefi = UEFI(self.cs)
        self.bootscript_PAs = None
        self.parsed_scripts = None

    def get_bootscript(self):
        if (self.bootscript_PAs is None) or (self.parsed_scripts is None):
            (self.bootscript_PAs, self.parsed_scripts) = self._uefi.get_s3_bootscript(False)
        return (self.bootscript_PAs, self.parsed_scripts)

    def is_supported(self):
        supported = self.cs.helper.EFI_supported()
        if not supported:
            self.logger.log("OS does not support UEFI Runtime API.  Skipping module.")
        else:
            _, ps = self.get_bootscript()
            if not ps:
                self.logger.log("Unable to locate boot script.  Skipping module.")
                supported = False
        return supported

    def modify_s3_reg(self, opcode, address, new_value):
        (bootscript_PAs, parsed_scripts) = self.get_bootscript()
        if parsed_scripts is None:
            self.logger.log_bad("Did not find boot script.")
            return False
        for bootscript_pa in bootscript_PAs:
            if bootscript_pa == 0:
                continue
            self.logger.log(f'[*] Looking for 0x{opcode:X} opcode in the script at 0x{bootscript_pa:016X}..')
            for e in parsed_scripts[bootscript_pa]:
                if (e.decoded_opcode is not None) and \
                   (opcode == e.decoded_opcode.opcode) and \
                   (address == e.decoded_opcode.address):

                    self.logger.log_good(f'Found opcode at offset 0x{e.offset_in_script:04X}')
                    self.logger.log(e)
                    pa = bootscript_pa + e.offset_in_script
                    self.logger.log(f'[*] Modifying S3 boot script entry at address 0x{pa:016X}..')

                    orig_entry_buf = self.cs.mem.read_physical_mem(pa, e.length)
                    self.logger.log("[*] Original entry:")
                    print_buffer_bytes(orig_entry_buf)

                    if opcode in write_opcodes:
                        e.decoded_opcode.values[0] = new_value
                    else:
                        e.decoded_opcode.value = new_value

                    entry_buf = encode_s3bootscript_entry(e)
                    self.cs.mem.write_physical_mem(pa, e.length, entry_buf)

                    new_entry_buf = self.cs.mem.read_physical_mem(pa, e.length)
                    self.logger.log("[*] Modified entry:")
                    print_buffer_bytes(new_entry_buf)
                    return True

        self.logger.log_bad(f'Did not find required 0x{opcode:X} opcode in the script')
        return False

    def modify_s3_dispatch(self):
        ep_size = len(self.DISPATCH_ENTRYPOINT_INSTR)
        (smram_base, _, _) = self.cs.cpu.get_SMRAM()
        (_, new_entrypoint) = self.cs.mem.alloc_physical_mem(ep_size, smram_base)
        self.cs.mem.write_physical_mem(new_entrypoint, ep_size, self.DISPATCH_ENTRYPOINT_INSTR)
        new_ep = self.cs.mem.read_physical_mem(new_entrypoint, ep_size)
        self.logger.log_good(f'Allocated new DISPATCH entry-point at 0x{new_entrypoint:016X} (size = 0x{ep_size:X}):')
        print_buffer_bytes(new_ep)

        (bootscript_PAs, parsed_scripts) = self.get_bootscript()
        if parsed_scripts is None:
            self.logger.log_bad("Did not find boot script.")
            return False
        for bootscript_pa in bootscript_PAs:
            if bootscript_pa == 0:
                continue
            self.logger.log(f'[*] Searching the script at 0x{bootscript_pa:016X} for DISPATCH opcodes..')
            for e in parsed_scripts[bootscript_pa]:
                if (e.decoded_opcode is not None) and (dispatch_opcode == e.decoded_opcode.opcode):

                    self.logger.log_good(f'Found DISPATCH opcode at offset 0x{e.offset_in_script:04X}')
                    self.logger.log(e)
                    pa = bootscript_pa + e.offset_in_script
                    self.logger.log(f'[*] Modifying S3 boot script entry at address 0x{pa:016X}..')

                    orig_entry_buf = self.cs.mem.read_physical_mem(pa, e.length)
                    self.logger.log("[*] Original entry:")
                    print_buffer_bytes(orig_entry_buf)

                    e.decoded_opcode.entrypoint = new_entrypoint
                    entry_buf = encode_s3bootscript_entry(e)
                    self.cs.mem.write_physical_mem(pa, e.length, entry_buf)

                    new_entry_buf = self.cs.mem.read_physical_mem(pa, e.length)
                    self.logger.log("[*] Modified entry:")
                    print_buffer_bytes(new_entry_buf)
                    self.logger.log('After sleep/resume, the system should hang')
                    return True

        self.logger.log_bad("Did not find any suitable DISPATCH opcodes")
        return False

    def modify_s3_dispatch_ep(self):
        ep_pa = None
        (bootscript_PAs, parsed_scripts) = self.get_bootscript()
        if parsed_scripts is None:
            self.logger.log_bad("Did not find boot script.")
            return False
        for script_pa in bootscript_PAs:
            if script_pa == 0:
                continue
            self.logger.log(f'[*] Looking for DISPATCH opcode in the script at 0x{script_pa:016X}..')
            for e in parsed_scripts[script_pa]:
                if (e.decoded_opcode is not None) and (dispatch_opcode == e.decoded_opcode.opcode):
                    ep_pa = e.decoded_opcode.entrypoint
                    self.logger.log_good(f'Found DISPATCH opcode at offset 0x{e.offset_in_script:04X} with entry-point 0x{ep_pa:016X}')
                    self.logger.log(e)
                    break
            if ep_pa is not None:
                break

        if ep_pa is None:
            self.logger.log_bad("Didn't find any DISPATCH opcodes")
            return False

        ep_size = len(self.DISPATCH_ENTRYPOINT_INSTR)
        self.cs.mem.write_physical_mem(ep_pa, ep_size, self.DISPATCH_ENTRYPOINT_INSTR)
        new_ep = self.cs.mem.read_physical_mem(ep_pa, ep_size)
        self.logger.log(f'[*] New DISPATCH entry-point at 0x{ep_pa:016X} (size = 0x{ep_size:X}):')
        print_buffer_bytes(new_ep)
        return True

    def modify_s3_mem(self, address, new_value):
        if address is None:
            (smram_base, _, _) = self.cs.cpu.get_SMRAM()
            (_, address) = self.cs.mem.alloc_physical_mem(0x1000, smram_base)
            self.logger.log(f'[*] Allocated memory at 0x{address:016X} as a target of MEM_WRITE opcode')

        val = self.cs.mem.read_physical_mem_dword(address)
        self.logger.log(f'[*] Original value at 0x{address:016X}: 0x{val:08X}')

        (bootscript_PAs, parsed_scripts) = self.get_bootscript()
        if parsed_scripts is None:
            self.logger.log_bad("Did not find boot script.")
            return False
        for bootscript_pa in bootscript_PAs:
            if bootscript_pa == 0:
                continue
            self.logger.log(f'[*] Looking for MEM_WRITE opcode in the script at 0x{bootscript_pa:016X}..')
            for e in parsed_scripts[bootscript_pa]:
                if (e.decoded_opcode is not None) and (cmd2opcode['mmio_wr'] == e.decoded_opcode.opcode):

                    self.logger.log_good(f'Found opcode at offset 0x{e.offset_in_script:X}')
                    self.logger.log(e)
                    pa = bootscript_pa + e.offset_in_script
                    self.logger.log(f'[*] Modifying S3 boot script entry at address 0x{pa:016X}..')

                    orig_entry_buf = self.cs.mem.read_physical_mem(pa, e.length)
                    self.logger.log("[*] Original entry:")
                    print_buffer_bytes(orig_entry_buf)

                    e.decoded_opcode.address = address
                    e.decoded_opcode.values[0] = new_value
                    entry_buf = encode_s3bootscript_entry(e)
                    self.cs.mem.write_physical_mem(pa, e.length, entry_buf)

                    new_entry_buf = self.cs.mem.read_physical_mem(pa, e.length)
                    self.logger.log("[*] Modified entry:")
                    print_buffer_bytes(new_entry_buf)
                    self.logger.log(f'After sleep/resume, read address 0x{address:08X} and look for value 0x{new_value:08X}')
                    return True

        self.logger.log_bad(f'Did not find required 0x{cmd2opcode["mmio_wr"]:X} opcode in the script')
        return False

    def modify_s3_add(self, new_opcode):
        e_index = None
        (bootscript_PAs, parsed_scripts) = self.get_bootscript()
        if parsed_scripts is None:
            self.logger.log_bad("Did not find boot script.")
            return False

        for bootscript_pa in bootscript_PAs:
            if bootscript_pa == 0:
                continue
            script_buffer = self.cs.mem.read_physical_mem(bootscript_pa, 4)
            script_type, _ = id_s3bootscript_type(script_buffer, False)
            self.logger.log(f'[*] S3 boot script type: 0x{script_type:0X}')

            self.logger.log(f'[*] Looking for TERMINATE opcode in the script at 0x{bootscript_pa:016X}..')
            for e in parsed_scripts[bootscript_pa]:
                if (e.index is not None) and (e.index != -1):
                    e_index = e.index + 1

                if (e.decoded_opcode is not None) and (terminate_opcode == e.decoded_opcode.opcode):
                    self.logger.log_good(f'Found TERMINATE opcode at offset 0x{e.offset_in_script:X}')
                    self.logger.log(e)
                    pa = bootscript_pa + e.offset_in_script
                    orig_entry_buf = self.cs.mem.read_physical_mem(pa, e.length)

                    self.logger.log("[*] New S3 boot script opcode:")
                    self.logger.log(new_opcode)
                    self.logger.log(f'[*] Adding new opcode entry at address 0x{pa:016X}..')
                    new_entry = create_s3bootscript_entry_buffer(script_type, new_opcode, e_index)
                    print_buffer_bytes(new_entry)

                    self.cs.mem.write_physical_mem(pa, len(new_entry), new_entry)
                    last_entry_pa = pa + len(new_entry)
                    self.logger.log(f'[*] Moving TERMINATE opcode to the last entry at 0x{last_entry_pa:016X}..')
                    self.cs.mem.write_physical_mem(last_entry_pa, len(orig_entry_buf), orig_entry_buf)
                    return True

        self.logger.log_bad("Did not find TERMINATE opcode")
        return False

    def run(self, module_argv):
        self.logger.start_test('S3 Resume Boot-Script Testing')
        sts = False

        op = module_argv[0].lower() if len(module_argv) > 0 else 'add_op'
        if op == 'replace_op':
            scmd = module_argv[1].lower() if len(module_argv) > 1 else 'dispatch_ep'
            if scmd in cmd2opcode:
                if len(module_argv) < 4:
                    self.logger.log_error(f'Expected module options: -a replace_op,{scmd},<reg_address>,<value>')
                    self.result.setStatusBit(self.result.status.UNSUPPORTED_FEATURE)
                    return self.result.getReturnCode(ModuleResult.ERROR)
                reg_address = int(module_argv[2], 16)
                value = int(module_argv[3], 16)
                sts = self.modify_s3_reg(cmd2opcode[scmd], reg_address, value)
                if sts:
                    self.logger.log(f'[*] After sleep/resume, check the value of register 0x{reg_address:X} is 0x{value:X}')
            elif 'dispatch' == scmd:
                sts = self.modify_s3_dispatch()
            elif 'dispatch_ep' == scmd:
                sts = self.modify_s3_dispatch_ep()
            elif 'mem' == scmd:
                new_value = int(module_argv[2], 16) if len(module_argv) >= 3 else 0xB007B007
                address = int(module_argv[3], 16) if len(module_argv) == 4 else None
                sts = self.modify_s3_mem(address, new_value)
            else:
                self.logger.log_error(f'Unrecognized module command-line argument: {scmd}')
                self.logger.log(examples_str)
                self.result.setStatusBit(self.result.status.UNSUPPORTED_FEATURE)
                return self.result.getReturnCode(ModuleResult.ERROR)
        elif op == 'add_op':
            scmd = module_argv[1].lower() if len(module_argv) > 1 else 'dispatch'
            new_opcode = None
            if scmd in cmd2opcode:
                if len(module_argv) < 5:
                    self.logger.log_error(f'Expected module options: -a add_op,{scmd},<reg_address>,<value>,<width>')
                    self.result.setStatusBit(self.result.status.UNSUPPORTED_FEATURE)
                    return self.result.getReturnCode(ModuleResult.ERROR)
                address = int(module_argv[2], 16)
                value = int(module_argv[3], 16)
                width = int(module_argv[4], 16)
                width_val = script_width_values[width]
                value_buff = struct.pack(f'<{script_width_formats[width_val]}', value)

                if cmd2opcode[scmd] in write_opcodes:
                    new_opcode = op_io_pci_mem(cmd2opcode[scmd], None, width_val, address, 0, 1, value_buff, None, None)
                else:
                    self.logger.log_error(f'Unsupported opcode: {scmd}')
                    self.logger.log(examples_str)
                    self.result.setStatusBit(self.result.status.UNSUPPORTED_FEATURE)
                    return self.result.getReturnCode(ModuleResult.ERROR)
            elif 'dispatch' == scmd:
                if len(module_argv) < 3:
                    (smram_base, _, _) = self.cs.cpu.get_SMRAM()
                    (_, entrypoint) = self.cs.mem.alloc_physical_mem(0x1000, smram_base)
                    self.cs.mem.write_physical_mem(entrypoint, len(self.DISPATCH_ENTRYPOINT_INSTR), self.DISPATCH_ENTRYPOINT_INSTR)
                else:
                    entrypoint = int(module_argv[2], 16)
                new_opcode = op_dispatch(dispatch_opcode, None, entrypoint)
            else:
                self.logger.log_error(f'Unrecognized opcode: {scmd}')
                self.logger.log(examples_str)
                self.result.setStatusBit(self.result.status.UNSUPPORTED_FEATURE)
                return self.result.getReturnCode(ModuleResult.ERROR)

            sts = self.modify_s3_add(new_opcode)
        else:
            self.logger.log_error(f'Unrecognized module command-line argument: {op}')
            self.logger.log(examples_str)
            self.result.setStatusBit(self.result.status.UNSUPPORTED_FEATURE)
            return self.result.getReturnCode(ModuleResult.ERROR)
        
        self.result.setStatusBit(self.result.status.VERIFY)

        if sts:
            self.logger.log_passed('The script has been modified. Go to sleep..')
            self.res = ModuleResult.PASSED
        else:
            self.res = ModuleResult.FAILED
        
        return self.result.getReturnCode(self.res)
