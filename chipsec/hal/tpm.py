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
Trusted Platform Module (TPM) HAL component

https://trustedcomputinggroup.org
"""

from chipsec.hal import hal_base
from chipsec.hal import acpi
from chipsec.hal import tpm_interface
from chipsec.library.tpm import tpm_defines


class TPM(hal_base.HALBase):
    def __init__(self, cs):
        super(TPM, self).__init__(cs)
        self.helper = cs.helper
        self.tpm_acpi = acpi.ACPI(self.cs)
        self.version = self.read_tpm_version()
        self.interface = self.read_tpm_interface()
        self.tpm = self.init_tpm()

    def read_tpm_version(self) -> str:
        tpm1_acpi_present = self.tpm_acpi.is_ACPI_table_present('TCPA')
        tpm2_acpi_present = self.tpm_acpi.is_ACPI_table_present('TPM2')
        if (not tpm1_acpi_present and not tpm2_acpi_present):
            raise RuntimeError('No TPM recognized')  # TODO: this might need a proper error
        elif tpm1_acpi_present and not tpm2_acpi_present:
            return tpm_defines.TPM1
        else:
            return tpm_defines.TPM2

    def read_tpm_interface(self) -> str:
        if self.version == tpm_defines.TPM1:
            return tpm_defines.TPM_FIFO_LEGACY
        tpm_interface_id = self.cs.mem.read_physical_mem_dword(tpm_defines.TPM2_INTERFACE_ADDR)
        tpm_interface_id = (int(tpm_interface_id) & 0xF)
        if tpm_interface_id == 0x0:
            return tpm_defines.TPM_CRB
        elif tpm_interface_id == 0x1:
            return tpm_defines.TPM_FIFO
        elif tpm_interface_id == 0xF:
            return tpm_defines.TPM_FIFO_LEGACY
        else:
            raise RuntimeError('No TPM interface recognized')

    def init_tpm(self) -> tpm_interface.TPM_BASE:
        if self.version == tpm_defines.TPM1:
            return tpm_interface.TPM1(self.cs)
        elif self.version == tpm_defines.TPM2:
            return tpm_interface.TPM2(self.cs, self.interface)
        else:
            raise RuntimeError('Invalid combination of TPM version and interface')
    
    def command(self, commandName: str, locality: str, command_argv: str) -> None:
        self.tpm.command(commandName, locality, command_argv)

    def send_command(self, Locality: int, command: bytes, size: int) -> None:
        self.tpm.send_command(Locality, command, size)

    def read_response(self, Locality: int):
        self.tpm.read_response(Locality)

    def dump_all(self, locality: str) -> None:
        for reg in tpm_defines.list_of_registers:
            self.dump_register(reg, locality)
            
    def log_register_header(self, register_name: str, locality: str) -> None:
        num_spaces = 32 + (-len(register_name) // 2)  # ceiling division
        self.logger.log('=' * 64)
        self.logger.log(f'{" " * num_spaces}{register_name}_{locality}')
        self.logger.log('=' * 64)

    def dump_register(self, register_name: str, locality: str) -> None:
        self.cs.Cfg.REGISTERS[register_name]['address'] = self.cs.Cfg.REGISTERS[register_name]['address'] ^ tpm_defines.LOCALITY[locality]
        register = self.cs.register.read_dict(register_name)

        self.log_register_header(register_name, locality)

        max_field_len = 0
        for field in register['FIELDS']:
            if len(field) > max_field_len:
                max_field_len = len(field)
        for field in register['FIELDS']:
            self.logger.log(f'\t{field}{" " * (max_field_len - len(field))}: {hex(register["FIELDS"][field]["value"])}')

    def identify(self) -> None:
        print(self.tpm)
