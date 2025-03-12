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


# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
#
# -------------------------------------------------------------------------------

"""
Access to SMBus Controller
"""
from typing import List
from chipsec.hal import hal_base
from chipsec.hal.common import iobar
from chipsec.library.exceptions import IOBARNotFoundError, ObjectInstanceNotFoundError, RegisterNotFoundError

SMBUS_COMMAND_QUICK = 0
SMBUS_COMMAND_BYTE = 1
SMBUS_COMMAND_BYTE_DATA = 2
SMBUS_COMMAND_WORD_DATA = 3
SMBUS_COMMAND_PROCESS_CALL = 4
SMBUS_COMMAND_BLOCK = 5
SMBUS_COMMAND_I2C_READ = 6
SMBUS_COMMAND_BLOCK_PROCESS = 7

SMBUS_POLL_COUNT = 1000

SMBUS_COMMAND_WRITE = 0
SMBUS_COMMAND_READ = 1


class SMBus(hal_base.HALBase):

    def __init__(self, cs):
        super(SMBus, self).__init__(cs)
        self.instance = None
        self.set_instance()
        self.get_common_registers()
        self.get_registers()
        self.i2c_mode = False

    def set_i2c_mode(self, is_i2c_mode_enabled):
        self.i2c_mode = is_i2c_mode_enabled

    def get_instances(self):
        smbus_obj = self.cs.device.get_obj('8086.SMBUS')
        if smbus_obj.instances:
            return smbus_obj.instances
        raise ObjectInstanceNotFoundError('SMBus instance not found')

    def set_instance(self, instance=None):
        _instances = self.get_instances()
        if instance is None:
            self.instance = _instances[0]
        elif instance in _instances:
            self.instance = instance
        else:
            raise RegisterNotFoundError(f'Instance {instance} is not within supported list {_instances}')

    def get_registers(self):
        self.smb_reg_status = self.cs.register.get_instance_by_name('8086.SMBUS.HST_STS', self.instance)
        self.smb_reg_control = self.cs.register.get_instance_by_name('8086.SMBUS.HST_CNT', self.instance)
        self.smb_reg_command = self.cs.register.get_instance_by_name('8086.SMBUS.HST_CMD', self.instance)
        self.smb_reg_address = self.cs.register.get_instance_by_name('8086.SMBUS.HST_SLVA', self.instance)
        self.smb_reg_data0 = self.cs.register.get_instance_by_name('8086.SMBUS.HST_D0', self.instance)
        self.smb_reg_data1 = self.cs.register.get_instance_by_name('8086.SMBUS.HST_D1', self.instance)
        self.smb_reg_aux_ctl = self.cs.register.get_instance_by_name('8086.SMBUS.HST_AUX_CTL', self.instance)
        self.smb_reg_block_db = self.cs.register.get_instance_by_name('8086.SMBUS.HST_BLOCK_DB', self.instance)
        self.smb_hcfg = self.cs.register.get_instance_by_name('8086.SMBUS.HCFG', self.instance)

    def get_common_registers(self):
        self.smb_cmd = self.cs.register.get_instance_by_name('8086.SMBUS.CMD', self.instance)

    def enable(self):
        self.logger.log_hal("[SMBUS] Enabling SMBus...")
        if not self.is_SMBus_host_controller_enabled():
            self.logger.log_hal("SMBus disabled; enabling...")
            self.enable_SMBus_host_controller()
        if self.i2c_mode is True:
            self.logger.log_hal("i2c mode is selected")
            if not self.is_pch_i2c_enabled():
                self.logger.log_hal("Intel PCH is not enabled to communicate with i2c devices; enabling...")
                self.enable_pch_i2c_comm()
        else:
            self.logger.log_hal("SMBUS mode is selected. disabling i2c mode")
            if self.is_pch_i2c_enabled():
                self.logger.log_hal("Intel PCH is enabled to communicate with i2c devices; disabling...")
                self.disable_pch_i2c_comm()
        if not self.is_SMBus_io_mem_space_enabled():
            self.logger.log_hal("SMBus io/mem space disabled; enabling...")
            self.enable_SMBus_io_mem_space()

        if not self.is_SMBus_host_controller_enabled():
            self.logger.log_hal("[SMBUS] SMBus disabled; enabling...")
            self.enable_SMBus_host_controller()
        self.logger.log_hal("[SMBUS] SMBus enabled attempted")

    def _txn_rw_read(self, target_address):
        self.smb_reg_address.set_value(0x0)
        self.smb_reg_address.set_field('RW', SMBUS_COMMAND_READ)
        hst_sa = self.smb_reg_address.set_field('Address', target_address)
        self.smb_reg_address.write(hst_sa)
        self.smb_reg_address.read()
        self.logger.log_hal(self.smb_reg_address)

    def _txn_rw_write(self, target_address):
        self.smb_reg_address.set_value(0x0)
        self.smb_reg_address.set_field('RW', SMBUS_COMMAND_WRITE)
        hst_sa = self.smb_reg_address.set_field('Address', target_address)
        self.smb_reg_address.write(hst_sa)

    def get_SMBus_Base_Address(self):
        if self.cs.hals.IOBAR.is_IO_BAR_defined('8086.SMBUS.SMBUS_BASE'):
            (sba_base, _) = self.cs.hals.IOBAR.get_IO_BAR_base_address('8086.SMBUS.SMBUS_BASE', self.instance)
            return sba_base
        else:
            raise IOBARNotFoundError('IOBARAccessError: SMBUS_BASE')

    def display_SMBus_info(self):
        self.logger.log(f"[smbus] SMBus Base Address: 0x{self.get_SMBus_Base_Address():04X}")
        self.smb_hcfg.read()
        self.logger.log(self.smb_hcfg)

    def is_SMBus_enabled(self):
        return self.cs.device.get_bus('8086.SMBUS')

    def is_SMBus_supported(self):
        if self.cs.device.get_bus('8086.SMBUS') is not None:
            return True
        else:
            return False

    def is_SMBus_host_controller_enabled(self):
        return self.smb_hcfg.get_field("HST_EN") == 1

    def is_pch_i2c_enabled(self):
        return ((self.smb_hcfg.read() & 4) >> 2) == 1

    def is_SMBus_io_mem_space_enabled(self):
        cmd = self.smb_cmd.read()
        self.logger.log_hal(self.smb_cmd)
        return (cmd & 0x3) == 0x3

    def enable_SMBus_host_controller(self):
        # Enable SMBus Host Controller Interface in HCFG
        reg_value = self.smb_hcfg.read()
        if 0 == (reg_value & 0x1):
            self.smb_hcfg.write(reg_value | 0x1)

    def disable_pch_i2c_comm(self):
        # Disable PCH connection to I2c devices
        reg_value = self.smb_hcfg.read()
        if not 0 == (reg_value & 0x04):
            self.smb_hcfg.write(reg_value & ~ 0x4)
        reg_value = self.smb_hcfg.read()
        if not 0 == (reg_value & 0x04):
            self.logger.log("PCH is enabled to connect with i2c devices")
        else:
            self.logger.log("PCH is disabled to connect with i2c devices")

    def enable_pch_i2c_comm(self):
        # Enable PCH connection to I2c devices
        reg_value = self.smb_hcfg.read()
        if 0 == (reg_value & 0x04):
            self.smb_hcfg.write(reg_value | 0x05)
        reg_value = self.smb_hcfg.read()
        if not 0 == (reg_value & 0x04):
            self.logger.log("PCH is enabled to connect with i2c devices")
        else:
            self.logger.log("PCH is not enabled to connect with i2c devices")

    def enable_SMBus_io_mem_space(self):
        # @TODO: check SBA is programmed
        # sba = self.get_SMBus_Base_Address()
        # Enable SMBus I/O Space
        cmd = self.smb_cmd.read()
        if 0 == (cmd & 0x1):
            self.smb_cmd.write(cmd | 0x1)

    def reset_SMBus_controller(self):
        reg_value = self.smb_hcfg.read()
        self.smb_hcfg.write(reg_value | 0x08)
        for _ in range(SMBUS_POLL_COUNT):
            if (self.smb_hcfg.read() & 0x08) == 0:
                return True
        return False

    # waits for SMBus to become ready
    def _is_smbus_ready(self):
        for i in range(SMBUS_POLL_COUNT):
            self.smb_reg_status.read()
            self.logger.log_hal(f"Status: 0x{self.smb_reg_status.value:X}")
            busy = self.smb_reg_status.get_field('BUSY')
            if 1 == busy:
                self.logger.log_hal("SMBus busy, waiting...")
                continue
            self.smb_reg_status.write(0xFF)
            break
        return 0 == busy

    # waits for SMBus transaction to complete
    def _wait_for_cycle(self):
        for i in range(SMBUS_POLL_COUNT):
            self.smb_reg_status.read()
            busy = self.smb_reg_status.get_field('BUSY')
            failed = self.smb_reg_status.get_field('FAILED')
            if 1 == busy:
                self.logger.log_hal("SMBus busy, waiting...")
                continue
            elif 1 == failed:
                self.logger.log_hal("SMBus transaction failed (FAILED/ERROR bit = 1)")
                reg_value = self.smb_hcfg.read()
                self.smb_hcfg.write(reg_value | 0x08)
                return False

            if self.cs.register.has_field(self.smb_reg_status.name, 'DEV_ERR'):
                if 1 == self.smb_reg_status.get_field('DEV_ERR'):
                    self.logger.log_hal("SMBus device error (invalid cmd, unclaimed cycle or time-out error)")
                    reg_value = self.smb_hcfg.read()
                    self.smb_hcfg.write(reg_value | 0x08)
                    return False
            if self.cs.register.has_field(self.smb_reg_status.name, 'BUS_ERR'):
                if 1 == self.smb_reg_status.get_field('BUS_ERR'):
                    self.logger.log_hal("SMBus bus error")
                    reg_value = self.smb_hcfg.read()
                    self.smb_hcfg.write(reg_value | 0x08)
                    return False
            break
        return (0 == busy)

    #
    # SMBus commands
    #
    def quick_write(self, target_address):
        ret_code = False
        if not self._is_smbus_ready():
            return ret_code

        self.logger.log_verbose(f"[smbus] quick write to device {target_address:X}")

        # clear status bits
        self.smb_reg_status.write(0xFF)
        # SMBus txn RW direction = Write, SMBus slave address = target_address
        self._txn_rw_write(target_address)

        # command = Byte Data
        self.smb_reg_control.write_field('SMB_CMD', SMBUS_COMMAND_QUICK)
        self.smb_reg_control.read()

        # send SMBus txn
        self.smb_reg_control.write_field('START', 1)
        self.smb_reg_control.read()

        # wait for cycle to complete
        ret_code = self._wait_for_cycle()
        # clear status bits
        self.smb_reg_data0.write(0x0)
        self.smb_reg_data0.read()
        self.logger.log_hal(f"[smbus] quick write to device {target_address:X} returned {str(ret_code)}")
        return ret_code

    def read_byte(self, target_address, offset):
        if not self._is_smbus_ready():
            self.logger.log(f"[smbus] controller is not ready {target_address:X}")
            return False

        # clear status bits
        self.smb_reg_status.write(0xFF)

        # SMBus txn RW direction = Read, SMBus slave address = target_address
        self._txn_rw_read(target_address)

        # command data = byte offset (bus txn address)
        self.smb_reg_command.write_field('DataOffset', offset)
        self.smb_reg_command.read()
        self.logger.log_hal(self.smb_reg_command)

        # command = Byte Data
        self.smb_reg_control.write_field('SMB_CMD', SMBUS_COMMAND_BYTE_DATA)
        self.smb_reg_control.read()

        # send SMBus txn
        self.smb_reg_control.write_field('START', 1)
        self.smb_reg_control.read()
        self.logger.log_hal(self.smb_reg_control)

        # wait for cycle to complete
        if not self._wait_for_cycle():
            return False

        # read the data
        value = self.smb_reg_data0.read()
        self.logger.log_hal(self.smb_reg_data0)
        self.smb_reg_data0.write(0x00)
        self.smb_reg_data0.read()

        self.logger.log_hal(f"[smbus] read device {target_address:X} off {offset:X} = {value:X}")
        return [value]

    def read_word(self, target_address, offset):
        if not self._is_smbus_ready():
            return False

        # clear status bits
        self.smb_reg_status.write(0xFF)
        self.smb_reg_status.read()

        # SMBus txn RW direction = Read, SMBus slave address = target_address
        self._txn_rw_read(target_address)

        # command data = byte offset (bus txn address)
        self.smb_reg_command.write_field('DataOffset', offset)
        self.smb_reg_command.read()
        self.logger.log_hal(self.smb_reg_command)

        # command = Byte Data
        self.smb_reg_control.write_field('SMB_CMD', SMBUS_COMMAND_WORD_DATA)
        self.smb_reg_control.read()

        # send SMBus txn
        self.smb_reg_control.write_field('START', 1)
        self.smb_reg_control.read()
        self.logger.log_hal(self.smb_reg_control)

        # wait for cycle to complete
        if not self._wait_for_cycle():
            return False

        # read the data
        valueL = self.smb_reg_data0.read()
        self.logger.log_hal(self.smb_reg_data0)
        self.smb_reg_data0.write(0x00)
        self.smb_reg_data0.read()
        valueH = self.smb_reg_data1.read()
        self.logger.log_hal(self.smb_reg_data1)
        self.smb_reg_data1.write(0x00)
        self.smb_reg_data1.read()

        self.logger.log_verbose(f"[smbus] read device {target_address:X} off {offset:X} = {valueH:X} {valueL:X}")
        return [valueL, valueH]

    def read_block(self, target_address, command):
        if not self._is_smbus_ready():
            return False

        # clear status bits
        self.smb_reg_status.write(0xFF)
        self.smb_reg_control.write_field('LAST_BYTE', 0)
        self.smb_reg_control.read()

        # SMBus txn RW direction = Read, SMBus slave address = target_address
        self._txn_rw_read(target_address)

        # auxiliary control reg
        self.smb_reg_aux_ctl.write_field('E32B', 1)
        self.smb_reg_aux_ctl.read()
        self.logger.log_hal(self.smb_reg_aux_ctl)

        # command data = byte offset (bus txn address)
        self.smb_reg_command.write_field('DataOffset', command)
        self.smb_reg_command.read()
        self.logger.log_hal(self.smb_reg_command)

        # command = Byte Data
        self.smb_reg_control.write_field('SMB_CMD', SMBUS_COMMAND_BLOCK)
        self.smb_reg_control.read()
        self.logger.log_hal(self.smb_reg_control)

        # send SMBus txn
        self.smb_reg_control.write_field('START', 1)
        self.smb_reg_control.read()
        self.logger.log_hal(self.smb_reg_control)

        # wait for cycle to complete
        if not self._wait_for_cycle():
            return False
        read_list = []
        to_read = self.smb_reg_data0.read()
        if to_read <= 0 or to_read > 32:
            return False

        while to_read:
            read_list.append(self.smb_reg_block_db.read())
            to_read -= 1
        self.smb_reg_control.write_field('LAST_BYTE', 1)
        self.smb_reg_control.read()

        self.smb_reg_data0.write(0x00)
        self.smb_reg_data0.read()

        self.logger.log_verbose(f"[smbus] block read device 0x{target_address:x} off 0x{command:x} = " + " 0x".join(f"{c:02x}" for c in read_list))
        return read_list

    def write_byte(self, target_address, offset, value):
        if not self._is_smbus_ready():
            return False

        # clear status bits
        self.smb_reg_status.write(0xFF)
        self.smb_reg_status.read()

        # SMBus txn RW direction = Write, SMBus slave address = target_address
        self._txn_rw_write(target_address)
        self.smb_reg_address.read()

        # command data = byte offset (bus txn address)
        self.smb_reg_command.write_field('DataOffset', offset)
        self.smb_reg_command.read()

        # write the data
        self.smb_reg_data0.write_field('Data', value)
        self.smb_reg_data0.read()

        # command = Byte Data
        self.smb_reg_control.write_field('SMB_CMD', SMBUS_COMMAND_BYTE_DATA)
        self.smb_reg_control.read()

        # send SMBus txn
        self.smb_reg_control.write_field('START', 1)
        self.smb_reg_control.read()

        # wait for cycle to complete
        if not self._wait_for_cycle():
            return False

        # clear status bits
        self.smb_reg_status.write(0x0)
        self.smb_reg_status.read()

        self.logger.log_verbose(f'[smbus] write to device {target_address:X} off {offset:X} = {value:X}')
        return True

    def write_word(self, target_address, offset, valueH, valueL):
        if not self._is_smbus_ready():
            return False

        # clear status bits
        self.smb_reg_status.write(0xFF)

        # SMBus txn RW direction = Write, SMBus slave address = target_address
        self._txn_rw_write(target_address)
        self.smb_reg_address.read()

        # command data = byte offset (bus txn address)
        self.smb_reg_command.write_field('DataOffset', offset)
        self.smb_reg_command.read()

        # write the data
        self.smb_reg_data0.write_field('Data', valueL)
        self.smb_reg_data0.read()
        self.smb_reg_data1.write_field('Data', valueH)
        self.smb_reg_data1.read()

        # command = Byte Data
        self.smb_reg_control.write_field('SMB_CMD', SMBUS_COMMAND_WORD_DATA)
        self.smb_reg_control.read()

        # send SMBus txn
        self.smb_reg_control.write_field('START', 1)
        self.smb_reg_control.read()

        # wait for cycle to complete
        if not self._wait_for_cycle():
            return False

        # clear status bits
        self.smb_reg_data0.write(0x00)
        self.smb_reg_data0.read()
        self.smb_reg_data1.write(0x00)
        self.smb_reg_data1.read()

        self.logger.log_verbose(f'[smbus] write to device {target_address:X} off {offset:X} = {valueH:X} {valueL:X}')
        return True

    def process_call(self, target_address, offset, valueH, valueL):
        if not self._is_smbus_ready():
            return False

        # clear status bits
        self.smb_reg_status.write(0xFF)

        # SMBus txn RW direction = Write, SMBus slave address = target_address
        self._txn_rw_write(target_address)
        self.smb_reg_address.read()

        # command data = byte offset (bus txn address)
        self.smb_reg_command.write_field('DataOffset', offset)
        self.smb_reg_command.read()

        # write the data
        self.smb_reg_data0.write(valueL)
        self.smb_reg_data0.read()
        self.logger.log_hal(self.smb_reg_data0)
        self.smb_reg_data1.write(valueH)
        self.smb_reg_data1.read()
        self.logger.log_hal(self.smb_reg_data1)

        # command = Byte Data
        self.smb_reg_control.write_field('SMB_CMD', SMBUS_COMMAND_PROCESS_CALL)
        self.smb_reg_control.read()

        # send SMBus txn
        self.smb_reg_control.write_field('START', 1)
        self.smb_reg_control.read()

        # wait for cycle to complete
        if not self._wait_for_cycle():
            return False

        # read the data
        valueL_R = self.smb_reg_data0.read()
        self.logger.log_hal(self.smb_reg_data0)
        valueH_R = self.smb_reg_data1.read()
        self.logger.log_hal(self.smb_reg_data1)

        # clear status bits
        self.smb_reg_data0.write(0x00)
        self.smb_reg_data0.read()
        self.smb_reg_data1.write(0x00)
        self.smb_reg_data1.read()
        self.logger.log_debug(f"[smbus] read device {target_address:X} off {offset:X} = {valueH_R:X} {valueL_R:X}")
        return [valueL_R, valueH_R]


class SMBusMMIO(SMBus):
    def __init__(self, cs):
        super(SMBusMMIO, self).__init__(cs)

    def get_registers(self):
        super(SMBusMMIO, self).get_registers()
        self.smb_reg_status = self.cs.register.get_instance_by_name('8086.SMBUS.HST_STS_MMIO', self.instance)
        self.smb_reg_control = self.cs.register.get_instance_by_name('8086.SMBUS.HST_CNT_MMIO', self.instance)
        self.smb_reg_command = self.cs.register.get_instance_by_name('8086.SMBUS.HST_CMD_MMIO', self.instance)
        self.smb_reg_address = self.cs.register.get_instance_by_name('8086.SMBUS.HST_SLVA_MMIO', self.instance)
        self.smb_reg_data0 = self.cs.register.get_instance_by_name('8086.SMBUS.HST_D0_MMIO', self.instance)
        self.smb_reg_data1 = self.cs.register.get_instance_by_name('8086.SMBUS.HST_D1_MMIO', self.instance)
        self.smb_reg_aux_ctl = self.cs.register.get_instance_by_name('8086.SMBUS.HST_AUX_CTL_MMIO', self.instance)
        self.smb_reg_block_db = self.cs.register.get_instance_by_name('8086.SMBUS.HST_BLOCK_DB_MMIO', self.instance)

    def enable(self) -> None:
        self.logger.log_hal("[SMBUSMMIO] Enabling SMBusMMIO...")
        if not self.is_SMBus_mmio_mem_space_enabled():
            self.logger.log_hal("SMBus mmio space disabled; enabling...")
            self.enable_SMBus_mmio_mem_space()
        else:
            self.logger.log_hal("SMBus mmio space enabled...")
        if not self.is_SMBus_host_controller_enabled():
            self.logger.log_hal("SMBus disabled; enabling...")
            self.enable_SMBus_host_controller()
        if self.i2c_mode is True:
            self.logger.log_hal("i2c mode is selected")
            if not self.is_pch_i2c_enabled():
                self.logger.log_hal("Intel PCH is not enabled to communicate with i2c devices; enabling...")
                self.enable_pch_i2c_comm()
        else:
            self.logger.log_hal("SMBUS mode is selected. disabling i2c mode")
            if self.is_pch_i2c_enabled():
                self.logger.log_hal("Intel PCH is enabled to communicate with i2c devices; disabling...")
                self.disable_pch_i2c_comm()
        if not self.is_SMBus_io_mem_space_enabled():
            self.logger.log_hal("SMBus io/mem space disabled; enabling...")
            self.enable_SMBus_io_mem_space()

        if not self.is_SMBus_host_controller_enabled():
            self.logger.log_hal("SMBus disabled; enabling...")
            self.enable_SMBus_host_controller()
        self.logger.log_hal("[SMBUSMMIO] SMBusMMIO Enabled attempted")

    def is_SMBus_mmio_mem_space_enabled(self):
        cmd = self.smb_cmd.read()
        self.logger.log_hal(self.smb_cmd)
        return (cmd.value & 0x3) == 0x3

    def get_SMBus_mmio_Base_Address(self):
        if self.cs.hals.MMIO.is_MMIO_BAR_defined('8086.SMBUS.SMBUS_MMIOBAR'):
            (smb_mmio_base, _) = self.cs.hals.MMIO.get_MMIO_BAR_base_address('8086.SMBUS.SMBUS_MMIOBAR', self.instance)
            self.logger.log_hal(f"SMBUS MMIO base: 0x{smb_mmio_base:016X} (assuming below 4GB)")
            return smb_mmio_base
        else:
            return False

    def enable_SMBus_mmio_mem_space(self):
        # @TODO: check SBA is programmed
        # sba = self.get_SMBus_mmio_Base_Address()
        # Enable SMBus I/O Space
        cmd = self.smb_cmd.read()
        if 0 == (cmd.value & 0x2):
            self.smb_cmd.write(cmd.value | 0x2)



haldata = {"arch":[hal_base.HALBase.MfgIds.Any], 'name': ['SMBus', 'SMBusMMIO']}
