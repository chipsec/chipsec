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
from chipsec.hal import iobar, hal_base
from chipsec.library.exceptions import IOBARNotFoundError, RegisterNotFoundError

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
        self.iobar = iobar.IOBAR(self.cs)
        self.smb_reg_status = 'SMBUS_HST_STS'
        self.smb_reg_command = 'SMBUS_HST_CMD'
        self.smb_reg_address = 'SMBUS_HST_SLVA'
        self.smb_reg_control = 'SMBUS_HST_CNT'
        self.smb_reg_data0 = 'SMBUS_HST_D0'
        self.smb_reg_data1 = 'SMBUS_HST_D1'

    def get_SMBus_Base_Address(self) -> int:
        if self.iobar.is_IO_BAR_defined('SMBUS_BASE'):
            (sba_base, _) = self.iobar.get_IO_BAR_base_address('SMBUS_BASE')
            return sba_base
        else:
            raise IOBARNotFoundError('IOBARAccessError: SMBUS_BASE')

    def get_SMBus_HCFG(self) -> int:
        if self.cs.register.is_defined('SMBUS_HCFG'):
            reg_value = self.cs.register.read('SMBUS_HCFG')
            if self.logger.HAL:
                self.cs.register.print('SMBUS_HCFG', reg_value)
            return reg_value
        else:
            raise RegisterNotFoundError('RegisterNotFound: SMBUS_HCFG')

    def display_SMBus_info(self) -> None:
        self.logger.log_hal(f'[smbus] SMBus Base Address: 0x{self.get_SMBus_Base_Address():04X}')
        self.get_SMBus_HCFG()

    def is_SMBus_enabled(self) -> bool:
        return self.cs.device.is_enabled('SMBUS')

    def is_SMBus_supported(self) -> bool:
        (did, vid) = self.cs.device.get_VendorID('SMBUS')
        self.logger.log_hal(f'[smbus] SMBus Controller (DID,VID) = (0x{did:04X},0x{vid:04X})')
        if (0x8086 == vid):
            return True
        else:
            self.logger.log_error(f'Unknown SMBus Controller (DID,VID) = (0x{did:04X},0x{vid:04X})')
            return False

    def is_SMBus_host_controller_enabled(self) -> int:
        hcfg = self.get_SMBus_HCFG()
        return self.cs.register.get_field("SMBUS_HCFG", hcfg, "HST_EN")

    def enable_SMBus_host_controller(self) -> None:
        # Enable SMBus Host Controller Interface in HCFG
        reg_value = self.cs.register.read('SMBUS_HCFG')
        if 0 == (reg_value & 0x1):
            self.cs.register.write('SMBUS_HCFG', (reg_value | 0x1))
        # @TODO: check SBA is programmed
        sba = self.get_SMBus_Base_Address()
        # Enable SMBus I/O Space
        cmd = self.cs.register.read('SMBUS_CMD')
        if 0 == (cmd & 0x1):
            self.cs.register.write('SMBUS_CMD', (cmd | 0x1))

    def reset_SMBus_controller(self) -> bool:
        reg_value = self.cs.register.read('SMBUS_HCFG')
        self.cs.register.write('SMBUS_HCFG', reg_value | 0x08)
        for i in range(SMBUS_POLL_COUNT):
            if (self.cs.register.read('SMBUS_HCFG') & 0x08) == 0:
                return True
        return False

    #
    # SMBus commands
    #

    # waits for SMBus to become ready
    def _is_smbus_ready(self) -> bool:
        busy = None
        for i in range(SMBUS_POLL_COUNT):
            #time.sleep( SMBUS_POLL_SLEEP_INTERVAL )
            busy = self.cs.register.read_field(self.smb_reg_status, 'BUSY')
            if 0 == busy:
                return True
        return 0 == busy

    # waits for SMBus transaction to complete
    def _wait_for_cycle(self) -> bool:
        busy = None
        for i in range(SMBUS_POLL_COUNT):
            #time.sleep( SMBUS_POLL_SLEEP_INTERVAL )
            sts = self.cs.register.read(self.smb_reg_status)
            busy = self.cs.register.get_field(self.smb_reg_status, sts, 'BUSY')
            intr = self.cs.register.get_field(self.smb_reg_status, sts, 'INTR')
            failed = self.cs.register.get_field(self.smb_reg_status, sts, 'FAILED')
            if 0 == busy and 1 == intr:
                # if self.logger.HAL:
                #    intr = chipsec.chipset.get_register_field( self.cs, self.smb_reg_status, sts, 'INTR' )
                #    self.logger.log( "[smbus]: INTR = {:d}".format(intr) )
                break
            elif 1 == failed:
                #kill = 0
                # if chipsec.chipset.register_has_field( self.cs, self.smb_reg_control, 'KILL' ):
                #    kill = chipsec.chipset.read_register_field( self.cs, self.smb_reg_control, 'KILL' )
                if self.logger.HAL:
                    self.logger.log_error("SMBus transaction failed (FAILED/ERROR bit = 1)")
                return False
            else:
                if self.cs.register.has_field(self.smb_reg_status, 'DEV_ERR'):
                    if 1 == self.cs.register.get_field(self.smb_reg_status, sts, 'DEV_ERR'):
                        if self.logger.HAL:
                            self.logger.log_error("SMBus device error (invalid cmd, unclaimed cycle or time-out error)")
                        return False
                if self.cs.register.has_field(self.smb_reg_status, 'BUS_ERR'):
                    if 1 == self.cs.register.get_field(self.smb_reg_status, sts, 'BUS_ERR'):
                        if self.logger.HAL:
                            self.logger.log_error("SMBus bus error")
                        return False
        return 0 == busy

    def read_byte(self, target_address: int, offset: int) -> int:
        # clear status bits
        self.cs.register.write(self.smb_reg_status, 0xFF)

        # SMBus txn RW direction = Read, SMBus slave address = target_address
        hst_sa = 0x0
        hst_sa = self.cs.register.set_field(self.smb_reg_address, hst_sa, 'RW', SMBUS_COMMAND_READ)
        hst_sa = self.cs.register.set_field(self.smb_reg_address, hst_sa, 'Address', target_address, True)
        self.cs.register.write(self.smb_reg_address, hst_sa)
        # command data = byte offset (bus txn address)
        self.cs.register.write_field(self.smb_reg_command, 'DataOffset', offset)
        # command = Byte Data
        # if self.cs.register.has_field( self.smb_reg_control, 'SMB_CMD' ):
        self.cs.register.write_field(self.smb_reg_control, 'SMB_CMD', SMBUS_COMMAND_BYTE_DATA)
        # send SMBus txn
        self.cs.register.write_field(self.smb_reg_control, 'START', 1)

        # wait for cycle to complete
        if not self._wait_for_cycle():
            return 0xFF
        # read the data
        value = self.cs.register.read_field(self.smb_reg_data0, 'Data')
        # clear status bits
        self.cs.register.write(self.smb_reg_status, 0xFF)
        # clear address/offset registers
        #chipsec.chipset.write_register( self.cs, self.smb_reg_address, 0x0 )
        #chipsec.chipset.write_register( self.cs, self.smb_reg_command, 0x0 )
        self.logger.log_hal(f'[smbus] read device {target_address:X} off {offset:X} = {value:X}')
        return value

    def write_byte(self, target_address: int, offset: int, value: int) -> bool:
        # clear status bits
        self.cs.register.write(self.smb_reg_status, 0xFF)

        # SMBus txn RW direction = Write, SMBus slave address = target_address
        hst_sa = 0x0
        hst_sa = self.cs.register.set_field(self.smb_reg_address, hst_sa, 'RW', SMBUS_COMMAND_WRITE)
        hst_sa = self.cs.register.set_field(self.smb_reg_address, hst_sa, 'Address', target_address, True)
        self.cs.register.write(self.smb_reg_address, hst_sa)
        # command data = byte offset (bus txn address)
        self.cs.register.write_field(self.smb_reg_command, 'DataOffset', offset)
        # write the data
        self.cs.register.write_field(self.smb_reg_data0, 'Data', value)
        # command = Byte Data
        # if self.cs.register.has_field( self.smb_reg_control, 'SMB_CMD' ):
        self.cs.register.write_field(self.smb_reg_control, 'SMB_CMD', SMBUS_COMMAND_BYTE_DATA)
        # send SMBus txn
        self.cs.register.write_field(self.smb_reg_control, 'START', 1)

        # wait for cycle to complete
        if not self._wait_for_cycle():
            return False
        # clear status bits
        self.cs.register.write(self.smb_reg_status, 0xFF)
        # clear address/offset registers
        #chipsec.chipset.write_register( self.cs, self.smb_reg_address, 0x0 )
        #chipsec.chipset.write_register( self.cs, self.smb_reg_command, 0x0 )
        self.logger.log_hal(f'[smbus] write to device {target_address:X} off {offset:X} = {value:X}')
        return True

    def read_range(self, target_address: int, start_offset: int, size: int) -> bytes:
        buffer = bytes(self.read_byte(target_address, start_offset + i) for i in range(size))
        self.logger.log_hal(f'[smbus] reading {size:d} bytes from device 0x{target_address:X} at offset {start_offset:X}')
        return buffer

    def write_range(self, target_address: int, start_offset: int, buffer: bytes) -> bool:
        for i, b in enumerate(buffer):
            self.write_byte(target_address, start_offset + i, b)
        self.logger.log_hal(f'[smbus] writing {size:d} bytes to device 0x{target_address:X} at offset {start_offset:X}')
        return True
