# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2024, AMD Corporation
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
# chipsec@amd.com
#

"""
"""

import time
from chipsec.library.logger import logger


class PSP:
    SMN_INDEX_ADDR = 0xb8
    SMN_DATA_ADDR = 0xbc
    SMU_PSP_SMN_BASE = 0x3800000
    SMU_PSP_MBOX_CMD_STATUS = SMU_PSP_SMN_BASE + 0x00010970
    SMU_PSP_MBOX_CMD_BUF_LO = SMU_PSP_SMN_BASE + 0x00010974
    SMU_PSP_MBOX_CMD_BUF_HI = SMU_PSP_SMN_BASE + 0x00010978
    PSP_CMD_GET_CAPABILITIES = 0x27
    PSP_CMD_GET_HSTI_STATE = 0x14
    TIMEOUT = 5

    def __init__(self, cs):
        self.cs = cs
        self.helper = cs.helper

    def smu_read32(self, reg):
        self.cs.pci.write_dword(0, 0, 0, self.SMN_INDEX_ADDR, reg)
        return self.cs.pci.read_dword(0, 0, 0, self.SMN_DATA_ADDR)

    def smu_write32(self, reg, val):
        self.cs.pci.write_dword(0, 0, 0, self.SMN_INDEX_ADDR, reg)
        return self.cs.pci.write_dword(0, 0, 0, self.SMN_DATA_ADDR, val)

    def psp_mbox_command(self, cmd):
        #  Command ID (bits [23:16]), Status (bits [15:0]) fields and Ready flag (bit #31)
        mbox_cmd_status_value = 0
        dword_size = 4
        num_buf = 4  # TODO: Build a table for each command
        buf_size = num_buf * dword_size  # TODO: Build a table for each command
        cmd = self.PSP_CMD_GET_HSTI_STATE

        # Todo: Add Reset and Recovery checks

        # poll for mailbox ready
        start_time = time.time()
        timeout = False
        while (True):
            mbox_cmd_status_value = self.smu_read32(self.SMU_PSP_MBOX_CMD_STATUS)
            timeout = (time.time() - start_time > self.TIMEOUT)
            if ((mbox_cmd_status_value & 0x80000000) or timeout):
                break

        if (timeout):
            logger().log_bad(f'Timeout polling for PSP Mailbox Ready (Idle)')
            return [0xbaddbadd]

        (buf_va, buf_pa) = self.helper.alloc_phys_mem(buf_size, 0x1000_0000_0000)

        # send physical address for msg buffer
        self.smu_write32(self.SMU_PSP_MBOX_CMD_BUF_LO, buf_pa & 0xFFFFFFFF)
        self.smu_write32(self.SMU_PSP_MBOX_CMD_BUF_HI, (buf_pa >> 32) & 0xFFFFFFFF)

        # send command
        mbox_cmd_status_value = (cmd << 16) & 0x00ff0000
        self.smu_write32(self.SMU_PSP_MBOX_CMD_STATUS, mbox_cmd_status_value)

        # poll command
        start_time = time.time()
        timeout = False

        while (True):
            mbox_cmd_status_value = self.smu_read32(self.SMU_PSP_MBOX_CMD_STATUS)
            timeout = (time.time() - start_time > self.TIMEOUT)
            if ((mbox_cmd_status_value & 0x80000000) or timeout):
                break

        if (timeout):
            logger().log_bad(f'Timeout polling for PSP Mailbox Ready (Complete)')
            self.helper.free_phys_mem(buf_va)
            return [0xbaddbadd]

        buffer = []
        for i in range(0, num_buf):
            buffer.append(int.from_bytes(self.helper.read_phys_mem(buf_pa + (i * dword_size), dword_size), 'little'))

        self.helper.free_phys_mem(buf_va)

        return buffer

    def query_HSTI(self) -> int:
        hsti_buffer = self.psp_mbox_command(self.PSP_CMD_GET_HSTI_STATE)
        if (len(hsti_buffer) > 1):
            return hsti_buffer[2]
        else:
            return 0
