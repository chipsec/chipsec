# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2018, Eclypsium, Inc.
# Copyright (c) 2019-2021, Intel Corporation
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

"""
This module checks that ME Manufacturing mode is not enabled.

References:

https://blog.ptsecurity.com/2018/10/intel-me-manufacturing-mode-macbook.html

`PCI_DEVS.H <https://github.com/coreboot/coreboot/blob/master/src/soc/intel/*/include/soc/pci_devs.h>`_

.. code-block::

    #define PCH_DEV_SLOT_CSE        0x16
    #define  PCH_DEVFN_CSE          _PCH_DEVFN(CSE, 0)
    #define  PCH_DEV_CSE            _PCH_DEV(CSE, 0)

https://github.com/coreboot/coreboot/blob/master/src/soc/intel/apollolake/cse.c

.. code-block::

    fwsts1 = dump_status(1, PCI_ME_HFSTS1);
    # Minimal decoding is done here in order to call out most important
    # pieces. Manufacturing mode needs to be locked down prior to shipping
    # the product so it's called out explicitly.
    printk(BIOS_DEBUG, "ME: Manufacturing Mode      : %s", (fwsts1 & (1 << 0x4)) ? "YES" : "NO");

`PCH.H <https://github.com/coreboot/coreboot/blob/master/src/southbridge/intel/*/pch.h>`_

.. code-block::

    #define PCH_ME_DEV                PCI_DEV(0, 0x16, 0)

`ME.H <https://github.com/coreboot/coreboot/blob/master/src/southbridge/intel/*/me.h>`_

.. code-block::

    struct me_hfs {
            u32 working_state: 4;
            u32 mfg_mode: 1;
            u32 fpt_bad: 1;
            u32 operation_state: 3;
            u32 fw_init_complete: 1;
            u32 ft_bup_ld_flr: 1;
            u32 update_in_progress: 1;
            u32 error_code: 4;
            u32 operation_mode: 4;
            u32 reserved: 4;
            u32 boot_options_present: 1;
            u32 ack_data: 3;
            u32 bios_msg_ack: 4;
    } __packed;

`ME_STATUS.C <https://github.com/coreboot/coreboot/blob/master/src/southbridge/intel/*/me_status.c>`_

.. code-block::

     printk(BIOS_DEBUG, "ME: Manufacturing Mode      : %s", hfs->mfg_mode ? "YES" : "NO");

This module checks the following:

    ``HFS.MFG_MODE BDF: 0:22:0 offset 0x40 - Bit [4]``

Usage:
    ``chipsec_main -m common.me_mfg_mode``

Examples:
    >>> chipsec_main.py -m common.me_mfg_mode

The module returns the following results:

    FAILED : HFS.MFG_MODE is set

    PASSED : HFS.MFG_MODE is not set.

Hardware registers used:
    - HFS.MFG_MODE
"""

from chipsec.module_common import BaseModule
from chipsec.library.returncode import ModuleResult
from typing import List


class me_mfg_mode(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self) -> bool:
        if self.cs.device.is_enabled("MEI1"):
            return True
        else:
            self.logger.log_important('MEI1 not enabled.  Skipping module.')
            return False

    def check_me_mfg_mode(self) -> int:
        me_mfg_mode_res = ModuleResult.FAILED
        me_hfs_reg = self.cs.register.read('HFS')
        me_mfg_mode = self.cs.register.get_field('HFS', me_hfs_reg, 'MFG_MODE')

        if 0 == me_mfg_mode:
            me_mfg_mode_res = ModuleResult.PASSED
            self.logger.log_passed("ME is not in Manufacturing Mode")
        else:
            self.logger.log_failed("ME is in Manufacturing Mode")
            self.result.setStatusBit(self.result.status.POTENTIALLY_VULNERABLE)

        return self.result.getReturnCode(me_mfg_mode_res)


    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test("ME Manufacturing Mode")
        self.res = self.check_me_mfg_mode()
        return self.res
