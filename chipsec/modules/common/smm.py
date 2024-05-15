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
Compatible SMM memory (SMRAM) Protection check module
This CHIPSEC module simply reads SMRAMC and checks that D_LCK is set.

Reference:
In 2006, `Security Issues Related to Pentium System Management Mode <http://www.ssi.gouv.fr/archive/fr/sciences/fichiers/lti/cansecwest2006-duflot.pdf>`_ outlined a configuration issue where compatibility SMRAM was not locked on some platforms. This means that ring 0 software was able to modify System Management Mode (SMM) code and data that should have been protected.

In Compatability SMRAM (CSEG), access to memory is defined by the SMRAMC register. When SMRAMC[D_LCK] is not set by the BIOS, SMRAM can be accessed even when the CPU is not in SMM. Such attacks were also described in `Using CPU SMM to Circumvent OS Security Functions <http://fawlty.cs.usfca.edu/~cruse/cs630f06/duflot.pdf>`_ and `Using SMM for Other Purposes <http://phrack.org/issues/65/7.html>`_.

usage:
    ``chipsec_main -m common.smm``

Examples:
    >>> chipsec_main.py -m common.smm

This module will only run on client (core) platforms that have PCI0.0.0_SMRAMC defined.
"""

from chipsec.module_common import BaseModule, MTAG_BIOS, MTAG_SMM
from chipsec.library.returncode import ModuleResult
from typing import List

TAGS = [MTAG_BIOS, MTAG_SMM]


class smm(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self) -> bool:
        if self.cs.is_core() and self.cs.register.is_defined('PCI0.0.0_SMRAMC'):
            return True
        self.logger.log("Either not a Core (client) platform or 'PCI0.0.0_SMRAMC' not defined for platform. Skipping module.")
        return False

    def check_SMRAMC(self) -> int:

        regval = self.cs.register.read('PCI0.0.0_SMRAMC')
        g_smrame = self.cs.register.get_field('PCI0.0.0_SMRAMC', regval, 'G_SMRAME')
        d_open = self.cs.register.get_field('PCI0.0.0_SMRAMC', regval, 'D_OPEN')
        d_lock = self.cs.register.get_field('PCI0.0.0_SMRAMC', regval, 'D_LCK')

        self.cs.register.print('PCI0.0.0_SMRAMC', regval)

        if 1 == g_smrame:
            self.logger.log("[*] Compatible SMRAM is enabled")
            # When D_LCK is set HW clears D_OPEN so generally no need to check for D_OPEN but doesn't hurt double checking
            if (1 == d_lock) and (0 == d_open):
                res = ModuleResult.PASSED
                self.logger.log_passed("Compatible SMRAM is locked down")
            else:
                res = ModuleResult.FAILED
                self.logger.log_failed("Compatible SMRAM is not properly locked. Expected ( D_LCK = 1, D_OPEN = 0 )")
                self.result.setStatusBit(self.result.status.LOCKS)
        else:
            res = ModuleResult.NOTAPPLICABLE
            self.result.setStatusBit(self.result.status.FEATURE_DISABLED)
            self.logger.log("[*] Compatible SMRAM is not enabled. Skipping..")

        return self.result.getReturnCode(res)

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test("Compatible SMM memory (SMRAM) Protection")
        self.res = self.check_SMRAMC()
        return self.res
