#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
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
#
import os
import platform
import tempfile
import unittest

import chipsec_main
from chipsec import logger


class GenericHardwareTest(unittest.TestCase):

    BOOT_MODE_LEGACY = 1
    BOOT_MODE_UEFI = 2

    def setUp(self):
        if hasattr(self, "SYSTEM") and platform.system() != self.SYSTEM:
            self.skipTest("Unsupported system {}".format(self.SYSTEM))

        if hasattr(self, "DIST") and platform.dist() != self.DIST:
            self.skipTest("Unsupported distribution {}".format(self.DIST))

        if (hasattr(self, "PRODUCT_NAME") and
                self.product_name() != self.PRODUCT_NAME):
            self.skipTest("Unsupported platform {}".format(self.PRODUCT_NAME))

        if (hasattr(self, "BIOS_VERSION") and
                self.bios_version() != self.BIOS_VERSION):
            self.skipTest("Unsupported BIOS version "
                          "{}".format(self.BIOS_VERSION))

        if hasattr(self, "BOOT_MODE") and self.boot_mode() != self.BOOT_MODE:
            self.skipTest("Unsupported boot type {}".format(self.BOOT_MODE))
        _, self.log_file = tempfile.mkstemp()

    def tearDown(self):
        os.remove(self.log_file)

    def _generic_main(self):
        cm = chipsec_main.ChipsecMain(["-l", self.log_file])
        error_code = cm.main()
        logger.logger().close()
        self.log = open(self.log_file).read()
        self.assertLessEqual(error_code, 31,
                             "At least one test raised an error")
        for test in self.PASS:
            self.assertIn("PASSED: {}".format(test), self.log)
        for test in self.SKIPPED:
            self.assertIn("SKIPPED: {}".format(test), self.log)
