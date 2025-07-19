# CHIPSEC: Platform Security Assessment Framework
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
#
import os.path

from tests.hardware import test_generic


class GenericUbuntuTest(test_generic.GenericHardwareTest):

    SYSTEM = 'Linux'
    DIST = ('Ubuntu', '16.04', 'xenial')

    PRODUCT_NAME_PATH = "/sys/class/dmi/id/product_name"
    BIOS_VERSION_PATH = "/sys/class/dmi/id/bios_version"
    BOOT_MODE_PATH = "/sys/firmware/efi"

    def product_name(self):
        try:
            product_name = open(self.PRODUCT_NAME_PATH).read().strip()
            return product_name
        except IOError:
            return None

    def bios_version(self):
        try:
            bios_version = open(self.BIOS_VERSION_PATH).read().strip()
            return bios_version
        except IOError:
            return None

    def boot_mode(self):
        """Check if the current boot method is UEFI or Legacy"""
        if os.path.isdir(self.BOOT_MODE_PATH):
            return self.BOOT_MODE_UEFI
        else:
            return self.BOOT_MODE_LEGACY
