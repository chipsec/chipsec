import os.path
import subprocess

from tests.hardware import test_generic

from chipsec.helper import oshelper


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
