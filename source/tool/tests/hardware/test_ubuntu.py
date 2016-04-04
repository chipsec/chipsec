import os.path
import subprocess

from tests.hardware import test_generic

from chipsec.helper import oshelper

class GenericUbuntuTest(test_generic.GenericHardwareTest):

    SYSTEM = 'Linux'
    DIST = ('Ubuntu', '14.04', 'trusty')

    def setUp(self):
        super(GenericUbuntuTest, self).setUp()
        self.load_driver()

    def tearDown(self):
        self.unload_driver()
        super(GenericUbuntuTest, self).tearDown()

    def load_driver(self):
        subprocess.call(["insmod",
                         os.path.join(os.path.dirname(__file__),
                                      "..", "..", "..",
                                      "drivers", "linux", "chipsec.ko")])

    def unload_driver(self):
        oshelper.helper().helper.close()
        subprocess.call(["rmmod", "chipsec"])

    def product_name(self):
        try:
            product_name = open("/sys/class/dmi/id/product_name").read().strip()
            return product_name
        except:
            return None

    def bios_version(self):
        try:
            bios_version = open("/sys/class/dmi/id/bios_version").read().strip()
            return bios_version
        except:
            return None
