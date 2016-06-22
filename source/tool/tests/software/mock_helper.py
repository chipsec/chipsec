from chipsec.helper import oshelper

class TestHelper(oshelper.Helper):
    """Default test helper that emulates a Broadwell architecture.

    See datasheet for registers definition:
    http://www.intel.com/content/www/us/en/chipsets/9-series-chipset-pch-datasheet.html
    """

    def __init__(self):
        self.os_system = "test_helper"
        self.os_release = "0"
        self.os_version = "0"
        self.os_machine = "test"
        self.driver_loaded = True

    def create(self, start_driver):
        pass

    def start(self, start_driver):
        pass

    def stop(self):
        pass

     # This will be used to probe the device, fake a Broadwell CPU
    def read_pci_reg(self, bus, device, function, address, size):
        if (bus, device, function) == (0, 0, 0):
            return 0x16008086
        else:
            raise Exception("Unexpected PCI read")
