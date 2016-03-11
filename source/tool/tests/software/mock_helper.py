from chipsec.helper import oshelper

class TestHelper(oshelper.Helper):

    def __init__(self):
        self.os_system = "test_helper"
        self.os_release = "0"
        self.os_version = "0"
        self.os_machine = "test"
        self.driver_loaded = True

    def create(self):
        pass

    def start(self):
        pass

    def stop(self):
        pass

     # This will be used to probe the device, fake a Broadwell CPU
    def read_pci_reg(self, bus, device, function, address, size):
        return 0x16008086
