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

    def create(self):
        pass

    def start(self):
        pass

    def stop(self):
        pass

     # This will be used to probe the device, fake a Broadwell CPU
    def read_pci_reg(self, bus, device, function, address, size):
        if (bus, device, function) == (0, 0, 0):
            return 0x16008086
        else:
            raise Exception("Unexpected PCI read")

class SPIHelper(TestHelper):
    """Generic SPI emulation

    Two regions are defined:
      * The flash descriptor [0x1000, 0x1FFF]
      * The BIOS image [0x2000, 0x2FFF]
    """
    RCBA_ADDR = 0xFED0000
    SPIBAR_ADDR = RCBA_ADDR + 0x3800
    SPIBAR_END = SPIBAR_ADDR + 0x200
    FRAP = SPIBAR_ADDR + 0x50
    FREG0 = SPIBAR_ADDR + 0x54
    LPC_BRIDGE_DEVICE = (0, 0x1F, 0)

    def read_pci_reg(self, bus, device, function, address, size):
        if (bus, device, function) == self.LPC_BRIDGE_DEVICE:
            if address == 0xF0:
                return self.RCBA_ADDR
            elif address == 0xDC:
                return 0xDEADBEEF
            else:
                raise Exception("Unexpected PCI read")
        else:
            return super(SPIHelper, self).read_pci_reg(bus, device,
                                                       function,
                                                       address, size)

    def read_mmio_reg(self, pa, size):
        if pa == self.FREG0:
            return 0x00010001
        elif pa == self.FREG0 + 4:
            return 0x00020002
        elif pa == self.FRAP:
            return 0xEEEEEEEE
        elif pa >= self.SPIBAR_ADDR and pa < self.SPIBAR_END:
            return 0x0
        else:
            raise Exception("Unexpected address")

    def write_mmio_reg(self, pa, size, value):
        if pa < self.SPIBAR_ADDR or pa > self.SPIBAR_END:
            raise Exception("Write to outside of SPIBAR")
