import struct

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

class FADTParsingHelper(TestHelper):
    """Test helper containing generic descriptor for RSDP, RSDT, and FADT to parse FADT

    Default entry for DSDT and X_DSDT inside FADT is 0x0

    Three regions are defined:
      * RSDP table [0xE0000, 0xE0014]
      * RSDT table [0x200, 0x228]
      * FADT table [0x400, 0x514]
    """
    RSDP_DESCRIPTOR = ("RSD PTR " +               # Signature
                       struct.pack("<B", 0x1) +   # Checksum
                       "TEST00" +                 # OEMID
                       struct.pack("<B", 0x0) +   # Revision
                       struct.pack("<I", 0x200))  # RSDT Address

    RSDT_DESCRIPTOR = ("RSDT" +                  # Signature
                       struct.pack("<I", 0x28) + # Length
                       struct.pack("<B", 0x1) +  # Revision
                       struct.pack("<B", 0x1) +  # Checksum
                       "OEMIDT" +                # OEMID
                       "OEMTBLID" +              # OEM Table ID
                       "OEMR" +                  # OEM Revision
                       "CRID" +                  # Creator ID
                       "CRRV" +                  # Creator Revision
                       struct.pack("<I", 0x400)) # Address of table

    FADT_DESCRIPTOR = ("FACP" +                       # Signature
                       struct.pack("<I", 0x114) +     # Length
                       struct.pack("<B", 0x1) +       # Revision
                       struct.pack("<B", 0x1) +       # Checksum
                       "OEMIDT" +                     # OEMID
                       "OEMTBLID" +                   # OEM Table ID
                       "OEMR" +                       # OEM Revision
                       "CRID" +                       # Creator ID
                       "CRRV" +                       # Creator Revision
                       struct.pack("<I", 0x500) +     # Address of FACS
                       struct.pack("<I", 0x0) +       # 32-bit address of DSDT
                       struct.pack("<B", 0x1) * 96 +  # Bits between DSDT and X_DSDT
                       struct.pack("<Q", 0x0) +       # X_DSDT
                       struct.pack("<B", 0x1) * 128)  # Remaining fields

    def read_phys_mem(self, pa_hi, pa_lo, length):
        if pa_lo == 0xE0000:
            return self.RSDP_DESCRIPTOR[:length]
        elif pa_lo == 0x200:
            return self.RSDT_DESCRIPTOR[:length]
        elif pa_lo == 0x400:
            return self.FADT_DESCRIPTOR[:length]
        else:
            return "\xFF" * length
