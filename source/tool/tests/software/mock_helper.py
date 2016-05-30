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

class ACPIHelper(TestHelper):
    """Generic ACPI emulation

    Emulates an RSDP that points to an RSDT by default.

    An XSDT is also provided.

    The provided RSDT and XSDT will contain the entries specified
    in RSDT_ENTRIES and XSDT_ENTRIES.

    RSDP will be placed inside EBDA which by default is located
    at 0x96000. In particular, RSDP can be found in 0x96100.

    Three regions are defined:
      * RSDP table [0x96100, 0x96114] or [0x96100, 0x96124]
      * XSDT table [0x100, 0x124 + 8 * len(XSDT_ENTRIES)]
      * RSDT table [0x200, 0x224 + 4 * len(RSDT_ENTRIES)]
    """
    USE_RSDP_REV_0 = True

    EBDA_ADDRESS = 0x96000
    EBDA_PADDING = 0x100
    RSDP_ADDRESS = EBDA_ADDRESS + EBDA_PADDING

    XSDT_ADDRESS = 0x100
    RSDT_ADDRESS = 0x200

    def _create_rsdp(self):
        rsdp = None
        if self.USE_RSDP_REV_0:
            # Emulate initial version of RSDP described in ACPI v1.0
            rsdp = ("RSD PTR " +                            # Signature
                    struct.pack("<B", 0x1) +                # Checksum
                    "TEST00" +                              # OEMID
                    struct.pack("<B", 0x0) +                # Revision
                    struct.pack("<I", self.RSDT_ADDRESS))   # RSDT Address
        else:
            # Emulate RSDP described in ACPI v2.0 onwards
            rsdp = ("RSD PTR " +                            # Signature
                    struct.pack("<B", 0x1) +                # Checksum
                    "TEST00" +                              # OEMID
                    struct.pack("<B", 0x2) +                # Revision
                    struct.pack("<I", self.RSDT_ADDRESS) +  # RSDT Address
                    struct.pack("<I", 0x24) +               # Length
                    struct.pack("<Q", self.XSDT_ADDRESS) +  # XSDT Address
                    struct.pack("<B", 0x0) +                # Extended Checksum
                    "AAA")                                  # Reserved
        return rsdp

    def _create_generic_acpi_table_header(self, signature, length):
        return (signature +                 # Signature
                struct.pack("<I", length) + # Length
                struct.pack("<B", 0x1) +    # Revision
                struct.pack("<B", 0x1) +    # Checksum
                "OEMIDT" +                  # OEMID
                "OEMTBLID" +                # OEM Table ID
                "OEMR" +                    # OEM Revision
                "CRID" +                    # Creator ID
                "CRRV")                     # Creator Revision

    def _create_rsdt(self):
        rsdt_length = 36 + 4 * len(self.rsdt_entries) # 36 : ACPI table header size
        rsdt = self._create_generic_acpi_table_header("RSDT", rsdt_length)
        for rsdt_entry in self.rsdt_entries:
            rsdt += struct.pack("<I", rsdt_entry)
        return rsdt

    def _create_xsdt(self):
        xsdt_length = 36 + 8 * len(self.xsdt_entries) # 36 : ACPI table header size
        xsdt = self._create_generic_acpi_table_header("XSDT", xsdt_length)
        for xsdt_entry in self.xsdt_entries:
            xsdt += struct.pack("<Q", xsdt_entry)
        return xsdt

    def _add_entry_to_rsdt(self, entry):
        self.rsdt_entries.append(entry)
        self.rsdt_descriptor = self._create_rsdt()

    def _add_entry_to_xsdt(self, entry):
        self.xsdt_entries.append(entry)
        self.xsdt_descriptor = self._create_xsdt()

    def __init__(self):
        super(ACPIHelper, self).__init__()
        self.rsdt_entries = []
        self.xsdt_entries = []
        self.rsdp_descriptor = self._create_rsdp()
        self.rsdt_descriptor = self._create_rsdt()
        self.xsdt_descriptor = self._create_xsdt()

    def read_phys_mem(self, pa_hi, pa_lo, length):
        if pa_lo == 0x40E:
            return struct.pack("<H", self.EBDA_ADDRESS >> 4)
        elif pa_lo >= self.EBDA_ADDRESS and \
            pa_lo < self.RSDP_ADDRESS + len(self.rsdp_descriptor):
            mem = "\x00" * self.EBDA_PADDING + self.rsdp_descriptor
            offset = pa_lo - self.EBDA_ADDRESS
            return mem[offset:offset+length]
        elif pa_lo == self.RSDT_ADDRESS:
            return self.rsdt_descriptor[:length]
        elif pa_lo == self.XSDT_ADDRESS:
            return self.xsdt_descriptor[:length]
        else:
            return "\xFF" * length

class DSDTParsingHelper(ACPIHelper):
    """Test helper containing generic descriptor for RSDP, RSDT, and FADT to parse DSDT

    Default entry for DSDT and X_DSDT inside FADT is 0x0

    One additional region is defined:
      * FADT table [0x400, 0x514]
    """
    USE_FADT_WITH_X_DSDT = True

    FADT_ADDRESS = 0x400
    DSDT_ADDRESS = 0x0
    X_DSDT_ADDRESS = 0x0

    def _add_fadt_to_sdt_entries(self):
        if self.USE_RSDP_REV_0:
            self._add_entry_to_rsdt(self.FADT_ADDRESS)
        else:
            self._add_entry_to_xsdt(self.FADT_ADDRESS)

    def _create_fadt(self):
        fadt = ""
        if self.USE_FADT_WITH_X_DSDT:
            fadt = self._create_generic_acpi_table_header("FACP", 0x10C)
            fadt += struct.pack("<I", 0x500)                # Address of FACS
            fadt += struct.pack("<I", self.DSDT_ADDRESS)    # 32-bit address of DSDT
            fadt += struct.pack("<B", 0x1) * 96             # Bits between DSDT and X_DSDT
            fadt += struct.pack("<Q", self.X_DSDT_ADDRESS)  # X_DSDT
            fadt += struct.pack("<B", 0x1) * 120            # Remaining fields
        else:
            fadt = self._create_generic_acpi_table_header("FACP", 0x74)
            fadt += struct.pack("<I", 0x500)                # Address of FACS
            fadt += struct.pack("<I", self.DSDT_ADDRESS)    # 32-bit address of DSDT
            fadt += struct.pack("<B", 0x1) * 72             # Remaining fields
        return fadt

    def __init__(self):
        super(DSDTParsingHelper, self).__init__()
        self._add_fadt_to_sdt_entries()
        self.fadt_descriptor = self._create_fadt()

    def read_phys_mem(self, pa_hi, pa_lo, length):
        if pa_lo == self.FADT_ADDRESS:
            return self.fadt_descriptor[:length]
        else:
            return super(DSDTParsingHelper, self).read_phys_mem(pa_hi, pa_lo, length)

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
