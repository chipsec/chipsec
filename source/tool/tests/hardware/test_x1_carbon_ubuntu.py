from tests.hardware import test_ubuntu


class X1CarbonUbuntuTest(test_ubuntu.GenericUbuntuTest):

    PRODUCT_NAME = '20FCS00Y01'
    BIOS_VERSION = 'N1FET34W (1.08 )'
    BOOT_MODE = test_ubuntu.GenericUbuntuTest.BOOT_MODE_UEFI
    PASS = [
        "chipsec.modules.common.bios_smi",
        "chipsec.modules.common.bios_ts",
        "chipsec.modules.common.bios_wp",
        "chipsec.modules.common.secureboot.variables",
        "chipsec.modules.common.smm",
        "chipsec.modules.common.smrr",
        "chipsec.modules.common.spi_desc",
        "chipsec.modules.common.spi_lock",
        "chipsec.modules.common.uefi.access_uefispec",
        "chipsec.modules.remap",
        "chipsec.modules.smm_dma"
    ]

    SKIPPED = []

    def test_main(self):
        self._generic_main()
