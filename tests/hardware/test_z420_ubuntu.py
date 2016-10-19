from tests.hardware import test_ubuntu


class Z420UbuntuTest(test_ubuntu.GenericUbuntuTest):

    PRODUCT_NAME = 'HP Z420 Workstation'
    BIOS_VERSION = 'J61 v03.88'
    BOOT_MODE = test_ubuntu.GenericUbuntuTest.BOOT_MODE_LEGACY
    PASS = [
        "chipsec.modules.common.bios_smi",
        "chipsec.modules.common.bios_ts",
        "chipsec.modules.common.bios_wp",
        "chipsec.modules.common.secureboot.variables",
        "chipsec.modules.common.smrr",
        "chipsec.modules.common.spi_desc",
        "chipsec.modules.common.spi_lock"
    ]

    # This platform does not support the following tests
    SKIPPED = [
        "chipsec.modules.common.smm",
        "chipsec.modules.remap",
        "chipsec.modules.smm_dma"
    ]

    def test_main(self):
        self._generic_main()
