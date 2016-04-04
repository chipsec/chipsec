from tests.hardware import test_ubuntu

class EliteBook1040UbuntuTest(test_ubuntu.GenericUbuntuTest):

    PRODUCT_NAME = 'HP EliteBook Folio 1040 G1'
    BIOS_VERSION = 'L83 Ver. 01.21'
    PASS = ["chipsec.modules.common.spi_desc",
            "chipsec.modules.common.bios_wp",
            "chipsec.modules.common.spi_lock",
            "chipsec.modules.common.smrr",
            "chipsec.modules.common.smm",
            "chipsec.modules.common.bios_ts",
            "chipsec.modules.common.bios_smi",
            "chipsec.modules.smm_dma",
            "chipsec.modules.remap"]

    SKIPPED = ["chipsec.modules.common.secureboot.variables",
               "chipsec.modules.common.uefi.s3bootscript",
               "chipsec.modules.common.uefi.access_uefispec",
               "chipsec.modules.module_template"]

    def setUp(self):
        super(EliteBook1040UbuntuTest, self).setUp()

    def test_main(self):
        self._generic_main()
