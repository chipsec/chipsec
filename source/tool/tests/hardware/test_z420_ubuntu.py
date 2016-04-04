from tests.hardware import test_ubuntu

class Z420UbuntuTest(test_ubuntu.GenericUbuntuTest):

    PRODUCT_NAME = 'HP Z420 Workstation'
    BIOS_VERSION = 'J61 v03.88'
    PASS = ["chipsec.modules.common.spi_desc",
            "chipsec.modules.common.bios_wp",
            "chipsec.modules.common.spi_lock",
            "chipsec.modules.common.smrr",
            "chipsec.modules.common.bios_ts",
            "chipsec.modules.common.bios_smi"]

    SKIPPED = ["chipsec.modules.common.smm",
               "chipsec.modules.common.secureboot.variables",
               "chipsec.modules.common.uefi.s3bootscript",
               "chipsec.modules.common.uefi.access_uefispec",
               "chipsec.modules.smm_dma",
               "chipsec.modules.remap",
               "chipsec.modules.module_template"]

    def setUp(self):
        super(Z420UbuntuTest, self).setUp()

    def tearDown(self):
        super(Z420UbuntuTest, self).tearDown()

    def test_main(self):
        self._generic_main()
