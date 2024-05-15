"""
This module checks current contents of UEFI firmware ROM or specified firmware image for bad EFI binaries as per the
VirusTotal API. These can be EFI firmware volumes, EFI executable binaries (PEI modules, DXE drivers..) or EFI sections.
The module can find EFI binaries by their UI names, EFI GUIDs, MD5/SHA-1/SHA-256 hashes
or contents matching specified regular expressions.

Important! This module can only detect bad or vulnerable EFI modules based on the file's reputation on VT.

Usage:
    chipsec_main.py -i -m tools.uefi.reputation -a <vt_api_key>[,<vt_threshold>,<fw_image>]
      vt_api_key   : API key to VirusTotal. Can be obtained by visting https://www.virustotal.com/gui/join-us.
                     This argument must be specified.
      vt_threshold : The minimal number of different AV vendors on VT which must claim an EFI module is malicious
                     before failing the test. Defaults to 10.
      fw_image     : Full file path to UEFI firmware image
                     If not specified, the module will dump firmware image directly from ROM

.. note::
    - Requires virustotal-api

"""
import time

from chipsec.module_common import BaseModule, MTAG_BIOS
from chipsec.library.returncode import ModuleResult
from chipsec.hal.spi_uefi import search_efi_tree, build_efi_model, EFIModuleType
from chipsec.hal.uefi import UEFI
from chipsec.hal.spi import SPI, BIOS
from chipsec.library.file import read_file

try:
    from virus_total_apis import PublicApi as VirusTotalPublicApi
    has_virus_total_apis = True
except ImportError:
    has_virus_total_apis = False

TAGS = [MTAG_BIOS]

DEF_FWIMAGE_FILE = 'fw.bin'

USAGE_TEXT = '''
Usage:

    chipsec_main.py -i -m tools.uefi.reputation -a <vt_api_key>[,<vt_threshold>,<fw_image>]

      vt_api_key   : API key to VirusTotal. Can be obtained by visiting https://www.virustotal.com/gui/join-us.
                     This argument must be specified.
      vt_threshold : The minimal number of different AV vendors on VT which must claim an EFI module is bad
                     before failing the test. Defaults to 10.
      fw_image     : Full file path to UEFI firmware image
                     If not specified, the module will dump firmware image directly from ROM
'''


class reputation(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.uefi = UEFI(self.cs)
        self.image = None
        self.vt_threshold = 10
        self.vt = None

    def is_supported(self):
        if has_virus_total_apis:
            return True
        else:
            self.logger.log_important("""Can't import module 'virus_total_apis'.
Please run 'pip install virustotal-api' and try again.""")
            return False

    def reputation_callback(self, efi_module):
        vt_report = self.vt.get_file_report(efi_module.SHA256)

        while vt_report["response_code"] == 204:
            # The Public API is limited to 4 requests per minute.
            if self.logger.DEBUG:
                self.logger.log("VT API quota exceeded, sleeping for 1 minute... (-.-)zzZZ")

            time.sleep(60)
            # Retry.
            vt_report = self.vt.get_file_report(efi_module.SHA256)

        if vt_report["results"]["response_code"] == 0:
            # Hash is unknown to VT.
            self.logger.log_important(f'Unfamiliar EFI binary found in the UEFI firmware image\n{efi_module}')
            return False

        if vt_report["results"]["positives"] >= self.vt_threshold:
            self.logger.log_bad(f'Suspicious EFI binary found in the UEFI firmware image\n{efi_module}')
            return True

        if self.logger.VERBOSE:
            self.logger.log(f'Benign EFI binary found in the UEFI firmware image\n{efi_module}')

        return False

    def check_reputation(self):
        res = ModuleResult.PASSED

        # parse the UEFI firmware image and look for EFI modules matching the blocked-list
        efi_tree = build_efi_model(self.image, None)
        match_types = EFIModuleType.SECTION_EXE
        matching_modules = search_efi_tree(efi_tree, self.reputation_callback, match_types)
        found = len(matching_modules) > 0
        self.logger.log('')
        if found:
            res = ModuleResult.WARNING
            self.logger.log_warning("Suspicious EFI binary found in the UEFI firmware image")
            self.result.setStatusBit(self.result.status.POTENTIALLY_VULNERABLE)
        else:
            self.logger.log_passed("Didn't find any suspicious EFI binary")
        return res

    def usage(self):
        self.logger.log(USAGE_TEXT)

    def run(self, module_argv):
        self.logger.start_test("Check for suspicious EFI binaries in UEFI firmware")

        self.usage()

        if len(module_argv) > 0:
            self.vt = VirusTotalPublicApi(module_argv[0])
        if len(module_argv) > 1:
            self.vt_threshold = int(module_argv[1])

        image_file = DEF_FWIMAGE_FILE
        if len(module_argv) > 2:
            # Use provided firmware image
            image_file = module_argv[2]
            self.logger.log(f'[*] Reading FW image from file: {image_file}')
        else:
            # Read firmware image directly from SPI flash memory
            self.spi = SPI(self.cs)
            (base, limit, _) = self.spi.get_SPI_region(BIOS)
            image_size = limit + 1 - base
            self.logger.log(f'[*] Dumping FW image from ROM to {image_file}: 0x{base:08X} bytes at [0x{limit:08X}:0x{image_size:08X}]')
            self.logger.log("[*] This may take a few minutes (instead, use 'chipsec_util spi dump')...")
            self.spi.read_spi_to_file(base, image_size, image_file)

        self.image = read_file(image_file)

        self.res = self.check_reputation()
        return self.result.getReturnCode(self.res)
