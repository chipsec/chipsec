# CHIPSEC: Platform Security Assessment Framework
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.

import os
import shutil
import tempfile
import unittest
import xml.etree.ElementTree as ET

from tests.cfg_checker import ConfigChecker


class TestConfigChecker(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.cfg_path = os.path.join(self.temp_dir, 'cfg')
        self.vendor_path = os.path.join(self.cfg_path, '8086')
        os.makedirs(self.vendor_path)
        self.checker = ConfigChecker()
        self.checker.cfg_path = self.cfg_path

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir)

    def _write_xml(self, relative_path, contents):
        xml_path = os.path.join(self.vendor_path, *relative_path.split('/'))
        xml_dir = os.path.dirname(xml_path)
        if not os.path.isdir(xml_dir):
            os.makedirs(xml_dir)
        with open(xml_path, 'w') as xml_file:
            xml_file.write(contents)
        return xml_path

    def _check_file(self, relative_path):
        xml_path = os.path.join(self.vendor_path, *relative_path.split('/'))
        root = ET.parse(xml_path).getroot()
        self.checker.check_bar_definitions(root, xml_path)

    def _log_contains(self, text):
        return any(text in message for message in self.checker.log_messages)

    def test_missing_config_reference_is_reported(self) -> None:
        self._write_xml('platform.xml', '''<?xml version="1.0"?>
<configuration platform="TST" req_pch="False">
  <pci>
    <device name="PMC" config="PMC.missing.xml" />
  </pci>
</configuration>
''')

        self._check_file('platform.xml')

        self.assertTrue(self.checker.inconsistency_found)
        self.assertTrue(self._log_contains('referenced config file does not exist: PMC.missing.xml'))

    def test_invalid_subcomponent_type_is_reported(self) -> None:
        self._write_xml('SPI/spi0.xml', '''<?xml version="1.0"?>
<configuration>
  <registers>
    <register name="SPIBAR0" type="pcicfg" offset="0x10" size="4" desc="SPI BAR">
      <field name="MEMBAR" bit="12" size="20" desc="Memory BAR"/>
    </register>
  </registers>
</configuration>
''')
        self._write_xml('platform.xml', '''<?xml version="1.0"?>
<configuration platform="TST" req_pch="False">
  <pci>
    <device name="SPI" config="SPI.spi0.xml">
      <subcomponent type="mmio" name="SPIBAR" register="SPIBAR0" base_field="MEMBAR" size="0x1000"/>
    </device>
  </pci>
</configuration>
''')

        self._check_file('platform.xml')

        self.assertTrue(self.checker.inconsistency_found)
        self.assertTrue(self._log_contains('subcomponent SPI.SPIBAR has invalid type mmio'))

    def test_subcomponent_bar_register_and_base_field_are_validated(self) -> None:
        self._write_xml('SPI/spi0.xml', '''<?xml version="1.0"?>
<configuration>
  <registers>
    <register name="SPIBAR0" type="pcicfg" offset="0x10" size="4" desc="SPI BAR">
      <field name="MEMBAR" bit="12" size="20" desc="Memory BAR"/>
    </register>
  </registers>
</configuration>
''')
        self._write_xml('platform.xml', '''<?xml version="1.0"?>
<configuration platform="TST" req_pch="False">
  <pci>
    <device name="SPI" config="SPI.spi0.xml">
      <subcomponent type="mmiobar" name="SPIBAR" register="SPIBAR" base_field="MEMBAR" size="0x1000"/>
      <subcomponent type="mmiobar" name="SPIBAR_FIELD" register="SPIBAR0" base_field="SPIBAR" size="0x1000"/>
    </device>
  </pci>
</configuration>
''')

        self._check_file('platform.xml')

        self.assertTrue(self.checker.inconsistency_found)
        self.assertTrue(self._log_contains('subcomponent SPI.SPIBAR references undefined BAR register SPIBAR'))
        self.assertTrue(self._log_contains('subcomponent SPI.SPIBAR_FIELD references undefined BAR base field SPIBAR0.SPIBAR'))

    def test_bar_register_can_come_from_sibling_subcomponent_config(self) -> None:
        self._write_xml('HOSTCTL/hostctl.xml', '''<?xml version="1.0"?>
<configuration>
  <registers>
    <register name="MCHBAR" type="pcicfg" offset="0x48" size="8" desc="MCH BAR">
      <field name="MCHBAR" bit="17" size="25" desc="MCH BAR"/>
    </register>
  </registers>
</configuration>
''')
        self._write_xml('MMIO/mmio0.xml', '''<?xml version="1.0"?>
<configuration>
  <registers>
    <register name="VTBAR" type="mmio" bar="MCHBAR" offset="0x5410" size="8" desc="VT-d BAR">
      <field name="BASE" bit="12" size="39" desc="Base"/>
    </register>
  </registers>
</configuration>
''')
        self._write_xml('platform.xml', '''<?xml version="1.0"?>
<configuration platform="TST" req_pch="False">
  <pci>
    <device name="HOSTCTL" config="HOSTCTL.hostctl.xml">
      <subcomponent type="mmiobar" name="MCHBAR" register="MCHBAR" base_field="MCHBAR" size="0x8000" config="MMIO.mmio0.xml"/>
      <subcomponent type="mmiobar" name="VTBAR" register="MCHBAR.VTBAR" base_field="BASE" size="0x1000"/>
    </device>
  </pci>
</configuration>
''')

        self._check_file('platform.xml')

        self.assertFalse(self.checker.inconsistency_found)
        self.assertEqual([], self.checker.log_messages)


if __name__ == '__main__':
    unittest.main()
