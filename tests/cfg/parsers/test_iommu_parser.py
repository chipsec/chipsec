# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2026, Intel Corporation
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Contact information:
# chipsec@intel.com
#

import unittest
import xml.etree.ElementTree as ET
from types import SimpleNamespace

from chipsec.cfg.parsers.iommu_parser import (
    IOMMUParser,
    IOMMUCommands,
    iommuentry,
    fieldentry,
)
from chipsec.parsers import Stage


REGISTER_XML = """
<mmio>
    <register name="VER" type="mmio" size="4" offset="0x0" default="0x10" desc="Version">
        <field name="MIN" bit="0" size="4" access="RO" default="0x0" desc="Minor" />
        <field name="MAX" bit="4" size="4" access="RO" default="0x1" desc="Major" />
    </register>
    <register name="CAP" type="mmio" size="8" offset="0x8" default="N/A" desc="Capability" />
</mmio>
"""


class TestIOMMUParser(unittest.TestCase):
    """Cover the IOMMU register parser in chipsec.cfg.parsers.iommu_parser."""

    def setUp(self):
        self.cfg = SimpleNamespace()
        self.parser = IOMMUParser(self.cfg)
        self.parser.startup()

    def test_startup_initializes_reg_store(self):
        self.assertEqual(self.cfg.IOMMU_REGS, [])

    def test_startup_is_idempotent(self):
        self.cfg.IOMMU_REGS.append('existing')
        self.parser.startup()
        self.assertEqual(self.cfg.IOMMU_REGS, ['existing'])

    def test_parser_metadata(self):
        self.assertEqual(self.parser.parser_name(), 'IOMMU')
        self.assertEqual(self.parser.get_stage(), Stage.EXTRA)
        self.assertIn('register', self.parser.get_metadata())

    def test_access_handler_parses_registers_and_fields(self):
        node = ET.fromstring(REGISTER_XML)
        self.parser.access_handler(node, None)

        self.assertEqual(len(self.cfg.IOMMU_REGS), 2)
        ver = self.cfg.IOMMU_REGS[0]
        self.assertIsInstance(ver, iommuentry)
        self.assertEqual(ver.name, 'VER')
        self.assertEqual(ver.size, 4)
        self.assertEqual(ver.offset, 0x0)
        self.assertEqual(ver.default, 0x10)
        self.assertEqual(len(ver.fields), 2)
        self.assertIsInstance(ver.fields[0], fieldentry)
        self.assertEqual(ver.fields[0].name, 'MIN')
        self.assertEqual(ver.fields[1].bit, 4)

    def test_access_handler_handles_na_default(self):
        node = ET.fromstring(REGISTER_XML)
        self.parser.access_handler(node, None)

        cap = self.cfg.IOMMU_REGS[1]
        self.assertIsNone(cap.default)
        self.assertEqual(cap.fields, [])

    def test_convert_data_missing_entry_is_none(self):
        result = self.parser._convert_data({}, ['name', 'size'], ['size'], [])
        self.assertEqual(result, {'name': None, 'size': None})


class TestIOMMUCommands(unittest.TestCase):
    """Cover the IOMMU register helper in chipsec.cfg.parsers.iommu_parser."""

    def setUp(self):
        self.ver = iommuentry('VER', 'mmio', 4, 0x0, 0x10, 'Version', [])
        self.cap = iommuentry('CAP', 'mmio', 8, 0x8, None, 'Capability', [])
        self.cfg = SimpleNamespace(IOMMU_REGS=[self.ver, self.cap])
        self.cmds = IOMMUCommands(self.cfg)

    def test_get_reg_found(self):
        self.assertIs(self.cmds.get_reg('CAP'), self.cap)

    def test_get_reg_not_found_returns_none(self):
        self.assertIsNone(self.cmds.get_reg('MISSING'))

    def test_get_all_regs(self):
        self.assertEqual(self.cmds.get_all_regs(), [self.ver, self.cap])

    def test_engine_bases_roundtrip(self):
        bases = {'VTD0': 0xC3FE0000, 'VTD1': 0xC3FF0000}
        self.cmds.set_engine_bases(bases)
        self.assertEqual(self.cmds.get_engine_bases(), bases)
        self.assertEqual(self.cmds.get_engine_base('VTD1'), 0xC3FF0000)

    def test_get_engine_base_missing_returns_none(self):
        self.assertIsNone(self.cmds.get_engine_base('VTD9'))

    def test_compute_reg_address(self):
        self.assertEqual(self.cmds.compute_reg_address(self.cap, 0xC3FE0000), 0xC3FE0008)

    def test_init_without_regs_defaults_empty(self):
        cmds = IOMMUCommands(SimpleNamespace())
        self.assertEqual(cmds.get_all_regs(), [])


if __name__ == '__main__':
    unittest.main()
