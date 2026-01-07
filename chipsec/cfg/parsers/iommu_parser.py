# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2025, Intel Corporation
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

"""
IOMMU Register Parser - loads VT-d register definitions from XML
Pattern follows TPMI parser design for consistency with dynamic register binding.
"""

from chipsec.parsers import BaseConfigParser, BaseConfigHelper
from chipsec.parsers import Stage
from collections import namedtuple
from typing import List, Dict, Optional, Union

iommuentry = namedtuple('IOMMUEntry', ['name', 'type', 'size', 'offset', 'default', 'desc', 'fields'])
fieldentry = namedtuple('fieldEntry', ['name', 'bit', 'size', 'access', 'default', 'desc'])


class IOMMUParser(BaseConfigParser):
    def startup(self) -> None:
        """Initialize IOMMU register storage in config object."""
        if not hasattr(self.cfg, 'IOMMU_REGS'):
            setattr(self.cfg, 'IOMMU_REGS', [])

    def get_metadata(self) -> Dict[str, callable]:
        """Return metadata mapping for XML element handlers."""
        return {'register': self.access_handler}

    def parser_name(self) -> str:
        return 'IOMMU'

    def get_stage(self) -> Stage:
        """Run at EXTRA stage for vendor-specific configs."""
        return Stage.EXTRA

    def access_handler(self, et_node, stage_data) -> None:
        """
        Parse 'register' elements from IOMMU XML files.
        
        Args:
            et_node: ElementTree node containing register definitions
            stage_data: Stage processing context (unused)
        """
        for child in et_node.iter('register'):
            reg_fields = []
            for field in child.iter('field'):
                reg_fields.append(self._convert_field_data(field.attrib))
            child.attrib['fields'] = reg_fields
            self.cfg.IOMMU_REGS.append(self._convert_register_data(child.attrib))

    def _convert_data(self, xml_node: Dict[str, str], entries: List[str], 
                      int_fields: List[str], hex_fields: List[str]) -> Dict[str, Union[str, int, None]]:
        """
        Convert XML node attributes to typed dictionary.
        
        Args:
            xml_node: Raw XML attributes dict
            entries: List of expected attribute names
            int_fields: Fields to parse as decimal integers
            hex_fields: Fields to parse as hex integers
        
        Returns:
            Dictionary with typed values
        """
        tmp = {}
        for entry in entries:
            if entry in xml_node:
                if entry in int_fields:
                    tmp[entry] = int(xml_node[entry], 10)
                elif entry in hex_fields:
                    val = xml_node[entry]
                    if isinstance(val, str) and val.upper() == 'N/A':
                        tmp[entry] = None
                    else:
                        tmp[entry] = int(val, 16)
                else:
                    tmp[entry] = xml_node[entry]
            else:
                tmp[entry] = None
        return tmp

    def _convert_register_data(self, xml_node: Dict[str, str]) -> iommuentry:
        """
        Convert XML register node to iommuentry namedtuple.
        
        Args:
            xml_node: XML attributes dict with fields list
        
        Returns:
            iommuentry object
        """
        entries = ['name', 'type', 'size', 'offset', 'default', 'desc', 'fields']
        int_fields = ['size']
        hex_fields = ['offset', 'default']
        tmp = self._convert_data(xml_node, entries, int_fields, hex_fields)
        return iommuentry(tmp['name'], tmp['type'], tmp['size'], tmp['offset'], 
                         tmp['default'], tmp['desc'], tmp['fields'])

    def _convert_field_data(self, xml_node: Dict[str, str]) -> fieldentry:
        """
        Convert XML field node to fieldentry namedtuple.
        
        Args:
            xml_node: XML attributes dict for field
        
        Returns:
            fieldentry object
        """
        entries = ['name', 'bit', 'size', 'access', 'default', 'desc']
        int_fields = ['size', 'bit']
        hex_fields = ['default']
        tmp = self._convert_data(xml_node, entries, int_fields, hex_fields)
        return fieldentry(tmp['name'], tmp['bit'], tmp['size'], tmp['access'], 
                         tmp['default'], tmp['desc'])


class IOMMUCommands(BaseConfigHelper):
    """
    Configuration helper for IOMMU registers - manages register lookup and address binding.
    Similar to TPMICommands but for VT-d engines discovered via DMAR.
    """
    
    def __init__(self, cfg_obj):
        """
        Initialize IOMMUCommands with parsed register definitions.
        
        Args:
            cfg_obj: Configuration object containing IOMMU_REGS
        """
        super().__init__(cfg_obj)
        self.regs = getattr(self.cfg, 'IOMMU_REGS', [])
        self.engine_bases = {}  # Maps engine_name -> base_address

    def get_reg(self, name: str) -> Optional[iommuentry]:
        """
        Get register definition by name.
        
        Args:
            name: Register name (e.g., 'VER', 'CAP', 'GSTS')
        
        Returns:
            iommuentry object or None if not found
        """
        for reg in self.regs:
            if reg.name == name:
                return reg
        return None

    def get_all_regs(self) -> List[iommuentry]:
        """Return list of all register definitions."""
        return self.regs

    def set_engine_bases(self, bases: Dict[str, int]) -> None:
        """
        Set discovered VT-d engine base addresses from DMAR parsing.
        
        Args:
            bases: Dictionary mapping engine_name -> MMIO base address
                   e.g., {'VTD0': 0xC3FE0000, 'VTD1': 0xC3FF0000, ...}
        """
        self.engine_bases = bases

    def get_engine_bases(self) -> Dict[str, int]:
        """Return dictionary of discovered engine base addresses."""
        return self.engine_bases

    def get_engine_base(self, engine_name: str) -> Optional[int]:
        """
        Get base address for specific engine.
        
        Args:
            engine_name: Engine identifier (e.g., 'VTD0')
        
        Returns:
            Base address or None if engine not found
        """
        return self.engine_bases.get(engine_name)

    def compute_reg_address(self, reg: iommuentry, engine_base: int) -> int:
        """
        Compute final MMIO address for register on specific engine.
        
        Args:
            reg: Register definition with offset
            engine_base: VT-d engine MMIO base address
        
        Returns:
            Final address = engine_base + reg.offset
        """
        return engine_base + reg.offset


parsers = {IOMMUParser}
