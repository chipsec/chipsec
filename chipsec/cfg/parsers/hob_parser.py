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

"""
HOB definition parser - describes the payload of GUID extension HOBs in XML

A platform configuration file pulls in HOB definitions the same way it pulls in
other definitions, naming the IP node that will hold them:

    <hob>
        <definition name="HOB" config="HOB.hob0.xml" />
    </hob>

The included file declares one <structure> element per known GUID extension HOB,
with a <field> element per member of the corresponding C structure, in declaration
order:

    <hob>
        <structure name="PEI_PCD_DATABASE" guid="EA296D92-0B69-423C-8C28-33B4E0A91268">
            <field name="Signature"    type="guid"   desc="PcdDataBaseGuid" />
            <field name="BuildVersion" type="uint32" />
            <field name="Pad"          type="bytes"  size="6" />
        </structure>
    </hob>

Layouts are packed (no implicit alignment padding), so any padding present in the
C structure must be declared explicitly as a field.

Definitions are stored by GUID in Cfg.HOB_DEFINITIONS and each one is exposed as a
register whose fields are the structure members (byte offsets converted to bit
positions), published into the platform hierarchy as VID.<definition name>.<structure name>.
"""

import struct
from typing import Any, Dict, List, Optional

from chipsec.cfg.parsers.registers.hob import HobRegister
from chipsec.library.exceptions import PlatformConfigError
from chipsec.parsers import BaseConfigParser, BaseConfigHelper
from chipsec.parsers import Stage

# IP node used when a definition file is loaded without a <definition> entry
HOB_IP_NAME = 'HOB'

# EDK II base type -> struct format character for a single element
HOB_FIELD_FORMATS = {
    'uint8': 'B',
    'uint16': 'H',
    'uint32': 'I',
    'uint64': 'Q',
    'int8': 'b',
    'int16': 'h',
    'int32': 'i',
    'int64': 'q',
    'boolean': 'B',
    'guid': '16s',
    'bytes': 's',       # requires a size attribute
}

# Field type that carries an explicit size attribute
BYTES_TYPE = 'bytes'


class HobFieldDefinition:
    """A single member of a HOB structure."""

    def __init__(self, name: str, ftype: str, count: int = 1, size: int = 0, desc: str = '') -> None:
        self.name = name
        self.type = ftype
        self.count = count
        self.size = size
        self.desc = desc or name
        self.offset = 0     # byte offset within the structure, assigned by HobDefinition

    @property
    def fmt(self) -> str:
        """struct format fragment for this field."""
        if self.type == BYTES_TYPE:
            return f'{self.size}s'
        base_fmt = HOB_FIELD_FORMATS[self.type]
        if self.type == 'guid' and self.count > 1:
            return base_fmt * self.count
        return f'{self.count}{base_fmt}' if self.count > 1 else base_fmt

    @property
    def byte_size(self) -> int:
        """Width of this field in bytes."""
        return struct.calcsize(self.fmt)

    def __str__(self) -> str:
        arr = f'[{self.count}]' if self.count > 1 else ''
        return f'0x{self.offset:02X} {self.type}{arr} {self.name}'


class HobDefinition:
    """Declared layout of a GUID extension HOB payload."""

    def __init__(self, name: str, guid: str, fields: List[HobFieldDefinition],
                 desc: str = '', vid_str: str = '', ip_name: str = HOB_IP_NAME) -> None:
        self.name = name
        self.guid = guid
        self.fields = fields
        self.desc = desc or name
        self.vid_str = vid_str
        self.ip_name = ip_name
        self.fmt = '=' + ''.join(field.fmt for field in fields)
        self.FIELDS = self._build_fields()
        self.size = struct.calcsize(self.fmt)

    def _build_fields(self) -> Dict[str, Dict[str, Any]]:
        """Build a register-style field map, converting byte offsets to bit positions."""
        reg_fields: Dict[str, Dict[str, Any]] = {}
        offset = 0
        for field in self.fields:
            field.offset = offset
            reg_fields[field.name.upper()] = {
                'name': field.name,
                'bit': offset * 8,
                'size': field.byte_size * 8,
                'desc': field.desc,
                'access': 'RO',
                'ftype': field.type,
                'count': field.count,
            }
            offset += field.byte_size
        return reg_fields

    def create_register(self, data: bytes = b'', instance: Optional[Any] = None,
                        address: int = 0) -> HobRegister:
        """
        Create a register object for this definition.

        Args:
            data: Raw HOB payload; trailing data beyond the structure is ignored.
            instance: Register instance identifier.
            address: Physical address of the HOB the payload came from.

        Returns:
            A HobRegister whose fields are this definition's structure members.
        """
        reg = HobRegister({
            'name': self.name,
            'desc': self.desc,
            'FIELDS': self.FIELDS,
            'instance': instance,
            'size': self.size,
            'guid': self.guid,
            'vid_str': self.vid_str,
            'ip_name': self.ip_name,
            'address': address,
            'value': 0,
        })
        if data:
            reg.set_data(data)
        return reg

    def decode(self, data: bytes) -> Optional[Dict[str, object]]:
        """
        Decode a HOB payload into a dict of field name -> value.

        Data longer than the declared structure is allowed (trailing tables are
        common); data shorter than the declared structure returns None.
        """
        if len(data) < self.size:
            return None
        return self.create_register(data).get_decoded()

    def __str__(self) -> str:
        lines = [f'{self.name} {{{self.guid}}} (0x{self.size:X} bytes) - {self.desc}']
        for field in self.fields:
            lines.append(f'    {field}')
        return '\n'.join(lines)


def normalize_guid(guid: str) -> str:
    """Normalize a GUID string to the uppercase, brace-less form used by EFI_GUID_STR."""
    return guid.strip().strip('{}').upper()


class HOBParser(BaseConfigParser):
    def startup(self) -> None:
        """Initialize HOB definition storage in the config object."""
        if not hasattr(self.cfg, 'HOB_DEFINITIONS'):
            self.cfg.HOB_DEFINITIONS = {}

    def parser_name(self) -> str:
        return 'HOB'

    def get_stage(self) -> Stage:
        return Stage.CUST_SUPPORT

    def get_metadata(self) -> Dict[str, object]:
        return {'structure': self.handle_structure}

    def handle_structure(self, et_node, stage_data) -> None:
        """Parse a single <structure> declaration from a HOB definition file."""
        attrs = et_node.attrib
        if 'name' not in attrs or 'guid' not in attrs:
            self.logger.log_error('[hob] Structure declaration is missing a name or guid')
            return
        name = attrs['name']
        guid = normalize_guid(attrs['guid'])

        fields = []
        for field in et_node.iter('field'):
            field_def = self._convert_field(name, field.attrib)
            if field_def is None:
                return
            fields.append(field_def)
        if not fields:
            self.logger.log_debug(f'[hob] Definition {name} has no fields; skipping')
            return

        hob_def = HobDefinition(name, guid, fields, attrs.get('desc', ''),
                                getattr(stage_data, 'vid_str', '') or '',
                                getattr(stage_data, 'dev_name', '') or HOB_IP_NAME)
        definitions = self.cfg.HOB_DEFINITIONS
        if guid in definitions and definitions[guid].name != name:
            self.logger.log_debug(f'[hob] Replacing definition for {{{guid}}}: '
                                  f'{definitions[guid].name} -> {name}')
        definitions[guid] = hob_def
        self._add_to_platform(hob_def)
        self.logger.log_debug(f'    + {name:32}: {{{guid}}} 0x{hob_def.size:X} bytes, '
                              f'{len(fields):d} fields')

    def _add_to_platform(self, hob_def: HobDefinition) -> None:
        """Publish a definition into the platform hierarchy as VID.<IP>.NAME."""
        if not hob_def.vid_str or not hasattr(self.cfg, 'platform'):
            return
        try:
            vendor = self.cfg.platform.get_vendor(hob_def.vid_str)
        except PlatformConfigError:
            self.logger.log_debug(f'[hob] Vendor {hob_def.vid_str} not present; '
                                  f'{hob_def.name} not added to the platform hierarchy')
            return
        # The IP is normally created from the <definition> entry at the device stage
        if hob_def.ip_name not in vendor.ip_list:
            vendor.add_ip(hob_def.ip_name, self.cfg.HOB_DEFINITIONS)
        vendor.get_ip(hob_def.ip_name).add_register(hob_def.name.upper(), [hob_def.create_register()])

    def _convert_field(self, hob_name: str, attrs: Dict[str, str]) -> Optional[HobFieldDefinition]:
        """Convert a <field> element's attributes into a HobFieldDefinition."""
        if 'name' not in attrs or 'type' not in attrs:
            self.logger.log_error(f'[hob] Field in {hob_name} is missing a name or type')
            return None
        ftype = attrs['type'].lower()
        if ftype not in HOB_FIELD_FORMATS:
            self.logger.log_error(f'[hob] Unsupported field type "{attrs["type"]}" in {hob_name}.{attrs["name"]}')
            return None
        try:
            count = int(attrs.get('count', '1'), 0)
            size = int(attrs.get('size', '0'), 0)
        except ValueError:
            self.logger.log_error(f'[hob] Invalid count/size in {hob_name}.{attrs["name"]}')
            return None
        if ftype == BYTES_TYPE and size <= 0:
            self.logger.log_error(f'[hob] Field {hob_name}.{attrs["name"]} of type bytes requires a size')
            return None
        if count <= 0:
            self.logger.log_error(f'[hob] Field {hob_name}.{attrs["name"]} has an invalid count')
            return None
        return HobFieldDefinition(attrs['name'], ftype, count, size, attrs.get('desc', ''))


class HOBCommands(BaseConfigHelper):
    """Lookup helper for parsed HOB definitions."""

    def __init__(self, cfg_obj):
        super().__init__(cfg_obj)
        self.defs: Dict[str, HobDefinition] = getattr(self.cfg, 'HOB_DEFINITIONS', {})

    def get_by_guid(self, guid: str) -> Optional[HobDefinition]:
        """Get a HOB definition by GUID string."""
        return self.defs.get(normalize_guid(guid))

    def get_by_name(self, name: str) -> Optional[HobDefinition]:
        """Get a HOB definition by declared name (case-insensitive)."""
        for hob_def in self.defs.values():
            if hob_def.name.upper() == name.upper():
                return hob_def
        return None

    def get_definition(self, name_or_guid: str) -> Optional[HobDefinition]:
        """Get a HOB definition by either GUID or name."""
        return self.get_by_guid(name_or_guid) or self.get_by_name(name_or_guid)

    def get_all(self) -> List[HobDefinition]:
        """Return all parsed HOB definitions."""
        return list(self.defs.values())


parsers = [HOBParser]
