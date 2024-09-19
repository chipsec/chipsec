from collections import namedtuple
from enum import Enum

from chipsec.parsers import BaseConfigParser, BaseConfigHelper
from chipsec.parsers import Stage


range_entry = namedtuple('RangeEntry', ['name', 'group', 'access', 'start', 'end'])


class Access(Enum):
    UNKNOWN = 0
    NONE = 1
    RO = 2
    RW = 3


def _convert_range_data(xml_node):
    INT_KEYS = ['start', 'end']
    ACCESS_KEYS = ['access']
    ACCESS_CONVERT = {'unknown': Access.UNKNOWN, 'none': Access.NONE, 'ro': Access.RO, 'rw': Access.RW}
    node_data = {}
    for key in xml_node.attrib:
        if key in INT_KEYS:
            node_data[key] = int(xml_node.attrib[key], 0)
        elif key in ACCESS_KEYS:
            if xml_node.attrib[key].lower() in ACCESS_CONVERT:
                node_data[key] = ACCESS_CONVERT[xml_node.attrib[key].lower()]
            else:
                node_data[key] = Access.UNKNOWN
        else:
            node_data[key] = xml_node.attrib[key]
    return range_entry(node_data['name'], node_data['group'], node_data['access'],
                       node_data['start'], node_data['end'])


class CustomRangeParser(BaseConfigParser):
    def startup(self):
        if not hasattr(self.cfg, 'ACCESS_RANGES'):
            setattr(self.cfg, 'ACCESS_RANGES', {})

    def get_metadata(self):
        return {'access_ranges': self.access_handler}

    def get_stage(self):
        return Stage.CUST_SUPPORT

    def parser_name(self):
        return 'ACCESS_RANGES'

    def access_handler(self, et_node, stage_data):
        if stage_data.vid_str not in self.cfg.ACCESS_RANGES:
            self.cfg.ACCESS_RANGES[stage_data.vid_str] = {}
        if stage_data.dev_name not in self.cfg.ACCESS_RANGES[stage_data.vid_str]:
            self.cfg.ACCESS_RANGES[stage_data.vid_str][stage_data.dev_name] = []
        for range_node in et_node.iter('range'):
            node_data = _convert_range_data(range_node)
            self.logger.log_debug(f"    + {node_data.name:16}: {node_data}")
            self.cfg.ACCESS_RANGES[stage_data.vid_str][stage_data.dev_name].append(node_data)


class CustomRanges(BaseConfigHelper):
    def has_custom_ranges(self, vid_str, dev_name, group=None):
        if vid_str not in self.cfg.ACCESS_RANGES:
            return False
        if dev_name not in self.cfg.ACCESS_RANGES[vid_str]:
            return False
        if not group:
            return True
        for item in self.cfg.ACCESS_RANGES[vid_str][dev_name]:
            if item.group == group:
                return True
        return False

    def get_custom_ranges(self, vid_str, dev_name, group=None):
        ret_val = []
        if vid_str not in self.cfg.ACCESS_RANGES or dev_name not in self.cfg.ACCESS_RANGES[vid_str]:
            return ret_val
        for item in self.cfg.ACCESS_RANGES[vid_str][dev_name]:
            if group and item.group != group:
                continue
            ret_val.append(item)
        return ret_val


parsers = [CustomRangeParser]
