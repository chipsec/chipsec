from chipsec.parsers import BaseConfigParser, BaseConfigHelper
from chipsec.parsers import Stage

class GPIOParser(BaseConfigParser):
    def startup(self):
        if not hasattr(self.cfg, 'GPIO'):
            setattr(self.cfg, 'GPIO', {})

    def parser_name(self):
        return 'GPIO'

    def get_metadata(self):
        return {'configuration': self.platform_handler, 'community': self.community_handler}

    def get_stage(self):
        return Stage.EXTRA

    def platform_handler(self, et_node, stage_data):
        self.pch_code = et_node.get('pch_code')
        self.cfg.GPIO[self.pch_code] = {}

    def community_handler(self, et_node, stage_data):
        community = {}
        port = et_node.get('port_id')
        for subtree in et_node.iter('group'):
            group = self._convert_group_data(subtree)
            community.update(group)
        self.cfg.GPIO[self.pch_code].update({port: community})

    def _convert_group_data(self, et_node):
        group = {}
        group_name = et_node.get('name')
        if group_name in ['pad_ownership', 'config_lock', 'hostsoftware_ownership']:
            entries = ['name', 'offset', 'pad_cnt']
        elif group_name == 'pad_config':
            entries = ['name', 'offset']
        else:
            raise UnboundLocalError
        for subtree in et_node.iter('register'):
            register = self._convert_register(subtree, entries)
            group.update(register)
        return {group_name: group}

    def _convert_register(self, xml_node, entries):
        if set(entries) == set(xml_node.attrib):
            name = xml_node.attrib.pop('name')
            return {name: xml_node.attrib}


class GPIOCommands(BaseConfigHelper):
    def __init__(self, cfg_obj):
        super().__init__(cfg_obj)
        self.regs = self.cfg.GPIO
        self.start_addrs = {}




parsers = {GPIOParser}