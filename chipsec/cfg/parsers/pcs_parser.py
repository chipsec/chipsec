from chipsec.parsers import BaseConfigParser, BaseConfigHelper
from chipsec.parsers import Stage

class PCSParser(BaseConfigParser):
    def startup(self):
        if not hasattr(self.cfg, 'PCS'):
            setattr(self.cfg, 'PCS', {})

    def get_metadata(self):
        return {'configuration': self.platform_handler, 'pcs': self.pcs_handler}

    def parser_name(self):
        return 'PCS'

    def get_stage(self):
        return Stage.EXTRA

    def platform_handler(self, et_node, stage_data):
        self.chipset_code = et_node.get('chipset_code')
        self.cfg.PCS[self.chipset_code] = {}

    def pcs_handler(self, et_node, stage_data):
        pcs = et_node.attrib
        pcs['params'] = {}
        for subtree in et_node.iter('param'):
            param = self._convert_param_data(subtree)
            pcs['params'].update(param)
        self.cfg.PCS[self.chipset_code].update({pcs['index']: pcs})

    def _convert_param_data(self, et_node):
        param = et_node.attrib
        param['bitfields'] = {}
        param_value = et_node.get('value')
        entries = ['desc', 'bit', 'size']
        for subtree in et_node.iter('bitfield'):
            bitfield = self._convert_bitfield(subtree, entries)
            param['bitfields'].update(bitfield)
        return {param_value: param}

    def _convert_bitfield(self, xml_node, entries):
        if set(entries) == set(xml_node.attrib):
            name = xml_node.attrib.pop('bit')
            return {name: xml_node.attrib}


class PCSCommands(BaseConfigHelper):
    def __init__(self, cfg_obj):
        super().__init__(cfg_obj)
        self.regs = self.cfg.PCS
        self.start_addrs = {}




parsers = {PCSParser}