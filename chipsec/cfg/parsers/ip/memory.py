from chipsec.cfg.parsers.ip.generic import GenericConfig


class MemoryConfig(GenericConfig):
    def __init__(self, cfg_obj):
        super(MemoryConfig, self).__init__(cfg_obj)
        self.access = cfg_obj['access']
        self.address = cfg_obj['address']
        self.size = cfg_obj['size']

    def __str__(self) -> str:
        ret = f'name: {self.name}, access: {self.access}'
        ret += f', address: {self.address}, size: {self.size}'
        ret += f', config: {self.config}'
        return ret
