from chipsec.cfg.parsers.ip.generic import GenericConfig


class MSRConfig(GenericConfig):
    def __init__(self, cfg_obj):
        super(MSRConfig, self).__init__(cfg_obj)

    def __str__(self) -> str:
        ret = f'name: {self.name}'
        ret += f', config: {self.config}'
        return ret