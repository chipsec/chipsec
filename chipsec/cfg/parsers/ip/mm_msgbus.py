from chipsec.cfg.parsers.ip.generic import GenericConfig


class MM_MSGBUSConfig(GenericConfig):
    def __init__(self, cfg_obj):
        super(MM_MSGBUSConfig, self).__init__(cfg_obj)
        self.port = cfg_obj['port']

    def __str__(self) -> str:
        ret = f'name: {self.name}, port: {self.port}'
        ret += f', config: {self.config}'
        return ret