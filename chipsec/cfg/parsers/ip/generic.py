from chipsec.parsers import BaseConfigHelper

class GenericConfig(BaseConfigHelper):
    def __init__(self, cfg_obj):
        super(GenericConfig, self).__init__(cfg_obj)
        self.name = cfg_obj['name']
        if 'config' in cfg_obj:
            self.config = cfg_obj['config']
        else:
            self.config = []

    def add_config(self, config):
        for cfg in config:
            if cfg not in self.config:
                self.config.append(cfg)