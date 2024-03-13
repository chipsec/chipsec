# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2023, Intel Corporation
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

from collections import namedtuple
from enum import Enum
from chipsec.library.logger import logger


class Stage(Enum):
    NONE = 0
    GET_INFO = 10
    DEVICE_CFG = 20
    CORE_SUPPORT = 30
    CUST_SUPPORT = 40
    EXTRA = 50


# Stage - None
# - Never runs
# - stage_data - None
# - Returns None

# Stage.GET_INFO
# - Gathers platform information including values used in platform detection
# - stage_data - stage_info named tuple
# - Returns - info_data named tuple
stage_info = namedtuple('StageInfo', ['vid_str', 'configuration'])
info_data = namedtuple('InfoData', ['family', 'proc_code', 'pch_code', 'detect_vals', 'req_pch', 'vid_str', 'sku_list'])

# Stage.DEVICE_CFG
# - Determine device configuration files
# - stage_data - stage_dev named tuple for file being processed
# - Returns - A list of config_data named tuples
stage_dev = namedtuple('StageCore', ['vid_str', 'xml_file'])
config_data = namedtuple('DevData', ['vid_str', 'dev_name', 'xml_file'])

# Stage.CORE_SUPPORT
# - Parse all core XML tags and update configuration data directly in object
# - stage_data - config_data named tuple for the file being processed
# - Returns - None

# Stage.CUST_SUPPORT
# - Parse any custom XML tags and update configuration data directly in object
# - stage_data - config_data named tuple for the file being processed
# - Returns - None


class BaseConfigParser:
    def __init__(self, cfg_obj):
        self.logger = logger()
        self.cfg = cfg_obj

    def startup(self):
        return None

    def get_metadata(self):
        return {'template': self.def_handler}

    def get_stage(self):
        return Stage.NONE

    def def_handler(self, et_node, stage_data=None):
        return None


parsers = [BaseConfigParser]


class BaseConfigHelper:
    def __init__(self, cfg_obj):
        self.logger = logger()
        self.cfg = cfg_obj
