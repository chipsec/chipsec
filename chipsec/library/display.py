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
#

"""
Display functions
"""

import platform
import sys
from datetime import datetime
from typing import Sequence

from chipsec.chipset import Chipset
from chipsec.library.defines import os_version, get_version, get_message
from chipsec.library.gil import gil_status
from chipsec.library.logger import logger


def _chipsec_banner(arguments: Sequence[str], custom_str: str = '') -> str:
    """Creates the CHIPSEC banner string"""
    args = ' '.join(arguments)
    message = get_message()
    start_time = datetime.now().isoformat().replace('T',' ').split('.')[0]
    if custom_str:
        message += f'\n{custom_str}'
    banner = f'''
################################################################
##                                                            ##
##  CHIPSEC: Platform Hardware Security Assessment Framework  ##
##                                                            ##
################################################################
[CHIPSEC] Version  : {get_version()}
[CHIPSEC] Start    : {start_time}
[CHIPSEC] Arguments: {args}
{message}'''
    return banner


def print_banner(arguments: Sequence[str], custom_str: str = '') -> None:
    logger().log(_chipsec_banner(arguments, custom_str))


def _chipsec_environment(cs: Chipset) -> str:
    """Creates the CHIPSEC properties banner string"""
    (system, release, version, machine) = os_version()
    is_python_64 = True if (sys.maxsize > 2**32) else False
    python_version = platform.python_version()
    python_arch = '64-bit' if is_python_64 else '32-bit'
    (helper_name, driver_path) = cs.helper.get_info()

    banner_prop = f'''
[CHIPSEC] OS      : {system} {release} {version} {machine}
[CHIPSEC] Python  : {python_version} ({python_arch}) - {gil_status()} GIL
[CHIPSEC] Helper  : {helper_name} {driver_path}
'''
    if not is_python_64 and machine.endswith('64'):
        banner_prop += 'Python architecture (32-bit) is different from OS architecture (64-bit)'

    return banner_prop


def print_environment(cs: Chipset) -> None:
    if not cs.load_config:
        logger().log_warning('Not loading configurations. Platform will remain unknown.')
    logger().log(_chipsec_environment(cs))


def print_chipsec_info(cs: Chipset) -> None:
    print_environment(cs)
    cs.Cfg.print_platform_info()
    if cs.Cfg.is_pch_req() or cs.Cfg.is_pch_detected():
        cs.Cfg.print_pch_info()


def make_dict_hex(int_dict: dict) -> dict:
    hex_dict = {}
    for d in int_dict:
        if isinstance(int_dict[d], list):
            hex_dict[d] = [hex(item) if isinstance(item, int) else item for item in int_dict[d]]
        elif(isinstance(int_dict[d], int)):
            hex_dict[d] = hex(int_dict[d])
        else:
            hex_dict[d] = int_dict[d]

    return hex_dict
