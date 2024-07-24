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
Banner functions
"""

import platform
import sys
from typing import Sequence, Tuple
from chipsec.chipset import Chipset
from chipsec.library.logger import logger


def chipsec_banner(arguments: Sequence[str], version: str, message: str, custom_str: str = '') -> str:
    """Creates the CHIPSEC banner string"""
    args = ' '.join(arguments)
    if custom_str:
        message += f'\n{custom_str}'
    banner = f'''
################################################################
##                                                            ##
##  CHIPSEC: Platform Hardware Security Assessment Framework  ##
##                                                            ##
################################################################
[CHIPSEC] Version  : {version}
[CHIPSEC] Arguments: {args}
{message}'''
    return banner


def print_banner(arguments: Sequence[str], version: str, message: str, custom_str: str = '') -> None:
    logger().log(chipsec_banner(arguments, version, message, custom_str))


def chipsec_banner_properties(cs: Chipset, os_version: Tuple[str, str, str, str]) -> str:
    """Creates the CHIPSEC properties banner string"""
    (system, release, version, machine) = os_version
    is_python_64 = True if (sys.maxsize > 2**32) else False
    python_version = platform.python_version()
    python_arch = '64-bit' if is_python_64 else '32-bit'
    (helper_name, driver_path) = cs.helper.get_info()
    include_pch_str = cs.Cfg.is_pch_req() or (cs.Cfg.is_pch_req() is None)

    banner_prop = f'''
[CHIPSEC] OS      : {system} {release} {version} {machine}
[CHIPSEC] Python  : {python_version} ({python_arch})
[CHIPSEC] Helper  : {helper_name} {driver_path}
[CHIPSEC] Platform: {cs.Cfg.longname}
[CHIPSEC]    CPUID: {cs.Cfg.cpuid:05X}
[CHIPSEC]      VID: {cs.Cfg.vid:04X}
[CHIPSEC]      DID: {cs.Cfg.did:04X}
[CHIPSEC]      RID: {cs.Cfg.rid:02X}'''
    if include_pch_str:
        banner_prop += f'''
[CHIPSEC] PCH     : {cs.Cfg.pch_longname}
[CHIPSEC]      VID: {cs.Cfg.pch_vid:04X}
[CHIPSEC]      DID: {cs.Cfg.pch_did:04X}
[CHIPSEC]      RID: {cs.Cfg.pch_rid:02X}
'''
    if not is_python_64 and machine.endswith('64'):
        banner_prop += 'Python architecture (32-bit) is different from OS architecture (64-bit)'

    return banner_prop


def print_banner_properties(cs: Chipset, os_version: Tuple[str, str, str, str]) -> None:

    if not cs.load_config:
        logger().log_warning("Not loading configurations. Platform will remain unknown.")
    logger().log(chipsec_banner_properties(cs, os_version))
