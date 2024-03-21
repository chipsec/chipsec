# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
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


#
# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
# (c) 2010-2012 Intel Corporation
#
# -------------------------------------------------------------------------------

"""
Reading from/writing to files

usage:
    >>> read_file(filename)
    >>> write_file(filename, buffer)
"""

import os
from typing import Any
from chipsec.library.strings import get_datetime_str
from chipsec.library.logger import logger

TOOLS_DIR = 'chipsec_tools'


def read_file(filename: str, size: int = 0) -> bytes:
    try:
        with open(filename, 'rb') as f:
            if size:
                _file = f.read(size)
            else:
                _file = f.read()
            logger().log_debug(f"[file] Read {len(_file):d} bytes from '{filename:.256}'")
            return _file
    except OSError:
        logger().log_error(f"Unable to open file '{filename:.256}' for read access")
        return b''


def write_file(filename: str, buffer: Any, append: bool = False) -> bool:
    perm = 'a' if append else 'w'
    if isinstance(buffer, bytes) or isinstance(buffer, bytearray):
        perm += 'b'
    try:
        f = open(filename, perm)
    except OSError:
        logger().log_error(f"Unable to open file '{filename:.256}' for write access")
        return False
    f.write(buffer)
    f.close()

    logger().log_debug(f"[file] Wrote {len(buffer):d} bytes to '{filename:.256}'")
    return True


def write_unique_file(file_buffer: Any, file_name: str = '', file_extension: str = '') -> str:
    """Writes file with the name <file_name>_<year><month><day>-<hour><minute><second>.<file_extension>"""
    file_str = f'{file_name}_' if file_name else ''
    file_ext = f'.{file_extension}' if file_extension else ''
    file_name_str = f'{file_str}{get_datetime_str()}{file_ext}'
    return file_name_str if write_file(file_name_str, file_buffer) else ''


def get_main_dir() -> str:
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir, os.path.pardir))
    return path

def get_module_dir() -> str:
    path = os.path.join(get_main_dir(), "chipsec", "modules")
    return path