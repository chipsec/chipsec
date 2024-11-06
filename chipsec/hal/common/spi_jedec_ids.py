# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2018-2021, Intel Corporation
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
JEDED ID : Manufacturers and Device IDs
"""

from typing import Dict

class JEDEC_ID:

    MANUFACTURER: Dict[int, str] = {0xEF: 'Winbond',
                                    0xC2: 'Macronix'}

    DEVICE: Dict[int, str] = {0xEF4018: 'W25Q128 (SPI)',
                              0xEF6018: 'W25Q128 (QPI)',
                              0xEF4017: 'W25Q64FV (SPI)',
                              0xEF6017: 'W25Q64FV (QPI)',
                              0xEF7016: 'W25Q32JV',
                              0xEF4019: 'W25Q256',
                              0xC22017: 'MX25L6408',
                              0xC22018: 'MX25L12805'}
