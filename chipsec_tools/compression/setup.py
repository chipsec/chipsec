#!/usr/bin/python
# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2020, Intel Corporation
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

# This file incorporates work covered by the following copyright and permission notice


## @file
# package and install PyEfiCompressor extension
#
#  Copyright (c) 2008, Intel Corporation. All rights reserved.<BR>
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#

##
# Import Modules
#
from distutils.core import setup, Extension
import os

setup(
    name="EfiCompressor",
    version="0.01",
    ext_modules=[
        Extension(
            'EfiCompressor',
            sources=[
                'Decompress.c',
                'Compress.c',
                'EfiCompress.c',
                'TianoCompress.c',
                'EfiCompressor.c'
                ],
            include_dirs=[
                'Include',
                os.path.join('Include', 'Common'),
                os.path.join('Include', 'X64'),
                ],
            )
        ],
  )
