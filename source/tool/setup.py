#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2015, Intel Corporation
# 
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#



"""
Components for auxiliar tasks. Setup module for installing chipsec with distutils as a package
"""

import os
from setuptools import setup, find_packages
from distutils import dir_util
from chipsec import __version__

data_files = []

tool_dir = os.path.dirname(os.path.abspath(__file__))
build_dir = os.path.join(tool_dir, "build")
if os.path.exists( build_dir ):
    dir_util.remove_tree( build_dir )

setup(
        name            = 'chipsec',
        description     = 'CHIPSEC: Platform Security Assessment Framework',
        version         = __version__,
        author          = 'chipsec developers',
        author_email    = '',
        url             = 'https://github.com/chipsec/chipsec',

        data_files      = data_files,
        packages        = find_packages(exclude=['build']),

)
