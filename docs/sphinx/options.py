#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2019, Intel Corporation
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

import os
import sys

cwd = os.path.abspath(os.getcwd())
options_file = os.path.join(cwd, 'options.rst')

if not os.path.isfile(options_file):
    sys.exit(255)

with open(options_file, 'r') as f:
    lines = f.readlines()

new_lines = []
new_lines.append('::\n')
new_lines.append('\n')
for line in lines:
    if '--' in line and line.lstrip().find('--') != 0:
        slice_location = line.find('--')
        new_lines.append('  {}\n'.format(line[:slice_location]))
        new_lines.append('    {}'.format(line[slice_location:]))
    else:
        new_lines.append('  {}'.format(line))
new_lines.append('\n')

with open(options_file, 'w') as f:
    f.writelines(new_lines)

sys.exit(0)
