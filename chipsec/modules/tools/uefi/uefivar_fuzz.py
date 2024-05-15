# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2022, Intel Corporation
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
The module is fuzzing UEFI Variable interface.

The module is using UEFI SetVariable interface to write new UEFI variables
to SPI flash NVRAM with randomized name/attributes/GUID/data/size.

Usage:
    ``chipsec_main -m tools.uefi.uefivar_fuzz [-a <options>]``

Options:

    ``[-a <test>,<iterations>,<seed>,<test_case>]``

        - ``test``       : UEFI variable interface to fuzz (all, name, guid, attrib, data, size)
        - ``iterations`` : Number of tests to perform (default = 1000)
        - ``seed``       : RNG seed to use
        - ``test_case``  : Test case # to skip to (combined with seed, can be used to skip to failing test)

    All module arguments are optional

Examples::
    >>> chipsec_main.py -m tools.uefi.uefivar_fuzz
    >>> chipsec_main.py -m tools.uefi.uefivar_fuzz -a all,100000
    >>> chipsec_main.py -m tools.uefi.uefivar_fuzz -a data,1000,123456789
    >>> chipsec_main.py -m tools.uefi.uefivar_fuzz -a name,1,123456789,94

.. note::
    - This module returns a WARNING by default to indicate that a manual review is needed.
    - Writes may generate 'ERROR's, this can be expected behavior if the environment rejects them.

.. warning::
    - This module modifies contents of non-volatile SPI flash memory (UEFI Variable NVRAM).
    - This may render system UNBOOTABLE if firmware doesn't properly handle variable update/delete operations.

.. important::
    - Evaluate the platform for expected behavior to determine PASS/FAIL.
    - Behavior can include platform stability and retaining protections.

"""

import random
from time import time
from uuid import uuid4, UUID
import struct

from chipsec.module_common import BaseModule
from chipsec.library.returncode import ModuleResult
from chipsec.library.file import write_file
from chipsec.hal.uefi import UEFI
from chipsec.library.defines import bytestostring

from chipsec.fuzzing import primitives as prim


class uefivar_fuzz(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self._uefi = UEFI(self.cs)

    def is_supported(self):
        supported = self.cs.helper.EFI_supported()
        if not supported:
            self.logger.log_important("OS does not support UEFI Runtime API.  Skipping module.")
        return supported

    def rnd(self, n=1):
        rnum = b''
        for j in range(n):
            rnum += struct.pack("B", random.randint(0, 255))
        return rnum

    def usage(self):
        self.logger.log(__doc__.translate({ord('`'): None}))
        return True

    def run(self, module_argv):
        self.logger.start_test("Fuzz UEFI Variable Interface")

        self.logger.log_warning("Are you sure you want to continue fuzzing UEFI variable interface?")
        s = input("Type 'yes' to continue > ")
        if s.lower() not in ['yes', 'y']:
            return

        # Default options
        _NAME = 'FuzzerVarName'
        _GUID = UUID('414C4694-F4CF-0525-69AF-C99C8596530F')
        _ATTRIB = 0x07
        _SIZE = 0x08
        _DATA = struct.pack("B", 0x41) * _SIZE

        ITERATIONS = 1000
        SEED = int(time())
        CASE = 1
        BOUND_STR = 255  # tested value that can be increased or decreased to fit the limit bounds
        BOUND_INT = 1000

        FUZZ_NAME = True
        FUZZ_GUID = True
        FUZZ_ATTRIB = True
        FUZZ_DATA = True
        FUZZ_SIZE = True

        # Init fuzzing primitives
        name_prim = prim.string(value=_NAME, max_len=BOUND_STR)
        attrib_prim = prim.dword(value=_ATTRIB)  # i think the attrib field is 4 bytes large?
        data_prim = prim.random_data(value=_DATA, min_length=0, max_length=BOUND_INT)

        help_text = False

        if len(module_argv):
            fz_cli = module_argv[0].lower()
            if 'all' != fz_cli:
                FUZZ_NAME = False
                FUZZ_GUID = False
                FUZZ_ATTRIB = False
                FUZZ_DATA = False
                FUZZ_SIZE = False

                if 'name' == fz_cli:
                    FUZZ_NAME = True
                elif 'guid' == fz_cli:
                    FUZZ_GUID = True
                elif 'attrib' == fz_cli:
                    FUZZ_ATTRIB = True
                elif 'data' == fz_cli:
                    FUZZ_DATA = True
                elif 'size' == fz_cli:
                    FUZZ_SIZE = True
                else:
                    help_text = self.usage()

            if len(module_argv) > 1:
                if module_argv[1].isdigit():
                    ITERATIONS = int(module_argv[1])
                else:
                    help_text = self.usage()

            if len(module_argv) > 2:
                if module_argv[2].isdigit():
                    SEED = int(module_argv[2])
                else:
                    help_text = self.usage()

            if len(module_argv) > 3:
                if module_argv[3].isdigit():
                    CASE = int(module_argv[3])
                else:
                    help_text = self.usage()

        if not help_text:
            random.seed(SEED)
            write_file('SEED.txt', str(SEED))

            if not len(module_argv):
                fz_cli = 'all'
            self.logger.log(f'Test      : {fz_cli}')
            self.logger.log(f'Iterations: {ITERATIONS:d}')
            self.logger.log(f'Seed      : {SEED:d}')
            self.logger.log(f'Test case : {CASE:d}')
            self.logger.log('')
            for count in range(1, ITERATIONS + CASE):
                if FUZZ_NAME:
                    _NAME = ''
                    if name_prim.mutate():
                        _NAME = name_prim.render()
                    else:
                        # if mutate() returns false, we need to reload the primitive
                        name_prim = prim.string(value=_NAME, max_len=BOUND_STR)
                        _NAME = name_prim.render()

                if FUZZ_GUID:
                    _GUID = uuid4()

                if FUZZ_ATTRIB:
                    if attrib_prim.mutate():
                        _ATTRIB = attrib_prim.render()
                    else:
                        attrib_prim = prim.dword(value=_ATTRIB)
                        _ATTRIB = attrib_prim.render()

                if FUZZ_DATA:
                    if data_prim.mutate():
                        _DATA = data_prim.render()
                    else:
                        data_prim = prim.random_data(value=_DATA, min_length=0, max_length=BOUND_INT)
                        data_prim.mutate()
                        _DATA = data_prim.render()

                if FUZZ_SIZE:
                    if _DATA:
                        _SIZE = random.randrange(len(_DATA))
                    else:
                        _SIZE = random.randrange(1024)

                if count < CASE:
                    continue

                self.logger.log(f'  Running test #{count:d}:')
                self.logger.flush()
                status = self._uefi.set_EFI_variable(bytestostring(_NAME), str(_GUID), _DATA, _SIZE, _ATTRIB)
                self.logger.log(status)
                status = self._uefi.delete_EFI_variable(bytestostring(_NAME), str(_GUID))
                self.logger.log(status)

        self.logger.log_warning('Fuzzing complete: platform is in an unknown state.')
        self.logger.log_important('Evaluate the platform for expected behavior to determine PASS/FAIL')
        self.logger.log_important('Behavior can include platform stability and retaining protections.')

        self.result.setStatusBit(self.result.status.VERIFY)
        return self.result.getReturnCode(ModuleResult.WARNING)
