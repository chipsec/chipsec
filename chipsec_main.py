#!/usr/bin/env python3
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
Main application logic and automation functions
"""

# These are for debugging imports
import sys
import fnmatch
import argparse
import os
import re
import platform

import time
import traceback
from collections import OrderedDict

from typing import Dict, Sequence, Any, Optional

import chipsec.library.file
import chipsec.module
import chipsec.library.result_deltas
from chipsec.library import defines
from chipsec.library.returncode import ModuleResult, getModuleResultName
from chipsec import chipset
from chipsec.helper.oshelper import helper
from chipsec.library.logger import logger
from chipsec.library.banner import print_banner, print_banner_properties
from chipsec.testcase import ExitCode, TestCase, ReturnCodeResults, LegacyResults
from chipsec.library.exceptions import UnknownChipsetError, OsHelperError
from chipsec.library.options import Options
from chipsec.library.module_helper import enumerate_modules, print_modules

try:
    import importlib
except ImportError:
    pass


def parse_args(argv: Sequence[str]) -> Optional[Dict[str, Any]]:
    options = Options()

    default_helper = options.get_section_data('Main_Config', 'default_helper', None)

    """Parse the arguments provided on the command line."""
    parser = argparse.ArgumentParser(usage='%(prog)s [options]', formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=ExitCode.help_epilog, add_help=False)
    options = parser.add_argument_group('Options')
    options.add_argument('-h', '--help', help="Show this message and exit", action='store_true')
    options.add_argument('-m', '--module', dest='_module', help='Specify module to run (example: -m common.bios_wp)')
    options.add_argument('-mx', '--module_exclude', dest='_module_exclude', nargs='+', help='Specify module(s) to NOT run (example: -mx common.bios_wp common.cpu.cpu_info)')
    options.add_argument('-a', '--module_args', nargs='*', dest="_module_argv", help="Additional module arguments")
    options.add_argument('-v', '--verbose', help='Verbose logging', action='store_true')
    options.add_argument('--hal', help='HAL logging', action='store_true')
    options.add_argument('-d', '--debug', help='Debug logging', action='store_true')
    options.add_argument('-l', '--log', help='Output to log file')
    options.add_argument('-vv', '--vverbose', help='Very verbose logging (verbose + HAL + debug)', action='store_true')
    adv_options = parser.add_argument_group('Advanced Options')
    adv_options.add_argument('-p', '--platform', dest='_platform', help='Explicitly specify platform code',
                             choices=chipset.cs().Cfg.proc_codes, type=str.upper)
    adv_options.add_argument('--pch', dest='_pch', help='Explicitly specify PCH code', choices=chipset.cs().Cfg.pch_codes, type=str.upper)
    adv_options.add_argument('-n', '--no_driver', dest='_no_driver', action='store_true',
                             help="Chipsec won't need kernel mode functions so don't load chipsec driver")
    adv_options.add_argument('-i', '--ignore_platform', dest='_ignore_platform', action='store_true',
                             help='Run chipsec even if the platform is not recognized (Deprecated)')
    adv_options.add_argument('--csv', dest='_csv_out', help='Specify filename for CSV output')
    adv_options.add_argument('-j', '--json', dest='_json_out', help='Specify filename for JSON output')
    adv_options.add_argument('-x', '--xml', dest='_xml_out', help='Specify filename for xml output (JUnit style)')
    adv_options.add_argument('-k', '--markdown', dest='_markdown_out', help='Specify filename for markdown output')
    adv_options.add_argument('-t', '--moduletype', dest='USER_MODULE_TAGS', type=str.upper, default=[], help='Run tests of a specific type (tag)')
    adv_options.add_argument('--list_tags', dest='_list_tags', action='store_true', help='List all the available options for -t,--moduletype')
    adv_options.add_argument('-lm','--list_modules', dest='_list_modules', action='store_true', help='List all the available options for -m,--module/-mx,--module_exclude')
    adv_options.add_argument('-I', '--include', dest='IMPORT_PATHS', default=[], help='Specify additional path to load modules from')
    adv_options.add_argument('--failfast', help="Fail on any exception and exit (don't mask exceptions)", action='store_true')
    adv_options.add_argument('--no_time', help="Don't log timestamps", action='store_true')
    adv_options.add_argument('--deltas', dest='_deltas_file', help='Specifies a JSON log file to compute result deltas from')
    adv_options.add_argument('--helper', dest='_helper', help='Specify OS Helper', choices=helper().get_available_helpers(), default=default_helper)
    adv_options.add_argument('-nb', '--no_banner', dest='_show_banner', action='store_false', help="Chipsec won't display banner information")
    adv_options.add_argument('--skip_config', dest='_load_config', action='store_false', help='Skip configuration and driver loading')
    adv_options.add_argument('-nl', dest='_autolog_disable', action='store_true', help="Chipsec won't save logs automatically")
    adv_options.add_argument('-rc', dest='_return_codes', help='Return codes mode', action='store_true')

    par = vars(parser.parse_args(argv))
    if par['help']:
        if par['_show_banner']:
            print_banner(argv, defines.get_version(), defines.get_message())
        parser.print_help()
        return None
    elif par['_list_modules']:
        print_modules(enumerate_modules())
        return None
    else:
        return par


class ChipsecMain:

    def __init__(self, switches, argv):
        self.logger = logger()
        self.CHIPSEC_FOLDER = chipsec.library.file.get_main_dir()
        self.PYTHON_64_BITS = True if (sys.maxsize > 2**32) else False
        self.Import_Path = "chipsec.modules."
        self.Modules_Path = chipsec.library.file.get_module_dir()
        self.Loaded_Modules = []
        self.AVAILABLE_TAGS = []
        self.MODPATH_RE = re.compile(r"^\w+(\.\w+)*$")
        self.version = defines.get_version()
        self.message = defines.get_message()
        self.__dict__.update(switches)
        self.argv = argv
        self._cs = chipset.cs()
        self.parse_switches()

    ##################################################################################
    # Module API
    ##################################################################################

    def import_module(self, module_path):
        module = None
        if not self.MODPATH_RE.match(module_path):
            self.logger.log_error(f'Invalid module path: {module_path}')
        else:
            try:
                module = importlib.import_module(module_path)
            except BaseException as msg:
                self.logger.log_error(f'Exception occurred during import of {module_path}: "{str(msg)}"')
                if self.logger.DEBUG:
                    self.logger.log_bad(traceback.format_exc())
                if self.failfast:
                    raise msg
        return module

    def verify_module_tags(self, module):
        run_it = True
        module_tags, metadata_tags = module.get_tags()
        if len(metadata_tags) > 0:
            self.logger.log(f'[*] Metadata tags: {metadata_tags}')
        if len(self.USER_MODULE_TAGS) > 0 or self._list_tags:
            run_it = False
            for mt in module_tags:
                if self._list_tags:
                    if mt not in self.AVAILABLE_TAGS:
                        self.AVAILABLE_TAGS.append(mt)
                elif mt in self.USER_MODULE_TAGS:
                    run_it = True
        return run_it

    ##
    # full_path can be one of three things:
    # 1. the actual full path to the py or pyc file  i.e. c:\some_path\chipsec\modules\common\bios_wp.py
    # 2. a path to the pyc file inside a zip file    i.e. chipsec/modules/common/bios_wp.pyc
    # 3. the name of the module                      i.e. chipsec.modules.common.bios_wp
    def get_module_name(self, full_path):
        name = full_path.lower()
        # case #1, the full path: remove prefix
        if full_path.startswith(self.CHIPSEC_FOLDER + os.path.sep):
            name = full_path.replace(self.CHIPSEC_FOLDER + os.path.sep, '')
        else:
            for path in self.IMPORT_PATHS:
                if full_path.startswith(os.path.abspath(path) + os.path.sep):
                    name = full_path.replace(os.path.abspath(path) + os.path.sep, '')
        # case #1 and #2: remove the extension
        if name.lower().endswith('.py'):
            name = name[:-3]
        if name.lower().endswith('.pyc'):
            name = name[:-4]
        # case #1: replace slashes with dots
        name = name.replace(os.path.sep, '.')
        # case #2: when in a zip it is always forward slash
        name = name.replace('/', '.')

        # Add 'chipsec.modules.' if shor module name was provided and alternative import paths were not specified
        if [] == self.IMPORT_PATHS and not name.startswith(self.Import_Path):
            name = self.Import_Path + name

        return name

    #
    # module_path is a file path relative to chipsec
    # E.g. chipsec/modules/common/module.py
    #
    def load_module(self, module_path, module_argv):
        module_name = self.get_module_name(module_path)
        module = chipsec.module.Module(module_name)

        if module not in self.Loaded_Modules:
            if self._module_exclude:
                if not [i for i in self._module_exclude if i in module.name]:
                    self.Loaded_Modules.append((module, module_argv))
            else:
                self.Loaded_Modules.append((module, module_argv))
        return True

    def load_modules_from_path(self, from_path, recursive=True):
        if self.logger.DEBUG:
            self.logger.log(f'[*] Path: {os.path.abspath(from_path)}')
        for dirname, subdirs, mod_fnames in os.walk(os.path.abspath(from_path)):
            if not recursive:
                while len(subdirs) > 0:
                    subdirs.pop()
            for modx in mod_fnames:
                if fnmatch.fnmatch(modx, '*.py') and not fnmatch.fnmatch(modx, '__init__.py'):
                    self.load_module(os.path.join(dirname, modx), self._module_argv)
        self.Loaded_Modules.sort()

    def load_my_modules(self):
        #
        # Step 1.
        # Load modules common to all supported platforms
        #
        common_path = os.path.join(self.Modules_Path, 'common')
        self.logger.log(f'[*] loading common modules from "{common_path.replace(os.getcwd(), ".")}" ..')
        self.load_modules_from_path(common_path)
        #
        # Step 2.
        # Load platform-specific modules from the corresponding platform module directory
        #
        chipset_path = os.path.join(self.Modules_Path, self._cs.Cfg.code.lower())
        if (chipset.CHIPSET_CODE_UNKNOWN != self._cs.Cfg.code) and os.path.exists(chipset_path):
            self.logger.log(f'[*] loading platform specific modules from \"{chipset_path.replace(os.getcwd(), ".")}\" ..')
            self.load_modules_from_path(chipset_path)
        else:
            self.logger.log("[*] No platform specific modules to load")
        #
        # Step 3.
        # Enumerate all modules from the root module directory
        #
        self.logger.log(f'[*] loading modules from \"{self.Modules_Path.replace(os.getcwd(), ".")}\" ..')
        self.load_modules_from_path(self.Modules_Path, False)

    def load_user_modules(self):
        for import_path in self.IMPORT_PATHS:
            self.logger.log(f'[*] loading modules from \"{import_path}\" ..')
            self.load_modules_from_path(import_path)

    def clear_loaded_modules(self):
        del self.Loaded_Modules[:]

    def print_loaded_modules(self):
        if self.Loaded_Modules == []:
            self.logger.log("No modules have been loaded")
        for (modx, _) in self.Loaded_Modules:
            self.logger.log(f'[+] loaded {modx}')

    def run_module(self, modx, module_argv):
        result = None
        try:
            if not modx.do_import():
                return ModuleResult.ERROR
            if self.logger.DEBUG and not self._list_tags:
                self.logger.log(f'[*] Module path: {modx.get_location()}')

            if self.verify_module_tags(modx):
                result = modx.run(module_argv)
            else:
                modx.mod_obj.result.setStatusBit(modx.mod_obj.result.status.NOT_APPLICABLE)
                return modx.mod_obj.result.getReturnCode(ModuleResult.NOTAPPLICABLE)
        except BaseException as msg:
            if self.logger.DEBUG:
                self.logger.log_bad(traceback.format_exc())
            self.logger.log_error(f'Exception occurred during {modx.get_name()}.run(): \'{str(msg)}\'')
            raise msg
        return result
    
    def run_loaded_modules(self):
        results = ReturnCodeResults() if self._return_codes else LegacyResults()
        results.add_properties(self.properties())

        # Print a list of all loaded modules
        self.print_loaded_modules()
        if not self._list_tags:
            self.logger.log("[*] running loaded modules ..")

        t = time.time()
        for (modx, modx_argv) in self.Loaded_Modules:
            test_result = TestCase(modx.get_name())
            test_result.start_module()

            # Run the module
            try:
                result = self.run_module(modx, modx_argv)
            except BaseException:
                results.add_exception(modx)
                result = ModuleResult.ERROR
                if self.logger.DEBUG:
                    self.logger.log_bad(traceback.format_exc())
                if self.failfast:
                    raise

            # Populate results
            test_result.end_module(getModuleResultName(result, self._return_codes), result, modx_argv if modx_argv else None)
            results.add_testcase(test_result)

        runtime = time.time() - t if not self.no_time else None

        if self._json_out:
            chipsec.library.file.write_file(self._json_out, results.json_full())

        if self._xml_out:
            chipsec.library.file.write_file(self._xml_out, results.xml_full(self._xml_out, runtime))

        if self._markdown_out:
            chipsec.library.file.write_file(self._markdown_out, results.markdown_full(self._markdown_out))

        if self._csv_out:
            self.logger.log_csv(self._csv_out, results.test_cases)

        test_deltas = None
        if self._deltas_file is not None:
            prev_results = chipsec.library.result_deltas.get_json_results(self._deltas_file)
            if prev_results is None:
                self.logger.log_error("Delta processing disabled.  Displaying results summary.")
            else:
                test_deltas = chipsec.library.result_deltas.compute_result_deltas(prev_results, results.get_results())
                chipsec.library.result_deltas.display_deltas(test_deltas, self.no_time, t)
        elif not self._list_tags and results.get_current_testcase is not None:
            results.print_summary(runtime)
        else:
            self.logger.log("[*] Available tags are:")
            for at in self.AVAILABLE_TAGS:
                self.logger.log(f'    {at}')

        return results.get_return_code()

    ##################################################################################
    # Running all relevant modules
    ##################################################################################

    def run_all_modules(self):
        self.load_my_modules()
        self.load_user_modules()

        return self.run_loaded_modules()

    def parse_switches(self) -> None:
        """Configure logging parameters based on arguments"""
        self.logger.set_log_level(self.verbose, self.hal, self.debug, self.vverbose)
        if self.log:
            self.logger.set_log_file(self.log)
            self._autolog_disable = True
        if self._autolog_disable is False:
            self.logger.set_autolog_file()
        if self._return_codes:
            self.logger.log_warning("Return codes feature is currently Work in Progress!!!")
            self._cs.using_return_codes = True
        if self._module_argv and len(self._module_argv) == 1 and self._module_argv[0].count(','):
            self.logger.log("[*] Use of the -a command no longer needs to have arguments concatenated with ','")
            self._module_argv = self._module_argv[0].split(',')
        if self._ignore_platform:
            self.logger.log_warning("Ignoring unsupported platform warning and continue execution.")
            self.logger.log_warning("Most results cannot be trusted.")
            self.logger.log_warning("Unless a platform independent module is being run, do not file issues against this run.")


    def properties(self):
        ret = OrderedDict()
        ret["OS"] = f'{self._cs.helper.os_system} {self._cs.helper.os_release} {self._cs.helper.os_version} {self._cs.helper.os_machine}'
        ret["Python"] = f'Python {platform.python_version()}'
        ret["Platform"] = f'{self._cs.Cfg.longname}, CPUID: {self._cs.Cfg.cpuid}, VID: {self._cs.Cfg.vid:04X}, DID: {self._cs.Cfg.did:04X}, RID: {self._cs.Cfg.rid:02X}'
        if not self._cs.is_atom():
            ret["PCH"] = f'{self._cs.Cfg.pch_longname}, VID: {self._cs.Cfg.pch_vid:04X}, DID: {self._cs.Cfg.pch_did:04X} RID: {self._cs.Cfg.pch_rid:02X}'
        ret["Version"] = f'{self.version}'
        ret["Message"] = f'{self.message}'
        return ret

    ##################################################################################
    # Entry point for command-line execution
    ##################################################################################

    def main(self) -> int:

        if self._show_banner:
            print_banner(self.argv, defines.get_version(), defines.get_message())

        for import_path in self.IMPORT_PATHS:
            sys.path.append(os.path.abspath(import_path))

        try:
            self._cs.init(self._platform, self._pch, self._helper, not self._no_driver, self._load_config, self._ignore_platform)
        except UnknownChipsetError as msg:
            self.logger.log_error(f'Platform is not supported ({str(msg)}).')
            if self._ignore_platform:
                self.logger.log_error('To specify a cpu please use -p command-line option')
                self.logger.log_error('To specify a pch please use --pch command-line option\n')
                self.logger.log_error('If the correct configuration is not loaded, results should not be trusted.')
                if self.logger.DEBUG:
                    self.logger.log_bad(traceback.format_exc())
                if self.failfast:
                    raise msg
                return ExitCode.EXCEPTION
            self.logger.log_warning("Platform dependent functionality is likely to be incorrect")
        except OsHelperError as os_helper_error:
            self.logger.log_error(str(os_helper_error))
            if self.logger.DEBUG:
                self.logger.log_bad(traceback.format_exc())
            if self.failfast:
                raise os_helper_error
            return ExitCode.EXCEPTION
        except BaseException as be:
            self.logger.log_bad(traceback.format_exc())
            if self.failfast:
                raise be
            return ExitCode.EXCEPTION

        if self._show_banner:
            print_banner_properties(self._cs, defines.os_version())

        self.logger.log(" ")

        if self.logger.DEBUG:
            self.logger.log(f'[*] Running from {os.getcwd()}')

        self.main_return = 0
        if self._module:
            self.load_module(self._module, self._module_argv)
            self.main_return = self.run_loaded_modules()
        else:
            self.main_return = self.run_all_modules()
        if not self._no_driver:
            self._cs.destroy_helper()
        del self._cs
        self.logger.disable()
        return self.main_return

def run(cli_cmd: str = '') -> int:
    cli_cmds = []
    if cli_cmd:
        cli_cmds = cli_cmd.strip().split(' ')
    return main(cli_cmds)

def main(argv: Sequence[str] = sys.argv[1:]) -> int:
    par = parse_args(argv)
    if par is not None:
        chipsecMain = ChipsecMain(par, argv)
        return chipsecMain.main()
    return ExitCode.OK


if __name__ == "__main__":
    sys.exit(main())
