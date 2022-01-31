#!/usr/bin/env python3
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2021, Intel Corporation
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
Main application logic and automation functions
"""

## These are for debugging imports
import inspect
import sys
import fnmatch
import argparse
import json
import os
import re
import platform

import time
import traceback
from collections import OrderedDict
try:
    import zipfile
except ImportError:
    pass

import chipsec.file
import chipsec.module
import chipsec.result_deltas
from chipsec import defines
from chipsec import module_common
from chipsec import chipset
from chipsec.helper import oshelper
from chipsec.logger import logger
from chipsec.testcase import *
from chipsec.exceptions import UnknownChipsetError, OsHelperError

try:
    import importlib
except ImportError:
    pass

class ChipsecMain:

    def __init__(self, argv):
        self.CHIPSEC_FOLDER        = os.path.abspath(chipsec.file.get_main_dir())
        self.CHIPSEC_LOADED_AS_EXE = chipsec.file.main_is_frozen()
        self.PYTHON_64_BITS        = True if (sys.maxsize > 2**32) else False
        self.ZIP_MODULES_RE        = None
        self.Import_Path           = "chipsec.modules."
        self.Modules_Path          = os.path.join(self.CHIPSEC_FOLDER, "chipsec", "modules")
        self.Loaded_Modules        = []
        self.AVAILABLE_TAGS        = []
        self.MODPATH_RE            = re.compile(r"^\w+(\.\w+)*$")
        self.version               = defines.get_version()
        self.message               = defines.get_message()

        self.argv = argv
        self.parse_args()

    def init_cs(self):
        self._cs = chipset.cs()

    def print_banner(self):
        """
        Prints chipsec banner
        """
        logger().log( "################################################################\n"
                      "##                                                            ##\n"
                      "##  CHIPSEC: Platform Hardware Security Assessment Framework  ##\n"
                      "##                                                            ##\n"
                      "################################################################" )
        logger().log( "[CHIPSEC] Version {}".format(self.version) )
        logger().log( "[CHIPSEC] Arguments: {}".format( " ".join(self.argv) ) )
        logger().log( self.message )

    ##################################################################################
    # Module API
    ##################################################################################
    def f_mod(self, x):
        return ( x.find('__init__') == -1 and ZIP_MODULES_RE.match(x) )

    def map_modname(self, x):
        return (x.rpartition('.')[0]).replace('/', '.')
        #return ((x.split('/', 2)[2]).rpartition('.')[0]).replace('/','.')

    def map_pass(self, x):
        return x

    def import_module(self, module_path):
        module = None
        if not self.MODPATH_RE.match(module_path):
            logger().error( "Invalid module path: {}".format(module_path) )
        else:
            try:
                module = importlib.import_module( module_path )
            except BaseException as msg:
                logger().error( "Exception occurred during import of {}: '{}'".format(module_path, str(msg)) )
                if logger().DEBUG: logger().log_bad(traceback.format_exc())
                if self.failfast: raise msg
        return module

    def verify_module_tags(self, module):
        run_it = True      
        module_tags, metadata_tags = module.get_tags()
        if len(metadata_tags) > 0:
            logger().log("[*] Metadata tags: {}".format(metadata_tags))
        if len(self.USER_MODULE_TAGS) > 0 or self._list_tags:
            run_it = False
            for mt in module_tags:
                if self._list_tags:
                    if mt not in self.AVAILABLE_TAGS: self.AVAILABLE_TAGS.append(mt)
                elif mt in  self.USER_MODULE_TAGS:
                    run_it = True
        return run_it


    def run_module( self, modx, module_argv ):
        result = None
        try:
            if not modx.do_import(): return module_common.ModuleResult.ERROR
            if logger().DEBUG and not self._list_tags: logger().log( "[*] Module path: {}".format(modx.get_location()) )

            if self.verify_module_tags( modx ):
                result = modx.run( module_argv )
            else:
                return module_common.ModuleResult.SKIPPED
        except BaseException as msg:
            if logger().DEBUG: logger().log_bad(traceback.format_exc())
            logger().log_error_check( "Exception occurred during {}.run(): '{}'".format(modx.get_name(), str(msg)) )
            raise msg
        return result

    ##
    # full_path can be one of three things:
    # 1. the actual full path to the py or pyc file  i.e. c:\some_path\chipsec\modules\common\bios_wp.py
    # 2. a path to the pyc file inside a zip file    i.e. chipsec/modules/common/bios_wp.pyc
    # 3. the name of the module                      i.e. chipsec.modules.common.bios_wp
    def get_module_name( self, full_path):
        name = full_path
        # case #1, the full path: remove prefix
        if full_path.startswith(self.CHIPSEC_FOLDER +os.path.sep):
            name = full_path.replace ( self.CHIPSEC_FOLDER +os.path.sep, '')
        else:
            for path in self.IMPORT_PATHS:
                if full_path.startswith(os.path.abspath(path) +os.path.sep):
                    name = full_path.replace ( os.path.abspath(path) +os.path.sep, '')
        # case #1 and #2: remove the extension
        if name.lower().endswith('.py'): name = name[:-3]
        if name.lower().endswith('.pyc'): name = name[:-4]
        # case #1: replace slashes with dots
        name = name.replace( os.path.sep, '.' )
        # case #2: when in a zip it is always forward slash
        name = name.replace( '/', '.' )

        # Add 'chipsec.modules.' if shor module name was provided and alternative import paths were not specified
        if [] == self.IMPORT_PATHS and not name.startswith( self.Import_Path ):
            name = self.Import_Path + name

        return name



    #
    # module_path is a file path relative to chipsec
    # E.g. chipsec/modules/common/module.py
    #
    def load_module( self, module_path, module_argv ):
        module_name =  self.get_module_name(module_path)
        module = chipsec.module.Module(module_name)

        if module not in self.Loaded_Modules:
            self.Loaded_Modules.append( (module, module_argv) )
        return True

    def load_modules_from_path( self, from_path, recursive = True ):
        if logger().DEBUG: logger().log( "[*] Path: {}".format(os.path.abspath( from_path )) )
        for dirname, subdirs, mod_fnames in os.walk( os.path.abspath( from_path ) ):
            if not recursive:
                while len(subdirs) > 0:
                    subdirs.pop()
            for modx in mod_fnames:
                if fnmatch.fnmatch( modx, '*.py' ) and not fnmatch.fnmatch( modx, '__init__.py' ):
                    self.load_module( os.path.join( dirname, modx ), self._module_argv )
        self.Loaded_Modules.sort()

    def load_my_modules(self):
        #
        # Step 1.
        # Load modules common to all supported platforms
        #
        common_path = os.path.join( self.Modules_Path, 'common' )
        logger().log( "[*] loading common modules from \"{}\" ..".format(common_path.replace(os.getcwd(), '.')) )
        self.load_modules_from_path( common_path )
        #
        # Step 2.
        # Load platform-specific modules from the corresponding platform module directory
        #
        chipset_path = os.path.join( self.Modules_Path, self._cs.code.lower() )
        if (chipset.CHIPSET_CODE_UNKNOWN != self._cs.code) and os.path.exists( chipset_path ):
            logger().log( "[*] loading platform specific modules from \"{}\" ..".format(chipset_path.replace(os.getcwd(), '.')) )
            self.load_modules_from_path( chipset_path )
        else:
            logger().log( "[*] No platform specific modules to load" )
        #
        # Step 3.
        # Enumerate all modules from the root module directory
        logger().log( "[*] loading modules from \"{}\" ..".format(self.Modules_Path.replace(os.getcwd(), '.')) )
        self.load_modules_from_path( self.Modules_Path, False )

    def load_user_modules(self):
        for import_path in self.IMPORT_PATHS:
            logger().log( "[*] loading modules from \"{}\" ..".format(import_path) )
            self.load_modules_from_path(import_path)

    def clear_loaded_modules(self):
        del self.Loaded_Modules[:]


    def print_loaded_modules(self):
        if self.Loaded_Modules == []:
            logger().log( "No modules have been loaded" )
        for (modx, modx_argv) in self.Loaded_Modules:
            logger().log( "[+] loaded {}".format(modx) )


    def run_loaded_modules(self):

        results          = logger().Results
        results.add_properties(self.properties())

        # Print a list of all loaded modules
        self.print_loaded_modules()
        if not self._list_tags: logger().log( "[*] running loaded modules .." )

        t = time.time()
        for (modx, modx_argv) in self.Loaded_Modules:
            test_result = TestCase(modx.get_name())
            results.add_testcase(test_result)
            logger().start_module( modx.get_name( ) )

            # Run the module
            try:
                result = self.run_module( modx, modx_argv )
            except BaseException:
                results.add_exception(modx)
                result = module_common.ModuleResult.ERROR
                if logger().DEBUG: logger().log_bad(traceback.format_exc())
                if self.failfast: raise

            # Module uses the old API  display warning and try to run anyways
            if result == module_common.ModuleResult.DEPRECATED:
                logger().error( 'Module {} does not inherit BaseModule class'.format(str(modx)) )

            # Populate results

            test_result.add_result( module_common.getModuleResultName(result) )
            if modx_argv: test_result.add_arg( modx_argv )

            logger().end_module( modx.get_name() )

        if self._json_out:
            chipsec.file.write_file(self._json_out, results.json_full())

        if self._xml_out:
            chipsec.file.write_file(self._xml_out, results.xml_full(self._xml_out))

        if self._markdown_out:
            chipsec.file.write_file(self._markdown_out, results.markdown_full(self._markdown_out))

        test_deltas = None
        if self._deltas_file is not None:
            prev_results = chipsec.result_deltas.get_json_results(self._deltas_file)
            if prev_results is None:
                logger().error("Delta processing disabled.  Displaying results summary.")
            else:
                test_deltas = chipsec.result_deltas.compute_result_deltas(prev_results, results.get_results())

        if test_deltas is not None:
            chipsec.result_deltas.display_deltas(test_deltas, self.no_time, t)
        elif not self._list_tags:
            summary = results.order_summary()
            logger().log( "\n[CHIPSEC] ***************************  SUMMARY  ***************************" )
            if not self.no_time:
                logger().log( "[CHIPSEC] Time elapsed            {:.3f}".format(time.time() -t) )
            for k in summary.keys():
                if k == 'total':
                    logger().log( '[CHIPSEC] Modules {:16}{:d}'.format(k, summary[k]) )
                elif k == 'warnings':
                    logger().log( '[CHIPSEC] Modules with {:11}{:d}:'.format(k, len(summary[k])) )
                    for mod in summary[k]:
                        logger().log_warning(mod)
                elif k == 'exceptions':
                    if len(summary[k]) > 0:
                        logger().log( '[CHIPSEC] Modules with {:11}{:d}:'.format(k, len(summary[k])) )
                        for mod in summary[k]:
                            logger().error(mod)
                else:
                    logger().log( '[CHIPSEC] Modules {:16}{:d}:'.format(k, len(summary[k])) )
                    for mod in summary[k]:
                        if k == 'failed to run':
                            logger().error(mod)
                        elif k == 'passed':
                            logger().log_passed(mod)
                        elif k == 'information':
                            logger().log_information(mod)
                        elif k == 'failed':
                            logger().log_failed(mod)
                        elif k == 'not implemented':
                            logger().log_skipped(mod)
                        elif k == 'not applicable':
                            logger().log_not_applicable(mod)
            logger().log ('[CHIPSEC] *****************************************************************')
        else:
            logger().log( "[*] Available tags are:" )
            for at in self.AVAILABLE_TAGS: logger().log("    {}".format(at))

        return results.get_return_code()

    ##################################################################################
    # Running all relevant modules
    ##################################################################################

    def run_all_modules(self):
        if self.CHIPSEC_LOADED_AS_EXE:
            myzip = zipfile.ZipFile( os.path.join(self.CHIPSEC_FOLDER, "library.zip" ))
            global ZIP_MODULES_RE
            ZIP_MODULES_RE = re.compile(r"^chipsec\/modules\/\w+\.pyc$|^chipsec\/modules\/common\/(\w+\/)*\w+\.pyc$|^chipsec\/modules\/" +self._cs.code.lower() +r"\/\w+\.pyc$", re.IGNORECASE|re.VERBOSE)
            zip_modules = []
            zip_modules.extend( map(self.map_pass, filter(self.f_mod, myzip.namelist())) )
            logger().log( "Loaded modules from ZIP:" )
            for zmodx in zip_modules:
                module_name = self.get_module_name(zmodx)
                mod = chipsec.module.Module(module_name)
                logger().log(mod.get_name())
                self.Loaded_Modules.append( (mod, None) )
        else:
            self.load_my_modules()
        self.load_user_modules()

        return self.run_loaded_modules()

    def parse_args(self):
        """Parse the arguments provided on the command line.

        Returns: a pair (continue, exit_code). If continue is False,
          the exit_code should be returned.
        """
        parser = argparse.ArgumentParser(usage='%(prog)s [options]', formatter_class=argparse.RawDescriptionHelpFormatter, epilog=ExitCode.help_epilog, add_help=False)
        options = parser.add_argument_group('Options')
        options.add_argument('-h', '--help', help="show this message and exit", action='store_true')
        options.add_argument('-m', '--module', dest='_module', help='specify module to run (example: -m common.bios_wp)')
        options.add_argument('-a', '--module_args', nargs='*', dest="_module_argv", help="additional module arguments")
        options.add_argument('-v', '--verbose', help='verbose mode', action='store_true')
        options.add_argument('--hal', help='HAL mode', action='store_true')
        options.add_argument('-d', '--debug', help='debug mode', action='store_true')
        options.add_argument('-l', '--log', help='output to log file')
        options.add_argument('-vv', '--vverbose', help='very verbose HAL debug mode', action='store_true')
        adv_options = parser.add_argument_group('Advanced Options')
        adv_options.add_argument('-p', '--platform', dest='_platform', help='explicitly specify platform code', choices=chipset.cs().chipset_codes, type=str.upper)
        adv_options.add_argument('--pch', dest='_pch', help='explicitly specify PCH code', choices=chipset.cs().pch_codes, type=str.upper)
        adv_options.add_argument('-n', '--no_driver', dest='_no_driver', help="chipsec won't need kernel mode functions so don't load chipsec driver", action='store_true')
        adv_options.add_argument('-i', '--ignore_platform', dest='_unknownPlatform', help='run chipsec even if the platform is not recognized', action='store_false')
        adv_options.add_argument('-j', '--json', dest='_json_out', help='specify filename for JSON output')
        adv_options.add_argument('-x', '--xml', dest='_xml_out', help='specify filename for xml output (JUnit style)')
        adv_options.add_argument('-k', '--markdown', dest='_markdown_out', help='specify filename for markdown output')
        adv_options.add_argument('-t', '--moduletype', dest='USER_MODULE_TAGS', help='run tests of a specific type (tag)', type=str.upper, default=[])
        adv_options.add_argument('--list_tags', dest='_list_tags', help='list all the available options for -t,--moduletype', action='store_true')
        adv_options.add_argument('-I', '--include', dest='IMPORT_PATHS', help='specify additional path to load modules from', default=[])
        adv_options.add_argument('--failfast', help="fail on any exception and exit (don't mask exceptions)", action='store_true')
        adv_options.add_argument('--no_time', help="don't log timestamps", action='store_true')
        adv_options.add_argument('--deltas', dest='_deltas_file', help='specifies a JSON log file to compute result deltas from')
        adv_options.add_argument('--record', dest='_to_file', help='run chipsec and clone helper results into JSON file')
        adv_options.add_argument('--replay', dest='_from_file', help='replay a chipsec run with JSON file')
        adv_options.add_argument('--helper', dest='_driver_exists', help='specify OS Helper', choices=[i for i in oshelper.avail_helpers])
        adv_options.add_argument('-nb', '--no_banner', dest='_show_banner', help="chipsec won't display banner information", action='store_false')
        adv_options.add_argument('--skip_config', dest='_load_config', help='skip configuration and driver loading', action='store_false')

        parser.parse_args(self.argv, namespace=ChipsecMain)

        if self.help:
            parser.print_help()
        if self.verbose:
            logger().VERBOSE = True
        if self.hal:
            logger().HAL     = True
        if self.debug:
            logger().DEBUG   = True
        if self.vverbose:
            logger().VERBOSE = True
            logger().DEBUG   = True
            logger().HAL     = True
        if self.log:
            logger().set_log_file( self.log )
        if self._module_argv and len(self._module_argv) == 1 and self._module_argv[0].count(','):
            logger().log( "[*] Use of the -a command no longer needs to have arguments concatenated with ','")
            self._module_argv = self._module_argv[0].split(',')
        if self._unknownPlatform is False:
            logger().log( "[*] Ignoring unsupported platform warning and continue execution" )
        if self._from_file:
            self._driver_exists = "FileHelper"

    def properties( self ):
        ret = OrderedDict()
        ret["OS"] = "{} {} {} {}".format(self._cs.helper.os_system, self._cs.helper.os_release, self._cs.helper.os_version, self._cs.helper.os_machine)
        ret["Python"] = "Python {}".format(platform.python_version())
        ret["Platform"] = "{}, VID: {:04X}, DID: {:04X}, RID: {:02X}".format(self._cs.longname, self._cs.vid, self._cs.did, self._cs.rid)
        if not self._cs.is_atom():
            ret["PCH"] = "{}, VID: {:04X}, DID: {:04X} RID: {:02X}".format(self._cs.pch_longname, self._cs.pch_vid, self._cs.pch_did, self._cs.pch_rid)
        ret["Version"] ="{}".format(self.version)
        ret["Message"] = "{}".format(self.message)
        return ret

    def log_properties( self ):
        logger().log("[CHIPSEC] OS      : {} {} {} {}".format(self._cs.helper.os_system, self._cs.helper.os_release, self._cs.helper.os_version, self._cs.helper.os_machine) )
        logger().log("[CHIPSEC] Python  : {} ({})".format(platform.python_version(), "64-bit" if self.PYTHON_64_BITS else "32-bit"))
        logger().log("[CHIPSEC] Helper  : {} ({})".format(*self._cs.helper.helper.get_info()))
        logger().log("[CHIPSEC] Platform: {}\n[CHIPSEC]      VID: {:04X}\n[CHIPSEC]      DID: {:04X}\n[CHIPSEC]      RID: {:02X}".format(self._cs.longname, self._cs.vid, self._cs.did, self._cs.rid))
        if not self._cs.is_atom():
            logger().log("[CHIPSEC] PCH     : {}\n[CHIPSEC]      VID: {:04X}\n[CHIPSEC]      DID: {:04X}\n[CHIPSEC]      RID: {:02X}".format(self._cs.pch_longname, self._cs.pch_vid, self._cs.pch_did, self._cs.pch_rid))

        if not self.PYTHON_64_BITS and platform.machine().endswith("64"):
            logger().warn("Python architecture (32-bit) is different from OS architecture (64-bit)")

    ##################################################################################
    # Entry point for command-line execution
    ##################################################################################

    def main ( self ):
        if self.help:
            return ExitCode.OK

        self.init_cs()

        if self._show_banner:
            self.print_banner()

        for import_path in self.IMPORT_PATHS:
            sys.path.append(os.path.abspath( import_path ) )

        #if self._no_driver and self._driver_exists:
        #    logger().error( "incompatible options: --no_driver and --exists" )
        #    return ExitCode.EXCEPTION

        if self._load_config:
            try:
                self._cs.init( self._platform, self._pch, (not self._no_driver), self._driver_exists, self._to_file, self._from_file )
            except UnknownChipsetError as msg:
                logger().error( "Platform is not supported ({}).".format(str(msg)) )
                if self._unknownPlatform:
                    logger().error('To specify a cpu please use -p command-line option')
                    logger().error('To specify a pch please use --pch command-line option\n')
                    logger().error('To load legacy configuration and run anyways please use -i command-line option')
                    if logger().DEBUG: logger().log_bad(traceback.format_exc())
                    if self.failfast: raise msg
                    return  ExitCode.EXCEPTION
                logger().warn("Platform dependent functionality is likely to be incorrect")
            except OsHelperError as os_helper_error:
                logger().error(str(os_helper_error))
                if logger().DEBUG: logger().log_bad(traceback.format_exc())
                if self.failfast: raise os_helper_error
                return ExitCode.EXCEPTION
            except BaseException as be:
                logger().log_bad(traceback.format_exc())
                if self.failfast: raise be
                return ExitCode.EXCEPTION
        else:
            logger().warn("Platform dependent functionality is likely to be incorrect")

        if self._show_banner:
            self.log_properties()

        logger().log( " " )

        if logger().DEBUG: logger().log("[*] Running from {}".format(os.getcwd()))

        modules_failed = 0
        if self._module:
            self.load_module( self._module, self._module_argv )
            modules_failed = self.run_loaded_modules()
        else:
            modules_failed = self.run_all_modules()

        self._cs.destroy( (not self._no_driver) )
        del self._cs
        logger().disable()
        return modules_failed

def main(argv=None):
    chipsecMain = ChipsecMain( argv if argv else sys.argv[1:] )
    return chipsecMain.main()

if __name__ == "__main__":
    sys.exit( main() )
