#!/usr/bin/env python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2018, Intel Corporation
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
import __builtin__
savimp = __builtin__.__import__

def newimp(name, *x):
    caller = inspect.currentframe().f_back
    if 'chipsec' in name:
        print "%-35s -> %s" % (caller.f_globals.get('__name__'), name)
    return savimp(name, *x)
## Uncomment the following line to display  the imports that chipsec calls
#__builtin__.__import__ = newimp
## END DEBUG

import fnmatch
import getopt
import json
import os
import re
import sys
import time
import traceback
try:
    import zipfile
except:
    pass

import chipsec.file
import chipsec.module
import chipsec.result_deltas
from chipsec import defines
from chipsec import module_common
from chipsec import chipset
from chipsec.helper import oshelper
from chipsec.logger import logger

try:
  import importlib
except ImportError:
  pass

class ExitCode:
    OK            = 0
    SKIPPED       = 1
    WARNING       = 2
    DEPRECATED    = 4
    FAIL          = 8
    ERROR         = 16
    EXCEPTION     = 32
    INFORMATION   = 64
    NOTAPPLICABLE = 128
    def __init__(self):
        self._skipped       = False
        self._warning       = False
        self._deprecated    = False
        self._fail          = False
        self._error         = False
        self._exception     = False
        self._information   = False
        self._notapplicable = False

    def skipped(self):       self._skipped = True
    def warning(self):       self._warning = True
    def deprecated(self):    self._deprecated = True
    def fail(self):          self._fail = True
    def error(self):         self._error = True
    def exception(self):     self._exception = True
    def information(self):   self._information = True
    def notapplicable(self): self._notapplicable = True

    def get_code(self):
        exit_code = ExitCode.OK
        if self._skipped:       exit_code = exit_code | ExitCode.SKIPPED
        if self._warning:       exit_code = exit_code | ExitCode.WARNING
        if self._deprecated:    exit_code = exit_code | ExitCode.DEPRECATED
        if self._fail:          exit_code = exit_code | ExitCode.FAIL
        if self._error:         exit_code = exit_code | ExitCode.ERROR
        if self._exception:     exit_code = exit_code | ExitCode.EXCEPTION
        if self._information:   exit_code = exit_code | ExitCode.INFORMATION
        if self._notapplicable: exit_code = exit_code | ExitCode.NOTAPPLICABLE
        return exit_code

    def is_skipped(self):       return self._skipped
    def is_warning(self):       return self._warning
    def is_deprecated(self):    return self._deprecated
    def is_fail(self):          return self._fail
    def is_error(self):         return self._error
    def is_exception(self):     return self._exception
    def is_informaiton(self):   return self._information
    def is_notapplicable(self): return self._notapplicable


    def parse(self, code):
        code = int(code)
        self._skipped       = ( code & ExitCode.SKIPPED )    != 0
        self._warning       = ( code & ExitCode.WARNING )    != 0
        self._deprecated    = ( code & ExitCode.DEPRECATED ) != 0
        self._fail          = ( code & ExitCode.FAIL )       != 0
        self._error         = ( code & ExitCode.ERROR )      != 0
        self._exception     = ( code & ExitCode.EXCEPTION )  != 0
        self._information   = ( code & ExitCode.INFORMATION ) != 0
        self._notapplicable = ( code & ExitCode.NOTAPPLICABLE ) != 0

    def __str__(self):
        return """
        SKIPPED       = %r
        NOTAPPLICABLE = %r
        WARNING       = %r
        DEPRECATED    = %r
        FAIL          = %r
        ERROR         = %r
        EXCEPTION     = %r
        INFORMATION   = %r
        """%(
        self._skipped    ,
        self._warning    ,
        self._deprecated ,
        self._fail       ,
        self._error      ,
        self._exception  ,
        self._information,
        self._notapplicable)


class ChipsecMain:


    def __init__(self, argv):
        self.VERBOSE               = False
        self.CHIPSEC_FOLDER        = os.path.abspath(chipsec.file.get_main_dir())
        self.CHIPSEC_LOADED_AS_EXE = chipsec.file.main_is_frozen()
        self.USER_MODULE_TAGS      = []
        self.ZIP_MODULES_RE        = None
        self.Import_Path           = "chipsec.modules."
        self.Modules_Path          = os.path.join(self.CHIPSEC_FOLDER,"chipsec","modules")
        self.IMPORT_PATHS          = []
        self.Loaded_Modules        = []
        self._list_tags            = False
        self.AVAILABLE_TAGS        = []
        self.MODPATH_RE            = re.compile("^\w+(\.\w+)*$")
        self.failfast              = False
        self.no_time               = False
        self._output               = 'chipsec.log'
        self._module               = None
        self._module_argv          = None
        self._platform             = None
        self._pch                  = None
        self._driver_exists        = False
        self._no_driver            = False
        self._unkownPlatform       = True
        self._list_tags            = False
        self._json_out             = None
        self._deltas_file          = None
        self.version               = defines.get_version()

        self.argv = argv
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
        logger().log( "[CHIPSEC] Version %s" % self.version )
        logger().log( "[CHIPSEC] Arguments: %s"% " ".join(self.argv) )

    ##################################################################################
    # Module API
    ##################################################################################
    def f_mod(self,x):
        return ( x.find('__init__') == -1 and ZIP_MODULES_RE.match(x) )

    def map_modname(self,x):
        return (x.rpartition('.')[0]).replace('/','.')
        #return ((x.split('/', 2)[2]).rpartition('.')[0]).replace('/','.')

    def map_pass(self,x):
        return x

    def import_module(self,module_path):
        module = None
        if not self.MODPATH_RE.match(module_path):
            logger().error( "Invalid module path: %s" % module_path )
        else:
            try:
                module = importlib.import_module( module_path )
            except BaseException, msg:
                logger().error( "Exception occurred during import of %s: '%s'" % (module_path, str(msg)) )
                if logger().DEBUG: logger().log_bad(traceback.format_exc())
                if self.failfast: raise msg
        return module

    def verify_module_tags(self,module):
        run_it = True
        if len(self.USER_MODULE_TAGS) > 0 or self._list_tags:
            run_it = False
            module_tags= module.get_tags()
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
            if logger().DEBUG and not self._list_tags: logger().log( "[*] Module path: %s" % modx.get_location() )

            if self.verify_module_tags( modx ):
                result = modx.run( module_argv )
            else:
                return module_common.ModuleResult.SKIPPED
        except BaseException , msg:
            if logger().DEBUG: logger().log_bad(traceback.format_exc())
            logger().log_error_check( "Exception occurred during %s.run(): '%s'" % (modx.get_name(), str(msg)) )
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
        if full_path.startswith(self.CHIPSEC_FOLDER+os.path.sep):
            name = full_path.replace ( self.CHIPSEC_FOLDER+os.path.sep, '')
        else:
            for path in self.IMPORT_PATHS:
                if full_path.startswith(os.path.abspath(path)+os.path.sep):
                    name = full_path.replace ( os.path.abspath(path)+os.path.sep, '')
        # case #1 and #2: remove the extension
        if name.lower().endswith('.py') : name = name[:-3]
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
            self.Loaded_Modules.append( (module,module_argv) )
            if not self._list_tags: logger().log( "[+] loaded %s" % module.get_name() )
        return True

    def load_modules_from_path( self, from_path, recursive = True ):
        if logger().VERBOSE: logger().log( "[*] Path: %s" % os.path.abspath( from_path ) )
        for dirname, subdirs, mod_fnames in os.walk( os.path.abspath( from_path ) ) :
            if not recursive:
                while len(subdirs) > 0:
                    subdirs.pop()
            for modx in mod_fnames:
                if fnmatch.fnmatch( modx, '*.py' ) and not fnmatch.fnmatch( modx, '__init__.py' ):
                    self.load_module( os.path.join( dirname, modx ), None )

    def load_my_modules(self):
        #
        # Step 1.
        # Load modules common to all supported platforms
        #
        common_path = os.path.join( self.Modules_Path, 'common' )
        logger().log( "[*] loading common modules from \"%s\" .." % common_path.replace(os.getcwd(),'.') )
        self.load_modules_from_path( common_path )
        #
        # Step 2.
        # Load platform-specific modules from the corresponding platform module directory
        #
        chipset_path = os.path.join( self.Modules_Path, self._cs.code.lower() )
        if (chipset.CHIPSET_ID_UNKNOWN != self._cs.id) and os.path.exists( chipset_path ):
            logger().log( "[*] loading platform specific modules from \"%s\" .." % chipset_path.replace(os.getcwd(),'.') )
            self.load_modules_from_path( chipset_path )
        else:
            logger().log( "[*] No platform specific modules to load" )
        #
        # Step 3.
        # Enumerate all modules from the root module directory
        logger().log( "[*] loading modules from \"%s\" .." % self.Modules_Path.replace(os.getcwd(),'.') )
        self.load_modules_from_path( self.Modules_Path, False )


    def load_user_modules(self):
        for import_path in self.IMPORT_PATHS:
            logger().log( "[*] loading modules from \"%s\" .." % import_path )
            self.load_modules_from_path(import_path)

    def clear_loaded_modules(self):
        del self.Loaded_Modules[:]


    def print_loaded_modules(self):
        if self.Loaded_Modules == []:
            logger().log( "No modules have been loaded" )
        for (modx,modx_argv) in self.Loaded_Modules:
            logger().log( modx )


    def run_loaded_modules(self):

        failed        = []
        errors        = []
        warnings      = []
        passed        = []
        skipped       = []
        exceptions    = []
        information   = []
        notapplicable = []
        executed      = 0
        exit_code     = ExitCode()
        results       = {}

        if not self._list_tags: logger().log( "[*] running loaded modules .." )

        t = time.time()
        for (modx,modx_argv) in self.Loaded_Modules:
            executed += 1
            if not self._list_tags: logger().start_module( modx.get_name( ) )

            # Run the module
            try:
                result = self.run_module( modx, modx_argv )
            except BaseException:
                exceptions.append( modx )
                exit_code.exception()
                result = module_common.ModuleResult.ERROR
                if logger().DEBUG: logger().log_bad(traceback.format_exc())
                if self.failfast: raise

            # Module uses the old API  display warning and try to run anyways
            if result == module_common.ModuleResult.DEPRECATED:
                exit_code.deprecated()
                logger().error( 'Module %s does not inherit BaseModule class' % str(modx) )

            # Populate results dictionary to export to JSON
            r = {}
            r['result'] = module_common.getModuleResultName(result)
            if modx_argv: r['arg'] = modx_argv
            results[modx.get_name()] = r

            if not self._list_tags: logger().end_module( modx.get_name() )

            if result is None or module_common.ModuleResult.ERROR == result:
                errors.append( modx )
                exit_code.error()
            elif False == result or module_common.ModuleResult.FAILED == result:
                failed.append( modx )
                exit_code.fail()
            elif True == result or module_common.ModuleResult.PASSED == result:
                passed.append( modx )
            elif module_common.ModuleResult.WARNING == result:
                exit_code.warning()
                warnings.append( modx )
            elif module_common.ModuleResult.SKIPPED == result:
                exit_code.skipped()
                skipped.append( modx )
            elif module_common.ModuleResult.INFORMATION == result:
                information.append( modx )
            elif module_common.ModuleResult.NOTAPPLICABLE == result:
                exit_code.notapplicable()
                notapplicable.append( modx )

        if self._json_out:
            results_json = json.dumps(results, sort_keys=True, indent=2, separators=(',', ': '))
            chipsec.file.write_file(self._json_out, results_json)

        test_deltas = None
        if self._deltas_file is not None:
            prev_results = chipsec.result_deltas.get_json_results(self._deltas_file)
            if prev_results is None:
                logger().error("Delta processing disabled.  Displaying results summary.")
            else:
                test_deltas = chipsec.result_deltas.compute_result_deltas(prev_results, results)

        if test_deltas is not None:
            chipsec.result_deltas.display_deltas(test_deltas, self.no_time, t)
        elif not self._list_tags:
            logger().log( "" )
            logger().log( "[CHIPSEC] ***************************  SUMMARY  ***************************" )
            if not self.no_time:
                logger().log( "[CHIPSEC] Time elapsed          %.3f" % (time.time()-t) )
            logger().log( "[CHIPSEC] Modules total         %d" % executed )
            logger().log( "[CHIPSEC] Modules failed to run %d:" % len(errors) )
            for mod in errors: logger().error( str(mod) )
            logger().log( "[CHIPSEC] Modules passed        %d:" % len(passed) )
            for fmod in passed: logger().log_passed( str(fmod) )
            logger().log( "[CHIPSEC] Modules information   %d:" % len(information) )
            for fmod in information: logger().log_information( str(fmod) )
            logger().log( "[CHIPSEC] Modules failed        %d:" % len(failed) )
            for fmod in failed: logger().log_failed( str(fmod) )
            logger().log( "[CHIPSEC] Modules with warnings %d:" % len(warnings) )
            for fmod in warnings: logger().log_warning( str(fmod) )
            logger().log( "[CHIPSEC] Modules not implemented %d:" % len(skipped) )
            for fmod in skipped: logger().log_skipped( str(fmod) )
            logger().log( "[CHIPSEC] Modules not applicable %d:" % len(notapplicable) )
            for fmod in notapplicable: logger().log_not_applicable( str(fmod) )
            if len(exceptions) > 0:
                logger().log( "[CHIPSEC] Modules with Exceptions %d:" % len(exceptions) )
                for fmod in exceptions: logger().error( str(fmod) )
            logger().log( "[CHIPSEC] *****************************************************************" )
        else:
            logger().log( "[*] Available tags are:" )
            for at in self.AVAILABLE_TAGS: logger().log("    %s"%at)

        return exit_code.get_code()

    ##################################################################################
    # Running all relevant modules
    ##################################################################################

    def run_all_modules(self):
        if self.CHIPSEC_LOADED_AS_EXE:
            myzip = zipfile.ZipFile( os.path.join(self.CHIPSEC_FOLDER, "library.zip" ))
            global ZIP_MODULES_RE
            ZIP_MODULES_RE = re.compile("^chipsec\/modules\/\w+\.pyc$|^chipsec\/modules\/common\/(\w+\/)*\w+\.pyc$|^chipsec\/modules\/"+self._cs.code.lower()+"\/\w+\.pyc$", re.IGNORECASE|re.VERBOSE)
            zip_modules = []
            zip_modules.extend( map(self.map_pass, filter(self.f_mod, myzip.namelist())) )
            logger().log( "Loaded modules from ZIP:" )
            for zmodx in zip_modules:
                module_name = self.get_module_name(zmodx)
                mod = chipsec.module.Module(module_name)
                logger().log(mod.get_name())
                self.Loaded_Modules.append( (mod,None) )
        else:
            self.load_my_modules()
        self.load_user_modules()
        return self.run_loaded_modules()


    def usage(self):
        known_chipsets = "[ " + " | ".join(chipset.Chipset_Code) + " ]"
        known_pch = "[ " + " | ".join(chipset.pch_codes) + " ]"
        max_line_length = max(len(known_chipsets), len(known_pch)) + 1
        print "\n- Command Line Usage\n\t``# %.65s [options]``\n" % sys.argv[0]
        print "Options\n-------"
        print "====================== ====================================================="
        print "-m --module             specify module to run (example: -m common.bios_wp)"
        print "-a --module_args        additional module arguments, format is 'arg0,arg1..'"
        print "-v --verbose            verbose mode"
        print "-d --debug              show debug output"
        print "-l --log                output to log file"
        print "====================== ====================================================="
        print "\nAdvanced Options\n----------------"
        print "======================== " + "=" * max_line_length
        print "-p --platform             explicitly specify platform code. Should be among the supported platforms:"
        print "                          %s" % known_chipsets
        print "   --pch                  explicitly specify PCH code. Should be among the supported PCH:"
        print "                          {}".format(known_pch)
        print "-n --no_driver            chipsec won't need kernel mode functions so don't load chipsec driver"
        print "-i --ignore_platform      run chipsec even if the platform is not recognized"
        print "-j --json                 specify filename for JSON output."
        print "-x --xml                  specify filename for xml output (JUnit style)."
        print "-t --moduletype           run tests of a specific type (tag)."
        print "   --list_tags            list all the available options for -t,--moduletype"
        print "-I --include              specify additional path to load modules from"
        print "   --failfast             fail on any exception and exit (don't mask exceptions)"
        print "   --no_time              don't log timestamps"
        print "   --deltas               specifies a JSON log file to compute result deltas from"
        print "======================== " + "=" * max_line_length
        print "\nExit Code\n---------"
        print "CHIPSEC returns an integer exit code:\n"
        print "- Exit code is 0:       all modules ran successfully and passed"
        print "- Exit code is not 0:   each bit means the following:\n"
        print "    - Bit 0: SKIPPED    at least one module was skipped"
        print "    - Bit 1: WARNING    at least one module had a warning"
        print "    - Bit 2: DEPRECATED at least one module uses deprecated API"
        print "    - Bit 3: FAIL       at least one module failed"
        print "    - Bit 4: ERROR      at least one module wasn't able to run"
        print "    - Bit 5: EXCEPTION  at least one module thrown an unexpected exception"


    def parse_args(self):
        """Parse the arguments provided on the command line.

        Returns: a pair (continue, exit_code). If continue is False,
          the exit_code should be returned.
        """
        try:
            opts, args = getopt.getopt(self.argv, "ip:m:ho:vda:nl:t:j:x:I:",
            ["ignore_platform", "platform=", "pch=", "module=", "help", "output=",
              "verbose", "debug", "module_args=", "no_driver", "log=",
              "moduletype=", "json=", "xml=", "list_tags", "include", "failfast",
              "no_time", "deltas="])
        except getopt.GetoptError, err:
            print str(err)
            self.usage()
            return (False, ExitCode.EXCEPTION)

        for o, a in opts:
            if o in ("-v", "--verbose"):
                logger().VERBOSE = True
                logger().HAL     = True
                logger().DEBUG   = True
            elif o in ("-d", "--debug"):
                logger().DEBUG   = True
            elif o in ("-h", "--help"):
                self.usage()
                return (False, ExitCode.OK)
            elif o in ("-o", "--output"):
                self._output = a
            elif o in ("-p", "--platform"):
                self._platform = a.upper()
            elif o in ("--pch"):
                self._pch = a.upper()
            elif o in ("-m", "--module"):
                #_module = a.lower()
                self._module = a
            elif o in ("-a", "--module_args"):
                self._module_argv = a.split(',')
            elif o in ("-i", "--ignore_platform"):
                logger().log( "[*] Ignoring unsupported platform warning and continue execution" )
                self._unkownPlatform = False
            elif o in ("-l", "--log"):
                #logger().log( "[*] Output to log file '%s' (--log option or chipsec_main.logger().set_log_file in Python console)" % a )
                logger().set_log_file( a )
            elif o in ("-t", "--moduletype"):
                usertags = a.upper().split(",")
                for tag in usertags:
                    self.USER_MODULE_TAGS.append(tag)
            elif o in ("-n", "--no_driver"):
                self._no_driver = True
            elif o in ("-x", "--xml"):
                logger().set_xml_file(a)
            elif o in ("-j", "--json"):
                self._json_out = a
            elif o in ("--list_tags"):
                self._list_tags = True
            elif o in ("-I","--include"):
                self.IMPORT_PATHS.append(a)
            elif o in ("--failfast"):
                self.failfast = True
            elif o in ("--no_time"):
                self.no_time = True
            elif o in ("--deltas"):
                self._deltas_file = a
            else:
                assert False, "unknown option"
        return (True, None)

    ##################################################################################
    # Entry point for command-line execution
    ##################################################################################

    def main ( self ):
        (cont, exit_code) = self.parse_args()
        if not cont:
          return exit_code

        self.print_banner()

        for import_path in self.IMPORT_PATHS:
            sys.path.append(os.path.abspath( import_path ) )

        if self._no_driver and self._driver_exists:
            logger().error( "incompatible options: --no_driver and --exists" )
            return ExitCode.EXCEPTION

        try:
            self._cs.init( self._platform, self._pch, (not self._no_driver), self._driver_exists )
        except chipset.UnknownChipsetError , msg:
            logger().error( "Platform is not supported (%s)." % str(msg) )
            if self._unkownPlatform:
                logger().error( 'To run anyways please use -i command-line option\n\n' )
                if logger().DEBUG: logger().log_bad(traceback.format_exc())
                if self.failfast: raise msg
                return  ExitCode.EXCEPTION
            logger().warn("Platform dependent functionality is likely to be incorrect")
        except oshelper.OsHelperError as os_helper_error:
            logger().error(str(os_helper_error))
            if logger().DEBUG: logger().log_bad(traceback.format_exc())
            if self.failfast: raise os_helper_error
            return ExitCode.EXCEPTION
        except BaseException, be:
            logger().log_bad(traceback.format_exc())
            if self.failfast: raise be
            return ExitCode.EXCEPTION


        logger().log("[CHIPSEC] OS      : %s %s %s %s" % (self._cs.helper.os_system, self._cs.helper.os_release, self._cs.helper.os_version, self._cs.helper.os_machine) )
        logger().log("[CHIPSEC] Platform: %s\n[CHIPSEC]      VID: %04X\n[CHIPSEC]      DID: %04X" % (self._cs.longname, self._cs.vid, self._cs.did))
        logger().log("[CHIPSEC] PCH     : {}\n[CHIPSEC]      VID: {:04X}\n[CHIPSEC]      DID: {:04X}".format(self._cs.pch_longname, self._cs.pch_vid, self._cs.pch_did))
        #logger().log( "[CHIPSEC] CPU affinity: 0x%X" % self._cs.helper.get_affinity() )

        logger().xmlAux.add_test_suite_property("OS", "%s %s %s %s" % (self._cs.helper.os_system, self._cs.helper.os_release, self._cs.helper.os_version, self._cs.helper.os_machine))
        logger().xmlAux.add_test_suite_property("Platform", "%s, VID: %04X, DID: %04X" % (self._cs.longname, self._cs.vid, self._cs.did))
        logger().xmlAux.add_test_suite_property("PCH", "{}, VID: {:04X}, DID: {:04X}".format(self._cs.pch_longname, self._cs.pch_vid, self._cs.pch_did))
        logger().xmlAux.add_test_suite_property("CHIPSEC", "%s" % self.version)
        logger().log( " " )

        if logger().VERBOSE: logger().log("[*] Running from %s" % os.getcwd())

        modules_failed = 0
        if self._module:
            self.load_module( self._module, self._module_argv )
            modules_failed = self.run_loaded_modules()
        else:
            modules_failed = self.run_all_modules()

        logger().saveXML()

        self._cs.destroy( (not self._no_driver) )
        del self._cs
        logger().disable()
        return modules_failed

def main(argv=None):
    chipsecMain = ChipsecMain( argv if argv else sys.argv[1:] )
    return chipsecMain.main()

if __name__ == "__main__":
    sys.exit( main() )
