#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2014, Intel Corporation
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



#
## \addtogroup core 
# __chipsec_main.py__ -- main application logic and automation functions
#

__version__ = '1.0'

import os
import re
import sys
import fnmatch
import time
import traceback
from inspect import getmembers, isfunction, getargspec

import errno
import chipsec.module_common as module_common

_importlib = True
try:
    import importlib
except ImportError:
    _importlib = False
#import zipfile

from chipsec.logger import logger

version="    "
if os.path.exists('VERSION'):
    with open('VERSION', "r") as verFile:
        version = "." + verFile.read()

logger().log( '' )
logger().log( "################################################################\n"
              "##                                                            ##\n"
              "##  CHIPSEC: Platform Hardware Security Assessment Framework  ##\n"
              "##                                                            ##\n"
              "################################################################" )
logger().log( "version %s\n"% (__version__ + version ) )


from chipsec.module_common import  AVAILABLE_MODULES, DISABLED_MODULES, USER_MODULE_TAGS
from chipsec.helper.oshelper       import OsHelperError
from chipsec.chipset import cs, Chipset_Code, CHIPSET_ID_UNKNOWN, CHIPSET_ID_COMMON, UnknownChipsetError
_cs = cs()

from chipsec.file import *

VERBOSE = False
CHIPSEC_LOADED_AS_EXE = False


##################################################################################
# Module API
##################################################################################

ZIP_MODULES_RE = None
def f_mod(x):
    return ( x.find('__init__') == -1 and ZIP_MODULES_RE.match(x) )

def map_modname(x):
    return (x.rpartition('.')[0]).replace('/','.')
    #return ((x.split('/', 2)[2]).rpartition('.')[0]).replace('/','.')

Import_Path             = "chipsec.modules."
REL_MOD_PATH            = "chipsec" + os.path.sep + "modules"
INSTALL_MOD_PATH_PREFIX = os.path.join( sys.prefix, 'Lib' + os.path.sep + 'site-packages' )
INSTALL_MOD_PATH        = os.path.join( INSTALL_MOD_PATH_PREFIX, 'chipsec' + os.path.sep + 'modules' )

try:
    tool_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir( tool_dir )
except:
    pass

if os.path.exists( REL_MOD_PATH ):
    is_chipsec_installed = False
    Modules_Path = REL_MOD_PATH
else:
    is_chipsec_installed = True
    Modules_Path = INSTALL_MOD_PATH

Loaded_Modules  = []
_list_tags = False
AVAILABLE_TAGS = []

MODPATH_RE      = re.compile("^\w+(\.\w+)*$")

def isModuleDisabled(module_path):
    try:
        if(len(DISABLED_MODULES)>0):
            if(module_path in DISABLED_MODULES[_cs.id]):
                return True
    except KeyError, msg:
        logger().log(str(msg))
    return False

    
def run_module( module_path, module_argv ):  
    module_path = module_path.replace( os.sep, '.' )
    if not MODPATH_RE.match(module_path):
        logger().error( "Invalid module path: %s" % module_path )
        return None  
    else:
        try:
            if _importlib:
                module = importlib.import_module( module_path )
            else:
                #module = __import__(module_path)
                exec 'import ' + module_path
            # removed temporary
            #if isModuleDisabled( module_path ):
            #    logger().error( "Module cannot run on this platform: '%.256s'" % module_path )
            #    return False;
        
        except ImportError, msg:
            logger().error( "Exception occurred during import of %s: '%s'" % (module_path, str(msg)) )
            return None

    run_it = True
    if len(USER_MODULE_TAGS) > 0 or _list_tags:
        run_it = False
        module_tags=[]
        try:
            if _importlib:
                module_tags = getattr( module, 'TAGS' )
            else:
                exec ('module_tags = ' +module_path + '.TAGS')
        except:
            #logger().log(module_path)
            #logger().log_bad(traceback.format_exc())
            pass
        for mt in module_tags:
            if _list_tags:
                if mt not in AVAILABLE_TAGS: AVAILABLE_TAGS.append(mt)
            elif mt in  USER_MODULE_TAGS:
                run_it = True

    if module_argv:
        logger().log( "[*] Module arguments (%d):" % len(module_argv) )
        logger().log( module_argv )
    else:
        module_argv = []
    

    if run_it:
        try:
            result = False
            logger().start_module( module_path )
            if _importlib:
                result = getattr( module, 'run' )( module_argv )
            else:
                exec (module_path + '.run(module_argv)')
            logger().end_module( module_path )
            return result 
        except (None,Exception) , msg:
            if logger().VERBOSE: logger().log_bad(traceback.format_exc())
            logger().log_error_check( "Exception ocurred during %s.run(): '%s'" % (module_path, str(msg)) )
            logger().end_module( module_path )
            return None
    else:
        return module_common.ModuleResult.SKIPPED

#
# module_path is a file path relative to chipsec
# E.g. chipsec/modules/common/module.py
#
def load_module( module_path ):
    if is_chipsec_installed: full_path = os.path.join( INSTALL_MOD_PATH_PREFIX, module_path )
    else:                    full_path = module_path
    if logger().VERBOSE: logger().log( "[*] loading module from '%.256s'" % full_path )  
    if not ( os.path.exists(full_path) and os.path.isfile(full_path) ):
        logger().error( "Module file not found: '%.256s'" % full_path )
        return False

    module_path = module_path.replace( os.path.sep, '.' )[:-3]
    if module_path not in Loaded_Modules:              
        Loaded_Modules.append( module_path )
        if not _list_tags: logger().log( "[+] loaded %s" % module_path ) 
    return True


def unload_module( module_path ):
    if module_path in Loaded_Modules:
        Loaded_Modules.remove( module_path )
    return True


def load_my_modules():
    #
    # Step 1.
    # Load modules common to all supported platforms
    #
    common_path = os.path.join( Modules_Path, 'common' )
    logger().log( "[*] loading common modules from \"%s\" .." % common_path )

    for dirname, subdirs, mod_fnames in os.walk( common_path ):
        for modx in mod_fnames:
            if fnmatch.fnmatch( modx, '*.py' ) and not fnmatch.fnmatch( modx, '__init__.py' ):
                load_module( os.path.join( dirname, modx ) )
    #
    # Step 2.
    # Load platform-specific modules from the corresponding platform module directory
    #
    chipset_path = os.path.join( Modules_Path, _cs.code.lower() )
    if (CHIPSET_ID_UNKNOWN != _cs.id) and os.path.exists( chipset_path ):
        logger().log( "[*] loading platform specific modules from \"%s\" .." % chipset_path )
        for dirname, subdirs, mod_fnames in os.walk( chipset_path ):
            for modx in mod_fnames:
                if fnmatch.fnmatch( modx, '*.py' ) and not fnmatch.fnmatch( modx, '__init__.py' ):
                    load_module( os.path.join( dirname, modx ) )
    else:
        logger().log( "[*] No platform specific modules to load" )
    #
    # Step 3.
    # Enumerate all modules from the root module directory
    # Load modules which support current platform (register themselves with AVAILABLE_MODULES[current_platform_id])
    #
    logger().log( "[*] loading modules from \"%s\" .." % Modules_Path )
    for modx in os.listdir( Modules_Path ):
        if fnmatch.fnmatch(modx, '*.py') and not fnmatch.fnmatch(modx, '__init__.py'):
            __import__( Import_Path + modx.split('.')[0] )
            # removed temporary
            #if isModuleDisabled(modx):
            #    AVAILABLE_MODULES[ _cs.id ][modx.split('.')[0]] = "invalidmodule." + modx.split('.')[0]
                    
    for modx in AVAILABLE_MODULES[ CHIPSET_ID_COMMON ]:
        load_module( os.path.join( Modules_Path, modx + '.py' ) )
    try:
        for modx in AVAILABLE_MODULES[ _cs.id ]:
            load_module( os.path.join( Modules_Path, modx + '.py' ) )
    except KeyError:
        pass
    #print Loaded_Modules

def clear_loaded_modules():
    del Loaded_Modules[:]


def print_loaded_modules():
    if Loaded_Modules == []:
        logger().log( "No modules have been loaded" )
    for modx in Loaded_Modules:
        logger().log( modx )


def run_loaded_modules():
    if not _list_tags:
        logger().log( "[*] running loaded modules .." )
    else:
        logger().log( "\n[*] Available tags are:" )
    t = time.time()
    failed   = []
    errors   = []
    warnings = []
    passed   = []
    skipped  = []
    executed = 0
    
    from chipsec.module_common import ModuleResult
    for modx in Loaded_Modules:
        executed += 1 
        result = run_module( modx, None )
        if None == result or ModuleResult.ERROR == result:
            errors.append( modx )
        elif False == result or ModuleResult.FAILED == result:
            failed.append( modx )
        elif True == result or ModuleResult.PASSED == result:
            passed.append( modx )
        elif ModuleResult.WARNING == result:
            warnings.append( modx )
        elif ModuleResult.SKIPPED == result:
            skipped.append( modx )

    if not _list_tags:
        logger().log( "" )
        logger().log( "[CHIPSEC] ***************************  SUMMARY  ***************************" )
        logger().log( "[CHIPSEC] Time elapsed          %.3f" % (time.time()-t) )
        logger().log( "[CHIPSEC] Modules total         %d" % executed )
        logger().log( "[CHIPSEC] Modules failed to run %d:" % len(errors) )
        for mod in errors: logger().error( mod )
        logger().log( "[CHIPSEC] Modules passed        %d:" % len(passed) )
        for fmod in passed: logger().log_passed( fmod )
        logger().log( "[CHIPSEC] Modules failed        %d:" % len(failed) )
        for fmod in failed: logger().log_failed( fmod )
        logger().log( "[CHIPSEC] Modules with warnings %d:" % len(warnings) )
        for fmod in warnings: logger().log_warning( fmod )
        logger().log( "[CHIPSEC] Modules skipped %d:" % len(skipped) )
        for fmod in skipped: logger().log_skipped( fmod )
        logger().log( "[CHIPSEC] *****************************************************************" )
        logger().log( "[CHIPSEC] Version:   %s"% (__version__ + version ) )
    else:
        for at in AVAILABLE_TAGS:
            logger().log(" - %s"%at)

    return len(failed)



##################################################################################
# Running all chipset configuration security checks
##################################################################################

def run_all_modules():
    if CHIPSEC_LOADED_AS_EXE:
        import zipfile
        myzip = zipfile.ZipFile( "library.zip" )
        global ZIP_MODULES_RE
        ZIP_MODULES_RE = re.compile("^chipsec\/modules\/\w+\.pyc$|^chipsec\/modules\/common\/(\w+\/)*\w+\.pyc$|^chipsec\/modules\/"+_cs.code.lower()+"\/\w+\.pyc$", re.IGNORECASE|re.VERBOSE)
        Loaded_Modules.extend( map(map_modname, filter(f_mod, myzip.namelist())) )
        logger().log( "Loaded modules from ZIP:" )
        print Loaded_Modules
    else:
        load_my_modules()
    return run_loaded_modules()




def usage():
    print "\nUSAGE: %.64s [options]" % sys.argv[0]
    print "OPTIONS:"
    print "-m --module             specify module to run (example: -m common.bios)"
    print "-a --module_args        additional module arguments, format is 'arg0,arg1..'"
    print "-v --verbose            verbose mode"
    print "-l --log                output to log file"  
    print "\nADVANCED OPTIONS:"
    print "-p --platform           platform in [ %s ]" % (" | ".join( ["%.4s" % c for c in Chipset_Code]))
    print "-n --no_driver          chipsec won't need kernel mode functions so don't load chipsec driver"
    print "-i --ignore_platform    run chipsec even if the platform is an unrecognized platform."
    print "-e --exists             chipsec service has already been manually installed and started (driver loaded)."
    print "-x --xml                specify filename for xml output (JUnit style)."
    #Run specific tests help
    print "-t --moduletype         run tests of a specific type (tag)."
    print "--list_tags             list all the available options for -t,--moduletype"

##################################################################################
# Entry point for command-line execution
##################################################################################

if __name__ == "__main__":
    
    import getopt

    try:
        opts, args = getopt.getopt(sys.argv[1:], "ip:m:ho:vea:nl:t:x:",
        ["ignore_platform", "platform=", "module=", "help", "output=", "verbose", "exists", "module_args=", "no_driver", "log=",  "moduletype=", "xml=","list_tags"])
    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit(errno.EINVAL)

    _output      = 'chipsec.log'
    _module      = None
    _module_argv = None
    _platform    = None
    _file        = None
    _start_svc   = True
    _no_driver   = False
    _unkownPlatform = True
    _list_tags   = False

    for o, a in opts:
        if o in ("-v", "--verbose"):
            logger().VERBOSE = True
            logger().log( "[*] Verbose mode is ON (-v command-line option or chipsec_main.logger().VERBOSE in Python console)" )
        elif o in ("-h", "--help"):
            usage()
            sys.exit(0)
        elif o in ("-o", "--output"):
            _output = a
        elif o in ("-p", "--platform"):
            _platform = a.upper()
        elif o in ("-m", "--module"):
            #_module = a.lower()
            _module = a
            if not _module.startswith( Import_Path ):
                _module = Import_Path + _module
        elif o in ("-a", "--module_args"):
            _module_argv = a.split(',')
        elif o in ("-e", "--exists"):
            _start_svc = False
        elif o in ("-i", "--ignore_platform"):
            logger().log( "[*] Ignoring unsupported platform warning and continue execution" )
            _unkownPlatform = False
        #elif o in ("-f", "--file"):
        #    _file = read_file( a )
        elif o in ("-l", "--log"):
            logger().set_log_file( a )
            logger().log( "[*] Log console results to log folder when this mode is ON (-l command-line option or chipsec_main.logger().LOG_TO_COMPLETE_FILE in Python console)" )
            logger().log( "[*] Please check log results in " + logger().LOG_FILE_NAME )
        elif o in ("-t", "--moduletype"):
            usertags = a.upper().split(",")
            for tag in usertags:
                USER_MODULE_TAGS.append(tag)
        elif o in ("-n", "--no_driver"):
            _no_driver = True
        elif o in ("-x", "--xml"):
            logger().set_xml_file(a)
        elif o in ("--list_tags"):
            _list_tags = True
        else:
            assert False, "unknown option"

    # If no driver needed, we won't start/stop service
    if _no_driver: _start_svc = False

    try:
        # If no driver needed, we won't initialize chipset with automatic platform detection
        if not _no_driver: _cs.init( _platform, _start_svc )
    except UnknownChipsetError , msg:
        logger().error( "Platform is not supported (%s)." % str(msg) )
        if _unkownPlatform:
            logger().error( 'To run anyways please use -i command-line option\n\n' )
            if logger().VERBOSE: logger().log_bad(traceback.format_exc())
            sys.exit( errno.ENODEV )
        logger().warn("Platform dependent functionality is likely to be incorrect")
    except OsHelperError as os_helper_error:
        logger().error(str(os_helper_error))
        if logger().VERBOSE: logger().log_bad(traceback.format_exc())
        sys.exit(os_helper_error.errorcode)
    
    logger().log( " " )
    logger().log( "OS      : %s %s %s %s" % (_cs.helper.os_system, _cs.helper.os_release, _cs.helper.os_version, _cs.helper.os_machine) )
    logger().log( "Platform: %s\n          VID: %04X\n          DID: %04X" % (_cs.longname, _cs.vid, _cs.did))
    logger().log( "CHIPSEC : %s"% (__version__ + version ) )
    logger().xmlAux.add_test_suite_property( "OS", "%s %s %s %s" % (_cs.helper.os_system, _cs.helper.os_release, _cs.helper.os_version, _cs.helper.os_machine) )
    logger().xmlAux.add_test_suite_property( "Platform", "%s, VID: %04X, DID: %04X" % (_cs.longname, _cs.vid, _cs.did) )
    logger().xmlAux.add_test_suite_property( "CHIPSEC", "%s"% (__version__ + version ) )
    logger().log( " " )
    module_common.init()

    if logger().VERBOSE: logger().log("[*] Running from %s" % os.getcwd())

    # determine if CHIPSEC is loaded as chipsec.exe or in python
    frozen = hasattr(sys, "frozen") or hasattr(sys, "importers")
    CHIPSEC_LOADED_AS_EXE = True if frozen else False
    
    modules_failed = 0
    if _module:
        _module = _module.replace( os.sep, '.' );
        #if not CHIPSEC_LOADED_AS_EXE: load_module( _module );
        t0 = time.time()    
        result = run_module( _module, _module_argv )
        logger().log( "[CHIPSEC] (%s) time elapsed %.3f" % (_module,time.time()-t0) )
        #if not CHIPSEC_LOADED_AS_EXE: unload_module( _module );
    else:
        modules_failed = run_all_modules()

    logger().saveXML()

    _cs.destroy( _start_svc )
    del _cs
    logger().log("\n")
    
    sys.exit(-modules_failed)
