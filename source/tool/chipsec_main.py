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

__version__ = '1.1.0'


import os
import re
import sys
import fnmatch
import time
import traceback

import errno
import chipsec.file
import chipsec.module

_importlib = True
try:
    import importlib
except ImportError:
    _importlib = False
#import zipfile

from chipsec.logger import logger


CHIPSEC_FOLDER = os.path.abspath(chipsec.file.get_main_dir())
version="    "
VERSION_FILE = os.path.join( CHIPSEC_FOLDER , "VERSION" )
if os.path.exists( VERSION_FILE ):
    with open(VERSION_FILE, "r") as verFile:
        version = verFile.read()
        
def get_chipsec_version():
    return "%s"% (__version__)

logger().log( '' )
logger().log( "################################################################\n"
              "##                                                            ##\n"
              "##  CHIPSEC: Platform Hardware Security Assessment Framework  ##\n"
              "##                                                            ##\n"
              "################################################################" )
logger().log( "Version %s \n" %get_chipsec_version() )



from chipsec.helper.oshelper       import OsHelperError
from chipsec.chipset import cs, Chipset_Code, CHIPSET_ID_UNKNOWN, CHIPSET_ID_COMMON, UnknownChipsetError, AVAILABLE_MODULES, DISABLED_MODULES
_cs = cs()

from chipsec.file import *

VERBOSE = False
CHIPSEC_LOADED_AS_EXE = chipsec.file.main_is_frozen()
USER_MODULE_TAGS = []

##################################################################################
# Module API
##################################################################################

ZIP_MODULES_RE = None
def f_mod(x):
    return ( x.find('__init__') == -1 and ZIP_MODULES_RE.match(x) )

def map_modname(x):
    return (x.rpartition('.')[0]).replace('/','.')
    #return ((x.split('/', 2)[2]).rpartition('.')[0]).replace('/','.')

def map_pass(x):
    return x

Import_Path             = "chipsec.modules."
Modules_Path            = os.path.join(CHIPSEC_FOLDER,"chipsec","modules")
IMPORT_PATHS            = []

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

def import_module(module_path):
    module = None
    if not MODPATH_RE.match(module_path):
        logger().error( "Invalid module path: %s" % module_path )
    else:
        try:
            module = importlib.import_module( module_path )
            # Support for older Python < 2.5
            #if _importlib:
            #    module = importlib.import_module( module_path )
            #else:
            #    #module = __import__(module_path)
            #    exec 'import ' + module_path
        except BaseException, msg:
            logger().error( "Exception occurred during import of %s: '%s'" % (module_path, str(msg)) )
            if logger().VERBOSE: logger().log_bad(traceback.format_exc())
    return module

def verify_module_tags(module):
    run_it = True
    if len(USER_MODULE_TAGS) > 0 or _list_tags:
        run_it = False
        module_tags= module.get_tags()
        for mt in module_tags:
            if _list_tags:
                if mt not in AVAILABLE_TAGS: AVAILABLE_TAGS.append(mt)
            elif mt in  USER_MODULE_TAGS:
                run_it = True
    return run_it


def old_run_module( module_path, module_argv ):
    module_path = module_path.replace( os.sep, '.' )
    module = import_module(module_path)
    if module == None and _importlib: return None
    run_it = True
    if len(USER_MODULE_TAGS) > 0 or _list_tags:
        run_it = False
        module_tags=[]
        try:
            module_tags = getattr( module, 'TAGS' )
            # Support for older Python < 2.5
            #if _importlib:
            #    module_tags = getattr( module, 'TAGS' )
            #else:
            #    exec ('module_tags = ' +module_path + '.TAGS')
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
            result = getattr( module, 'run' )( module_argv )
            # Support for older Python < 2.5
            #if _importlib:
            #    result = getattr( module, 'run' )( module_argv )
            #else:
            #    exec ('result = ' + module_path + '.run(module_argv)')
            return result 
        except (None,Exception) , msg:
            if logger().VERBOSE: logger().log_bad(traceback.format_exc())
            logger().log_error_check( "Exception occurred during %s.run(): '%s'" % (module_path, str(msg)) )
            return None
    else:
        from chipsec.module_common import ModuleResult
        return ModuleResult.SKIPPED
    


def run_module( modx, module_argv ):
    from chipsec.module_common import ModuleResult
    result = None
    try:
        if not modx.do_import(): return ModuleResult.ERROR
        if not _list_tags: logger().log( "[*] Module path: %s" % modx.get_location() )

        if verify_module_tags( modx ):
            result = modx.run( module_argv )
        else:
            return ModuleResult.SKIPPED    
    except (None,Exception) , msg:
        result = ModuleResult.ERROR
        if logger().VERBOSE: logger().log_bad(traceback.format_exc())
        logger().log_error_check( "Exception occurred during %s.run(): '%s'" % (modx.get_name(), str(msg)) )
    return result

## 
# full_path can be one of three things:
# 1. the actual full path to the py or pyc file  i.e. c:\some_path\chipsec\modules\common\bios_wp.py
# 2. a path to the pyc file inside a zip file    i.e. chipsec/modules/common/bios_wp.pyc
# 3. the name of the module                      i.e. chipsec.modules.common.bios_wp
def get_module_name(full_path):
    name = full_path
    # case #1, the full path: remove prefix
    if full_path.startswith(CHIPSEC_FOLDER+os.path.sep):
        name = full_path.replace ( CHIPSEC_FOLDER+os.path.sep, '')
    else:
        for path in IMPORT_PATHS:
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
    if [] == IMPORT_PATHS and not name.startswith( Import_Path ):
        name = Import_Path + name

    return name



#
# module_path is a file path relative to chipsec
# E.g. chipsec/modules/common/module.py
#
def load_module( module_path, module_argv ):
    module_name =  get_module_name(module_path)
    module = chipsec.module.Module(module_name)

    if module not in Loaded_Modules:              
        Loaded_Modules.append( (module,module_argv) )
        if not _list_tags: logger().log( "[+] loaded %s" % module.get_name() ) 
    return True

# @TODO: Fix it!
def unload_module( module_path ):
    if module_path in Loaded_Modules:
        Loaded_Modules.remove( module_path )
    return True

def load_modules_from_path( from_path ):
    if logger().VERBOSE: logger().log_bad( os.path.abspath( from_path ) )
    for dirname, subdirs, mod_fnames in os.walk( os.path.abspath( from_path ) ):
        for modx in mod_fnames:
            if fnmatch.fnmatch( modx, '*.py' ) and not fnmatch.fnmatch( modx, '__init__.py' ):
                load_module( os.path.join( dirname, modx ), None )

def load_my_modules():
    #
    # Step 1.
    # Load modules common to all supported platforms
    #
    common_path = os.path.join( Modules_Path, 'common' )
    logger().log( "[*] loading common modules from \"%s\" .." % common_path.replace(os.getcwd(),'.') )
    load_modules_from_path( common_path )
    #
    # Step 2.
    # Load platform-specific modules from the corresponding platform module directory
    #
    chipset_path = os.path.join( Modules_Path, _cs.code.lower() )
    if (CHIPSET_ID_UNKNOWN != _cs.id) and os.path.exists( chipset_path ):
        logger().log( "[*] loading platform specific modules from \"%s\" .." % chipset_path.replace(os.getcwd(),'.') )
        load_modules_from_path( chipset_path )
    else:
        logger().log( "[*] No platform specific modules to load" )
    #
    # Step 3.
    # Enumerate all modules from the root module directory
    # Load modules which support current platform (register themselves with AVAILABLE_MODULES[current_platform_id])
    #
    logger().log( "[*] loading modules from \"%s\" .." % Modules_Path.replace(os.getcwd(),'.') )
    for modx in os.listdir( os.path.abspath( Modules_Path ) ):
        if fnmatch.fnmatch(modx, '*.py') and not fnmatch.fnmatch(modx, '__init__.py'):
            import_modx = Import_Path + modx.split('.')[0]
            try:
                __import__( import_modx )
            except BaseException, e:
                logger().log_bad("Failed to import module %s : %s"%(import_modx,str(e)))
                raise
            # removed temporary
            #if isModuleDisabled(modx):
            #    AVAILABLE_MODULES[ _cs.id ][modx.split('.')[0]] = "invalidmodule." + modx.split('.')[0]
    for modx in AVAILABLE_MODULES[ CHIPSET_ID_COMMON ]:
        load_module( os.path.join( os.path.abspath( Modules_Path ), modx + '.py' ), None )
    try:
        for modx in AVAILABLE_MODULES[ _cs.id ]:
            load_module( os.path.join( os.path.abspath( Modules_Path ), modx + '.py' ), None )
    except KeyError:
        pass
    #print Loaded_Modules
    
def load_user_modules():
    for import_path in IMPORT_PATHS:
        logger().log( "[*] loading modules from \"%s\" .." % import_path )
        load_modules_from_path(import_path)

def clear_loaded_modules():
    del Loaded_Modules[:]


def print_loaded_modules():
    if Loaded_Modules == []:
        logger().log( "No modules have been loaded" )
    for (modx,modx_argv) in Loaded_Modules:
        logger().log( modx )


def run_loaded_modules():
    from chipsec.module_common import ModuleResult

    failed   = []
    errors   = []
    warnings = []
    passed   = []
    skipped  = []
    executed = 0
    
    if not _list_tags: logger().log( "[*] running loaded modules .." )

    t = time.time()
    for (modx,modx_argv) in Loaded_Modules:
        executed += 1 
        if not _list_tags: logger().start_module( modx.get_name( ) )
        result = run_module( modx, modx_argv )
        if result == ModuleResult.DEPRECATED:
            logger().log_warning( 'Module %s does not inherit BaseModule class. Attempting to locate run function..' % str(modx) )
            result = old_run_module( modx.get_name(), modx_argv )
        if not _list_tags: logger().end_module( modx.get_name() )
        
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
        for mod in errors: logger().error( str(mod) )
        logger().log( "[CHIPSEC] Modules passed        %d:" % len(passed) )
        for fmod in passed: logger().log_passed( str(fmod) )
        logger().log( "[CHIPSEC] Modules failed        %d:" % len(failed) )
        for fmod in failed: logger().log_failed( str(fmod) )
        logger().log( "[CHIPSEC] Modules with warnings %d:" % len(warnings) )
        for fmod in warnings: logger().log_warning( str(fmod) )
        logger().log( "[CHIPSEC] Modules skipped %d:" % len(skipped) )
        for fmod in skipped: logger().log_skipped( str(fmod) )
        logger().log( "[CHIPSEC] *****************************************************************" )
        logger().log( "[CHIPSEC] Version:   %s"% get_chipsec_version() )
    else:
        logger().log( "[*] Available tags are:" )
        for at in AVAILABLE_TAGS: logger().log("    %s"%at)

    return len(failed)



##################################################################################
# Running all chipset configuration security checks
##################################################################################

def run_all_modules():
    if CHIPSEC_LOADED_AS_EXE:
        import zipfile
        myzip = zipfile.ZipFile( os.path.join(CHIPSEC_FOLDER, "library.zip" ))
        global ZIP_MODULES_RE
        ZIP_MODULES_RE = re.compile("^chipsec\/modules\/\w+\.pyc$|^chipsec\/modules\/common\/(\w+\/)*\w+\.pyc$|^chipsec\/modules\/"+_cs.code.lower()+"\/\w+\.pyc$", re.IGNORECASE|re.VERBOSE)
        zip_modules = []
        zip_modules.extend( map(map_pass, filter(f_mod, myzip.namelist())) )
        logger().log( "Loaded modules from ZIP:" )
        for zmodx in zip_modules:
            module_name = get_module_name(zmodx)
            mod = chipsec.module.Module(module_name)
            logger().log(mod.get_name())
            Loaded_Modules.append( (mod,None) )
    else:
        load_my_modules()
    load_user_modules()
    return run_loaded_modules()




def usage():
    print "\nUSAGE: %.65s [options]" % sys.argv[0]
    print "OPTIONS:"
    print "-m --module             specify module to run (example: -m common.bios)"
    print "-a --module_args        additional module arguments, format is 'arg0,arg1..'"
    print "-v --verbose            verbose mode"
    print "-l --log                output to log file"  
    print "\nADVANCED OPTIONS:"
    print "-p --platform           explicitly specify platform code. Should be among the supported platforms:"
    print "                        [ %s ]" % (" | ".join( ["%.4s" % c for c in Chipset_Code]))
    print "-n --no_driver          chipsec won't need kernel mode functions so don't load chipsec driver"
    print "-i --ignore_platform    run chipsec even if the platform is not recognized"
    print "-e --exists             chipsec service has already been manually installed and started (driver loaded)."
    print "-x --xml                specify filename for xml output (JUnit style)."
    print "-t --moduletype         run tests of a specific type (tag)."
    print "   --list_tags          list all the available options for -t,--moduletype"
    print "-I --import             specify additional path to load modules from"

##################################################################################
# Entry point for command-line execution
##################################################################################

if __name__ == "__main__":
    import getopt

    try:
        opts, args = getopt.getopt(sys.argv[1:], "ip:m:ho:vea:nl:t:x:I:",
        ["ignore_platform", "platform=", "module=", "help", "output=",
          "verbose", "exists", "module_args=", "no_driver", "log=",  
          "moduletype=", "xml=","list_tags", "include"])
    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit(errno.EINVAL)

    _output         = 'chipsec.log'
    _module         = None
    _module_argv    = None
    _platform       = None
    _start_svc      = True
    _no_driver      = False
    _unkownPlatform = True
    _list_tags      = False

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
        elif o in ("-a", "--module_args"):
            _module_argv = a.split(',')
        elif o in ("-e", "--exists"):
            _start_svc = False
        elif o in ("-i", "--ignore_platform"):
            logger().log( "[*] Ignoring unsupported platform warning and continue execution" )
            _unkownPlatform = False
        elif o in ("-l", "--log"):
            logger().log( "[*] Output to log file '%s' (--log option or chipsec_main.logger().set_log_file in Python console)" % a )
            logger().set_log_file( a )
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
        elif o in ("-I","--import"):
            IMPORT_PATHS.append(a)
        else:
            assert False, "unknown option"

    for import_path in IMPORT_PATHS:
        sys.path.append(os.path.abspath( import_path ) )

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
    logger().log( "CHIPSEC : %s"% get_chipsec_version() )
    logger().xmlAux.add_test_suite_property( "OS", "%s %s %s %s" % (_cs.helper.os_system, _cs.helper.os_release, _cs.helper.os_version, _cs.helper.os_machine) )
    logger().xmlAux.add_test_suite_property( "Platform", "%s, VID: %04X, DID: %04X" % (_cs.longname, _cs.vid, _cs.did) )
    logger().xmlAux.add_test_suite_property( "CHIPSEC", "%s"% get_chipsec_version() )
    logger().log( " " )

    if logger().VERBOSE: logger().log("[*] Running from %s" % os.getcwd())

    modules_failed = 0
    if _module:
        load_module( _module, _module_argv )
        modules_failed = run_loaded_modules()
        #unload_module( _module );
    else:
        modules_failed = run_all_modules()

    logger().saveXML()

    _cs.destroy( _start_svc )
    del _cs
    
    sys.exit(-modules_failed)
