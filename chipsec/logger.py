#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2016, Intel Corporation
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



# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
# (c) 2010-2012 Intel Corporation
#
# -------------------------------------------------------------------------------
"""
Logging functions
"""
import logging as pyLogging
import coloredlogs
import platform
import string
import sys
import os
from time import localtime, strftime

from chipsec.xmlout import xmlAux
import traceback


RESET     =0
BRIGHT    =1
DIM       =2
UNDERLINE =3
BLINK     =4
REVERSE   =7
HIDDEN    =8

BLACK     =0
RED       =1
GREEN     =2
YELLOW    =3
BLUE      =4
MAGENTA   =5
CYAN      =6
WHITE     =7

LOG_PATH                = os.path.join( os.getcwd(), "logs" )
#LOG_STATUS_FILE_NAME    = ""
#LOG_COMPLETED_FILE_NAME = ""

#
# Colored output
#
if "windows" == platform.system().lower():

    try:
        import WConio

        COLOR_ID = {
                  BLACK  : WConio.BLACK,
                  RED    : WConio.LIGHTRED,
                  GREEN  : WConio.LIGHTGREEN,
                  YELLOW : WConio.YELLOW,
                  BLUE   : WConio.LIGHTBLUE,
                  MAGENTA: WConio.MAGENTA,
                  CYAN   : WConio.CYAN,
                  WHITE  : WConio.WHITE
                  }

        def log_color( fg_color, text ):
            """
            Store current attribute settings
            """
            old_setting = WConio.gettextinfo()[4] & 0x00FF
            WConio.textattr( COLOR_ID[ fg_color ] )
            print("{}".format(text))
            WConio.textattr( old_setting )

    except ImportError, e:
        #print "WConio package is not installed. No colored output"
        def log_color( fg_color, text ):
            print("{}".format(text))

elif "linux" == platform.system().lower():

    class ColorLogger:
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'
        END = 0
        LIGHT = 90
        DARK  = 30
        BACKGROUND = 40
        LIGHT_BACKGROUND = 100
        GRAY   = 0
        RED    = 1
        GREEN  = 2
        YELLOW = 3
        BLUE   = 4
        PURPLE = 5
        CYAN   = 6
        WHITE  = 7
        NORMAL = 8

        def log_test(self):
            print("{}BOLD{}".format(ColorLogger.BOLD,ColorLogger.ENDC))
            print("{}UNDERLINE{}".format(ColorLogger.UNDERLINE,ColorLogger.ENDC))
            for color_type in (ColorLogger.LIGHT,ColorLogger.DARK,ColorLogger.BACKGROUND,ColorLogger.LIGHT_BACKGROUND):
                for code in xrange(ColorLogger.GRAY, ColorLogger.NORMAL+1):
                    self.log(color_type+code, color_type, code )


        def log(self,msg, color_type=LIGHT,color=8):
            print(ColorLogger.format(msg, color_type, color))

        @staticmethod
        def format(msg, color_type=LIGHT,color=8):
            return ( '\033[%im%s%s'%(color_type+color,str(msg),ColorLogger.ENDC))

    COLOR_ID = {
      BLACK  : ColorLogger.NORMAL,
      RED    : ColorLogger.RED,
      GREEN  : ColorLogger.GREEN,
      YELLOW : ColorLogger.YELLOW,
      BLUE   : ColorLogger.BLUE,
      MAGENTA: ColorLogger.PURPLE,
      CYAN   : ColorLogger.CYAN,
      WHITE  : ColorLogger.WHITE
      }

    """Mapping of log level names to default font styles."""
    coloredlogs.DEFAULT_LEVEL_STYLES = dict(
        spam=dict(color='green', faint=True),
        debug=dict(color='green'),
        verbose=dict(color='magenta'),
        info=dict(),
        notice=dict(color='magenta'),
        warning=dict(color='yellow'),
        success=dict(color='green', bold=coloredlogs.CAN_USE_BOLD_FONT),
        error=dict(color='red'),
        critical=dict(color='blue'))
    

    def log_color( text ):
        """
        Function not used
        """
        #pyLogging.getLogger(__name__) 
        #print ("{}".format(text))
        #coloredlogs.install(fmt='%(message)s',level=pyLogging.DEBUG)
        """
        if fg_color == YELLOW:
            pyLogging.warn(text)                        
        elif fg_color == RED:
            pyLogging.error(text)
        elif fg_color == BLUE:
            pyLogging.critical(text)
        elif fg_color == GREEN:
            pyLogging.debug
        """

else:
    def log_color( fg_color, text ):
        print("{}".format(text))




class LoggerError (RuntimeWarning):
    pass

class Logger:

    
    
    """Class for logging to console, text file or XML."""

    def __init__( self ):
        """The Constructor."""
        pass
        self.mytime = localtime()
        self.logfile = None
        self.logstream = None
        self.logFormatter = coloredlogs.ColoredFormatter("%(message)s")
        self.rootLogger = pyLogging.getLogger(__name__)
        self.ALWAYS_FLUSH = False
        self.DEBUG = pyLogging.DEBUG
        self.INFO = pyLogging.INFO
        self.CRITICAL = pyLogging.CRITICAL
        self.verbose = pyLogging.addLevelName(15,"verbose")
        #Used for interaction with XML output classes.
        self.xmlAux = xmlAux()
        #pyLogging.basicConfig(format=self.logFormatter)
        #self._set_log_files()

    def set_xml_file(self, name=None):
        self.xmlAux.set_xml_file(name)

    def saveXML(self):
        self.xmlAux.saveXML()

    def set_log_file( self, name=None ):
        """Sets the log file for the output."""
        # Close current log file if it's opened
        self.disable()
        self.LOG_FILE_NAME = name
        # specifying name=None effectively disables logging to file
        

        if self.LOG_FILE_NAME:
            # Open new log file and keep it opened
            try:
                logPath = os.getcwd() #gets current working directory

                self.logfile = pyLogging.FileHandler("{0}/{1}".format(logPath, self.LOG_FILE_NAME),mode='w') #creates FileHandler for log file
                self.rootLogger.addHandler(self.logfile) #adds filehandler to root logger
        
                self.logstream = pyLogging.StreamHandler(sys.stdout) #creates stream handler for log output
                self.logstream.setFormatter(self.logFormatter)
                self.rootLogger.addHandler(self.logstream) #adds streamhandler to root logger
                
                self.rootLogger.setLevel(level=self.DEBUG) #sets rootlogger level
                self.LOG_TO_FILE = True

            except None:
                print("WARNING: Could not open log file '{}'".format(self.LOG_FILE_NAME))
    #################################################################
    """
    def set_default_log_file( self ):
        ""Sets the default log file for the output.""
        # Close current log file if it's opened
        self.disable()
        if not os.path.exists( LOG_PATH ): os.makedirs( LOG_PATH )
        self.LOG_FILE_NAME = os.path.join( LOG_PATH, strftime( '%Y_%m_%d__%H%M%S', self.mytime ) + '.log')
        # Open new log file and keep it opened
        try:
            self.logfile = open( self.LOG_FILE_NAME, 'a+' )
            self.LOG_TO_FILE = True
        except None:
            print ("WARNING: Could not open log file '{}'".format(self.LOG_FILE_NAME))
    """
    #################################################################

    #################################################################
    """
    def set_status_log_file( self ):
        ""Sets the status log file for the output.""
        if not os.path.exists(LOG_PATH):
            os.makedirs(LOG_PATH)
        self.LOG_STATUS_FILE_NAME =   os.path.join( LOG_PATH, strftime('%Y_%m_%d__%H%M%S', self.mytime ) + '_results.log')
        self.LOG_TO_STATUS_FILE = True
    """
    #################################################################

    def close( self ):
        """Closes the log file."""
        if self.logfile:
            try:
                self.rootLogger.removeHandler(self.logfile)
                self.logfile.close()                
            except None:
                print ("WARNING: Could not close log file")
            finally:
                self.logfile = None

    def disable( self ):
        """Disables the logging to file and closes the file if any."""
        self.LOG_TO_FILE = False
        self.LOG_FILE_NAME = None
        self.close()
        #self.LOG_TO_STATUS_FILE = False
        #self.LOG_STATUS_FILE_NAME = None

    ######################################################################
    """
    def __del__(self):
        ""Disables the logger.""
        self.disable()
    """
    ######################################################################

    ######################################################################
    # Logging functions
    ######################################################################

    def flush(self):
        sys.stdout.flush()
        if self.LOG_TO_FILE and self.logfile is not None:
            # not sure why flush doesn't work as excpected
            # self.logfile.flush()
            # close and re-open log file
            try:
                self.logfile.close()
                self.logfile = open( self.LOG_FILE_NAME, 'a+' )
            except None:
                self.disable()


    def set_always_flush( self, val ):
        self.ALWAYS_FLUSH = val

    def log( self, text):
        """Sends plain text to logging."""
        
        if self.LOG_TO_FILE: self._save_to_log_file( text )
        else:
            if self.rootLogger:
                coloredlogs.install(fmt='%(message)s',level=pyLogging.DEBUG)
                print ("{}".format(text))
                if self.ALWAYS_FLUSH: sys.stdout.flush()
            else:
                print("{}".format(text))
        if self.xmlAux.useXML: self.xmlAux.append_stdout(text)
        #if isStatus: self._save_to_status_log_file( text ) #status file not used #doesnt affect code
        #self._log(text, None, None)
    
    ##############################################################################
    """  
    def _log(self, text, color, isStatus):
        "Internal method for logging"
        if self.LOG_TO_FILE: self._save_to_log_file( text )
        else:
            if color: log_color( color, text )
            else:
                print ("{}".format(text))
                if self.ALWAYS_FLUSH: sys.stdout.flush()
        if self.xmlAux.useXML: self.xmlAux.append_stdout(text)
        #if isStatus: self._save_to_status_log_file( text ) #status file not used
    """
    ############################################################################
    def error( self, text ):
        """Logs an Error message"""
        text = "ERROR: " + text
        self.rootLogger.error(text)
        #self._log(text, RED, None)

    def warn( self, text ):
        """Logs an Warning message"""
        text = "WARNING: " + text
        self.rootLogger.warning(text)
        #self._log(text, YELLOW, None)
    
    def verbose( self, text):
        """Logs an Verbose message"""
        if self.VERBOSE:
            self.rootLogger.log(self.verbose, text )

    def log_passed_check( self, text ):
        """Logs a Test as PASSED, this is used for XML output.
           If XML file was not specified, then it will just print a PASSED test message.
        """
        self.log_passed(text)
        self.xmlAux.passed_check()

    def log_failed_check( self, text ):
        """Logs a Test as FAILED, this is used for XML output.
           If XML file was not specified, then it will just print a FAILED test message.
        """
        self.log_failed(text)
        self.xmlAux.failed_check( text )

    def log_error_check( self, text ):
        """Logs a Test as ERROR, this is used for XML output.
           If XML file was not specified, then it will just print a ERROR test message.
        """
        self.error(text)
        self.xmlAux.error_check( text )

    def log_skipped_check( self, text ):
        """Logs a Test as Not Implemented, this is used for XML output.
           If XML file was not specified, then it will just print a NOT IMPLEMENTED test message.
        """
        self.log_skipped(text)
        self.xmlAux.skipped_check( text )

    def log_warn_check( self, text ):
        """Logs a Warning test, a warning test is considered equal to a PASSED test.
           Logs a Test as PASSED, this is used for XML output."""
        self.log_warning(text)
        self.xmlAux.passed_check()

    def log_information_check( self, text ):
        """Logs a Information test, an information test.
           Logs a Test as INFORMATION, this is used for XML output."""
        self.log_information(text)
        self.xmlAux.information_check(text)

    def log_not_applicable_check( self, text):
        """Logs a Test as Not Applicable, this is used for XML output.
           If XML file was not specified, then it will just print a NOT APPLICABLE test message """
        self.log_not_applicable(text)
        self.xmlAux.not_applicable_check()


    def log_passed( self, text ):
        """Logs a passed message."""
        text = "[+] PASSED: " + text
        self.rootLogger.debug(text)
        #self._log(text, GREEN, True)

    def log_failed( self, text ):
        """Logs a failed message."""
        text = "[-] FAILED: " + text
        self.rootLogger.error(text)
        #self._log(text, RED, True)

    def log_warning( self, text ):
        """Logs a Warning message"""
        text = "[!] WARNING: " + text
        self.rootLogger.warning(text)
        #self._log(text, YELLOW, None)
        #self.xmlAux.passed_check()

    def log_skipped( self, text ):
        """Logs a NOT IMPLEMENTED message."""
        text = "[*] NOT IMPLEMENTED: " + text
        self.rootLogger.warning(text)
        #self._log(text, YELLOW, True)

    def log_not_applicable(self, text):
        """Logs a NOT APPLICABLE message."""
        text = "[*] NOT APPLICABLE: " + text
        self.rootLogger.warning(text)
        #self._log(text, YELLOW, True)

    def log_heading( self, text ):
        """Logs a heading message."""
        self.rootLogger.critical(text)
        #self._log(text, BLUE, None)

    def log_important( self, text ):
        """Logs a important message."""
        text = "[!] " + text
        self.rootLogger.error(text)
        #self._log(text, RED, None)

    def log_result( self, text ):
        """Logs a result message."""
        text = "[+] " + text
        self.rootLogger.debug(text)
        #self._log(text, GREEN, None)

    def log_bad( self, text ):
        """Logs a bad message, so it calls attention in the information displayed."""
        text = "[-] " + text
        self.rootLogger.error(text)
        #self._log(text, RED, None)

    def log_good( self, text ):
        """Logs a message, if colors available, displays in green."""
        text = "[+] " + text
        self.rootLogger.debug(text)
        #self._log(text, GREEN, None)

    def log_unknown( self, text ):
        """Logs a message with a question mark."""
        text = "[?] " + text
        self.rootLogger.info(text)
        #self._log(text, None, None)

    def log_information( self, text):
        """Logs a message with information message"""
        text = "[#] INFORMATION: " + text
        self.rootLogger.debug(text)
        #self._log(text, GREEN, None)

    def start_test( self, test_name ):
        """Logs the start point of a Test, this is used for XML output.
           If XML file was not specified, it will just display a banner for the test name.
        """
        text =        "[x][ =======================================================================\n"
        text = text + "[x][ Module: " + test_name + "\n"
        text = text + "[x][ ======================================================================="
        self.rootLogger.critical(text)
        #self._log(text, BLUE, True)
        self.xmlAux.start_test( test_name )


    def start_module( self, module_name ):
        """Displays a banner for the module name provided."""
        #text = "\n[*] start module: %s" % module_name
        #self._log(text, WHITE, None)
        text = "\n[*] running module: %s" % module_name
        self.rootLogger.info(text)
        #self.log( "\n[*] running module: %s" % module_name )
        self.xmlAux.start_module( module_name )

    def end_module( self, module_name ):
        #text = "\n[-] *** Done *** %s" % module_name
        #self._log(text, None, None)
        self.xmlAux.end_module( module_name )

    def _write_log( self, text, filename ):
        
        self.rootLogger.log(self.INFO,text) #writes text to defined log file
        
        if self.ALWAYS_FLUSH:
            # not sure why flush doesn't work as excpected
            # self.logfile.flush()
            # close and re-open log file
            try:
                self.logfile.close()
                self.logfile = open( self.LOG_FILE_NAME, 'a+' )
            except None:
                self.disable()

    ########################################################################
    """
    def _save_to_status_log_file(self, text):
        if(self.LOG_TO_STATUS_FILE):
            self._write_log(text, self.LOG_STATUS_FILE_NAME)
    """
    #######################################################################

    def _save_to_log_file(self, text):
        if(self.LOG_TO_FILE):
            self._write_log(text, self.LOG_FILE_NAME)

    VERBOSE    = False
    UTIL_TRACE = False
    HAL        = False
    DEBUG      = False

    LOG_TO_STATUS_FILE   = False
    LOG_STATUS_FILE_NAME = ""
    LOG_TO_FILE          = False
    LOG_FILE_NAME        = ""

_logger  = Logger()
def logger():
    """Returns a Logger instance."""
    return _logger


##################################################################################
# Hex dump functions
##################################################################################

def dump_buffer( arr, length = 8 ):
    """Dumps the buffer."""
    tmp=[]
    tmp_str=[]
    i=1
    for c in arr:
        tmp+=["%2.2x "%ord(c)]
        #if 0xD == ord(c) or 0xA == ord(c):
        if c in string.whitespace:
            ch = " "
        else:
            ch = ord(c)
        tmp_str+=["%c"%ch]
        if i%length==0:
            tmp+=["| "]
            tmp+=tmp_str
            tmp+=["\n"]
            tmp_str=[]
        #print tmp
        #print "\n"
        i+=1
    if 0 != len(arr)%length:
        tmp+=[ (length - len(arr)%length) * 3*" " ]
        tmp+=["| "]
        tmp+=tmp_str
        tmp+=["\n"]
    return "".join(tmp)

def print_buffer( arr, length = 16 ):
    """Prints the buffer."""
    tmp=[]
    tmp_str=[]
    i=1
    for c in arr:
        tmp+=["%2.2x "%ord(c)]
        if (not c in string.printable) or (c in string.whitespace):
            ch = " "
        else:
            ch = ord(c)
        tmp_str+=["%c"%ch]
        if i%length==0:
            tmp+=["| "]
            tmp+=tmp_str
            tmp_s = "".join(tmp)
            logger().log( tmp_s )
            tmp_str=[]
            tmp=[]
        i+=1

    if 0 != len(arr)%length:
        tmp+=[ (length - len(arr)%length) * 3*" " ]
        tmp+=["| "]
        tmp+=tmp_str
        tmp_s = "".join(tmp)
        logger().log( tmp_s )


def pretty_print_hex_buffer( arr, length = 16 ):
    _str = ["    _"]
    for n in xrange(length):
        _str += ["%02X__" % n]
    for n in xrange(len(arr)):
        if n%length == 0: _str += ["\n%02X | " % n]
        _str += ["%02X  " % arr[n]]
    logger().log( ''.join(_str) )
