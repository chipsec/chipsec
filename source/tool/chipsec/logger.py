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



# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
# (c) 2010-2012 Intel Corporation
#
# -------------------------------------------------------------------------------
"""
Logging functions
"""

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
            print text
            WConio.textattr( old_setting )

    except ImportError, e:
        #print "WConio package is not installed. No colored output"
        def log_color( fg_color, text ):
            print text

elif "linux" == platform.system().lower():
    def log_color( fg_color, text ):
        #_text = "\033[%dm" + text + "\033[0m" % (fg_color + 30) #FIXME:     _text = "\033[%dm" + text + "\033[0m" % (fg_color + 30) \n TypeError: not all arguments converted during string formatting

        print text #_text

else:
    def log_color( fg_color, text ):
        print text




class LoggerError (RuntimeWarning):
    pass

class Logger:
    """Class for logging to console, text file or XML."""

    def __init__( self ):
        """The Constructor."""
        pass
        self.mytime = localtime()
        self.logfile = None
        self.ALWAYS_FLUSH = False
        #Used for interaction with XML output classes.
        self.xmlAux = xmlAux()
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
                self.logfile = open( self.LOG_FILE_NAME, 'a+' )
                self.LOG_TO_FILE = True
            except None:
                print ("WARNING: Could not open log file '%s'" % name)

    def set_default_log_file( self ):
        """Sets the default log file for the output."""
        # Close current log file if it's opened
        self.disable()
        if not os.path.exists( LOG_PATH ): os.makedirs( LOG_PATH )
        self.LOG_FILE_NAME = os.path.join( LOG_PATH, strftime( '%Y_%m_%d__%H%M%S', self.mytime ) + '.log')
        # Open new log file and keep it opened
        try:
            self.logfile = open( self.LOG_FILE_NAME, 'a+' )
            self.LOG_TO_FILE = True
        except None:
            print ("WARNING: Could not open log file '%s'" % self.LOG_FILE_NAME)

    def set_status_log_file( self ):
        """Sets the status log file for the output."""
        if not os.path.exists(LOG_PATH):
            os.makedirs(LOG_PATH)
        self.LOG_STATUS_FILE_NAME =   os.path.join( LOG_PATH, strftime('%Y_%m_%d__%H%M%S', self.mytime ) + '_results.log')
        self.LOG_TO_STATUS_FILE = True

    def close( self ):
        """Closes the log file."""
        if self.logfile:
            try:
                self.logfile.close()
            except None:
                print 'WARNING: Could not close log file'
            finally:
                self.logfile = None

    def disable( self ):
        """Disables the logging to file and closes the file if any."""
        self.LOG_TO_FILE = False
        self.LOG_FILE_NAME = None
        self.close()
        #self.LOG_TO_STATUS_FILE = False
        #self.LOG_STATUS_FILE_NAME = None

    def __del__(self):
        """Disables the logger."""
        self.disable()

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
        self._log(text, None, None)


    def _log(self, text, color, isStatus):
        """Internal method for logging"""
        if self.LOG_TO_FILE: self._save_to_log_file( text )
        else:
            if color: log_color( color, text )
            else:
                print text
                if self.ALWAYS_FLUSH: sys.stdout.flush()
        if self.xmlAux.useXML: self.xmlAux.append_stdout(text)
        if isStatus: self._save_to_status_log_file( text )

    def error( self, text ):
        """Logs an Error message"""
        text = "ERROR: " + text
        self._log(text, RED, None)

    def warn( self, text ):
        """Logs an Warning message"""
        text = "WARNING: " + text
        self._log(text, YELLOW, None)

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
        """Logs a Test as SKIPPED, this is used for XML output.
           If XML file was not specified, then it will just print a SKIPPED test message.
        """
        self.log_skipped(text)
        self.xmlAux.skipped_check( text )

    def log_warn_check( self, text ):
        """Logs a Warning test, a warning test is considered equal to a PASSED test.
           Logs a Test as PASSED, this is used for XML output."""
        self.log_warning(text)
        self.xmlAux.passed_check()


    def log_passed( self, text ):
        """Logs a passed message."""
        text = "[+] PASSED: " + text
        self._log(text, GREEN, True)

    def log_failed( self, text ):
        """Logs a failed message."""
        text = "[-] FAILED: " + text
        self._log(text, RED, True)

    def log_warning( self, text ):
        """Logs a Warning message"""
        text = "[!] WARNING: " + text
        self._log(text, YELLOW, None)
        #self.xmlAux.passed_check()

    def log_skipped( self, text ):
        """Logs a skipped message."""
        text = "[*] SKIPPED: " + text
        self._log(text, YELLOW, True)

    def log_heading( self, text ):
        """Logs a heading message."""
        self._log(text, BLUE, None)

    def log_important( self, text ):
        """Logs a important message."""
        text = "[!] " + text
        self._log(text, RED, None)

    def log_result( self, text ):
        """Logs a result message."""
        text = "[+] " + text
        self._log(text, GREEN, None)

    def log_bad( self, text ):
        """Logs a bad message, so it calls attention in the information displayed."""
        text = "[-] " + text
        self._log(text, RED, None)

    def log_good( self, text ):
        """Logs a message, if colors available, displays in green."""
        text = "[+] " + text
        self._log(text, GREEN, None)

    def log_unknown( self, text ):
        """Logs a message with a question mark."""
        text = "[?] " + text
        self._log(text, None, None)

    def start_test( self, test_name ):
        """Logs the start point of a Test, this is used for XML output.
           If XML file was not specified, it will just display a banner for the test name.
        """
        text =        "[x][ =======================================================================\n"
        text = text + "[x][ Module: " + test_name + "\n"
        text = text + "[x][ ======================================================================="
        self._log(text, BLUE, True)
        self.xmlAux.start_test( test_name )


    def start_module( self, module_name ):
        """Displays a banner for the module name provided."""
        #text = "\n[*] start module: %s" % module_name
        #self._log(text, WHITE, None)
        self.log( "\n[*] running module: %s" % module_name )
        self.xmlAux.start_module( module_name )

    def end_module( self, module_name ):
        #text = "\n[-] *** Done *** %s" % module_name
        #self._log(text, None, None)
        self.xmlAux.end_module( module_name )

    def _write_log( self, text, filename ):
        print >> self.logfile, text
        if self.ALWAYS_FLUSH:
            # not sure why flush doesn't work as excpected
            # self.logfile.flush()
            # close and re-open log file
            try:
                self.logfile.close()
                self.logfile = open( self.LOG_FILE_NAME, 'a+' )
            except None:
                self.disable()

    def _save_to_status_log_file(self, text):
        if(self.LOG_TO_STATUS_FILE):
            self._write_log(text, self.LOG_STATUS_FILE_NAME)

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
