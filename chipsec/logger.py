#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2020, Intel Corporation
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
Logging functions
"""
import logging as pyLogging
import platform
import string
import binascii
import sys
import os
from time import localtime, strftime
import atexit

from chipsec.testcase import TestCase, ChipsecResults
import traceback
try:
    import WConio
    has_WConio = True
except ImportError:
    has_WConio = False
    #raiseImportError('WConio package not installed. No colored output')

LOG_PATH                = os.path.join( os.getcwd(), "logs" )
#LOG_STATUS_FILE_NAME    = ""
#LOG_COMPLETED_FILE_NAME = ""

class ColorLogger( pyLogging.Formatter ):
    """Colored Output for Python Logging"""

    def format( self, record ):
        message = pyLogging.Formatter.format(self,record)
        message = self.log_color(message,record)
        return message

    if "windows" == platform.system().lower():
        if has_WConio:
            BLACK = WConio.BLACK
            RED = WConio.LIGHTRED
            GREEN = WConio.LIGHTGREEN
            YELLOW = WConio.YELLOW
            BLUE = WConio.LIGHTBLUE
            MAGENTA = WConio.MAGENTA
            CYAN = WConio.CYAN
            WHITE = WConio.WHITE

            LEVEL_ID = {
            pyLogging.DEBUG: GREEN,
            pyLogging.INFO: WHITE,
            pyLogging.WARNING: YELLOW,
            pyLogging.CRITICAL: BLUE,
            pyLogging.ERROR: RED
            }

            def log_color ( self, message, record ):
                """ Testing """
                if record.levelno in self.LEVEL_ID:
                    WConio.textcolor( self.LEVEL_ID[record.levelno] )
                    return message

            old_setting = WConio.gettextinfo()[4] & 0x00FF
            atexit.register(WConio.textcolor, old_setting)

        else:
            def log_color( self, message, record ):
                return message

    elif "linux" == platform.system().lower():
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
        LIGHT_GRAY  = 7
        NORMAL = 8
        WHITE = 9
        csi = '\x1b['
        reset = '\x1b[0m'

        LEVEL_ID = {
            pyLogging.DEBUG: GREEN,
            pyLogging.INFO: WHITE,
            pyLogging.WARNING: YELLOW,
            pyLogging.CRITICAL: BLUE,
            pyLogging.ERROR: RED
            }

        def log_color( self, message, record) :
            if record.levelno in self.LEVEL_ID:
                color = self.LEVEL_ID[record.levelno]
                params = []
                params.append(str(color + 30))
                message = ''.join((self.csi, ';'.join(params),
                                    'm',message,self.reset))
            return message

    else:
        def log_color( self, message, record ):
            return message

class LoggerError (RuntimeWarning):
    pass

class Logger:

    """Class for logging to console, text file, XML."""

    def __init__( self ):
        """The Constructor."""
        self.mytime = localtime()
        self.logfile = None
        self.debug = pyLogging.DEBUG
        self.info = pyLogging.INFO
        self.rootLogger = pyLogging.getLogger(__name__)
        self.rootLogger.setLevel(self.debug)
        self.ALWAYS_FLUSH = False
        pyLogging.addLevelName(15,"verbose")
        self.verbose = 15
        self.logstream = pyLogging.StreamHandler(sys.stdout)
        self.logstream.setFormatter(ColorLogger()) #applys colorization to output
        self.rootLogger.addHandler(self.logstream) #adds streamhandler to root logger
        self.Results = ChipsecResults()

    def set_log_file( self, name=None ):
        """Sets the log file for the output."""
        # Close current log file if it's opened
        self.disable()
        self.LOG_FILE_NAME = name
        # specifying name=None effectively disables logging to file

        if self.LOG_FILE_NAME:
            # Open new log file and keep it opened
            try:
                self.logfile = pyLogging.FileHandler(filename = self.LOG_FILE_NAME,mode='w') #creates FileHandler for log file
                self.rootLogger.addHandler(self.logfile) #adds filehandler to root logger

                self.LOG_TO_FILE = True
            except Exception:
                print("WARNING: Could not open log file '{}'".format(self.LOG_FILE_NAME))
            self.rootLogger.removeHandler(self.logstream)
        else:
            try:
                self.rootLogger.addHandler(self.logstream)
            except:
                pass

    def close( self ):
        """Closes the log file."""
        if self.logfile:
            try:
                self.rootLogger.removeHandler(self.logfile)
                self.rootLogger.removeHandler(self.logstream)
                self.logfile.close()
                self.logstream.flush()
            except Exception:
                print ("WARNING: Could not close log file")
            finally:
                self.logfile = None

    def disable( self ):
        """Disables the logging to file and closes the file if any."""
        self.LOG_TO_FILE = False
        self.LOG_FILE_NAME = None
        self.close()

    ######################################################################
    # Logging functions
    ######################################################################

    def flush(self):
        sys.stdout.flush()
        if self.LOG_TO_FILE and self.logfile is not None:
            # flush should work with new python logging
            try:
                self.rootLogger.removeHandler(self.logfile)
                self.logfile.flush()
                self.rootLogger.addHandler(self.logfile)
            except Exception:
                self.disable()

    def set_always_flush( self, val ):
        self.ALWAYS_FLUSH = val

    def log( self, text, level=pyLogging.INFO):
        """Sends plain text to logging."""
        if self.Results.get_current() is not None:
            self.Results.get_current().add_output(text)
        if self.LOG_TO_FILE: self._save_to_log_file( text )
        else:
            if self.rootLogger:
                self.rootLogger.log(level, text)
                if self.ALWAYS_FLUSH: sys.stdout.flush()
            else:
                print(text)

    def error( self, text ):
        """Logs an Error message"""
        text = "ERROR: " + text
        self.log(text, pyLogging.ERROR)

    def warn( self, text ):
        """Logs an Warning message"""
        text = "WARNING: " + text
        self.log(text, pyLogging.WARNING)

    def verbose_log( self, text):
        """Logs an Verbose message"""
        if self.VERBOSE:
            self.log(text, self.verbose)

    def log_passed_check( self, text ):
        """Logs a Test as PASSED"""
        self.log_passed(text)

    def log_failed_check( self, text ):
        """Logs a Test as FAILED"""
        self.log_failed(text)

    def log_error_check( self, text ):
        """Logs a Test as ERROR"""
        self.error(text)

    def log_skipped_check( self, text ):
        """Logs a Test as Not Implemented"""
        self.log_skipped(text)

    def log_warn_check( self, text ):
        """Logs a Warning test, a warning test is considered equal to a PASSED test"""
        self.log_warning(text)

    def log_information_check( self, text ):
        """Logs a Information test, an information test"""
        self.log_information(text)

    def log_not_applicable_check( self, text):
        """Logs a Test as Not Applicable"""
        self.log_not_applicable(text)

    def log_passed( self, text ):
        """Logs a passed message."""
        text = "[+] PASSED: " + text
        self.log(text, pyLogging.DEBUG)

    def log_failed( self, text ):
        """Logs a failed message."""
        text = "[-] FAILED: " + text
        self.log(text, pyLogging.ERROR)

    def log_warning( self, text ):
        """Logs a Warning message"""
        text = "[!] WARNING: " + text
        self.log(text, pyLogging.WARNING)

    def log_skipped( self, text ):
        """Logs a NOT IMPLEMENTED message."""
        text = "[*] NOT IMPLEMENTED: " + text
        self.log(text, pyLogging.WARNING)

    def log_not_applicable(self, text):
        """Logs a NOT APPLICABLE message."""
        text = "[*] NOT APPLICABLE: " + text
        self.log(text, pyLogging.WARNING)

    def log_heading( self, text ):
        """Logs a heading message."""
        self.log(text, pyLogging.CRITICAL)

    def log_important( self, text ):
        """Logs a important message."""
        text = "[!] " + text
        self.log(text, pyLogging.ERROR)

    def log_result( self, text ):
        """Logs a result message."""
        text = "[+] " + text
        self.log(text, pyLogging.DEBUG)

    def log_bad( self, text ):
        """Logs a bad message, so it calls attention in the information displayed."""
        text = "[-] " + text
        self.log(text, pyLogging.ERROR)

    def log_good( self, text ):
        """Logs a message, if colors available, displays in green."""
        text = "[+] " + text
        self.log(text, pyLogging.DEBUG)

    def log_unknown( self, text ):
        """Logs a message with a question mark."""
        text = "[?] " + text
        self.log(text, pyLogging.INFO)

    def log_information( self, text):
        """Logs a message with information message"""
        text = "[#] INFORMATION: " + text
        self.log(text, pyLogging.DEBUG)

    def start_test( self, test_name ):
        """Logs the start point of a Test"""
        text =        "[x][ =======================================================================\n"
        text = text + "[x][ Module: " + test_name + "\n"
        text = text + "[x][ ======================================================================="
        self.log(text, pyLogging.CRITICAL)

    def start_module( self, module_name ):
        """Displays a banner for the module name provided."""
        text = "\n[*] running module: {}".format(module_name)
        self.log(text, pyLogging.INFO)
        if self.Results.get_current() is not None:
            self.Results.get_current().add_desc(module_name)
            self.Results.get_current().set_time()


    def end_module( self, module_name ):
        if self.Results.get_current() is not None:
            self.Results.get_current().set_time()
        #text = "\n[-] *** Done *** %s" % module_name
        #self._log(text, None, None)

    def _write_log( self, text, filename ):
        self.rootLogger.log(self.info, text) #writes text to defined log file
        if self.ALWAYS_FLUSH:
            # not sure why flush doesn't work as excpected
            # self.logfile.flush()
            # close and re-open log file
            try:
                self.logfile.close()
                self.logfile = open( self.LOG_FILE_NAME, 'a+' )
            except Exception:
                self.disable()

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

def hex_to_text( value ):
    '''Generate text string based on bytestrings'''
    text = binascii.unhexlify('{:x}'.format(value))[::-1]
    if isinstance( text, str ):
        return text   # Python 2.x
    else:
        return text.decode( 'latin-1' )   # Python 3.x


def bytes2string( buffer, length=16 ):
    '''Generate text string based on str with ASCII side panel'''
    output       = []
    num_string   = []
    ascii_string = []
    index        = 1
    for c in buffer:
        num_string += ['{:02X} '.format(ord(c))]
        if ( not (c in string.printable) or (c in string.whitespace) ):
            ascii_string += ['{}'.format(' ')]
        else:
            ascii_string += ['{}'.format(c)]
        if index%length == 0:
            num_string += ['| ']
            num_string += ascii_string
            output.append( ''.join(num_string) )
            ascii_string = []
            num_string   = []
        index += 1
    if 0 != len(buffer)%length:
        num_string += [ (length - len(buffer)%length) * 3*' ' ]
        num_string += ['| ']
        num_string += ascii_string
        output.append( ''.join(num_string) )
    return '\n'.join(output)


def dump_buffer( arr, length = 8 ):
    """Dumps the buffer (str) with ASCII"""
    return bytes2string( arr, length )


def print_buffer( arr, length = 16 ):
    """Prints the buffer (str) with ASCII"""
    prt_str = bytes2string( arr, length )
    logger().log( prt_str )


def dump_buffer_bytes( arr, length = 8):
    """Dumps the buffer (bytes, bytearray) with ASCII"""
    output       = []
    num_string   = []
    ascii_string = []
    index        = 1
    for c in arr:
        num_string += ['{:02X} '.format(c)]
        if ( not (chr(c) in string.printable) or (chr(c) in string.whitespace) ):
            ascii_string += ['{}'.format(' ')]
        else:
            ascii_string += [chr(c)]
        if index%length == 0:
            num_string += ['| ']
            num_string += ascii_string
            output.append( ''.join(num_string) )
            ascii_string = []
            num_string   = []
        index += 1
    if 0 != len(arr)%length:
        num_string += [ (length - len(arr)%length) * 3*' ' ]
        num_string += ['| ']
        num_string += ascii_string
        output.append( ''.join(num_string) )
    return output
    return '\n'.join(output)


def print_buffer_bytes( arr, length = 16 ):
    """Prints the buffer (bytes, bytearray) with ASCII"""
    prt_str = dump_buffer_bytes( arr, length )
    logger().log( prt_str )


def pretty_print_hex_buffer( arr, length = 16 ):
    """Prints the buffer (bytes, bytearray) in a grid"""
    _str = ["    _"]
    for n in range(length):
        _str += ["{:02X}__".format(n)]
    for n in range(len(arr)):
        if n%length == 0: _str += ["\n{:02X} | ".format(n)]
        _str += ["{:02X}  ".format(arr[n])]
    logger().log( ''.join(_str) )


def dump_data( data, length = 16 ):
    """Dumps the buffer with ASCII"""
    if isinstance( data, str ):
        dump_buffer( data, length )
    else:
        dump_buffer_bytes( data, length )


def print_data( data, length = 16 ):
    """Prints the buffer with ASCII"""
    if isinstance( data, str ):
        print_buffer( data, length )
    else:
        print_buffer_bytes( data, length )