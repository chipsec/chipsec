# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
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
Logging functions
"""
import logging as pyLogging
import platform
import string
import binascii
import sys
import os
import atexit
from typing import Tuple, Dict
from time import localtime, strftime

from chipsec.testcase import ChipsecResults

try:
    # Prefer WConio2 over the original WConio as it is more up-to-date and better maintained.
    # See https://pypi.org/project/WConio2/ for more details.
    import WConio2 as WConio
    has_WConio = True
except ImportError:
    try:
        import WConio
        has_WConio = True
    except ImportError:
        has_WConio = False

LOG_PATH = os.path.join(os.getcwd(), "logs")


class chipsecrecordfactory(pyLogging.LogRecord):
    try:
        is_atty = sys.stdout.isatty()
    except AttributeError:
        is_atty = False
    if is_atty and os.getenv('NO_COLOR') is None and \
       (("windows" == platform.system().lower() and has_WConio) or "linux" == platform.system().lower()):
        if "windows" == platform.system().lower() and has_WConio:
            colors = {
                'BLACK': WConio.BLACK,
                'RED': WConio.LIGHTRED,
                'GREEN': WConio.LIGHTGREEN,
                'YELLOW': WConio.YELLOW,
                'BLUE': WConio.LIGHTBLUE,
                'PURPLE': WConio.LIGHTMAGENTA,
                'CYAN': WConio.CYAN,
                'WHITE': WConio.WHITE,
                'LIGHT_GRAY': WConio.LIGHTGRAY,
            }

            def getMessage(self) -> str:
                color = None
                msg = str(self.msg)
                if self.args:
                    color = self.args[0]
                if color in self.colors:
                    WConio.textcolor(self.colors[color])
                    return msg

            old_setting = WConio.gettextinfo()[4] & 0x00FF
            atexit.register(WConio.textcolor, old_setting)

        elif "linux" == platform.system().lower():
            ENDC = '\033[0m'
            BOLD = '\033[1m'
            UNDERLINE = '\033[4m'
            csi = '\x1b['
            reset = '\x1b[0m'
            colors = {
                'END': 0,
                'LIGHT': 90,
                'DARK': 30,
                'BACKGROUND': 40,
                'LIGHT_BACKGROUND': 100,
                'GRAY': 0,
                'RED': 1,
                'GREEN': 2,
                'YELLOW': 3,
                'BLUE': 4,
                'PURPLE': 5,
                'CYAN': 6,
                'LIGHT_GRAY': 7,
                'NORMAL': 8,
                'WHITE': 9,
            }

            def getMessage(self) -> str:
                color = None
                msg = str(self.msg)
                if self.args:
                    color = self.args[0]
                if color in self.colors:
                    params = []
                    params.append(str(self.colors[color] + 30))
                    msg = ''.join((self.csi, ';'.join(params),
                                  'm', msg, self.reset))
                return msg
    else:
        def getMessage(self) -> str:
            msg = str(self.msg)
            return msg


class Logger:
    """Class for logging to console, text file, XML."""

    def __init__(self):
        """The Constructor."""
        self.mytime = localtime()
        self.logfile = None
        self.rootLogger = pyLogging.getLogger(__name__)
        self.rootLogger.setLevel(pyLogging.INFO)
        self.ALWAYS_FLUSH = False
        pyLogging.addLevelName(19, "verbose")
        pyLogging.addLevelName(18, "hal")
        self.logstream = pyLogging.StreamHandler(sys.stdout)
        # Respect https://no-color.org/ convention, and disable colorization
        # when the output is not a terminal (eg. redirection to a file)
        pyLogging.setLogRecordFactory(chipsecrecordfactory)  # applies colorization to output
        self.rootLogger.addHandler(self.logstream)  # adds streamhandler to root logger
        self.Results = ChipsecResults()

    def setlevel(self):
        if self.DEBUG:
            self.rootLogger.setLevel(pyLogging.DEBUG)
        elif self.HAL:
            self.rootLogger.setLevel(pyLogging.getLevelName("hal"))
        elif self.VERBOSE:
            self.rootLogger.setLevel(pyLogging.getLevelName("verbose"))
        else:
            self.rootLogger.setLevel(pyLogging.INFO)

    def set_log_file(self, name=None):
        """Sets the log file for the output."""
        # Close current log file if it's opened
        self.disable()
        self.LOG_FILE_NAME = name
        # specifying name=None effectively disables logging to file

        if self.LOG_FILE_NAME:
            # Open new log file and keep it opened
            try:
                # creates FileHandler for log file
                self.logfile = pyLogging.FileHandler(filename=self.LOG_FILE_NAME, mode='w')
                self.rootLogger.addHandler(self.logfile)  # adds filehandler to root logger
                self.LOG_TO_FILE = True
            except Exception:
                print("WARNING: Could not open log file '{}'".format(self.LOG_FILE_NAME))
            self.rootLogger.removeHandler(self.logstream)
        else:
            try:
                self.rootLogger.addHandler(self.logstream)
            except Exception:
                pass

    def close(self):
        """Closes the log file."""
        if self.logfile:
            try:
                self.rootLogger.removeHandler(self.logfile)
                self.rootLogger.removeHandler(self.logstream)
                self.logfile.close()
                self.logstream.flush()
            except Exception:
                print("WARNING: Could not close log file")
            finally:
                self.logfile = None

    def disable(self):
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

    def set_always_flush(self, val):
        self.ALWAYS_FLUSH = val

    def _log(self, text, level=pyLogging.INFO, color=None):
        """Sends plain text to logging."""
        if self.Results.get_current() is not None:
            self.Results.get_current().add_output(text)
        try:
            self.rootLogger.log(level, text, color)
            if self.ALWAYS_FLUSH:
                self.flush()
        except BaseException:
            print(text)

    def log(self, text):
        """Plain Log message"""
        self._log(text, pyLogging.INFO, "WHITE")

    # -------------------------------------------------------
    # These logger methods are deprecated and will be removed
    # -------------------------------------------------------

    def error(self, text):  # Use log_error()
        """Logs an Error message"""
        text = "ERROR: " + text
        self.log_error(text)

    def warn(self, text):  # Use log_warning()
        """Logs an Warning message"""
        text = "WARNING: " + text
        self.log_warning(text)

    def log_passed_check(self, text):
        """Logs a Test as PASSED"""
        self.log_passed(text)

    def log_failed_check(self, text):  # Duplicate of log_failed()
        """Logs a Test as FAILED"""
        self.log_failed(text)

    def log_error_check(self, text):  # Duplicate of log_error()
        """Logs a Test as ERROR"""
        self.log_error(text)

    def log_skipped_check(self, text):  # Duplicate of log_skipped()
        """Logs a Test as Not Implemented"""
        self.log_skipped(text)

    def log_warn_check(self, text):  # Duplicate of log_warning()
        """Logs a Warning test, a warning test is considered equal to a PASSED test"""
        self.log_warning(text)

    def log_information_check(self, text):  # Duplicate of log_information()
        """Logs a Information test, an information test"""
        self.log_information(text)

    def log_not_applicable_check(self, text):  # Duplicate of log_not_applicable()
        """Logs a Test as Not Applicable"""
        self.log_not_applicable(text)

    def log_result(self, text):  # Duplicate of log_good()
        """Logs a result message."""
        text = "[+] " + text
        self.log_good(text)

    # -----------------------------
    # End deprecated logger methods
    # -----------------------------

    def log_verbose(self, text):
        """Logs a Verbose message"""
        self._log(text, pyLogging.getLevelName("verbose"), "LIGHT_GRAY")

    def log_hal(self, text):
        """Logs a hal message"""
        self._log(text, pyLogging.getLevelName("hal"), "LIGHT_GRAY")

    def log_debug(self, text):
        """Logs a debug message"""
        self._log(text, pyLogging.DEBUG, "LIGHT_GRAY")

    def log_passed(self, text):
        """Logs a passed message."""
        text = "[+] PASSED: " + text
        self._log(text, pyLogging.INFO, "GREEN")

    def log_failed(self, text):
        """Logs a failed message."""
        text = "[-] FAILED: " + text
        self._log(text, pyLogging.INFO, "RED")

    def log_error(self, text):
        """Logs an Error message"""
        text = "[-] ERROR: " + text
        self._log(text, pyLogging.ERROR, "PURPLE")

    def log_warning(self, text):
        """Logs an Warning message"""
        text = "WARNING: " + text
        self._log(text, pyLogging.INFO, "YELLOW")

    def log_skipped(self, text):
        """Logs a SKIPPED message."""
        text = "[*] SKIPPED: " + text
        self._log(text, pyLogging.INFO, "YELLOW")

    def log_not_applicable(self, text):
        """Logs a NOT APPLICABLE message."""
        text = "[*] NOT APPLICABLE: " + text
        self._log(text, pyLogging.INFO, "YELLOW")

    def log_heading(self, text):
        """Logs a heading message."""
        self._log(text, pyLogging.INFO, "BLUE")

    def log_important(self, text):
        """Logs an important message."""
        text = "[!] " + text
        self._log(text, pyLogging.INFO, "RED")

    def log_bad(self, text):
        """Logs a bad message, so it calls attention in the information displayed."""
        text = "[-] " + text
        self._log(text, pyLogging.INFO, "RED")

    def log_good(self, text):
        """Logs a message, if colors available, displays in green."""
        text = "[+] " + text
        self._log(text, pyLogging.INFO, "GREEN")

    def log_unknown(self, text):
        """Logs a message with a question mark."""
        text = "[?] " + text
        self._log(text, pyLogging.INFO, "WHITE")

    def log_information(self, text):
        """Logs a message with information message"""
        text = "[#] INFORMATION: " + text
        self._log(text, pyLogging.INFO, "WHITE")

    def start_test(self, test_name):
        """Logs the start point of a Test"""
        text = "[x][ =======================================================================\n"
        text = text + "[x][ Module: " + test_name + "\n"
        text = text + "[x][ ======================================================================="
        self._log(text, pyLogging.INFO, "BLUE")

    def start_module(self, module_name):
        """Displays a banner for the module name provided."""
        text = "\n[*] Running module: {}".format(module_name)
        self._log(text, pyLogging.INFO, "WHITE")
        if self.Results.get_current() is not None:
            self.Results.get_current().add_desc(module_name)
            self.Results.get_current().set_time()

    def end_module(self, module_name):
        if self.Results.get_current() is not None:
            self.Results.get_current().set_time()

    def _write_log(self, text, filename):
        """Write text to defined log file"""
        self.rootLogger.log(self.info, text)
        if self.ALWAYS_FLUSH:
            try:
                self.logfile.close()
                self.logfile = open(self.LOG_FILE_NAME, 'a+')
            except Exception:
                self.disable()

    def _save_to_log_file(self, text):
        if self.LOG_TO_FILE:
            self._write_log(text, self.LOG_FILE_NAME)

    VERBOSE = False
    UTIL_TRACE = False
    HAL = False
    DEBUG = False

    LOG_TO_STATUS_FILE = False
    LOG_STATUS_FILE_NAME = ""
    LOG_TO_FILE = False
    LOG_FILE_NAME = ""


_logger = Logger()


def logger():
    """Returns a Logger instance."""
    return _logger

def aligned_column_spacing(table_data: list[Tuple[str, Dict[str, str]]]) -> Tuple[int, ...]:
    clean_data = clean_data_table(table_data)
    all_column_widths = get_column_widths(clean_data)
    required_widths = find_required_col_widths(all_column_widths)
    return tuple(required_widths)

def clean_data_table(data_table: list[Tuple[str, Dict[str, str]]]) -> list[list[str]]:
    clean_table = [extract_column_values(row) for row in data_table]
    return clean_table

def extract_column_values(row_data: Tuple[str, Dict[str, str]]) -> list[str]:
    clean_row = [row_data[0]]
    additional_column_values = row_data[1].values()
    [clean_row.append(value) for value in additional_column_values]
    return clean_row

def get_column_widths(data: list[list[str]]) -> list[list[int]]:
    col_widths = [[len(col) for col in row] for row in data]
    return col_widths

def find_required_col_widths(col_data: list[list[int]], minimum_width = 2) -> Tuple[int, ...]:
    columns_per_row = len(col_data[0])
    max_widths = ([(max(rows[i] for rows in col_data)) for i in range(columns_per_row)])
    for i in range(len(max_widths)):
        max_widths[i] = max_widths[i] if max_widths[i] > minimum_width else minimum_width
    return max_widths

##################################################################################
# Hex dump functions
##################################################################################

def hex_to_text(value):
    '''Generate text string based on bytestrings'''
    text = binascii.unhexlify('{:x}'.format(value))[::-1]
    if isinstance(text, str):
        return text   # Python 2.x
    else:
        return text.decode('latin-1')   # Python 3.x


def bytes2string(buffer, length=16):
    '''Generate text string based on str with ASCII side panel'''
    output = []
    num_string = []
    ascii_string = []
    index = 1
    for c in buffer:
        num_string += ['{:02X} '.format(ord(c))]
        if not (c in string.printable) or (c in string.whitespace):
            ascii_string += ['{}'.format(' ')]
        else:
            ascii_string += ['{}'.format(c)]
        if (index % length) == 0:
            num_string += ['| ']
            num_string += ascii_string
            output.append(''.join(num_string))
            ascii_string = []
            num_string = []
        index += 1
    if 0 != (len(buffer) % length):
        num_string += [(length - len(buffer) % length) * 3 * ' ']
        num_string += ['| ']
        num_string += ascii_string
        output.append(''.join(num_string))
    return '\n'.join(output)


def dump_buffer(arr, length=8):
    """Dumps the buffer (str) with ASCII"""
    return bytes2string(arr, length)


def print_buffer(arr, length=16):
    """Prints the buffer (str) with ASCII"""
    prt_str = bytes2string(arr, length)
    logger().log(prt_str)


def dump_buffer_bytes(arr, length=8):
    """Dumps the buffer (bytes, bytearray) with ASCII"""
    output = []
    num_string = []
    ascii_string = []
    index = 1
    for c in arr:
        num_string += ['{:02X} '.format(c)]
        if not (chr(c) in string.printable) or (chr(c) in string.whitespace):
            ascii_string += ['{}'.format(' ')]
        else:
            ascii_string += [chr(c)]
        if (index % length) == 0:
            num_string += ['| ']
            num_string += ascii_string
            output.append(''.join(num_string))
            ascii_string = []
            num_string = []
        index += 1
    if 0 != (len(arr) % length):
        num_string += [(length - len(arr) % length) * 3 * ' ']
        num_string += ['| ']
        num_string += ascii_string
        output.append(''.join(num_string))
    return '\n'.join(output)


def print_buffer_bytes(arr, length=16):
    """Prints the buffer (bytes, bytearray) with ASCII"""
    prt_str = dump_buffer_bytes(arr, length)
    logger().log(prt_str)


def pretty_print_hex_buffer(arr, length=16):
    """Prints the buffer (bytes, bytearray) in a grid"""
    _str = ["    _"]
    for n in range(length):
        _str += ["{:02X}__".format(n)]
    for n in range(len(arr)):
        if (n % length) == 0:
            _str += ["\n{:02X} | ".format(n)]
        _str += ["{:02X}  ".format(arr[n])]
    logger().log(''.join(_str))


def dump_data(data, length=16):
    """Dumps the buffer with ASCII"""
    if isinstance(data, str):
        dump_buffer(data, length)
    else:
        dump_buffer_bytes(data, length)


def print_data(data, length=16):
    """Prints the buffer with ASCII"""
    if isinstance(data, str):
        print_buffer(data, length)
    else:
        print_buffer_bytes(data, length)
