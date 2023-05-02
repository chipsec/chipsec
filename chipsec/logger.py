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
import logging
import platform
import string
import binascii
import sys
import os
import atexit
from time import localtime, strftime
from typing import Tuple, Dict, List, Optional
from enum import Enum

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
if not os.path.exists(LOG_PATH):
    os.mkdir(LOG_PATH)

LOGGER_NAME = 'CHIPSEC'


class level(Enum):
    DEBUG = 10
    HELPER = 11
    HAL = 12
    VERBOSE = 13
    INFO = 20
    GOOD = 21
    BAD = 22
    IMPORTANT = 23
    WARNING = 30
    ERROR = 40
    CRITICAL = 50
    EXCEPTION = 60


class chipsecFilter(logging.Filter):
    def __init__(self, name: str = ...) -> None:
        super().__init__(name)

    def filter(self, record):
        if record.levelno == level.ERROR.value:
            record.additional = 'ERROR: '
        elif record.levelno == level.WARNING.value:
            record.additional = 'WARNING: '
        elif record.levelno == level.IMPORTANT.value:
            record.additional = '[!] '
        elif record.levelno == level.GOOD.value:
            record.additional = '[+] '
        elif record.levelno == level.BAD.value:
            record.additional = '[-] '
        elif record.levelno == level.DEBUG.value:
            record.additional = '[*] [DEBUG] '
        elif record.levelno == level.VERBOSE.value:
            record.additional = '[*] [VERBOSE] '
        elif record.levelno == level.HAL.value:
            record.additional = '[*] [HAL] '
        elif record.levelno == level.HELPER.value:
            record.additional = '[*] [HELPER] '
        else:
            record.additional = ''
        return True


class chipsecLogFormatter(logging.Formatter):
    def __init__(self, fmt: Optional[str] = ..., datefmt: Optional[str] = ..., style='%') -> None:
        super().__init__(fmt, datefmt, style)
        self.infmt = fmt

    def format(self, record):
        if record.args:
            record.args = tuple()
        formatter = logging.Formatter(self.infmt)
        return formatter.format(record)


class chipsecStreamFormatter(logging.Formatter):
    try:
        is_atty = sys.stdout.isatty()
    except AttributeError:
        is_atty = False
    # Respect https://no-color.org/ convention, and disable colorization
    # when the output is not a terminal (eg. redirection to a file)
    mPlatform = platform.system().lower()
    if is_atty and os.getenv('NO_COLOR') is None and (("windows" == mPlatform and has_WConio) or "linux" == mPlatform):
        if "windows" == mPlatform:
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

            old_setting = WConio.gettextinfo()[4] & 0x00FF
            atexit.register(WConio.textcolor, old_setting)

        elif "linux" == mPlatform:
            csi = '\x1b['
            reset = '\x1b[0m'
            colors = {
                'END': '30',
                'LIGHT': '120',
                'DARK': '60',
                'BACKGROUND': '70',
                'LIGHT_BACKGROUND': '130',
                'GRAY': '30',
                'RED': '31',
                'GREEN': '32',
                'YELLOW': '33',
                'BLUE': '34',
                'PURPLE': '35',
                'CYAN': '36',
                'LIGHT_GRAY': '37',
                'NORMAL': '38',
                'WHITE': '39',
            }
        else:
            colors = {}
    else:
        colors = {}

    def __init__(self, fmt: Optional[str] = ..., datefmt: Optional[str] = ..., style='%') -> None:
        super().__init__(fmt, datefmt, style)
        self.infmt = fmt
        self.levelfmt = '[%(levelname)s]  %(message)s'

    def format(self, record):
        if record.levelno == level.DEBUG.value:
            color = 'BLUE'
        elif record.levelno in [level.VERBOSE.value, level.HAL.value, level.HELPER.value]:
            color = 'LIGHT_GRAY'
        elif record.levelno == level.GOOD.value:
            color = 'GREEN'
        elif record.levelno == level.IMPORTANT.value:
            color = 'CYAN'
        elif record.levelno == level.WARNING.value:
            color = 'YELLOW'
        elif record.levelno in [level.ERROR.value, level.BAD.value]:
            color = 'RED'
        elif record.levelno in [level.EXCEPTION.value, level.CRITICAL.value]:
            color = 'PURPLE'
        else:
            color = 'WHITE'
        if record.args:
            if record.args[0] is not None and record.args[0] in self.colors:
                color = record.args[0]
            record.args = tuple()
        if color in self.colors and "linux" == self.mPlatform:
            log_fmt = f'{self.csi};{self.colors[color]}m{self.infmt}{self.reset}'
        else:
            log_fmt = self.infmt
        if color in self.colors and "windows" == self.mPlatform:
            WConio.textcolor(self.colors[color])
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


class Logger:
    """Class for logging to console, text file, XML."""

    def __init__(self, profile='debug.conf'):
        """The Constructor."""
        self.mytime = localtime()
        self.logfile = None
        self.ALWAYS_FLUSH = False
        self.logstream = logging.StreamHandler(sys.stdout)
        logname = f"{strftime('%a%b%d%y-%H%M%S')}.log"
        logPath = os.path.join(LOG_PATH, logname)
        fileH = logging.FileHandler(logPath)
        self.chipsecLogger = logging.getLogger(LOGGER_NAME)
        self.chipsecLogger.setLevel(logging.DEBUG)
        self.chipsecLogger.addHandler(self.logstream)
        self.chipsecLogger.addHandler(fileH)
        self.chipsecLogger.addFilter(chipsecFilter(LOGGER_NAME))
        self.chipsecLogger.propagate = False
        logging.addLevelName(level.VERBOSE.value, level.VERBOSE.name)
        logging.addLevelName(level.HAL.value, level.HAL.name)
        logging.addLevelName(level.HELPER.value, level.HELPER.name)
        logFormatter = chipsecLogFormatter('%(additional)s%(message)s')
        streamFormatter = chipsecStreamFormatter('%(additional)s%(message)s')
        self.logstream.setFormatter(streamFormatter)
        fileH.setFormatter(logFormatter)

    def log(self, text: str, level: level = level.INFO, color: Optional[str] = ...) -> None:
        """Sends plain text to logging."""
        self.chipsecLogger.log(level.value, text, color)

    def log_verbose(self, text: str) -> None:  # Use log('text', level.VERBOSE)
        """Logs a Verbose message"""
        self.log(text, level.VERBOSE)

    def log_hal(self, text: str) -> None:  # Use log("text", level.HAL)
        """Logs a hal message"""
        self.log(text, level.HAL)

    def log_helper(self, text: str) -> None:
        """Logs a helper message"""
        self.log(text, level.HELPER)

    def log_debug(self, text: str) -> None:   # Use log("text", level.DEBUG)
        """Logs a debug message"""
        self.log(text, level.DEBUG)

    def setlevel(self) -> None:
        if self.DEBUG:
            self.chipsecLogger.setLevel(level.DEBUG.value)
        elif self.HAL:
            self.chipsecLogger.setLevel(level.HAL.value)
        elif self.VERBOSE:
            self.chipsecLogger.setLevel(level.VERBOSE.value)
        else:
            self.chipsecLogger.setLevel(level.INFO.value)

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
                self.logfile = logging.FileHandler(filename=self.LOG_FILE_NAME, mode='w')
                self.chipsecLogger.addHandler(self.logfile)  # adds filehandler to root logger
                self.LOG_TO_FILE = True
            except Exception:
                print(f'WARNING: Could not open log file: {self.LOG_FILE_NAME}')
            self.chipsecLogger.removeHandler(self.logstream)
        else:
            try:
                self.chipsecLogger.addHandler(self.logstream)
            except Exception:
                pass

    def close(self) -> None:
        """Closes the log file."""
        if self.logfile:
            try:
                self.chipsecLogger.removeHandler(self.logfile)
                self.chipsecLogger.removeHandler(self.logstream)
                self.logfile.close()
                self.logstream.flush()
            except Exception:
                print('WARNING: Could not close log file')
            finally:
                self.logfile = None

    def disable(self) -> None:
        """Disables the logging to file and closes the file if any."""
        self.LOG_TO_FILE = False
        self.LOG_FILE_NAME = None
        self.close()

    def flush(self) -> None:
        sys.stdout.flush()
        if self.LOG_TO_FILE and self.logfile is not None:
            # flush should work with new python logging
            try:
                self.chipsecLogger.removeHandler(self.logfile)
                self.logfile.flush()
                self.chipsecLogger.addHandler(self.logfile)
            except Exception:
                self.disable()

    def set_always_flush(self, val) -> None:
        self.ALWAYS_FLUSH = val

    # -------------------------------------------------------
    # These logger methods are deprecated and will be removed
    # -------------------------------------------------------

    def _log(self, text, level=level.INFO, color=None) -> None:
        """Sends plain text to logging."""
        try:
            self.chipsecLogger.log(level.value, text, color)
            if self.ALWAYS_FLUSH:
                self.flush()
        except BaseException:
            print(text)

    def log_passed(self, text):   # Use log("text", self.logger.GOOD)
        """Logs a passed message."""
        text = f'PASSED: {text}'
        self.log(text, level.GOOD)

    def log_failed(self, text):
        """Logs a failed message."""
        text = f'FAILED: {text}'
        self.log(text, level.BAD)

    def log_error(self, text):   # Use log("text", level.ERROR)
        """Logs an Error message"""
        self.log(text, level.ERROR)

    def log_warning(self, text):   # Use log("text", level.WARNING)
        """Logs an Warning message"""
        self.log(text, level.WARNING)

    def log_not_applicable(self, text):
        """Logs a NOT APPLICABLE message."""
        text = f'NOT APPLICABLE: {text}'
        self.log(text, level.INFO, "YELLOW")

    def log_heading(self, text):
        """Logs a heading message."""
        self.log(text, level.INFO, "BLUE")

    def log_important(self, text):   # Use log("text", level.IMPORTANT)
        """Logs an important message."""
        self.log(text, level.IMPORTANT)

    def log_bad(self, text):   # Use log("text", level.BAD)
        """Logs a bad message, so it calls attention in the information displayed."""
        self.log(text, level.BAD)

    def log_good(self, text):   # Use log("text", level.GOOD)
        """Logs a message, if colors available, displays in green."""
        self.log(text, level.GOOD)

    def log_unknown(self, text):
        """Logs a message with a question mark."""
        text = f'[?] {text}'
        self.log(text)

    def log_information(self, text):    # Use log("text")
        """Logs a message with information message"""
        text = f'[#] INFORMATION: {text}'
        self.log(text)

    # -----------------------------
    # End deprecated logger methods
    # -----------------------------

    def start_test(self, test_name: str) -> None:
        """Logs the start point of a Test"""
        text = '[x][ =======================================================================\n'
        text = f'{text}[x][ Module: {test_name}\n'
        text = f'{text}[x][ ======================================================================='
        self.log(text, level.INFO, 'BLUE')


    def _write_log(self, text, filename):
        """Write text to defined log file"""
        self.chipsecLogger.log(level.INFO.value, text)
        if self.ALWAYS_FLUSH:
            try:
                self.logfile.close()
                self.logfile = open(self.LOG_FILE_NAME, 'a+')
            except Exception:
                self.disable()

    def _save_to_log_file(self, text):
        if self.LOG_TO_FILE:
            self._write_log(text, self.LOG_FILE_NAME)

    VERBOSE: bool = False
    UTIL_TRACE: bool = False
    HAL: bool = False
    DEBUG: bool = False

    LOG_TO_STATUS_FILE: bool = False
    LOG_STATUS_FILE_NAME: str = ''
    LOG_TO_FILE: bool = False
    LOG_FILE_NAME: str = ''


_logger = Logger()


def logger() -> Logger:
    """Returns a Logger instance."""
    return _logger


def aligned_column_spacing(table_data: List[Tuple[str, Dict[str, str]]]) -> Tuple[int, ...]:
    clean_data = clean_data_table(table_data)
    all_column_widths = get_column_widths(clean_data)
    required_widths = find_required_col_widths(all_column_widths)
    return tuple(required_widths)


def clean_data_table(data_table: List[Tuple[str, Dict[str, str]]]) -> List[List[str]]:
    clean_table = [extract_column_values(row) for row in data_table]
    return clean_table


def extract_column_values(row_data: Tuple[str, Dict[str, str]]) -> List[str]:
    clean_row = [row_data[0]]
    additional_column_values = row_data[1].values()
    [clean_row.append(value) for value in additional_column_values]
    return clean_row


def get_column_widths(data: List[List[str]]) -> List[List[int]]:
    col_widths = [[len(col) for col in row] for row in data]
    return col_widths


def find_required_col_widths(col_data: List[List[int]], minimum_width=2) -> List[int]:
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
    text = binascii.unhexlify(f'{value:x}')[::-1]
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
        num_string += [f'{ord(c):02X} ']
        if not (c in string.printable) or (c in string.whitespace):
            ascii_string += [' ']
        else:
            ascii_string += [f'{c}']
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
        num_string += [f'{c:02X} ']
        if not (chr(c) in string.printable) or (chr(c) in string.whitespace):
            ascii_string += [' ']
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
    _str = ['    _']
    for n in range(length):
        _str += [f'{n:02X}__']
    for n in range(len(arr)):
        if (n % length) == 0:
            _str += [f'\n{n:02X} | ']
        _str += [f'{arr[n]:02X}  ']
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
