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
from typing import Sequence, Tuple, Dict, List
from enum import Enum
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
if not os.path.exists(LOG_PATH):
    os.mkdir(LOG_PATH)

LOGGER_NAME = 'CHIPSEC'


class chipsecRecordFactory(logging.LogRecord):
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
                if self.name != LOGGER_NAME:
                    return super().getMessage()
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
                if self.name != LOGGER_NAME:
                    return super().getMessage()
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
            if self.name == LOGGER_NAME:
                return str(self.msg)
            return super.getMessage()


class Logger:
    """Class for logging to console, text file, XML."""

    class level(Enum):
        DEBUG = 10
        VERBOSE = 11
        HAL = 12
        HELPER = 13
        INFO = 20
        GOOD = 21
        IMPORTANT = 22
        WARNING = 30
        BAD = 31
        ERROR = 40
        CRITICAL = 50
        EXCEPTION = 60

    def __init__(self, profile='debug.conf'):
        """The Constructor."""
        self.mytime = localtime()
        self.logfile = None
        self.ALWAYS_FLUSH = False
        self.logstream = logging.StreamHandler(sys.stdout)
        logname = strftime('%a%b%d%y-%H%M%S') + '.log'
        logPath = os.path.join(LOG_PATH, logname)
        fileH = logging.FileHandler(logPath)
        self.chipsecLogger = logging.getLogger(LOGGER_NAME)
        self.chipsecLogger.setLevel(logging.DEBUG)
        self.chipsecLogger.addHandler(self.logstream)
        self.chipsecLogger.addHandler(fileH)
        logging.addLevelName(11, "VERBOSE")
        logging.addLevelName(12, "HAL")
        logging.addLevelName(13, "HELPER")
        logging.setLogRecordFactory(chipsecRecordFactory)  # applies colorization to output
        self.Results = ChipsecResults()

    def log(self, text: str, level: level = level.INFO) -> None:
        """Sends plain text to logging."""
        if self.Results.get_current() is not None:
            self.Results.get_current().add_output(text)
        try:
            if level == self.level.DEBUG:
                self.chipsecLogger.debug(text, 'BLUE')
            elif level == self.level.VERBOSE:
                self.chipsecLogger.log(11, f'[*] [VERBOSE] {text}', 'LIGHT_GRAY')
            elif level == self.level.HAL:
                self.chipsecLogger.log(12, f'[*] [HAL] {text}', 'LIGHT_GRAY')
            elif level == self.level.HELPER:
                self.chipsecLogger.log(13, f'[*] [HELPER] {text}', 'LIGHT_GRAY')
            elif level == self.level.GOOD:
                self.chipsecLogger.info(f'[+] {text}', 'GREEN')
            elif level == self.level.IMPORTANT:
                self.chipsecLogger.info(f'[!] {text}', 'CYAN')
            elif level == self.level.WARNING:
                self.chipsecLogger.warning(f'WARNING: {text}', 'YELLOW')
            elif level == self.level.BAD:
                self.chipsecLogger.info(f'[-] {text}', 'RED')
            elif level == self.level.ERROR:
                self.chipsecLogger.error(f'ERROR: {text}', 'RED')
            elif level == self.level.CRITICAL:
                self.chipsecLogger.critical(f'{text}', 'PURPLE')
            elif level == self.level.EXCEPTION:
                self.chipsecLogger.exception(f'{text}', 'PURPLE')
            else:
                self.chipsecLogger.info(f'{text}', 'WHITE')
        except Exception:
            self.chipsecLogger.exception(f'{text}', 'PURPLE')

    def setlevel(self):
        if self.DEBUG:
            self.chipsecLogger.setLevel(logging.DEBUG)
        elif self.HAL:
            self.chipsecLogger.setLevel(logging.getLevelName('HAL'))
        elif self.VERBOSE:
            self.chipsecLogger.setLevel(logging.getLevelName('VERBOSE'))
        else:
            self.chipsecLogger.setLevel(logging.INFO)

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

    def disable(self):
        """Disables the logging to file and closes the file if any."""
        self.LOG_TO_FILE = False
        self.LOG_FILE_NAME = None
        self.close()

    def flush(self):
        sys.stdout.flush()
        if self.LOG_TO_FILE and self.logfile is not None:
            # flush should work with new python logging
            try:
                self.chipsecLogger.removeHandler(self.logfile)
                self.logfile.flush()
                self.chipsecLogger.addHandler(self.logfile)
            except Exception:
                self.disable()

    def set_always_flush(self, val):
        self.ALWAYS_FLUSH = val

    # -------------------------------------------------------
    # These logger methods are deprecated and will be removed
    # -------------------------------------------------------

    def _log(self, text, level=logging.INFO, color=None):
        """Sends plain text to logging."""
        try:
            self.chipsecLogger.log(level, text, color)
            if self.ALWAYS_FLUSH:
                self.flush()
        except BaseException:
            print(text)

    def log_verbose(self, text):  # Use log('text', self.logger.VERBOSE)
        """Logs a Verbose message"""
        self.log(text, self.level.VERBOSE)

    def log_hal(self, text):  # Use log("text", self.logger.HAL)
        """Logs a hal message"""
        self.log(text, self.level.HAL)

    def log_debug(self, text):   # Use log("text", self.logger.DEBUG)
        """Logs a debug message"""
        self.log(text, self.level.DEBUG)

    def log_passed(self, text):   # Use log("text", self.logger.GOOD)
        """Logs a passed message."""
        text = f'PASSED: {text}'
        self.log(text, self.level.GOOD)

    def log_failed(self, text):
        """Logs a failed message."""
        text = f'FAILED: {text}'
        self.log(text, self.level.BAD)

    def log_error(self, text):   # Use log("text", self.logger.ERROR)
        """Logs an Error message"""
        self.log(text, self.level.ERROR)

    def log_warning(self, text):   # Use log("text", self.logger.WARNING)
        """Logs an Warning message"""
        self.log(text, self.level.WARNING)

    def log_skipped(self, text):
        """Logs a SKIPPED message."""
        text = f'SKIPPED: " {text}'
        self.log(text, self.level.WARNING)

    def log_not_applicable(self, text):   # Use log("text", self.logger.NOTAPPLICABLE)
        """Logs a NOT APPLICABLE message."""
        text = f'NOT APPLICABLE: {text}'
        self.log(text, self.level.WARNING)

    def log_heading(self, text):
        """Logs a heading message."""
        self.log(text)

    def log_important(self, text):   # Use log("text", self.logger.IMPORTANT)
        """Logs an important message."""
        self.log(text, self.level.BAD)

    def log_bad(self, text):   # Use log("text", self.logger.BAD)
        """Logs a bad message, so it calls attention in the information displayed."""
        self.log(text, self.level.BAD)

    def log_good(self, text):   # Use log("text", self.logger.GOOD)
        """Logs a message, if colors available, displays in green."""
        self.log(text, self.level.GOOD)

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
        text = text + '[x][ Module: ' + test_name + '\n'
        text = text + '[x][ ======================================================================='
        self.chipsecLogger.info(text, 'BLUE')

    def print_banner(self, arguments: Sequence[str], version, message) -> None:
        """Prints CHIPSEC banner"""
        args = ' '.join(arguments)
        self.log('################################################################\n'
                 '##                                                            ##\n'
                 '##  CHIPSEC: Platform Hardware Security Assessment Framework  ##\n'
                 '##                                                            ##\n'
                 '################################################################')
        self.log(f'[CHIPSEC] Version  : {version}')
        self.log(f'[CHIPSEC] Arguments: {args}')
        self.log(message)

    def print_banner_properties(self, cs, os_version) -> None:
        """Prints CHIPSEC properties banner"""
        (system, release, version, machine) = os_version
        is_python_64 = True if (sys.maxsize > 2**32) else False
        python_version = platform.python_version()
        python_arch = '64-bit' if is_python_64 else '32-bit'
        (helper_name, driver_path) = cs.helper.helper.get_info()

        self.log(f'[CHIPSEC] OS      : {system} {release} {version} {machine}')
        self.log(f'[CHIPSEC] Python  : {python_version} ({python_arch})')
        self.log(f'[CHIPSEC] Helper  : {helper_name} ({driver_path})')
        self.log(f'[CHIPSEC] Platform: {cs.longname}')
        self.log(f'[CHIPSEC]    CPUID: {cs.get_cpuid()}')
        self.log(f'[CHIPSEC]      VID: {cs.vid:04X}')
        self.log(f'[CHIPSEC]      DID: {cs.did:04X}')
        self.log(f'[CHIPSEC]      RID: {cs.rid:02X}')
        if not cs.is_atom():
            self.log(f'[CHIPSEC] PCH     : {cs.pch_longname}')
            self.log(f'[CHIPSEC]      VID: {cs.pch_vid:04X}')
            self.log(f'[CHIPSEC]      DID: {cs.pch_did:04X}')
            self.log(f'[CHIPSEC]      RID: {cs.pch_rid:02X}')

        if not is_python_64 and machine.endswith('64'):
            self.log_warning('Python architecture (32-bit) is different from OS architecture (64-bit)')

    def _write_log(self, text, filename):
        """Write text to defined log file"""
        self.chipsecLogger.log(self.info, text)
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


def find_required_col_widths(col_data: List[List[int]], minimum_width=2) -> Tuple[int, ...]:
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
    _str = ['    _']
    for n in range(length):
        _str += ['{:02X}__'.format(n)]
    for n in range(len(arr)):
        if (n % length) == 0:
            _str += ['\n{:02X} | '.format(n)]
        _str += ['{:02X}  '.format(arr[n])]
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
