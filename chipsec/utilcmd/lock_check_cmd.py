# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2021, Intel Corporation
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

from time import time
from argparse import ArgumentParser

from chipsec.command import BaseCommand
from chipsec.hal.locks import locks, LockResult
from chipsec.defines import is_set


class LOCKCHECKCommand(BaseCommand):
    """
    >>> chipsec_util check list
    >>> chipsec_util check lock <lockname>
    >>> chipsec_util check lock <lockname1, lockname2, ...>
    >>> chipsec_util check all

    Examples:

    >>> chipsec_util check list
    >>> chipsec_util check lock DebugLock
    >>> chipsec_util check all
    """

    version = "0.5"

    def requires_driver(self):
        parser = ArgumentParser(prog='chipsec_util check', usage=LOCKCHECKCommand.__doc__)

        parser_lockname = ArgumentParser(add_help=False)
        parser_lockname.add_argument('lockname', type=str, nargs='+', help="locknames")

        subparsers = parser.add_subparsers()

        # list
        parser_list = subparsers.add_parser('list')
        parser_list.set_defaults(func=self.list_locks)

        # checkall
        parser_checkall = subparsers.add_parser('all')
        parser_checkall.set_defaults(func=self.checkall_locks)

        # check
        parser_check = subparsers.add_parser('lock', parents=[parser_lockname])
        parser_check.set_defaults(func=self.check_lock)

        parser.parse_args(self.argv[2:], namespace=self)

        return True

    def log_key(self):
        self.logger.log("""
KEY:
\tLock Name - Name of Lock within configuration file
\tState - Lock Configuration
\t\tUndefined - Lock is not defined within configuration
\t\tUndoc -  Lock is missing configuration information
\t\tHidden - Lock is in a disabled or hidden state (unable to read the lock)
\t\tUnlocked - Lock does not match value within configuration
\t\tLocked - Lock matches value within configuration
\t\tRW/O - Lock is identified as register is RW/O\n\n""")

    def log_header(self):
        ret = '{:^27}|{:^16}|{:^16}\n{}'.format('Lock Name', 'State', 'Consistent', '-' * 58)
        if not self.logger.HAL:
            self.logger.log(ret)
        return "\n\n{}".format(ret)

    def list_locks(self):
        self.logger.log('Locks identified within the configuration:')
        for lock in self._locks.get_locks():
            self.logger.log(lock)
        self.logger.log('')
        return

    def checkall_locks(self):
        locks = self._locks.get_locks()
        if not locks:
            self.logger.log('Did not find any locks')
            return
        if self.logger.VERBOSE:
            self.log_key()
        res = self.log_header()
        for lock in locks:
            is_locked = self._locks.is_locked(lock)
            res = "{}\n{}".format(res, self.check_log(lock, is_locked))
        if self.logger.HAL:
            self.logger.log(res)
        return

    def check_lock(self):
        if self.logger.VERBOSE:
            self.log_key()
        res = self.log_header()
        for lock in self.lockname:
            is_locked = self._locks.is_locked(lock)
            res = "{}\n{}".format(res, self.check_log(lock, is_locked))
        if self.logger.HAL:
            self.logger.log(res)
        return

    def check_log(self, lock, is_locked):
        consistent = "N/A"
        if not is_set(is_locked, LockResult.DEFINED):
            res_str = 'Undefined'
        elif not is_set(is_locked, LockResult.HAS_CONFIG):
            res_str = 'Undoc'
        elif not is_set(is_locked, LockResult.CAN_READ):
            res_str = 'Hidden'
        elif self.cs.get_lock_type(lock) == "RW/O":
            res_str = 'RW/O'
        elif is_set(is_locked, LockResult.LOCKED):
            res_str = 'Locked'
        elif not is_set(is_locked, LockResult.LOCKED):
            res_str = 'UnLocked'
        else:
            res_str = 'Unknown'
        if res_str in ["RW/O", "Locked", "UnLocked"] and is_set(is_locked, LockResult.INCONSISTENT):
            consistent = "No"
        elif res_str in ["RW/O", "Locked", "UnLocked"] and not is_set(is_locked, LockResult.INCONSISTENT):
            consistent = "Yes"
        res = '{:27}|  {:14}|{:^16}'.format(lock[:26], res_str, consistent)
        if not self.logger.HAL:
            self.logger.log(res)
        return res

    def run(self):
        CONSISTENCY_CHECKING = True
        self.logger.set_always_flush(True)
        try:
            self._locks = locks(self.cs)
        except Exception as msg:
            self.logger.log(msg)
            return
        t = time()
        self.func()
        self.logger.set_always_flush(False)
        self.logger.log("[CHIPSEC] (Lock Check) time elapsed {:.3f}".format(time() - t))


commands = {'check': LOCKCHECKCommand}
