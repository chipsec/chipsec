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

"""
>>> chipsec_util check list
>>> chipsec_util check lock <lockname>
>>> chipsec_util check lock <lockname1, lockname2, ...>
>>> chipsec_util check all

Examples:

>>> chipsec_util check list
>>> chipsec_util check lock DebugLock
>>> chipsec_util check all

KEY:
    Lock Name - Name of Lock within configuration file
    State     - Lock Configuration
    
        Undefined - Lock is not defined within configuration
        Undoc     - Lock is missing configuration information
        Hidden    - Lock is in a disabled or hidden state (unable to read the lock)
        Unlocked  - Lock does not match value within configuration
        Locked    - Lock matches value within configuration
        RW/O      - Lock is identified as register is RW/O

"""

from argparse import ArgumentParser

from chipsec.command import BaseCommand, toLoad
from chipsec.hal.locks import locks, LockResult
from chipsec.library.defines import is_set


class LOCKCHECKCommand(BaseCommand):

    version = "0.5"

    def requirements(self) -> toLoad:
        return toLoad.All

    def parse_arguments(self) -> None:
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

        parser.parse_args(self.argv, namespace=self)

    def set_up(self) -> None:
        self.flip_consistency_checking = False
        if not self.cs.consistency_checking:
            self.flip_consistency_checking = True
            self.cs.consistency_checking = True
        self.logger.set_always_flush(True)
        self._locks = locks(self.cs)
    
    def tear_down(self) -> None:
        self.logger.set_always_flush(False)
        if self.flip_consistency_checking:
            self.cs.consistency_checking = False

    def log_key(self) -> None:
        self.logger.log("""
KEY:
\tLock Name - Name of Lock within configuration file
\tState - Lock Configuration
\t\tUndefined - Lock is not defined within configuration
\t\tUndoc - Lock is missing configuration information
\t\tHidden - Lock is in a disabled or hidden state (unable to read the lock)
\t\tUnlocked - Lock does not match value within configuration
\t\tLocked - Lock matches value within configuration
\t\tRW/O - Lock is identified as register is RW/O\n\n""")

    def log_header(self) -> str:
        ret = f'{"Lock Name":^27}|{"State":^16}|{"Consistent":^16}\n{"-" * 58}'
        if not self.logger.HAL:
            self.logger.log(ret)
        return f"\n\n{ret}"

    def list_locks(self) -> None:
        self.logger.log('Locks identified within the configuration:')
        for lock in self._locks.get_locks():
            self.logger.log(lock)
        self.logger.log('')
        return

    def checkall_locks(self) -> None:
        locks = self._locks.get_locks()
        if not locks:
            self.logger.log('Did not find any locks')
            return
        if self.logger.VERBOSE:
            self.log_key()
        res = self.log_header()
        for lock in locks:
            is_locked = self._locks.is_locked(lock)
            is_locked_str = self.check_log(lock, is_locked)
            res = f"{res}\n{is_locked_str}"
        if self.logger.HAL:
            self.logger.log(res)
        return

    def check_lock(self) -> None:
        if self.logger.VERBOSE:
            self.log_key()
        res = self.log_header()
        for lock in self.lockname:
            is_locked = self._locks.is_locked(lock)
            is_locked_str = self.check_log(lock, is_locked)
            res = f"{res}\n{is_locked_str}"
        if self.logger.HAL:
            self.logger.log(res)
        return

    def check_log(self, lock: str, is_locked: int) -> str:
        consistent = "N/A"
        if not is_set(is_locked, LockResult.DEFINED):
            res_str = 'Undefined'
        elif not is_set(is_locked, LockResult.HAS_CONFIG):
            res_str = 'Undoc'
        elif not is_set(is_locked, LockResult.CAN_READ):
            res_str = 'Hidden'
        elif self.cs.lock.get_type(lock) == "RW/O":
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
        res = f'{lock[:26]:27}|  {res_str:14}|{consistent:^16}'
        if not self.logger.HAL:
            self.logger.log(res)
        return res


commands = {'check': LOCKCHECKCommand}
