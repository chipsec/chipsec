#!/usr/local/bin/python
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
Management and communication with Windows kernel mode driver which provides access to hardware resources

  Usage:
    1. Add `from chipsec.helper.remote import *` to helpers.py and comment out all the other helpers
    2. > set CHIPSEC_REMOTE_ADDRESS=192.168.1.1:5000
    3. > run any chipsec script

"""

__version__ = '1.0'

import os
import sys
import time
import socket
from chipsec.logger          import logger
from chipsec.helper.oshelper import Helper

class RemoteHelper(Helper):

    def __init__(self):
        super(RemoteHelper, self).__init__()
        self.REMOTE_VARIABLES_LIST = ['os_system', 'os_release', 'os_version', 'os_machine', 'os_uname']
        self.host = 'localhost'
        self.port = 5000
        self.conn = None
        self.data = ''

    def __getattr__(self, name):
        def func(*args, **kwargs):
            return self.get_result(str([name, args, kwargs]))
        if self.conn is None:
            return 'Unknown'   ## driver is not loaded yet!
        if name in self.REMOTE_VARIABLES_LIST:
            return self.get_result(str([name]))
        return func

    def get_result(self, msg):
        self.send_line(msg)
        result = self.recv_line()
        try:
            values  = eval(result)
            success = len(values) == 2
        except Exception as e:
            success = False
        if not success:
            raise Exception('[helper] Invalid response from the remote helper: ' + result)
        if not values[0]:
            raise Exception(values[1])
        return values[1]

    def send_line(self, msg):
        result = False
        try:
            result = self.conn.sendall(msg + '\n')
        except socket.error as e:
            logger().error("[helper] Remote Helper send error: %s" % e)
        return result

    def recv_line(self):
        line = ''
        try:
            while '\n' not in self.data:
                self.data += self.conn.recv(1024)
            line, self.data = self.data.split('\n', 1)
        except socket.error as e:
            logger().error("[helper] Remote Helper recv error: %s" % e)
        return line

###############################################################################################
# Driver/service management functions
###############################################################################################
                                                                                                            
    def create(self, start_driver):
        VARIABLE_NAME = 'CHIPSEC_REMOTE_ADDRESS'
        addr = os.environ.get(VARIABLE_NAME, '')
        if not addr:
            logger().error("[helper] %s environment variable is not defined!" % VARIABLE_NAME)
        else:
            addr = addr.split(':', 2)
            if len(addr) == 1:
                self.host = addr[0]
            else:
                try:
                    self.port = int(addr[1])
                    self.host = addr[0]
                except:
                    logger().error("[helper] %s environment variable has invalid address!" % VARIABLE_NAME)

        self.data = ''
        if logger().VERBOSE:
            logger().log("[helper] Remote Helper created")


    def start(self, start_driver):
        logger().log("[helper] Connecting to %s:%d ..." % (self.host, self.port))

        while True:
            try:
                self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.conn.connect((self.host, self.port))
                break
            except socket.error as e:
                if logger().VERBOSE:
                    logger().log(e)
                else:
                    sys.stdout.write('.')
                time.sleep(1.0)

        if logger().VERBOSE:
            logger().log("[helper] Remote Helper connected")
        self.driver_loaded = True


    def stop(self):
        self.conn.close()
        if logger().VERBOSE:
            logger().log("[helper] Remote Helper disconnected")

    def delete(self):
        if logger().VERBOSE:
            logger().log("[helper] Remote Helper deleted")

    def destroy(self):
        self.stop()
        self.delete()

#
# Get instance of this OS helper
#
def get_helper():
    return RemoteHelper( )
