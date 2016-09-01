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

"""
 Usage:
   ``chipsec_main.py -i -m tools.remote [ -a <ipaddr:port> ]``

"""

import time
import errno
import socket
from chipsec.module_common import *
from chipsec.file import *

class Remote(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.sock = None
        self.conn = None
        self.data = ''

    def send_line(self, msg):
        return self.conn.sendall(msg + '\n')

    def recv_line(self):
        line = ''
        while '\n' not in self.data:
            buffer = self.conn.recv(1024)
            self.data += buffer
            if not buffer:
                return ''
        line, self.data = self.data.split('\n', 1)
        return line

    def execute_helper_command(self):
        try:
            values = self.recv_line()
            if not values:
                logger().log('\nConnection reset by peer!\n')
                return False
            try:
                values = eval(values)
                attr = getattr(self.cs.helper.helper, values[0])
                if callable(attr):
                    result = [True, attr(*values[1], **values[2])]
                else:
                    result = [True, attr]
            except Exception as e:
                result = [False, e]
            self.send_line(str(result))
        except socket.error as e:
            if e.errno == errno.ECONNRESET:
                logger().log('\nConnection reset by peer!\n')
            elif logger().VERBOSE:
                logger().error(str(e))
            return False
        return True
                
    def run(self, module_argv):
        self.logger.start_test('Client for remote helper')
        host = socket.gethostname()
        port = 5000
        if module_argv:
            args = module_argv[0].split(':')            
            if len(args) == 1:
                host = args[0]
            elif len(args) == 2:
                try:
                    port = int(args[1])
                    host = args[0]
                except ValueError:
                    self.logger.error("Invalid port: %s" % args[1])
                    return ModuleResult.FAILED
            else:
                self.logger.error("Invalid parameter: %s" % module_argv[0])
                return ModuleResult.FAILED

        host = socket.gethostbyname(host)

        while True:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.bind((host, port))
                self.sock.listen(1)
                break
            except socket.error as e:
                if e.errno != errno.EADDRINUSE:
                    logger().error(e)
                    return ModuleResult.FAILED

        logger().log('Waiting for connections on %s:%d' % (host, port))

        while True:
            count = 0
            self.conn, addr = self.sock.accept()
            logger().log('Got connection from: %s:%d ' % addr)
            while self.execute_helper_command():
                count += 1
                if count % 1000 == 0:
                    sys.stdout.write(str(count))
                sys.stdout.write('.')

            self.conn.close()

        return ModuleResult.PASSED
