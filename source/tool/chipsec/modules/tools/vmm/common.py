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


import sys
import socket
import struct
import random
import os.path
import json
import pprint
import binascii
from random                     import getrandbits, randint
from time                       import strftime, localtime
from chipsec.module_common      import *
from chipsec.defines            import *

class BaseModuleDebug(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
        self.debug = False
        self.promt = ''

    def __del__(self):
        pass

    ##
    ##  msg
    ##
    def msg(self, message):
        sys.stdout.write('[%s]  %s\n' % (self.promt, message))
        return

    ##
    ##  err
    ##
    def err(self, message):
        sys.stdout.write('[%s]  **** ERROR: %s\n' % (self.promt, message))
        return

    ##
    ##  dbg
    ##
    def dbg(self, message):
        if self.debug:
            sys.stdout.write('[%s]  %s\n' % (self.promt, message))
        return

    ##
    ##  hex
    ##
    def hex(self, title, data, w = 16):
        if title and data:
            title = '-'*6 + title + '-'*w*3
            sys.stdout.write('[%s]  %s' % (self.promt, title[:w*3+15]))
        a = 0
        for c in data:
          if a % w== 0:
              sys.stdout.write('\n[%s]  %08X: ' % (self.promt, a))
          elif a % w % 8 == 0:
             sys.stdout.write('| ')          
          sys.stdout.write('%02x ' % ord(c))
          a = a + 1
        sys.stdout.write('\n')
        return

    ##
    ##  fatal
    ##
    def fatal(self, message):
        sys.stdout.write('[%s]  **** FATAL: %s\n' % (self.promt, message))
        exit(1)
        return

    ##
    ##  info_bitwise
    ##
    def info_bitwise(self, reg, desc):
        i = 0
        while reg <> 0:
            if i in desc:
                self.msg('       Bit %2d:  %d  %s' % (i, reg & 0x1, desc[i]))
            i  += 1
            reg = reg >> 1
        return

class BaseModuleSupport(BaseModuleDebug):
    def __init__(self):
        BaseModuleDebug.__init__(self)
        self.initial_data        = []
        self.path = os.path.dirname(os.path.realpath(__file__)) + "\\"
        with open(self.path + "hv\\initial_data.json", "r") as json_file:
            self.initial_data = json.load(json_file)

    def __del__(self):
        #self.dump_initial_data("initial_data_auto_generated.json")
        BaseModuleDebug.__del__(self)

    def get_initial_data(self, statuses, vector, size, padding = '\x00'):
        connectionid_message = [(' '.join(["%02x" % ord(x) for x in DD(k)])) for k,v in self.hv_connectionid.iteritems() if v == 1]
        connectionid_event   = [(' '.join(["%02x" % ord(x) for x in DD(k)])) for k,v in self.hv_connectionid.iteritems() if v == 2]
        result = []
        for status in statuses:
            for item in self.initial_data:
                if (int(item['vector'], 16) == vector) and (item['status'] == status):
                    data = item['data']
                    data = data.replace('CONNECTION_ID_MESSAGE_TYPE', random.choice(connectionid_message))
                    data = data.replace('CONNECTION_ID_EVENT_TYPE',   random.choice(connectionid_event))
                    buffer = str(bytearray.fromhex(data)) + padding * size
                    result.append(buffer[:size])
        if not result:
            result = [padding * size]
        return result

    def add_initial_data(self, vector, buffer, status):
        found  = False
        buffer = buffer.rstrip("\x00")
        buffer = " ".join("%02x" % x for x in buffer)
        for item in self.initial_data:
            if int(item['vector'], 16) == vector:
                if item['data'] == buffer:
                    found = True
                    break
        if not found:
            self.initial_data.append({"vector": "%02x" % vector, "status": status, "data": buffer})
        return

    def dump_initial_data(self, filename):
        if self.initial_data:
            with open(self.path + filename, "w") as json_file:
                json.dump(self.initial_data, json_file, indent = 4)
        return

class BaseModuleHwAccess(BaseModuleSupport):

    ##
    ##  cpuid_info
    ##
    def cpuid_info(self, eax, ecx, desc):
        val = self.cs.cpu.cpuid(eax, ecx)
        self.msg('')
        self.msg('CPUID.%Xh.%Xh > %s' % (eax, ecx, desc))
        self.msg('EAX: 0x%08X EBX: 0x%08X ECX: 0x%08X EDX: 0x%08X' % (val[0], val[1], val[2], val[3]))
        return val

    ##
    ##  rdmsr
    ##
    def rdmsr(self, msr):
        temp = sys.stdout
        sys.stdout = open(os.devnull, 'wb')
        try:
            for tid in range(self.cs.msr.get_cpu_thread_count()):
                (eax, edx) = self.cs.msr.read_msr(tid, msr)
        except:
            sys.stdout = temp
            raise
        sys.stdout = temp
        return (edx, eax)

    ##
    ##  wrmsr
    ##
    def wrmsr(self, msr, value):
        temp = sys.stdout
        sys.stdout = open(os.devnull, 'wb')
        try:
            for tid in range(self.cs.msr.get_cpu_thread_count()):
                self.cs.msr.write_msr(tid, msr, value & 0xFFFFFFFF, value >> 32)
        except:
            sys.stdout = temp
            raise
        sys.stdout = temp
        return

### COMMON ROUTINES ############################################################

def weighted_choice(choices):
    total = sum(w for c, w in choices)
    r = random.uniform(0, total)
    x = 0
    for c, w in choices:
        if x + w >= r:
            return c
        x += w
    assert False, "Invalid parameters"

def rand_dd(n, rndbytes = 1, rndbits = 1):
    weights = [(0x00000000, 0.85), (0xFFFFFFFF, 0.10), (0xFFFF0000, 0.05), (0xFFFFFF00, 0.05)]
    buffer  = ''
    for i in xrange(n):
        buffer += DD(weighted_choice(weights))
    buffer = list(buffer)
    for i in xrange(rndbytes):
        pos = randint(0, len(buffer) - 1)
        buffer[pos] = chr(randint(0, 255))
    for i in xrange(rndbits):
        pos = randint(0, len(buffer) - 1)
        buffer[pos] = chr(ord(buffer[pos]) ^ (0x1 << randint(0, 7)))
    buffer = ''.join(buffer)
    return buffer

def overwrite(buffer, string, position):
    return buffer[:position] + string + buffer[position + len(string):]

def get_int_arg(arg):
    try:
       arg = int(eval(arg))
    except:
       print "\n  ERROR: Invalid parameter\n"
       exit(1)
    return arg

def hv_hciv(rep_start, rep_count, call_code, fast = 0):
    return (((rep_start & 0x0FFF) << 48) + ((rep_count & 0x0FFF) << 32) + ((fast & 0x1) << 16) + (call_code & 0xFFFF))

def uuid(id):
    return '{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}' % struct.unpack('<LHH8B', id)

### OPTIONAL ROUTINES ##########################################################

class session_logger(object):
    def __init__(self, log, details):
        self.defstdout = sys.stdout
        self.log       = log
        self.log2term  = True
        self.log2file  = True
        if self.log:
#            logpath = 'logs/'
#            logfile = '%s.log' % details
            logpath = 'logs/%s/' % strftime("%Yww%W.%w", localtime())
            logfile = '%s-%s.log' % (details, strftime("%H%M", localtime()))
            try:
                os.makedirs(logpath)
            except OSError:
                pass
            self.terminal = sys.stdout
            self.logfile = open(logpath + logfile, 'a')
    def write(self, message):
        if self.log and self.log2term:
            self.terminal.write(message)
        if self.log and self.log2file:
            self.logfile.write(message)
    def closefile(self):
        if self.log:
            self.logfile.close()
            sys.stdout = self.defstdout
