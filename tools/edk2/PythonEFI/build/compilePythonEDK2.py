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



import sys
import os
import shutil
import fnmatch
from distutils import dir_util
import subprocess
import platform

TARGET_X64 = 'X64'
TARGET_IA32 = 'IA32'
TARGET_I586 = 'i586'

TARGETS= [TARGET_X64 ,TARGET_IA32, TARGET_I586 ]
asmFiles = {TARGET_X64:  'cpu.asm',
            TARGET_IA32: 'cpu_ia32.asm',
            TARGET_I586: 'cpu_ia32_gcc.s'}

class PythonEDk2:
    
    def __init__(self):
        self.edk2_path = ''
        self.target = TARGET_X64
        self.is_linux = ("linux" == platform.system().lower())
        
    def usage(self):
        print "\nUSAGE: %.65s --edk2 <edk2-path>  [--target <target>]" % sys.argv[0]
        print "OPTIONS:"
        print "    -e, --edk2             specify path where edk2 exist in the local filesystem"
        print "    -t, --target           one of X64, IA32, i586. if none is specified X64 is used"
        print " "
        print "NOTES:"
        print "    By default the tool chanins used are GCC46 for Linux and VS2012x86 for windows"
        print "    if you need to use a different toolchain please modify manually the EDKII file Conf/target.txt "
        print "    This script will not change the value unless the current value is MYTOOLS, in that case it will "
        print "    modify it to be the default values mentioned above."


    def parse_args(self, argv):
        import getopt
        try:
            opts, args = getopt.getopt(argv, "e:ht:",
            ["edk2=","help","target="])
        except getopt.GetoptError, err:
            print str(err)
            self.usage()
            return 1
        
        for o, a in opts:
            if o in ("-e", "--edk2"):
                self.edk2_path = a
            elif o in ("-h", "--help"):
                self.usage()
                return 0
            elif o in ("-t", "--target"):
                self.target = a
        
        if len(self.edk2_path) <=0:
            self.usage()
            return 1
        if self.target not in TARGETS:
            print "\n\nERROR: Invalid target \"%s\". Valid targets are: %s"%(self.target, TARGETS)
            return 1
        if self.target == TARGET_I586 and not self.is_linux:
            print"\n\nERROR: Target \"%s\" can only be compiled in linux"%(self.target)
            return 1
        return 0

    
    def setupTarget(self):
        efi_path = os.path.join(self.edk2_path,"AppPkg","Applications","Python","Efi")
        for file in os.listdir('..'):
            if fnmatch.fnmatch(file, '*.asm') or fnmatch.fnmatch(file, '*.s') or fnmatch.fnmatch(file, '*.c'):
                print "copying %-60s to %s"%(file , efi_path)
                shutil.copy(os.path.join(os.pardir,file) , efi_path)
        print
        py_mod = os.path.join(self.edk2_path,"AppPkg","Applications","Python","PyMod-2.7.2")
        py_dir = os.path.join(self.edk2_path,"AppPkg","Applications","Python","Python-2.7.2")
        print py_dir
        #for dir in os.listdir(py_mod):
        print "copying %-80s to %s"%(py_mod , py_dir)
        reserve_mode=1
        preserve_times=1,
        preserve_symlinks=0
        update=0
        verbose=5
        dry_run=0
        dir_util.copy_tree(py_mod , py_dir, reserve_mode, preserve_times,
          preserve_symlinks, update, verbose, dry_run)
        print
        import fileinput
        # un-comment the line in AppPkg.dsc to compile python
        AppPkg_dsc = os.path.join(self.edk2_path,"AppPkg","AppPkg.dsc")
        for line in fileinput.input(AppPkg_dsc, inplace=True):
            if line.strip().startswith('#') and 'PythonCore.inf' in line:
                sys.stdout.write( line.replace('#','',1) )
            else:
                sys.stdout.write( line )
        # add the assembly file to the sources for compilation
        PythonCore_inf = os.path.join(self.edk2_path,"AppPkg","Applications","Python","PythonCore.inf")
        in_sources= False
        wrote_asm = False
        for line in fileinput.input(PythonCore_inf, inplace=True):
            if not in_sources:
                if "[Sources]" in  line: 
                    in_sources = True
                sys.stdout.write( line )
            else:
                if "cpu" in line:
                    sys.stdout.write ( "  Efi/%s\n"%asmFiles[self.target])
                    wrote_asm = True
                elif len(line.strip()) <= 1:
                    in_sources = False
                    if not wrote_asm:
                        sys.stdout.write ( "  Efi/%s\n"%asmFiles[self.target])
                    sys.stdout.write( line )
                else:
                    sys.stdout.write( line )
        
        target_txt = os.path.join(self.edk2_path,"Conf","target.txt")
        
        if self.is_linux: tool_chain_tag = "GCC46"
        else: tool_chain_tag = "VS2012x86"
        
        for line in fileinput.input(target_txt, inplace=True):
            if "MYTOOLS" in  line:
                sys.stdout.write(line.replace("MYTOOLS",tool_chain_tag))
            elif "MAX_CONCURRENT_THREAD_NUMBER" in line and "#" not in line:
                sys.stdout.write("MAX_CONCURRENT_THREAD_NUMBER = 12\n")
            elif line.startswith("TARGET"):
                sys.stdout.write(line.replace("RELEASE", "DEBUG"))
                
            else:
                sys.stdout.write(line)
        
        # un-comment pyexpath from config.c
        config_c = os.path.join(self.edk2_path,"AppPkg","Applications","Python","Efi","config.c" )
        for line in fileinput.input(config_c, inplace=True):
            if line.strip().startswith('/') and ('pyexpat' in line or
                                                  '_md5' in line or
                                                  '_sha' in line or 
                                                  '_sha256' in line or
                                                  '_sha512' in line):
                sys.stdout.write( line.replace('/','',2) )
            else:
                sys.stdout.write( line )
        
        march ='-march=i586'
        tools_def = os.path.join(self.edk2_path,"Conf","tools_def.txt")
        for line in fileinput.input(tools_def, inplace=True):
            if line.strip().startswith("DEFINE GCC46_IA32_CC_FLAGS"):
                if self.target == TARGET_I586:
                    if not march in line:
                        sys.stdout.write( "%s %s\n" %(line.strip(), march) )
                    else:
                        sys.stdout.write( line )
                else:
                    if march in line:
                        sys.stdout.write( line.replace(march, '') )
                    else:
                        sys.stdout.write( line )
            else:
                sys.stdout.write( line )
        

    def compile(self):
        env = os.environ.copy()
        print self.edk2_path
        if self.is_linux:
            ec = subprocess.call(['pwd' ], shell=True, stderr=subprocess.STDOUT, env = env, cwd = self.edk2_path)
            ec = subprocess.call(['bash','-c','source edksetup.sh' ],  stderr=subprocess.STDOUT, env = env, cwd = self.edk2_path)
        else:
            ec = subprocess.call(["edk2setup" ], shell=True, stderr=subprocess.STDOUT, env = env, cwd = self.edk2_path)
        
        if ec == 0:
            self.setupTarget()
            env = os.environ.copy()
            if self.is_linux:
                ec = subprocess.call(["pwd"], shell=True, stderr=subprocess.STDOUT, env = env)
                ec = subprocess.call(['bash', '-c',"chmod 775 build_edk2_python.sh",self.edk2_path, self.target ],stderr=subprocess.STDOUT, env = env)
                ec = subprocess.call(["./build_edk2_python.sh",self.edk2_path, self.target ],stderr=subprocess.STDOUT, env = env)
            else:
                ec = subprocess.call(["build_edk2_python",self.edk2_path, self.target ], shell=True, stderr=subprocess.STDOUT, env = env)
        print ec
        return ec



if __name__ == "__main__":
    pythonEDk2 = PythonEDk2()
    ec = pythonEDk2.parse_args(sys.argv[1:])
    if ec == 0:
        ec = pythonEDk2.compile()
    sys.exit(ec)
