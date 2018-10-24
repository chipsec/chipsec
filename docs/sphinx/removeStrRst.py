#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2018, Intel Corporation
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


import os

doc_path = os.getcwd()
src_path = os.path.abspath(os.path.join(doc_path, '..\..'))
log_list = os.listdir( doc_path )
log_path = doc_path.replace( '\\', '/' )

# Remove subheaders from all rst modules
def modulesRst():
    for dirname, subdirs, rstFiles in os.walk(os.path.join(doc_path, 'modules')) :
        for file in rstFiles:
            index = 0
            log = ''
            f = open(os.path.join('modules', file), 'r')
            firstLine = f.readline()
            f.close()

            f = open(os.path.join('modules', file), 'r')
            contents = f.read()
            f.close()

            contents = contents.replace( 'Submodules\n----------', '' )
            contents = contents.replace( 'Module contents\n---------------', '' )
            contents = contents.replace( 'Subpackages\n-----------', '' )
            contents = contents.replace( ':undoc-members:', ':private-members:' )

            if 'package' in firstLine:
                index = contents.find( '.. toctree' )
            else:
                if 'chipsec.modules' in firstLine:
                    modName = file.split( '.' )[ -2 ]
                    modname = '/test_chipsec_main_' + modName + '.log'
                    if modname[1:] in log_list:
                        log = logFile( modname )
                        log_list.remove( modname[1:] )

            f = open(os.path.join('modules', file), 'w')
            f.write( contents[index:] + log )
            f.close()


def logFile( fileName ):
    f = open( log_path + fileName, 'r' )
    log = '\n\n.. code-block:: python\n\n'
    while True:
        line = f.readline()
        if line == '':
            break
        if 'Arguments' in line:
            remLog = line.find('-x')
            line = line[:remLog]
        if 'Module path' in line:
            remPath = line.find('source')
            line = line.replace( line[17:remPath-1], '<chipsec_path>')
        log += '\t' + line
    f.close()
    return log

# Create rst for xml files
def xmlRst():
    for dirname, subdirs, cfgFiles in os.walk(os.path.join(src_path, 'chipsec', 'cfg')):
        moduleStr = ''
        for cfg in cfgFiles:
            if ".py" not in cfg:
                moduleStr += '\tchipsec.cfg.{0}.rst\n'.format(cfg)
                f = open(os.path.join(src_path, 'chipsec', 'cfg', cfg), 'r')
                xmlContent = f.read()
                f.close()
                commentBegins = xmlContent.find('<!--')
                commentEnds = xmlContent.find('-->')
                xmlComment = xmlContent[commentBegins+4:commentEnds] + '\n'
                f = open(os.path.join(doc_path, 'modules', 'chipsec.cfg.' + cfg + '.rst'), 'w')
                title = "chipsec.cfg." + cfg
                f.write( title + "\n" + "="*len(title) + "\n\n" + xmlComment )
                f.close()
        f = open(os.path.join(doc_path, 'modules', 'chipsec.cfg.rst'), 'w')
        f.write(".. toctree::\n\n" + moduleStr)
        f.close()

if __name__ == "__main__":
    modulesRst()
    xmlRst()
