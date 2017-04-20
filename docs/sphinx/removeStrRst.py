#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2017, Intel Corporation
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

thisPath = os.getcwd()
logsList = os.listdir( thisPath )
logsPath = thisPath.replace( '\\', '/' )
           
# Remove subheaders from all rst modules
def modulesRst():
    for dirname, subdirs, rstFiles in os.walk( os.path.abspath( '.\\modules' ) ) :
        for file in rstFiles:
            index = 0
            log = ''
            f = open( 'modules/' + file, 'r' )
            firstLine = f.readline()
            f.close()

            f = open( 'modules/' + file, 'r' )
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
                    if modname[1:] in logsList: 
                        log = logFile( modname )
                        logsList.remove( modname[1:] )
                                
            f = open( 'modules/' + file, 'w' )
            f.write( contents[index:] + log )
            f.close()


def logFile( fileName ):
    f = open( logsPath + fileName, 'r' )
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
    for dirname, subdirs, cfgFiles in os.walk( os.path.abspath( '..\\chipsec\\cfg' ) ) :
        moduleStr = '' 
        for cfg in cfgFiles:
            if ".py" not in cfg:
                moduleStr += '\tchipsec.cfg.{0}.rst\n'.format(cfg)          
                f = open( '..\\chipsec\\cfg\\' + cfg, 'r' )
                xmlContent = f.read()
                f.close()
                commentBegins = xmlContent.find('<!--')
                commentEnds = xmlContent.find('-->')
                xmlComment = xmlContent[commentBegins+4:commentEnds] + '\n'
                f = open( '.\\modules\\chipsec.cfg.' + cfg + '.rst', 'w' )
                title = "chipsec.cfg." + cfg
                f.write( title + "\n" + "="*len(title) + "\n\n" + xmlComment )
                f.close()
        f = open( '.\\modules\\chipsec.cfg.rst', 'w' )
        f.write(".. toctree::\n\n" + moduleStr )
        f.close()
    
if __name__ == "__main__":
    modulesRst()
    xmlRst()