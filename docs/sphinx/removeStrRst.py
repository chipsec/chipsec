#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2021, Intel Corporation
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
src_path = os.path.abspath(os.path.join(doc_path, '..', '..'))

# Remove subheaders from all rst modules
def modulesRst():
    for _, _, rstFiles in os.walk(os.path.join(doc_path, 'modules')):
        for file in rstFiles:
            f = open(os.path.join('modules', file), 'r')
            title = f.readline().split('.')
            contents = f.read()
            f.close()

            contents = contents.replace('Submodules\n----------\n\n', '')
            contents = contents.replace('Subpackages\n-----------\n\n', '')
            contents = contents.replace('Module contents\n---------------\n\n', '')

            f = open(os.path.join('modules', file), 'w')
            f.write(title[-1] + contents)
            f.close()

# Create rst for xml files
def xmlRst():
    for _, _, cfgFiles in os.walk(os.path.join(src_path, 'chipsec', 'cfg', '8086')):
        moduleStr = ''
        for cfg in cfgFiles:
            if ".py" not in cfg:
                moduleStr += '\tchipsec.cfg.8086.{0}.rst\n'.format(cfg)
                f = open(os.path.join(src_path, 'chipsec', 'cfg', '8086', cfg), 'r')
                xmlContent = f.read()
                f.close()
                commentBegins = xmlContent.find('<!--')
                commentEnds = xmlContent.find('-->')
                xmlComment = xmlContent[commentBegins +4:commentEnds] + '\n'
                f = open(os.path.join(doc_path, 'modules', 'chipsec.cfg.8086.' + cfg + '.rst'), 'w')
                path = "chipsec\\\\cfg\\\\8086\\\\" + cfg
                f.write( cfg[:-4] + "\n" + "=" *len(cfg) + "\n\n" + "Path: " + path + "\n\n" + xmlComment )
                f.close()
        f = open(os.path.join(doc_path, 'modules', 'chipsec.cfg.8086.rst'), 'w')
        f.write(".. toctree::\n\n" + moduleStr)
        f.close()

def getVersion():
    ver_path = os.path.join(src_path, 'chipsec', 'VERSION')
    scover_path = os.path.join(doc_path, '_templates','scover.tmpl')

    f = open(os.path.join(ver_path), 'r')
    version = f.read()
    f.close()

    f = open(os.path.join(scover_path), 'r')
    contents = f.read()
    f.close()

    splitContents = contents.split('\n')
    contents = contents.replace(splitContents[8], 'version ' + version)
    f = open(os.path.join(scover_path), 'w')
    f.write(contents)
    f.close()
    

if __name__ == "__main__":
    modulesRst()
    xmlRst()
    getVersion()
