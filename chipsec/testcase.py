#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2018-2019, Intel Corporation
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

import json
import time
import os
from collections import OrderedDict
import xml.etree.ElementTree as ET
import xml.dom.minidom

class ExitCode:
    OK            = 0
    SKIPPED       = 1
    WARNING       = 2
    DEPRECATED    = 4
    FAIL          = 8
    ERROR         = 16
    EXCEPTION     = 32
    INFORMATION   = 64
    NOTAPPLICABLE = 128

    help_epilog = """\
  Exit Code
  ---------
  CHIPSEC returns an integer exit code:
  - Exit code is 0:       all modules ran successfully and passed
  - Exit code is not 0:   each bit means the following:
      - Bit 0: NOT IMPLEMENTED at least one module was not implemented for the platform
      - Bit 1: WARNING         at least one module had a warning
      - Bit 2: DEPRECATED      at least one module uses deprecated API
      - Bit 3: FAIL            at least one module failed
      - Bit 4: ERROR           at least one module wasn't able to run
      - Bit 5: EXCEPTION       at least one module threw an unexpected exception
      - Bit 6: INFORMATION     at least one module contained information
      - Bit 7: NOT APPLICABLE  at least one module was not applicable for the platform

"""


class ChipsecResults():
    def __init__(self):
        self.test_cases = []
        self.properties = None
        self.summary = False
        self.exceptions = []
        self.time = None

    def add_properties(self,properties):
        self.properties = properties

    def add_testcase(self,test):
        self.test_cases.append(test)

    def get_results(self):
        return self.test_cases

    def get_current(self):
        if len(self.test_cases) == 0 or self.summary:
            return None
        return self.test_cases[len(self.test_cases)-1]

    def add_exception(self,name):
        self.exceptions.append(str(name))

    def order_summary(self):
        if self.time is None:
            self.set_time()
        self.summary = True
        ret = OrderedDict()
        passed        = []
        failed        = []
        errors        = []
        warnings      = []
        skipped       = []
        information   = []
        notapplicable = []
        executed      = 0
        for test in self.test_cases:
            executed +=1
            fields = test.get_fields()
            if fields['result'] == 'Passed':
                passed.append(fields['name'])
            elif fields['result'] == 'Failed':
                failed.append(fields['name']) 
            elif fields['result'] == 'Error':
                errors.append(fields['name'])
            elif fields['result'] == 'Warning':
                warnings.append(fields['name'])
            elif fields['result'] == 'Skipped':
                skipped.append(fields['name'])
            elif fields['result'] == 'Information':
                information.append(fields['name'])
            elif fields['result'] == 'NotApplicable':
                notapplicable.append(fields['name']) 
        ret['total']  = executed
        ret['failed to run'] = errors
        ret['passed'] = passed
        ret['information'] = information
        ret['failed'] = failed
        ret['warnings'] = warnings
        ret['not implemented'] = skipped
        ret['not applicable'] = notapplicable
        ret['exceptions'] = self.exceptions 
        return ret

    def get_return_code(self):
        summary = self.order_summary()
        if len(summary['failed to run']) != 0:
            return ExitCode.ERROR
        elif len(summary['exceptions']) != 0:
            return ExitCode.EXCEPTION
        elif len(summary['failed']) != 0:
            return ExitCode.FAIL
        elif len(summary['warnings']) != 0:
            return ExitCode.WARNING
        elif len(summary['not implemented']) != 0:
            return ExitCode.SKIPPED
        elif len(summary['not applicable']) != 0:
            return ExitCode.NOTAPPLICABLE
        elif len(summary['information']) != 0:
            return ExitCode.INFORMATION
        else:
            return ExitCode.OK

    def set_time(self, pTime=None):
        """Sets the time"""
        if pTime is not None:
            self.time = pTime
        else:
            if len(self.test_cases) > 1:
                self.time = self.get_current().endTime - self.test_cases[0].startTime
            else:
                self.time = self.test_cases[0].time

    def get_results(self):
        results = {}
        for test in self.test_cases:
            results[test.name] = {"result":test.result}
        return results

    def xml_summary(self):
        summary = self.order_summary()
        xml_element = ET.Element("Summary")
        for k in summary.keys():
            temp = dict()
            if k == 'total':
                temp['name'] = k
                temp['total'] = "{:d}".format(summary[k])
                m_element = ET.SubElement( xml_element, 'result', temp)
            else:
                temp['name'] = k
                temp['total'] = "{:d}".format(len(summary[k]))
                m_element = ET.SubElement( xml_element, 'result', temp)
                for mod in summary[k]:
                    n_element = ET.SubElement( m_element, 'module')
                    n_element.text = mod
        return ET.tostring( xml_element, None, None )

    def json_summary(self):
        summary = self.order_summary()
        js = json.dumps(summary, sort_keys=False, indent=2, separators=(',', ': '))
        return js

    def json_full(self):
        summary = self.get_results()
        js = json.dumps(summary, sort_keys=False, indent=2, separators=(',', ': '))
        return js

    def xml_full(self, name):
        xml_element = ET.Element("testsuites")
        summary = self.order_summary()
        summary_dict = dict()
        for k in summary.keys():
            if k == 'total':
                summary_dict[k] = "{:d}".format(summary[k])
            else:
                summary_dict[k.replace(" ","")] = "{:d}".format(len(summary[k]))
        summary_dict["name"] = os.path.basename( os.path.splitext(name)[0] )
        summary_dict["time"] = "{:5f}".format( self.time )
        ts_element = ET.SubElement(xml_element,"testsuite",summary_dict)
        #add properties
        pr_element = ET.SubElement(ts_element,"properties")
        prop_dict = dict()
        for k in self.properties:
            prop_dict["name"]  = k
            prop_dict["value"] = self.properties[k]
            p_element = ET.SubElement(pr_element,"property",prop_dict)
        #add test cases
        for test in self.test_cases:
            tc_element =  ET.SubElement(ts_element, "testcase", {'classname':test.name,'name':test.desc, 'time':'{}'.format("{:5f}".format(test.time)if test.time is not None else "0.0")})
            r_element =   ET.SubElement(tc_element, "pass", {"type":test.result})
            out_element = ET.SubElement(tc_element, "system-out")
            out_element.text = test.output
        return xml.dom.minidom.parseString(ET.tostring( xml_element, None, None )).toprettyxml()

class TestCase():
    def __init__(self, name):
        self.name = name
        self.result = ''
        self.output = ''
        self.argv = ''
        self.desc = ''
        self.startTime = None
        self.endTime = None
        self.time = None

    def add_output(self, text):
        self.output += str(text)

    def add_result(self, result):
        self.result = result

    def add_arg(self, arg):
        self.argv = arg

    def add_desc(self, desc):
        self.desc = desc

    def set_time(self, pTime=None):
        """Sets the time"""
        if pTime is not None:
            self.time = pTime
        elif self.startTime is None:
            self.startTime = time.time()
        else:
            self.endTime = time.time()
            self.time = self.endTime - self.startTime

    def get_fields(self):
        return {'name':self.name,'output':self.output,'result':self.result}
