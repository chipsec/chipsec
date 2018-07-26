import json
import time
import os
from collections import OrderedDict
import xml.etree.ElementTree as ET

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
            return ERROR
        elif len(summary['exceptions']) != 0:
            return EXCEPTION
        elif len(summary['failed']) != 0:
            return FAIL
        elif len(summary['warnings']) != 0:
            return WARNING
        elif len(summary['skipped']) != 0:
            return SKIPPED
        elif len(summary['not applicable']) != 0:
            return NOTAPPLICABLE
        elif len(summary['information']) != 0:
            return INFORMATION
        else:
            return OK

    def set_time(self, pTime=None):
        """Sets the time"""
        if pTime is not None:
            self.time = pTime
        else:
            if len(self.test_cases) > 1:
                self.time = self.get_current().endTime - self.test_cases[0].startTime
            else:
                self.time = self.test_cases[0].time
        
    def txt_summary(self):
        summary = self.order_summary()
        txt =  '[CHIPSEC] ***************************  SUMMARY  ***************************\n'
        for k in summary.keys():
            if k == 'total':
                txt += '[CHIPSEC] Modules {:16}{:d}\n'.format(k,summary[k])
            else:
                txt += '[CHIPSEC] Modules {:16}{:d}\n'.format(k,len(summary[k]))
                for mod in summary[k]:
                    txt += '    {}\n'.format(mod)
        txt += '[CHIPSEC] *****************************************************************\n'
        return txt
        
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

    def xml_full(self, name):
        self.set_time()
        xml_element = ET.Element("testsuites")
        summary = self.order_summary()
        summary_dict = dict()
        for k in summary.keys():
            if k == 'total':
                summary_dict[k] = "{:d}".format(summary[k])
            else:
                summary_dict[k] = "{:d}".format(len(summary[k]))
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
            tc_element =  ET.SubElement(ts_element, "testcase", {'classname':test.name,'name':test.desc, 'time':"{:5f}".format(test.time)})
            r_element =   ET.SubElement(tc_element, "pass", {"type":test.result})
            out_element = ET.SubElement(tc_element, "system-out")
            out_element.text = test.output
        return ET.tostring( xml_element, None, None )

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
		self.output += text
		
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
        elif self.startTime == None:
            self.startTime = time.time()
        else:    
            self.endTime = time.time()
            self.time = self.endTime - self.startTime

    def get_fields(self):
        return {'name':self.name,'output':self.output,'result':self.result}