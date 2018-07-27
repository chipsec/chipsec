import json
from collections import OrderedDict

class ChipsecResults():
    def __init__(self):
        self.test_cases = []
        self.properties = None
        self.summary = False
        
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
        ret['passed'] = passed
        ret['information'] = information
        ret['failed'] = failed
        ret['warnings'] = warnings
        ret['not implemented'] = skipped
        ret['not applicable'] = notapplicable
        ret['with Exceptions'] =errors 
        return ret
        
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
        txt += '[CHIPSEC] *****************************************************************'
        return txt
        
    def xml_summary(self):
        summary = self.order_summary()
        xml =  '<?xml version="1.0" ?>\n'
        xml += '<Summary>\n'
        for k in summary.keys():
            if k == 'total':
                xml += '  <Metric name="Modules {}">\n    <total>\n      {:d}\n    </total>\n  </Metric>\n'.format(k,summary[k])
            else:
                xml += '  <Metric name="Modules {}">\n    <total>\n      {:d}\n    </total>\n'.format(k,len(summary[k]))
                for mod in summary[k]:
                    xml += '    <name>\n      {}\n    </name>\n'.format(mod)
                xml += '    </Metric name=Modules {}>\n'.format(k)
        xml += '</Summary>\n'
        return xml
        
    def json_summary(self):
        summary = self.order_summary()
        js = json.loads(json.dumps(summary, sort_keys=True, indent=2, separators=(',', ': ')))
        return js
                
class TestCase():
    def __init__(self, name):
        self.name = name
        self.result = ''
        self.output = ''
        self.argv = ''
        
    def add_output(self, text):
		self.output += text
		
    def add_result(self, result):
        self.result = result
        
    def add_arg(self, arg):
        self.argv = arg
		
    def get_fields(self):
		return {'name':self.name,'output':self.output,'result':self.result}
