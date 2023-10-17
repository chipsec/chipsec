# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2018-2022, Intel Corporation
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Contact information:
# chipsec@intel.com
#

import json
import time
import os
from collections import OrderedDict
import xml.etree.ElementTree as ET
import xml.dom.minidom
from chipsec.logger import logger
from typing import Dict, List, Type, Optional


class ExitCode:
    OK = 0
    WARNING = 2
    DEPRECATED = 4
    FAIL = 8
    ERROR = 16
    EXCEPTION = 32
    INFORMATION = 64
    NOTAPPLICABLE = 128

    help_epilog = """\
  Exit Code
  ---------
  CHIPSEC returns an integer exit code:
  - Exit code is 0:       all modules ran successfully and passed
  - Exit code is not 0:   each bit means the following:
      - Bit 1: WARNING         at least one module had a warning
      - Bit 2: DEPRECATED      at least one module uses deprecated API
      - Bit 3: FAIL            at least one module failed
      - Bit 4: ERROR           at least one module wasn't able to run
      - Bit 5: EXCEPTION       at least one module threw an unexpected exception
      - Bit 6: INFORMATION     at least one module contained information
      - Bit 7: NOT APPLICABLE  at least one module was not applicable for the platform

"""

class TestCase:
    def __init__(self, name: str) -> None:
        self.name = name
        self.result = ''
        self.output = ''
        self.argv = ''
        self.desc = ''
        self.startTime = 0
        self.endTime = 0
        self.time = None

    def get_fields(self) -> Dict[str, str]:
        return {'name': self.name, 'output': self.output, 'result': self.result}

    def start_module(self) -> None:
        """Displays a banner for the module name provided."""
        text = f'\n[*] Running module: {self.name}'
        logger().log_heading(text)
        self.startTime = time.time()
        self.desc = self.name

    def end_module(self, result: str, arg: str) -> None:
        self.result = result
        self.argv = arg
        self.endTime = time.time()
        self.time = self.endTime - self.startTime


class ChipsecResults:
    def __init__(self, rc: bool = False):
        self.test_cases = []
        self.properties = None
        self.summary = False
        self.exceptions = []
        self.time = None
        self.using_return_codes = rc

    def add_properties(self, properties: Dict[str, str]) -> None:
        self.properties = properties

    def add_testcase(self, test: Type[TestCase]) -> None:
        self.test_cases.append(test)

    def get_current(self) -> Optional[Type[TestCase]]:
        if len(self.test_cases) == 0 or self.summary:
            return None
        return self.test_cases[len(self.test_cases) - 1]

    def add_exception(self, name):
        self.exceptions.append(str(name))

    def get_return_code(self) -> Dict[str, List[TestCase]]:
        if self.using_return_codes:
            return self.get_return_codeRC()
        return self.get_return_codeL()
    
    # -------------------------------------------------------
    # Legacy results
    # -------------------------------------------------------
    def order_summaryL(self) -> Dict[str, List[TestCase]]:
        self.summary = True
        ret = OrderedDict()
        passed = []
        failed = []
        errors = []
        warnings = []
        information = []
        notapplicable = []
        executed = 0
        for test in self.test_cases:
            executed += 1
            fields = test.get_fields()
            if fields['result'] == 'Passed':
                passed.append(fields['name'])
            elif fields['result'] == 'Failed':
                failed.append(fields['name'])
            elif fields['result'] == 'Error':
                errors.append(fields['name'])
            elif fields['result'] == 'Warning':
                warnings.append(fields['name'])
            elif fields['result'] == 'Information':
                information.append(fields['name'])
            elif fields['result'] == 'NotApplicable':
                notapplicable.append(fields['name'])
        ret['total'] = executed
        ret['failed to run'] = errors
        ret['passed'] = passed
        ret['information'] = information
        ret['failed'] = failed
        ret['warnings'] = warnings
        ret['not applicable'] = notapplicable
        ret['exceptions'] = self.exceptions
        return ret

    def get_return_codeL(self) -> int:
        summary = self.order_summaryL()
        if len(summary['failed to run']) != 0:
            return ExitCode.ERROR
        elif len(summary['exceptions']) != 0:
            return ExitCode.EXCEPTION
        elif len(summary['failed']) != 0:
            return ExitCode.FAIL
        elif len(summary['warnings']) != 0:
            return ExitCode.WARNING
        elif len(summary['not applicable']) != 0:
            return ExitCode.NOTAPPLICABLE
        elif len(summary['information']) != 0:
            return ExitCode.INFORMATION
        else:
            return ExitCode.OK
    # -------------------------------------------------------
        
    def order_summaryRC(self):
        if self.time is None:
            self.set_time()
        self.summary = True
        ret = OrderedDict()
        passed = []
        failed = []
        executed = 0
        for test in self.test_cases:
            executed += 1
            fields = test.get_fields()
            if fields['result'] == 'Passed':
                passed.append(fields['name'])
            elif fields['result'] == 'Failed':
                failed.append(fields['name'])
        ret['total'] = executed
        ret['failed'] = failed
        ret['passed'] = passed
        ret['exceptions'] = self.exceptions
        return ret

    def get_return_codeRC(self):
        summary = self.order_summaryRC()
        if len(summary['failed']) != 0:
            return ExitCode.FAIL
        else:
            return ExitCode.OK


    def set_time(self, pTime: Optional[float] = None) -> None:
        """Sets the time"""
        if pTime is not None:
            self.time = pTime
        else:
            if len(self.test_cases) > 1:
                self.time = self.get_current().endTime - self.test_cases[0].startTime
            else:
                self.time = self.test_cases[0].time

    def get_results(self) -> Dict[str, int]:
        results = {}
        for test in self.test_cases:
            results[test.name] = {'result': test.result}
        return results

    def xml_summary(self) -> str:
        summary = self.order_summary()
        xml_element = ET.Element("Summary")
        for value in summary.keys():
            temp = {}
            if value == 'total':
                temp['name'] = value
                temp['total'] = f'{summary[value]:d}'
                m_element = ET.SubElement(xml_element, 'result', temp)
            else:
                temp['name'] = value
                temp['total'] = f'{len(summary[value]):d}'
                m_element = ET.SubElement(xml_element, 'result', temp)
                for mod in summary[value]:
                    n_element = ET.SubElement(m_element, 'module')
                    n_element.text = mod
        return ET.tostring(xml_element, "unicode", None)

    def json_summary(self) -> str:
        summary = self.order_summary()
        js = json.dumps(summary, sort_keys=False, indent=2, separators=(',', ': '))
        return js

    def json_full(self) -> str:
        summary = self.get_results()
        js = json.dumps(summary, sort_keys=False, indent=2, separators=(',', ': '))
        return js

    def xml_full(self, name: str, runtime: Optional[float] = None) -> str:
        xml_element = ET.Element('testsuites')
        summary = self.order_summary()
        summary_dict = {}
        for value in summary.keys():
            if value == 'total':
                summary_dict[value] = f'{summary[value]:d}'
            else:
                summary_dict[value.replace(' ', '')] = f'{len(summary[value]):d}'
        summary_dict["name"] = os.path.basename(os.path.splitext(name)[0])
        if runtime is not None:
            summary_dict["time"] = f'{runtime:5f}'
        ts_element = ET.SubElement(xml_element, "testsuite", summary_dict)
        # add properties
        pr_element = ET.SubElement(ts_element, "properties")
        prop_dict = {}
        if self.properties is not None:
            for value in self.properties:
                prop_dict["name"] = value
                prop_dict["value"] = self.properties[value]
                ET.SubElement(pr_element, "property", prop_dict)
        # add test cases
        for test in self.test_cases:
            ttime = test.time if test.time is not None else 0.0
            tc_element = ET.SubElement(ts_element, "testcase", {'classname': test.name, 'name': test.desc, 'time': f'{ttime:5f}'})
            ET.SubElement(tc_element, "pass", {"type": test.result})
            out_element = ET.SubElement(tc_element, "system-out")
            out_element.text = test.output
        return xml.dom.minidom.parseString(ET.tostring(xml_element, None, None)).toprettyxml()

    def markdown_full(self, name: str) -> str:
        passed = []
        failed = []
        error = []
        warning = []
        information = []
        notapplicable = []
        deprecated = []
        destination = {'Passed': passed,
                       'Failed': failed,
                       'Error': error,
                       'Warning': warning,
                       'Information': information,
                       'NotApplicable': notapplicable,
                       'Deprecated': deprecated
                       }

        for test in self.test_cases:
            # Test case as header level 4
            out_string = f'#### {test.name.replace("chipsec.modules.", ""):s}\n'
            for line in test.output.splitlines(True):
                # Format output as code
                out_string += f'    {line:s}'
            destination[test.result].append(out_string)

        ret_string = ''
        for result in destination:
            # Category as header level 1
            ret_string += f'\n# {result:s}:{len(destination[result]):d}\n'
            ret_string += ''.join(destination[result])
        return ret_string
    
    def print_summary(self, runtime: Optional[float] = None) -> None:
        if self.using_return_codes:
            self.print_summaryRC(runtime)
        else:
            self.print_summaryL(runtime)

    def print_summaryL(self, runtime: Optional[float] = None) -> None:
        summary = self.order_summaryL()
        filler = '*' * 27
        logger().log(f'\n[CHIPSEC] {filler}  SUMMARY  {filler}')
        if runtime is not None:
            logger().log(f'[CHIPSEC] Time elapsed            {runtime:.3f}')

        for result in summary.keys():
            if result == 'total':
                logger().log(f'[CHIPSEC] Modules {result:16}{summary[result]:d}')
            elif result == 'warnings':
                logger().log(f'[CHIPSEC] Modules with {result:11}{len(summary[result]):d}:')
                for mod in summary[result]:
                    logger().log_warning(mod)
            elif result == 'exceptions':
                if len(summary[result]) > 0:
                    logger().log(f'[CHIPSEC] Modules with {result:11}{len(summary[result]):d}:')
                    for mod in summary[result]:
                        logger().log_error(mod)
            else:
                logger().log(f'[CHIPSEC] Modules {result:16}{len(summary[result]):d}:')
                for mod in summary[result]:
                    if result == 'failed to run':
                        logger().log_error(mod)
                    elif result == 'passed':
                        logger().log_passed(mod)
                    elif result == 'information':
                        logger().log_information(mod)
                    elif result == 'failed':
                        logger().log_failed(mod)
                    elif result == 'not applicable':
                        logger().log_not_applicable(mod)
        logger().log('[CHIPSEC] *****************************************************************')

    def print_summaryRC(self, runtime: Optional[float] = None) -> None:
        summary = self.order_summaryRC()
        filler = '*' * 27
        logger().log(f'\n[CHIPSEC] {filler}  SUMMARY  {filler}')
        if runtime is not None:
            logger().log(f'[CHIPSEC] Time elapsed            {runtime:.3f}')

        for result in summary.keys():
            if result == 'total':
                logger().log(f'[CHIPSEC] Modules {result:16}{summary[result]:d}')
            elif result == 'exceptions':
                if len(summary[result]) > 0:
                    logger().log(f'[CHIPSEC] Modules with {result:11}{len(summary[result]):d}:')
                    for mod in summary[result]:
                        logger().log_error(mod)
            else:
                logger().log(f'[CHIPSEC] Modules {result:16}{len(summary[result]):d}:')
                for mod in summary[result]:
                    logger().log(f"    {mod}")
        logger().log('[CHIPSEC] *****************************************************************')
