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
from typing import Dict, Type, Optional


class ExitCode:
    OK = 0
    SKIPPED = 1
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
      - Bit 0: SKIPPED         at least one module was skipped for the platform
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
        self.startTime = None
        self.endTime = None
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
    def __init__(self):
        self.test_cases = []
        self.properties = None
        self.summary = False
        self.exceptions = []
        self.time = None

    def add_properties(self, properties: Dict[str, str]) -> None:
        self.properties = properties

    def add_testcase(self, test: Type[TestCase]) -> None:
        self.test_cases.append(test)

    def get_current(self) -> Type[TestCase]:
        if len(self.test_cases) == 0 or self.summary:
            return None
        return self.test_cases[len(self.test_cases) - 1]

    def add_exception(self, name):
        self.exceptions.append(str(name))

    def order_summary(self) -> None:
        self.summary = True
        ret = OrderedDict()
        passed = []
        failed = []
        errors = []
        warnings = []
        skipped = []
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
            elif fields['result'] == 'Skipped':
                skipped.append(fields['name'])
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
        ret['skipped'] = skipped
        ret['not applicable'] = notapplicable
        ret['exceptions'] = self.exceptions
        return ret

    def get_return_code(self) -> int:
        summary = self.order_summary()
        if len(summary['failed to run']) != 0:
            return ExitCode.ERROR
        elif len(summary['exceptions']) != 0:
            return ExitCode.EXCEPTION
        elif len(summary['failed']) != 0:
            return ExitCode.FAIL
        elif len(summary['warnings']) != 0:
            return ExitCode.WARNING
        elif len(summary['skipped']) != 0:
            return ExitCode.SKIPPED
        elif len(summary['not applicable']) != 0:
            return ExitCode.NOTAPPLICABLE
        elif len(summary['information']) != 0:
            return ExitCode.INFORMATION
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
        for k in summary.keys():
            temp = {}
            if k == 'total':
                temp['name'] = k
                temp['total'] = "{:d}".format(summary[k])
                m_element = ET.SubElement(xml_element, 'result', temp)
            else:
                temp['name'] = k
                temp['total'] = "{:d}".format(len(summary[k]))
                m_element = ET.SubElement(xml_element, 'result', temp)
                for mod in summary[k]:
                    n_element = ET.SubElement(m_element, 'module')
                    n_element.text = mod
        return ET.tostring(xml_element, None, None)

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
        for k in summary.keys():
            if k == 'total':
                summary_dict[k] = f'{summary[k]:d}'
            else:
                summary_dict[k.replace(' ', '')] = f'{len(summary[k]):d}'
        summary_dict["name"] = os.path.basename(os.path.splitext(name)[0])
        if runtime is not None:
            summary_dict["time"] = f'{runtime:5f}'
        ts_element = ET.SubElement(xml_element, "testsuite", summary_dict)
        # add properties
        pr_element = ET.SubElement(ts_element, "properties")
        prop_dict = {}
        for k in self.properties:
            prop_dict["name"] = k
            prop_dict["value"] = self.properties[k]
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
        skipped = []
        information = []
        notapplicable = []
        deprecated = []
        destination = {'Passed': passed,
                       'Failed': failed,
                       'Error': error,
                       'Warning': warning,
                       'Skipped': skipped,
                       'Information': information,
                       'NotApplicable': notapplicable,
                       'Deprecated': deprecated
                       }

        for test in self.test_cases:
            # Test case as header level 4
            out_string = f'#### {test.name.replace("chipsec.modules.", ""):s}\n'
            for line in test.output.splitlines(True):
                # Format output as code
                out_string += '    {:s}'.format(line)
            destination[test.result].append(out_string)

        ret_string = ''
        for result in destination:
            # Category as header level 1
            ret_string += f'\n# {result:s}:{len(destination[result]):d}\n'
            ret_string += ''.join(destination[result])
        return ret_string

    def print_summary(self, runtime: Optional[float] = None) -> None:
        summary = self.order_summary()
        filler = '*' * 27
        logger().log(f'\n[CHIPSEC] {filler}  SUMMARY  {filler}')
        if runtime is not None:
            logger().log(f'[CHIPSEC] Time elapsed            {runtime:.3f}')

        for k in summary.keys():
            if k == 'total':
                logger().log(f'[CHIPSEC] Modules {k:16}{summary[k]:d}')
            elif k == 'warnings':
                logger().log(f'[CHIPSEC] Modules with {k:11}{len(summary[k]):d}:')
                for mod in summary[k]:
                    logger().log_warning(mod)
            elif k == 'exceptions':
                if len(summary[k]) > 0:
                    logger().log(f'[CHIPSEC] Modules with {k:11}{len(summary[k]):d}:')
                    for mod in summary[k]:
                        logger().log_error(mod)
            else:
                logger().log(f'[CHIPSEC] Modules {k:16}{len(summary[k]):d}:')
                for mod in summary[k]:
                    if k == 'failed to run':
                        logger().log_error(mod)
                    elif k == 'passed':
                        logger().log_passed(mod)
                    elif k == 'information':
                        logger().log_information(mod)
                    elif k == 'failed':
                        logger().log_failed(mod)
                    elif k == 'skipped':
                        logger().log_skipped(mod)
                    elif k == 'not applicable':
                        logger().log_not_applicable(mod)
        logger().log('[CHIPSEC] *****************************************************************')
