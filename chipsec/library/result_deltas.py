# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2018-2019, Intel Corporation
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
import xml.etree.ElementTree as ET

import chipsec.library.file
from chipsec.library.logger import logger
from chipsec.library.defines import bytestostring


def get_json_results(json_file):
    file_data = chipsec.library.file.read_file(json_file)
    if file_data == 0:
        return None
    try:
        json_data = json.loads(bytestostring(file_data))
    except Exception:
        logger().log_error(f'Unable to load JSON file: {json_file}')
        return None
    return json_data


def compute_result_deltas(previous, current):
    deltas = {}
    all_tests = set(current)
    all_tests.update(previous)
    for test in all_tests:
        new_res = prev_res = "-------"
        try:
            new_res = current[test]["result"]
        except Exception:
            logger().log_debug("Exception getting current result")
        try:
            prev_res = previous[test]["result"]
        except Exception:
            logger().log_debug("Exception getting previous result")
        if new_res != prev_res:
            deltas[test] = {'previous': prev_res, 'current': new_res}
    return deltas


def display_deltas(deltas, hide_time, start_time):
    logger().log("")
    logger().log("[CHIPSEC] **********************  TEST DELTA SUMMARY  *********************")
    if not hide_time:
        logger().log(f'[CHIPSEC] Time elapsed          {time.time() - start_time:.3f}')
    if deltas:
        logger().log(f'[*] {"Test":46}| {"Previous":10} | {"Current":10}')
        logger().log(f'[*] {"-" * 71}')
        for test in deltas:
            logger().log_bad(f'{test:46}| {deltas[test]["previous"]:10} | {deltas[test]["current"]:10}')
    else:
        logger().log_good("No changes detected.")
    logger().log("[CHIPSEC] *****************************************************************")


def log_deltas_json(deltas, outfile):
    deltas_json = json.dumps(deltas, sort_keys=True, indent=2, separators=(',', ': '))
    chipsec.library.file.write_file(outfile, deltas_json)


def log_deltas_xml(deltas, outfile):
    xml_deltas = ET.ElementTree(ET.Element('deltas'))
    delta_root = xml_deltas.getroot()
    delta_root.text = '\n    '
    delta_root.tail = '\n'
    element = None
    for test in deltas:
        element = ET.SubElement(delta_root, 'test', {'current': deltas[test]['current'], 'previous': deltas[test]['previous']})
        element.text = test
        element.tail = '\n    '
    if element is not None:
        element.tail = '\n'
    else:
        delta_root.text = '\n'
    xml_deltas.write(outfile)
