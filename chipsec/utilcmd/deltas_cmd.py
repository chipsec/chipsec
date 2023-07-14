# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2018-2021, Intel Corporation
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

"""
>>> chipsec_util deltas <previous> <current> [out-format] [out-name]

out-format - JSON | XML
out-name - Output file name

Example:
>>> chipsec_util deltas run1.json run2.json

"""

from time import time
from argparse import ArgumentParser

from chipsec.command import BaseCommand, toLoad
import chipsec.result_deltas


class DeltasCommand(BaseCommand):

    def requirements(self) -> toLoad:
        return toLoad.Nil
    
    def parse_arguments(self) -> None:
        parser = ArgumentParser(usage=__doc__)
        parser.add_argument('_prev_log', metavar='<previous>', help='previous log file')
        parser.add_argument('_cur_log', metavar='<current>', help='current log file')
        parser.add_argument('_out_format', metavar='out-format', choices=['JSON', 'XML'], default='JSON', help='output format')
        parser.add_argument('_out_name', metavar='out-name', nargs='?', default=None, help='output filename')
        parser.parse_args(self.argv, namespace=self)

    def run(self) -> None:
        start_time = time()

        # Read files and determine deltas
        previous = chipsec.result_deltas.get_json_results(self._prev_log)
        current = chipsec.result_deltas.get_json_results(self._cur_log)
        if previous is None or current is None:
            self.logger.log_error('Unable to process JSON log files.')
            return
        deltas = chipsec.result_deltas.compute_result_deltas(previous, current)

        # Generate output file here...
        if self._out_name:
            if self._out_format == 'JSON':
                chipsec.result_deltas.log_deltas_json(deltas, self._out_name)
            elif self._out_format.upper() == 'XML':
                chipsec.result_deltas.log_deltas_xml(deltas, self._out_name)
            else:
                self.logger.log_error(f'Output log format not supported: {self._out_format}')

        # Display the results
        chipsec.result_deltas.display_deltas(deltas, True, start_time)

        return


commands = {'deltas': DeltasCommand}
