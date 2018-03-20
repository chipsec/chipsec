#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2018, Intel Corporation
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

import time

from chipsec.command import BaseCommand
import chipsec.result_deltas

class DeltasCommand(BaseCommand):
    """
    >>> chipsec_util deltas <previous> <current> [out-format] [out-name]

    out-format - JSON | XML
    out-name - Output file name

    Example:
    >>> chipsec_util deltas run1.json run2.json

    """

    def requires_driver(self):
        return False

    def run(self):
        nargs = len(self.argv)
        if nargs < 4 or nargs > 6:
            print(DeltasCommand.__doc__)
            return

        # Set default values and extract arguments
        start_time = time.time()
        prev_log = None
        cur_log = None
        out_format = None
        out_name = None
        if nargs >= 4:
            prev_log = self.argv[2]
            cur_log = self.argv[3]
        if nargs == 6:
            out_format = self.argv[4]
            out_name = self.argv[5]

        # Read files and determine deltas
        previous = chipsec.result_deltas.get_json_results(prev_log)
        current = chipsec.result_deltas.get_json_results(cur_log)
        if previous is None or current is None:
            self.logger.error('Unable to process JSON log files.')
            return
        deltas = chipsec.result_deltas.compute_result_deltas(previous, current)

        # Generate output file here...
        if out_format and out_name:
            if out_format.upper() == 'JSON':
                chipsec.result_deltas.log_deltas_json(deltas, out_name)
            elif out_format.upper() == 'XML':
                chipsec.result_deltas.log_deltas_xml(deltas, out_name)
            else:
                self.logger.error('Output log format not supported: {}'.format(out_format))

        # Display the results
        chipsec.result_deltas.display_deltas(deltas, True, start_time)

        return

commands = {'deltas': DeltasCommand}
