# CHIPSEC: Platform Security Assessment Framework
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
#
import os
import tempfile
import unittest

from tests.software import mock_helper

from chipsec.library import logger
from chipsec import chipset


class TestChipsecCs(unittest.TestCase):
    """Test the commands exposed by chipsec_utils.

    Each test may define its virtual helper and then call the _chipsec_util
    method with the command line arguments.
    """

    def setUp(self):
        """Setup the environment for the utils tests.

        We mock the helper registry to only contain our emulated helper.
        """
        fileno, self.log_file = tempfile.mkstemp()
        os.close(fileno)
        chipset._chipset = None

    def tearDown(self):
        os.remove(self.log_file)
        chipset._chipset = None

    def _chipsec_cs(self, arg, helper_class=mock_helper.TestHelper, platform=None, pch=None):
        """Run the chipsec chipset commands

        Each test may setup a virtual helper to emulate the expected behaviour
        from the hardware. If no helper is provided, TestHelper will be used.
        It verifies that no error is being reported. self.log will be populated
        with the output.
        """
        _cs = chipset.cs()
        logger.logger().HAL = True
        logger.logger().VERBOSE = True
        logger.logger().set_log_file(self.log_file)
        try:
            _cs.init(platform, pch, helper_class())
            ret = getattr(_cs.Cfg, arg.split()[0])()
        finally:
            logger.logger().close()
        with open(self.log_file, 'rb') as log:
            self.log = log.read()
        return ret


from chipsec.library.register import RegisterType
class DummyCS:
    class DummyCfg:
        REGISTERS = {
            'TEST_MSR': {
            'type': RegisterType.MSR,
            'msr': 0x123,
            'size': 4,
            'desc': "Test MSR Register",
            'FIELDS': {
                'FIELD1': {'bit': 0, 'size': 8, 'desc': "Test Field 1"},
            }
            },
            'TEST_PCI': {
            'type': RegisterType.PCICFG,
            'device': 'DEV1',
            'dev': 1,
            'fun': 0,
            'offset': 0x10,
            'size': 4,
            'desc': "Test PCI Register",
            'FIELDS': {
                'FIELD2': {'bit': 8, 'size': 8, 'desc': "Test PCI Field 2"}
            }
            },
            'TEST_MMIO': {
            'type': RegisterType.MMIO,
            'bar': 'TEST_MMIO_BAR',
            'offset': 0x20,
            'size': 4,
            'desc': "Test MMIO Register",
            'FIELDS': {
                'FIELD3': {'bit': 16, 'size': 8, 'desc': "Test MMIO Field 3"}
            }
            },
            'TEST_BAD_MMIO': {
            'type': RegisterType.MMIO,
            'bar': 'BAD',
            'offset': 0x20,
            'size': 4,
            'desc': "Test MMIO Register",
            'FIELDS': {
                'FIELD3': {'bit': 16, 'size': 8, 'desc': "Test MMIO Field 3"}
            }
            }
        }
        MMIO_BARS = {
            'TEST_MMIO_BAR': {
            'device': 'DEV1',
            'bar': 0,
            'desc': "Test MMIO BAR"
            }
        }
        CONFIG_PCI = {
            'DEV1': {'dev': 1, 'fun': 0}
        }
        MEMORY_RANGES = {}
        IMA_REGISTERS = {}

    class DummyDevice:
        def get_bus(self, device): return [0]
        def get_first_bus(self, reg): return 0
        def get_first(self, bus): return bus

    class DummyMMIO:
        def get_MMIO_BAR_base_address(self, bar, bus=None): return (0,) if bar == "BAD" else (1, )
        def read_MMIO_BAR_reg(self, bar, offset, size, bus): return 0xDEADBEEF
        def read_MMIO_reg(self, address, offset, size): return 0xBEEF
        def read_mmcfg_reg(self, b, d, f, o, size): return 0xFEED
        def write_MMIO_BAR_reg(self, bar, offset, value, size, bus): pass
        def write_MMIO_reg(self, address, offset, value, size): pass
        def write_mmcfg_reg(self, b, d, f, o, size, value): pass

    class DummyMSR:
        def read_msr(self, cpu_thread, msr): return (0xABCD, 0x1234)
        def write_msr(self, cpu_thread, msr, eax, edx): pass

    class DummyIO:
        def _read_port(self, port, size): return 0xFF
        def _write_port(self, port, value, size): pass

    class DummyIOBAR:
        def get_IO_BAR_base_address(self, bar): return (1, )
        def read_IO_BAR_reg(self, bar, offset, size): return 0xCAFE
        def write_IO_BAR_reg(self, bar, offset, size, value): pass

    class DummyMsgBus:
        def msgbus_reg_read(self, port, offset): return 0xAABB
        def mm_msgbus_reg_read(self, port, offset): return 0xCCDD
        def msgbus_reg_write(self, port, offset, value): pass
        def mm_msgbus_reg_write(self, port, offset, value): pass

    class DummyMem:
        def write_physical_mem(self, address, size, value): pass

    class DummyCPU:
        def get_cpu_topology(self):
            return {'packages': {0: [0]}, 'cores': {0: [0]}}

    class DummyHelper:
        def get_threads_count(self): return 1

    def __init__(self):
        self.Cfg = self.DummyCfg()
        self.device = self.DummyDevice()
        self.mmio = self.DummyMMIO()
        self.msr = self.DummyMSR()
        self.io = self.DummyIO()
        self.iobar = self.DummyIOBAR()
        self.msgbus = self.DummyMsgBus()
        self.mem = self.DummyMem()
        self.cpu = self.DummyCPU()
        self.helper = self.DummyHelper()
        self.consistency_checking = False