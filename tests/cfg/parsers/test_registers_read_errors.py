# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2026, Intel Corporation
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
Register parsers must let CSReadError propagate unchanged.

Every consumer in the framework (ObjList.read, mmio BAR resolution, and the
modules' graceful-degradation paths) catches CSReadError. If a parser re-wraps
it in its own *RegisterError, a hardware read failure that should downgrade a
module to WARNING/NOT_APPLICABLE becomes an unhandled exception instead.
"""

import unittest
from unittest.mock import MagicMock, patch

from chipsec.library.exceptions import (
    CSReadError,
    IOBARRegisterError,
    IORegisterError,
    MemoryRegisterError,
    MMCFGRegisterError,
    MMIORegisterError,
    MM_MSGBUSRegisterError,
    MSGBUSRegisterError,
    MSRRegisterError,
)


def base_cfg(**overrides):
    cfg = {'name': 'REG', 'desc': 'test register', 'FIELDS': {}}
    cfg.update(overrides)
    return cfg


def pci_obj(bus=0, dev=0x1F, fun=0):
    pci = MagicMock()
    pci.bus, pci.dev, pci.fun = bus, dev, fun
    return pci


class _ReadErrorPropagationMixin:
    """Shared assertions: CSReadError passes through, anything else is wrapped."""

    cs_patch_target = None   # e.g. 'chipsec.cfg.parsers.registers.msr.cs'
    wrapped_error = None     # parser-specific *RegisterError

    def make_register(self, mock_cs):
        raise NotImplementedError

    def hal_read(self, mock_cs):
        """Return the HAL mock the parser's read() calls."""
        raise NotImplementedError

    def hal_write(self, mock_cs):
        """Return the HAL mock the parser's write() calls."""
        raise NotImplementedError

    def _with_cs(self):
        mock_cs = MagicMock()
        patcher = patch(self.cs_patch_target, return_value=mock_cs)
        patcher.start()
        self.addCleanup(patcher.stop)
        return mock_cs

    def test_read_propagates_csreaderror(self):
        mock_cs = self._with_cs()
        reg = self.make_register(mock_cs)
        self.hal_read(mock_cs).side_effect = CSReadError('hardware read failed')
        with self.assertRaises(CSReadError) as ctx:
            reg.read()
        self.assertNotIsInstance(ctx.exception, self.wrapped_error)
        self.assertEqual(str(ctx.exception), 'hardware read failed')

    def test_read_wraps_other_errors(self):
        mock_cs = self._with_cs()
        reg = self.make_register(mock_cs)
        self.hal_read(mock_cs).side_effect = RuntimeError('boom')
        with self.assertRaises(self.wrapped_error):
            reg.read()

    def test_write_propagates_csreaderror(self):
        mock_cs = self._with_cs()
        reg = self.make_register(mock_cs)
        self.hal_write(mock_cs).side_effect = CSReadError('hardware write failed')
        with self.assertRaises(CSReadError) as ctx:
            reg.write(0)
        self.assertNotIsInstance(ctx.exception, self.wrapped_error)
        self.assertEqual(str(ctx.exception), 'hardware write failed')

    def test_write_wraps_other_errors(self):
        mock_cs = self._with_cs()
        reg = self.make_register(mock_cs)
        self.hal_write(mock_cs).side_effect = RuntimeError('boom')
        with self.assertRaises(self.wrapped_error):
            reg.write(0)


class TestMMMsgBusRegisterReadErrors(_ReadErrorPropagationMixin, unittest.TestCase):
    cs_patch_target = 'chipsec.cfg.parsers.registers.mm_msgbus.cs'
    wrapped_error = MM_MSGBUSRegisterError

    def make_register(self, mock_cs):
        from chipsec.cfg.parsers.registers.mm_msgbus import MM_MSGBUSRegisters
        return MM_MSGBUSRegisters(base_cfg(name='RC', port=0xC3, offset=0x3400, size=4))

    def hal_read(self, mock_cs):
        return mock_cs.hals.mmmsgbus.read

    def hal_write(self, mock_cs):
        return mock_cs.hals.mmmsgbus.write


class TestMsgBusRegisterReadErrors(_ReadErrorPropagationMixin, unittest.TestCase):
    cs_patch_target = 'chipsec.cfg.parsers.registers.msgbus.cs'
    wrapped_error = MSGBUSRegisterError

    def make_register(self, mock_cs):
        from chipsec.cfg.parsers.registers.msgbus import MSGBUSRegisters
        return MSGBUSRegisters(base_cfg(port=0x04, offset=0x100, size=4))

    def hal_read(self, mock_cs):
        return mock_cs.hals.msgbus.msgbus_reg_read

    def hal_write(self, mock_cs):
        return mock_cs.hals.msgbus.msgbus_reg_write


class TestMMCFGRegisterReadErrors(_ReadErrorPropagationMixin, unittest.TestCase):
    cs_patch_target = 'chipsec.cfg.parsers.registers.mmcfg.cs'
    wrapped_error = MMCFGRegisterError

    def make_register(self, mock_cs, pci=None):
        from chipsec.cfg.parsers.registers.mmcfg import MMCFGRegisters
        return MMCFGRegisters(base_cfg(offset=0xDC, size=1), pci or pci_obj())

    def hal_read(self, mock_cs):
        return mock_cs.hals.mmcfg.read_mmcfg_reg

    def hal_write(self, mock_cs):
        return mock_cs.hals.mmcfg.write_mmcfg_reg

    def test_absent_device_raises_csreaderror_like_pcicfg(self):
        mock_cs = self._with_cs()
        reg = self.make_register(mock_cs, pci=pci_obj(bus=None))
        with self.assertRaises(CSReadError) as ctx:
            reg.read()
        self.assertNotIsInstance(ctx.exception, MMCFGRegisterError)
        self.assertIn('PCI Device is not available', str(ctx.exception))
        self.hal_read(mock_cs).assert_not_called()

        with self.assertRaises(CSReadError):
            reg.write(0)
        self.hal_write(mock_cs).assert_not_called()


class TestMMIORegisterReadErrors(_ReadErrorPropagationMixin, unittest.TestCase):
    cs_patch_target = 'chipsec.cfg.parsers.registers.mmio.cs'
    wrapped_error = MMIORegisterError

    def make_register(self, mock_cs):
        from chipsec.cfg.parsers.registers.mmio import MMIORegisters
        mock_cs.hals.mmio.get_MMIO_BAR_base_address.return_value = (0xFE000000, 0x1000)
        reg = MMIORegisters(base_cfg(offset=0x10, size=4, bar='PWRMBASE'))
        reg.get_instance = MagicMock(return_value=None)
        return reg

    def hal_read(self, mock_cs):
        return mock_cs.hals.mmio.read_MMIO_reg

    def hal_write(self, mock_cs):
        return mock_cs.hals.mmio.write_MMIO_reg

    def test_bar_resolution_csreaderror_propagates(self):
        mock_cs = self._with_cs()
        reg = self.make_register(mock_cs)
        mock_cs.hals.mmio.get_MMIO_BAR_base_address.side_effect = CSReadError('[mmio] Base address was determined to be 0')
        with self.assertRaises(CSReadError) as ctx:
            reg.read()
        self.assertNotIsInstance(ctx.exception, MMIORegisterError)

    def test_write_subset_propagates_csreaderror(self):
        mock_cs = self._with_cs()
        reg = self.make_register(mock_cs)
        self.hal_write(mock_cs).side_effect = CSReadError('nope')
        with self.assertRaises(CSReadError) as ctx:
            reg.write_subset(0, 1, 0)
        self.assertNotIsInstance(ctx.exception, MMIORegisterError)


class TestIORegisterReadErrors(_ReadErrorPropagationMixin, unittest.TestCase):
    cs_patch_target = 'chipsec.cfg.parsers.registers.io.cs'
    wrapped_error = IORegisterError

    def make_register(self, mock_cs):
        from chipsec.cfg.parsers.registers.io import IORegisters
        return IORegisters(base_cfg(port=0x70, size=1))

    def hal_read(self, mock_cs):
        return mock_cs.hals.io.read

    def hal_write(self, mock_cs):
        return mock_cs.hals.io.write


class TestIOBARRegisterReadErrors(_ReadErrorPropagationMixin, unittest.TestCase):
    cs_patch_target = 'chipsec.cfg.parsers.registers.iobar.cs'
    wrapped_error = IOBARRegisterError

    def make_register(self, mock_cs):
        from chipsec.cfg.parsers.registers.iobar import IOBARRegisters
        mock_cs.hals.iobar.get_IO_BAR_base_address.return_value = (0x1800, 0x100)
        reg = IOBARRegisters(base_cfg(offset=0x04, size=2, bar='ABASE'))
        reg.get_instance = MagicMock(return_value=None)
        return reg

    def hal_read(self, mock_cs):
        return mock_cs.hals.io.read

    def hal_write(self, mock_cs):
        return mock_cs.hals.io.write

    def test_bar_resolution_csreaderror_propagates_on_read(self):
        mock_cs = self._with_cs()
        reg = self.make_register(mock_cs)
        mock_cs.hals.iobar.get_IO_BAR_base_address.side_effect = CSReadError(
            'BAR resolution failed'
        )

        with self.assertRaises(CSReadError) as ctx:
            reg.read()

        self.assertNotIsInstance(ctx.exception, IOBARRegisterError)

    def test_bar_resolution_csreaderror_propagates_on_write(self):
        mock_cs = self._with_cs()
        reg = self.make_register(mock_cs)
        mock_cs.hals.iobar.get_IO_BAR_base_address.side_effect = CSReadError(
            'BAR resolution failed'
        )

        with self.assertRaises(CSReadError) as ctx:
            reg.write(0)

        self.assertNotIsInstance(ctx.exception, IOBARRegisterError)


class TestMemoryRegisterReadErrors(_ReadErrorPropagationMixin, unittest.TestCase):
    cs_patch_target = 'chipsec.cfg.parsers.registers.memory.cs'
    wrapped_error = MemoryRegisterError

    def make_register(self, mock_cs):
        from chipsec.cfg.parsers.registers.memory import MEMORYRegisters
        return MEMORYRegisters(base_cfg(offset=0, range=None, size=4, address=0xFED00000, limit=None, access='mmio'))

    def hal_read(self, mock_cs):
        return mock_cs.hals.mmio.read_MMIO_reg

    def hal_write(self, mock_cs):
        return mock_cs.hals.mmio.write_MMIO_reg


class TestMSRRegisterReadErrors(_ReadErrorPropagationMixin, unittest.TestCase):
    cs_patch_target = 'chipsec.cfg.parsers.registers.msr.cs'
    wrapped_error = MSRRegisterError

    def make_register(self, mock_cs):
        from chipsec.cfg.parsers.registers.msr import MSRRegisters
        mock_cs.hals.msr.read_msr.return_value = (0, 0)
        return MSRRegisters(base_cfg(instance=0, msr=0x1F2, size=8))

    def hal_read(self, mock_cs):
        return mock_cs.hals.msr.read_msr

    def hal_write(self, mock_cs):
        return mock_cs.hals.msr.write


if __name__ == '__main__':
    unittest.main()
