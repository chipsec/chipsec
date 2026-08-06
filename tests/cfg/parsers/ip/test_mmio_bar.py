# CHIPSEC: Platform Security Assessment Framework
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.

import unittest

from chipsec.cfg.parsers.ip.mmio_bar import MMIOBarConfig
from chipsec.cfg.parsers.ip.platform import Bar
from chipsec.library.exceptions import MMIOBarConfigError, PlatformConfigError


def _fixed_address_cfg(**overrides):
    cfg = {
        'name': 'HPETBAR',
        'fixed_address': 0xFED00000,
        'size': 0x400,
    }
    cfg.update(overrides)
    return cfg


class TestFixedAddressMMIOBar(unittest.TestCase):

    def test_fixed_address_only_construction(self) -> None:
        bar_cfg = MMIOBarConfig(_fixed_address_cfg())

        self.assertEqual('HPETBAR', bar_cfg.name)
        self.assertEqual(0xFED00000, bar_cfg.fixed_address)
        self.assertIsNone(bar_cfg.register)
        self.assertIsNone(bar_cfg.base_field)

    def test_fixed_address_only_validates(self) -> None:
        bar_cfg = MMIOBarConfig(_fixed_address_cfg())

        self.assertTrue(bar_cfg.validate_mmio_config())

    def test_incomplete_register_pair_without_fixed_address_raises(self) -> None:
        with self.assertRaises(MMIOBarConfigError):
            MMIOBarConfig({'name': 'MCHBAR', 'register': '8086.HOSTCTL.MCHBAR'})

        with self.assertRaises(MMIOBarConfigError):
            MMIOBarConfig({'name': 'MCHBAR', 'base_field': 'MCHBAR'})

    def test_incomplete_register_pair_allowed_with_fixed_address(self) -> None:
        bar_cfg = MMIOBarConfig(_fixed_address_cfg(register='8086.HOSTCTL.HPET'))

        self.assertTrue(bar_cfg.validate_mmio_config())

    def test_non_integer_fixed_address_raises(self) -> None:
        with self.assertRaises(MMIOBarConfigError):
            MMIOBarConfig(_fixed_address_cfg(fixed_address='invalid'))

        with self.assertRaises(MMIOBarConfigError):
            MMIOBarConfig(_fixed_address_cfg(fixed_address='0xFED00000'))

    def test_non_integer_fixed_address_fails_validation(self) -> None:
        bar_cfg = MMIOBarConfig(_fixed_address_cfg())
        bar_cfg.fixed_address = 'invalid'

        self.assertFalse(bar_cfg.validate_mmio_config())

    def test_get_bar_register_name_raises_for_fixed_address(self) -> None:
        bar = Bar('HPETBAR', MMIOBarConfig(_fixed_address_cfg()))

        with self.assertRaises(PlatformConfigError):
            bar.get_bar_register_name()


if __name__ == "__main__":
    unittest.main()
