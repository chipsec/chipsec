# CHIPSEC: Platform Security Assessment Framework
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.

import unittest

from chipsec.cfg.parsers.ip.platform import Bar, IP, Platform, Vendor
from chipsec.library.exceptions import BARNotFoundError, PlatformConfigError


class TestIPAndBarHierarchy(unittest.TestCase):

    def test_ip_add_and_get_bar(self) -> None:
        ip = IP("pch", {})
        bar_obj = {"base": 0x1000}

        ip.add_bar("BAR0", bar_obj)

        self.assertEqual(["BAR0"], ip.bar_list)
        self.assertIs(ip.get_bar("bar0").obj, bar_obj)
        self.assertIs(ip.get_bar("BAR0").obj, bar_obj)

    def test_bar_add_and_get_nested_bar(self) -> None:
        root_bar = Bar("root", {})
        nested_obj = {"base": 0x2000}

        root_bar.add_bar("SUBBAR", nested_obj)

        self.assertEqual(["SUBBAR"], root_bar.bar_list)
        self.assertIs(root_bar.get_bar("subbar").obj, nested_obj)
        self.assertIs(root_bar.get_bar("SUBBAR").obj, nested_obj)

    def test_get_next_level_and_wildcard_match(self) -> None:
        ip = IP("gfx", {})
        ip.add_bar("CFG0", {"id": 0})
        ip.add_bar("CFG1", {"id": 1})

        direct = ip._get_next_level("CFG0")
        wildcard = ip.get_next_levels("CFG*")

        self.assertEqual("CFG0", direct.name)
        self.assertEqual(2, len(wildcard))
        self.assertEqual({"CFG0", "CFG1"}, {bar.name for bar in wildcard})

    def test_missing_bar_errors_match_current_behavior(self) -> None:
        ip = IP("cpu", {})
        bar = Bar("root", {})

        with self.assertRaises(BARNotFoundError):
            ip.get_bar("missing")
        with self.assertRaises(BARNotFoundError):
            bar.get_bar("missing")

        with self.assertRaises(PlatformConfigError):
            ip._get_next_level("missing")
        with self.assertRaises(PlatformConfigError):
            bar._get_next_level("missing")

    def test_get_register_matches_recurses_all_children(self) -> None:
        platform = Platform()
        vendor = Vendor("INTEL")
        platform.add_vendor(vendor)

        vendor.add_ip("SOC", {})
        ip = vendor.get_ip("SOC")

        ip_reg = object()
        bar_reg = object()
        nested_bar_reg = object()

        ip.add_register("IP_REG", [ip_reg])
        ip.add_bar("BAR0", {})
        bar = ip.get_bar("BAR0")
        bar.add_register("BAR_REG", [bar_reg])

        bar.add_bar("SUBBAR", {})
        subbar = bar.get_bar("SUBBAR")
        subbar.add_register("SUBBAR_REG", [nested_bar_reg])

        vendor_matches = vendor.get_register_matches("*_REG")
        platform_matches = platform.get_register_matches("*_REG")

        self.assertEqual(3, len(vendor_matches))
        self.assertEqual(3, len(platform_matches))
        self.assertIn(ip_reg, vendor_matches)
        self.assertIn(bar_reg, vendor_matches)
        self.assertIn(nested_bar_reg, vendor_matches)
        self.assertIn(ip_reg, platform_matches)
        self.assertIn(bar_reg, platform_matches)
        self.assertIn(nested_bar_reg, platform_matches)


if __name__ == "__main__":
    unittest.main()
