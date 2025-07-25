from unittest import TestCase
from chipsec.library.register import Register, RegisterType
from tests.software.cs import DummyCS

class TestRegister(TestCase):
    def setUp(self):
        self.cs = DummyCS()
        self.reg = Register(self.cs)

    def test_is_defined(self):
        self.assertTrue(self.reg.is_defined('TEST_MSR'))
        self.assertFalse(self.reg.is_defined('NON_EXISTENT'))
        self.assertFalse(self.reg.is_defined('TEST_BAD_MMIO'))
        self.assertTrue(self.reg.is_defined('TEST_MMIO'))

    def test_get_def(self):
        d = self.reg.get_def('TEST_MSR')
        self.assertEqual(d['type'], RegisterType.MSR)
        self.assertIn('FIELDS', d)

    def test_get_field_mask(self):
        mask = self.reg.get_field_mask('TEST_MSR', 'FIELD1')
        self.assertEqual(mask, 0xFF)

    def test_get_field(self):
        value = self.reg.get_field('TEST_MSR', 0x1234, 'FIELD1')
        self.assertEqual(value, 0x34)

    def test_set_field(self):
        val = self.reg.set_field('TEST_MSR', 0xFFFF, 'FIELD1', 0x12)
        self.assertEqual(val & 0xFF, 0x12)

    def test_read_msr(self):
        val = self.reg.read('TEST_MSR')
        self.assertIsInstance(val, int)

    def test_read_all_msr(self):
        vals = self.reg.read_all('TEST_MSR')
        self.assertIsInstance(vals, list)

    def test_write_msr(self):
        self.assertTrue(self.reg.write('TEST_MSR', 0x12345678))

    def test_has_field(self):
        self.assertTrue(self.reg.has_field('TEST_MSR', 'FIELD1'))
        self.assertFalse(self.reg.has_field('TEST_MSR', 'NON_EXISTENT_FIELD'))

    def test_has_all_fields(self):
        self.assertTrue(self.reg.has_all_fields('TEST_MSR', ['FIELD1']))
        self.assertFalse(self.reg.has_all_fields('TEST_MSR', ['FIELD1', 'NON_EXISTENT_FIELD']))

    def test_is_msr(self):
        self.assertIn(self.reg.is_msr('TEST_MSR'), [True, False])

    def test_is_pci(self):
        self.assertIn(self.reg.is_pci('TEST_PCI'), [True, False])

    def test_is_all_ffs(self):
        self.assertIn(self.reg.is_all_ffs('TEST_MSR', 0xFFFFFFFF), [True, False])

    def test_is_field_all_ones(self):
        self.assertTrue(self.reg.is_field_all_ones('TEST_MSR', 'FIELD1', 0xFF))

    def test_read_field(self):
        val = self.reg.read_field('TEST_MSR', 'FIELD1')
        self.assertIsInstance(val, int)

    def test_write_field(self):
        self.assertTrue(self.reg.write_field('TEST_MSR', 'FIELD1', 0xAA))

    def test_read_dict(self):
        d = self.reg.read_dict('TEST_MSR')
        self.assertIn('value', d)

    def test_print(self):
        s = self.reg.print('TEST_MSR', 0x12345678)
        self.assertIsInstance(s, str)