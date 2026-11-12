import unittest
from make_z5_calibration import make_input, validate_input, SIZE


class SyntheticCalibrationTest(unittest.TestCase):
    def test_generated_input_has_explicit_fields(self):
        data = make_input()
        self.assertEqual(len(data), SIZE)
        self.assertEqual(data[0xB8012], 0x19)
        self.assertEqual(data[-4:], b'ENDM')
        self.assertTrue(validate_input(data))

    def test_rejects_size_footer_and_undeclared_data(self):
        data = bytearray(make_input())
        for changed in (data[:-1], data[:-4] + b'FAIL'):
            with self.assertRaises(ValueError):
                validate_input(changed)
        data[0x100] = 1
        with self.assertRaises(ValueError):
            validate_input(data)
