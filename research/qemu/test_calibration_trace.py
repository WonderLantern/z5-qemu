import struct
import unittest
from calibration_trace import observe


class CalibrationTraceTest(unittest.TestCase):
    def test_only_target_descriptor_is_recorded(self):
        class Remote:
            def memory(self, address, size):
                if address == 0xC18EB388:
                    return struct.pack('<I', 123)
                if address == 0xC100002C:
                    return struct.pack('<I', 0xC8500000)
                return bytes(size)
        regs = dict(r15=hex(0x1008E4C2), r0=hex(0xC1000000), r4='0x0', r14='0x1')
        self.assertEqual(observe(Remote(), regs, 'cpu', 'boot')['guest_ms'], 123)
        regs['r0'] = hex(0xC2000000)
        self.assertIsNone(observe(Remote(), regs, 'cpu', 'boot'))

    def test_footer_probe_ignores_other_regions(self):
        class Remote:
            def memory(self, address, size):
                if address == 0xC18EB388:
                    return struct.pack('<I', 456)
                return b'ENDM' if address == 0xC18811D4 else b'\xff' * size
        regs = dict(r15=hex(0x1008E788), r0=hex(0xC18811D4),
                    r1=hex(0x13FFFFFC), r2='0x4', r14='0x1')
        row = observe(Remote(), regs, 'cpu', 'boot')
        self.assertEqual((row['expected_marker'], row['observed_marker']), ('454e444d', 'ffffffff'))
        regs['r1'] = '0x13000000'
        self.assertIsNone(observe(Remote(), regs, 'cpu', 'boot'))
