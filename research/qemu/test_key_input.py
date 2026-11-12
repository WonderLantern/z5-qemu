"""Native switch input must preserve unrelated controls and always release."""
import struct
import unittest

from key_input import press_key, switch_payloads, key_metadata


class KeyInputTests(unittest.TestCase):
    def snapshot(self):
        data = bytearray(0x174)
        for offset, value in zip((4, 0x18, 0x2c, 0x40), (0x200, 0x4000, 0x100, 3)):
            struct.pack_into('<I', data, offset, value)
        for offset, value in zip((0x64, 0x6c, 0x74, 0x7c, 0x84, 0x8c), range(1, 7)):
            struct.pack_into('<H', data, offset, value)
        struct.pack_into('<2I', data, 0x94, 7, 8)
        return bytes(data)

    def test_disp_uses_sw2_not_the_legacy_info_ao(self):
        self.assertEqual(key_metadata('disp'), dict(ao_index=None, switch_group=2, switch_mask='0x100000'))
        self.assertEqual(key_metadata('i'), dict(ao_index=72))
        self.assertEqual(key_metadata('half_press'), dict(ao_index=None, switch_group=0, switch_mask='0x80000000'))

    def test_switch_input_preserves_all_other_switches_and_encoders(self):
        data = self.snapshot()
        pressed, released = switch_payloads(data, 2, 0x100000)
        self.assertEqual(struct.unpack('<8I6H2I', released), (0x200, 0x4000, 0x100, 3, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8))
        expected = bytearray(released)
        struct.pack_into('<I', expected, 8, 0x100100)
        self.assertEqual(pressed, expected)
        self.assertEqual(data, self.snapshot())
        with self.assertRaises(ValueError): switch_payloads(bytes(16), 2, 0x100000)
        with self.assertRaises(ValueError): switch_payloads(data, 2, 0x100)

    def test_disp_releases_after_an_interrupted_hold(self):
        calls = []
        def call(name, address, payload, arguments):
            calls.append((name, address, payload, arguments))
            return dict(return_r0='0xc1f99450')
        def settle():
            raise TimeoutError('hold interrupted')
        with self.assertRaisesRegex(TimeoutError, 'hold interrupted'):
            press_key('disp', call, lambda address, size: self.snapshot(), settle)
        self.assertEqual([x[1] for x in calls], [0x101ed79e, 0x101ed678, 0x101ed678])
        self.assertEqual(calls[-1][2], switch_payloads(self.snapshot(), 2, 0x100000)[1])

    def test_i_still_uses_the_original_ao_protocol(self):
        calls = []
        press_key('i', lambda *args: calls.append(args), None, None)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1], 0x1059ae16)
        words = struct.unpack('<8I', calls[0][2])
        self.assertEqual(words, (0, 0, 1 << 8, 0, 10, 0, 0, 0))

    def test_failed_press_preserves_the_incomplete_fixture_evidence(self):
        calls = []
        def call(name, address, payload, arguments):
            calls.append(address)
            if address == 0x101ed678:
                raise TimeoutError('press fixture incomplete')
            return dict(return_r0='0xc1f99450')
        with self.assertRaisesRegex(TimeoutError, 'press fixture incomplete'):
            press_key('disp', call, lambda *args: self.snapshot(), lambda: None)
        self.assertEqual(calls, [0x101ed79e, 0x101ed678])


if __name__ == '__main__':
    unittest.main()
