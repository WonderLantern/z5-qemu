"""画面验收必须同时有图像内容与客体绘制、扫描输出证据。"""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from q3_display import frame_stats, q3_accepted, q4_frame_settled, SafeRemote, checked_ram_fixture, apply_capture_status_standin, sensor_error_suppressed, SENSOR_ERROR_CODES, CARD_NO_MEDIA, CARD_SLOT_STATE, Q4_KEYS


class DisplayTests(unittest.TestCase):
    def test_q4_change_gate_rejects_unchanged_or_blank_screens(self):
        self.assertFalse(q4_frame_settled('old', ['old', 'old'], True, True))
        self.assertFalse(q4_frame_settled('old', ['new', 'new'], False, True))
        self.assertTrue(q4_frame_settled('old', ['new', 'new'], True, True))
        self.assertTrue(q4_frame_settled('old', ['old', 'old'], True, False))
    def test_calibration_fixture_never_hides_error_44(self):
        self.assertTrue(sensor_error_suppressed(0x44, False))
        self.assertFalse(sensor_error_suppressed(0x44, True))
        self.assertTrue(sensor_error_suppressed(0x3e, True))
        self.assertFalse(sensor_error_suppressed(0x21, True))
        self.assertFalse(sensor_error_suppressed(0x34, True, True))
        self.assertTrue(sensor_error_suppressed(0x3e, True, True))
        self.assertFalse(sensor_error_suppressed(0x3f, True, True, True))
        self.assertTrue(sensor_error_suppressed(0x3f, True, True, False))
        self.assertTrue(sensor_error_suppressed(0x3e, True, True, True))
    def test_capture_status_requires_expected_value_and_allows_repeated_read(self):
        class Fake:
            def __init__(self, value): self.value, self.writes = value, []
            def memory(self, address, size): return self.value
            def command(self, value): self.writes.append(value); self.value = b'\x00'; return 'OK'
        device, records = Fake(b'\x02'), []
        apply_capture_status_standin(device, records)
        apply_capture_status_standin(device, records)
        self.assertEqual(len(records), 1)
        self.assertEqual(len(device.writes), 1)
        with self.assertRaises(ValueError): apply_capture_status_standin(Fake(b'\x00'), [])
        with self.assertRaises(ValueError): apply_capture_status_standin(Fake(b'\x03'), records)
    def test_q4_keys_match_native_ao_indices(self):
        # C1.50 AO table 0x1072FE84 / ID_SW names; identical to the Z7 emulator's KEYS
        self.assertEqual(Q4_KEYS, {'right': 34, 'left': 35, 'up': 36, 'down': 37,
                                   'menu': 67, 'play': 68, 'delete': 69, 'i': 72, 'ok': 74,
                                   'help': 70, 'disp': 71, 'zoom_in': 75, 'zoom_out': 76})
        press = [0] * 8
        press[Q4_KEYS['menu'] // 32] = 1 << (Q4_KEYS['menu'] % 32)
        self.assertEqual(press[2], 1 << 3)   # the bit the Q3 startup MENU press already used

    def test_button_keys_match_firmware_name_table(self):
        # AO entry {enabled, bank, group, mask} == {1, 1, 1, second word of the ID_SW1 name entry}.
        import struct
        from pathlib import Path
        image = Path(__file__).resolve().parents[2] / 'output/stage2-20261106-115959/eg1650_015001.bi'
        if not image.exists():
            self.skipTest('decrypted C1.50 image not present (never committed)')
        data, base = image.read_bytes(), 0x10020000
        names = {}
        for i in range(96):
            entry = data[0x10736F78 + 40 * i - base:0x10736F78 + 40 * (i + 1) - base]
            names[entry.split(b'\0')[0].decode()] = struct.unpack_from('<I', entry, 36)[0]
        expected = {'menu': 'MENU', 'play': 'PLAY', 'delete': 'DELETE', 'i': 'I', 'ok': 'OK',
                    'help': 'HELP', 'disp': 'INFO', 'zoom_in': 'ZOOM', 'zoom_out': 'THUMBNAIL'}
        for key, name in expected.items():
            ao = struct.unpack_from('<4I', data, 0x1072FE84 + 16 * Q4_KEYS[key] - base)
            self.assertEqual(ao, (1, 1, 1, names['ID_SW1_' + name]), key)

    def test_card_standin_reports_no_media(self):
        # FUN_102a49e8 maps media-status reply 1 -> slot setting 0 ("no memory card")
        self.assertEqual(CARD_NO_MEDIA, 1)
        self.assertEqual(CARD_SLOT_STATE, 0xC253DC80)

    def test_sensor_standin_skips_only_sensor_device_codes(self):
        for code in (0x34, 0x35, 0x36, 0x3E, 0x3F, 0x44):
            self.assertIn(code, SENSOR_ERROR_CODES)
        # card ("Card" 0x16..0x1B, 0x20), full (0x0E..0x12), other device codes stay native
        for code in (0x00, 0x0E, 0x12, 0x16, 0x1B, 0x20, 0x21, 0x22, 0x33, 0x37, 0x3D, 0x45):
            self.assertNotIn(code, SENSOR_ERROR_CODES)

    def test_fixture_mismatch_never_writes_and_success_is_recorded(self):
        class Fake:
            def __init__(self): self.writes = []
            def memory(self, address, size): return bytes(size)
            def command(self, value): self.writes.append(value); return 'OK'
        target, records = Fake(), []
        with self.assertRaises(ValueError):
            checked_ram_fixture(target, records, 'test', 0xC1800000, b'\x01', b'\x02')
        self.assertEqual(target.writes, [])
        self.assertEqual(records, [])
        checked_ram_fixture(target, records, 'test', 0xC1800000, b'\x00', b'\x02')
        self.assertEqual(target.writes, ['Mc1800000,1:02'])
        self.assertEqual(records[0]['before'], '00')
        self.assertEqual(records[0]['after'], '02')

    def test_blank_and_truncated_screenshots_are_rejected(self):
        self.assertFalse(frame_stats(b'P6\n2 2\n255\n' + bytes(12))['nonuniform'])
        with self.assertRaises(ValueError):
            frame_stats(b'P6\n2 2\n255\n' + bytes(11))

    def test_pixels_without_native_draw_and_lcd_evidence_do_not_pass(self):
        frame = frame_stats(b'P6\n2 2\n255\n' + bytes(range(12)))
        self.assertFalse(q3_accepted(frame, False, True))
        self.assertFalse(q3_accepted(frame, True, False))
        self.assertTrue(q3_accepted(frame, True, True))

    def test_upstream_call_adapter_never_uses_legacy_multi_cpu_step(self):
        class Fake:
            def __init__(self): self.commands = []
            def command(self, value): self.commands.append(value); return 'OK'
        target = Fake()
        adapter = SafeRemote(target)
        adapter.command('Hcp01.02')
        adapter.command('s')
        adapter.command('Hc-1')
        adapter.command('c')
        adapter.command('Hg0')
        self.assertEqual(target.commands, ['vCont;s:p01.02', 'vCont;c', 'Hg0'])


if __name__ == '__main__':
    unittest.main()
