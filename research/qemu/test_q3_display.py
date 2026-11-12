"""画面验收必须同时有图像内容与客体绘制、扫描输出证据。"""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from q3_display import frame_stats, q3_accepted, q4_frame_settled, guest_elapsed_ms, q4_guest_budget_ok, trace_register_matches, SafeRemote, checked_ram_fixture, apply_capture_status_standin, sensor_error_suppressed, SENSOR_ERROR_CODES, CARD_NO_MEDIA, CARD_SLOT_STATE, Q4_KEYS, startup_wait_action, card_open_policy, FS_CREATE_MODE, decode_native_menu_page, native_menu_snapshot, menu_expectation_met, prepare_q3_startup


class DisplayTests(unittest.TestCase):
    def test_sensor_trace_noisy_point_cannot_hide_later_request(self):
        from q3_display import reserve_sensor_trace_record
        counts = {}
        self.assertTrue(reserve_sensor_trace_record(counts, 0x1005929e, limit=2))
        self.assertTrue(reserve_sensor_trace_record(counts, 0x1005929e, limit=2))
        self.assertFalse(reserve_sensor_trace_record(counts, 0x1005929e, limit=2))
        self.assertTrue(reserve_sensor_trace_record(counts, 0x10205528, limit=2))

    def test_diagnostic_setting_write_records_before_and_after(self):
        from q3_display import write_observed_setting
        replies = iter([{'return_r0': '0xffffffff'}, {'return_r0': '0x1'}, {'return_r0': '0x1a'}])
        calls = []
        def call(name, function, payload, args):
            calls.append((name, args))
            return next(replies)
        row = write_observed_setting(call, 'early', 0x1400, 26)
        self.assertEqual((row['before'], row['after']), ('0xffffffff', '0x1a'))
        self.assertEqual([x[0] for x in calls], ['early_read_1400', 'early_write_1400', 'early_check_1400'])
        with self.assertRaises(ValueError):
            write_observed_setting(lambda *args: {}, 'early', 0x1400, 26)

    def test_startup_environment_rejects_unknown_values_before_writing(self):
        from q3_display import validate_startup_environment
        self.assertEqual(validate_startup_environment(0, 0, b'\0\0', b'\0\0', b'\x01\0\0\0'),
                         (b'\x01\0', b'\xff\xff'))
        for values in ((1, 0, b'\0\0', b'\0\0', b'\x01\0\0\0'),
                       (0, 0, b'\x01\0', b'\0\0', b'\x01\0\0\0'),
                       (0, 0, b'\0\0', b'\0\0', b'\0\0\0\0')):
            with self.assertRaises(ValueError): validate_startup_environment(*values)

    def test_explicit_screen_fingerprint_gates_expected_image(self):
        from q3_display import frame_expectation_met, parse_frame_expectations
        self.assertTrue(frame_expectation_met(None, 'abc'))
        self.assertTrue(frame_expectation_met('abc', 'abc'))
        self.assertFalse(frame_expectation_met('abc', 'def'))
        self.assertEqual(parse_frame_expectations('a' * 64 + ',*', 2), ['a' * 64, None])
        with self.assertRaises(ValueError): parse_frame_expectations('a' * 63, 1)
        with self.assertRaises(ValueError): parse_frame_expectations('a' * 64, 2)

    def test_q3_startup_calls_only_when_explicitly_enabled(self):
        calls, stops = [], []
        class Fake:
            def memory(self, address, size): return bytes(size)
        def call(name, function, payload, args):
            calls.append(name)
            return {'output': bytes(12).hex()}
        prepare_q3_startup(False, Fake(), call, stops.append)
        self.assertEqual(calls, [])
        self.assertEqual(stops, [0x100531bc])
        stops.clear()
        prepare_q3_startup(True, Fake(), call, stops.append)
        self.assertEqual(calls, ['native_image_pool_configuration', 'native_image_pool_init',
                                 'diagnostic_power_report', 'diagnostic_system_report', 'diagnostic_control_power_on'])
    def test_q4_guest_budget_is_bounded_and_wrap_safe(self):
        self.assertTrue(q4_guest_budget_ok(100, 60100, 60000))
        self.assertFalse(q4_guest_budget_ok(100, 60101, 60000))
        self.assertTrue(q4_guest_budget_ok(0xfffffff0, 0x10, 32))
        self.assertFalse(q4_guest_budget_ok(0xfffffff0, 0x11, 32))
    def test_menu_expectation_requires_page_and_absolute_row(self):
        sample = {'status': 'ok', 'page': {'page_id': 248, 'row': 3}}
        self.assertTrue(menu_expectation_met(None, None))
        self.assertTrue(menu_expectation_met((248, 3), sample))
        self.assertFalse(menu_expectation_met((248, 2), sample))
        self.assertFalse(menu_expectation_met((1, 3), sample))
        self.assertFalse(menu_expectation_met((248, 3), {'status': 'invalid'}))
    def test_menu_stack_snapshot_validates_pointers_and_empty_stack(self):
        import struct
        page = bytearray(0x2c)
        struct.pack_into('<H', page, 2, 248)
        struct.pack_into('<HH', page, 0x16, 1, 0)
        struct.pack_into('<I', page, 0x28, 0xc18739e0)
        class Fake:
            values = {0xc181dfd0: struct.pack('<I', 0xc1810000),
                      0xc1810000: struct.pack('<IIII', 4, 0, 1, 0xc1810100),
                      0xc1810100: struct.pack('<I', 0xc1834f7c), 0xc1834f7c: page}
            def memory(self, address, size): return self.values[address][:size]
        remote = Fake()
        self.assertEqual(native_menu_snapshot(remote)['page']['row'], 1)
        remote.values = dict(remote.values, **{})
        remote.values[0xc1810000] = struct.pack('<IIII', 4, 0, 0, 0xc1810100)
        self.assertEqual(native_menu_snapshot(remote)['status'], 'empty')
        remote.values[0xc1810000] = struct.pack('<IIII', 4, 0, 100000, 0xc1810100)
        self.assertEqual(native_menu_snapshot(remote)['status'], 'invalid')
    def test_native_page_decodes_scroll_and_visible_cursor(self):
        import struct
        data = bytearray(0x2c)
        struct.pack_into('<H', data, 2, 0x1fe)
        struct.pack_into('<HH', data, 0x16, 2, 7)
        struct.pack_into('<I', data, 0x28, 0xc18741c0)
        self.assertEqual(decode_native_menu_page(data),
                         dict(page_id=0x1fe, field_16=2, field_18=7, row=9, header='0xc18741c0'))
        with self.assertRaises(ValueError): decode_native_menu_page(data[:20])
    def test_card_file_intercepts_only_exact_mapped_paths(self):
        mapped = {'A:\\Z5APP.BIN': b'payload', 'A:\\SHUTTER\\MENU.DAT': b'config'}
        self.assertEqual(card_open_policy('a:\\z5app.bin', 0, mapped, 0), 'mapped')
        self.assertEqual(card_open_policy('A:\\OTHER.BIN', 0, mapped, 0), 'stock')
        self.assertEqual(card_open_policy('A:\\SHUTTER\\NEW.DAT', FS_CREATE_MODE, mapped, 1), 'stock')
        self.assertEqual(card_open_policy('B:\\Z5APP.BIN', 0, mapped, 0), 'stock')
        self.assertEqual(card_open_policy('A:\\SHUTTER\\MENU.DAT', FS_CREATE_MODE, mapped, 0), 'create')
        self.assertEqual(card_open_policy('A:\\SHUTTER\\MENU.DAT', 0, mapped, 1), 'fail')
    def test_startup_wait_bypass_is_opt_in_and_rejects_unknown_waits(self):
        self.assertIsNone(startup_wait_action(False, (2, 0, 0x40, 4), 2))
        self.assertIsNone(startup_wait_action(False, (2, 0, 0x40, 4), 0))
        self.assertEqual(startup_wait_action(True, (0, 0, 0x40, 4), 2), (2, 0x40))
        self.assertEqual(startup_wait_action(True, (2, 0, 0, 0), 0), (0, 2))
        self.assertIsNone(startup_wait_action(True, (0, 0, 0, 0), 2))
        with self.assertRaises(ValueError): startup_wait_action(True, (0, 0, 0x41, 4), 2)
        with self.assertRaises(ValueError): startup_wait_action(True, (0, 0, 0x40, 5), 2)
        with self.assertRaises(ValueError): startup_wait_action(True, (3, 0, 0, 0), 0)
    def test_trace_filter_uses_half_open_guest_register_range(self):
        fixture = dict(register='r0', start=0xc1fc0000, end=0xc1ff0000)
        self.assertTrue(trace_register_matches(fixture, {'r0': '0xc1fc0000'}))
        self.assertTrue(trace_register_matches(fixture, {'r0': '0xc1feffff'}))
        self.assertFalse(trace_register_matches(fixture, {'r0': '0xc1ff0000'}))
        self.assertTrue(trace_register_matches(None, {}))

    def test_q4_stable_frames_must_span_requested_guest_observation(self):
        self.assertFalse(q4_frame_settled('old', ['new', 'new'], True, True,
                                          elapsed_ms=19999, min_guest_ms=20000))
        self.assertTrue(q4_frame_settled('old', ['new', 'new'], True, True,
                                         elapsed_ms=20000, min_guest_ms=20000))
        self.assertFalse(q4_frame_settled('old', ['new', 'new'], False, False,
                                          elapsed_ms=20000, min_guest_ms=20000))
        self.assertEqual(guest_elapsed_ms(0xfffffff0, 0x10), 32)

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
                                   'help': 70, 'disp': None, 'half_press': None, 'zoom_in': 75, 'zoom_out': 76})
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
                    'help': 'HELP', 'zoom_in': 'ZOOM', 'zoom_out': 'THUMBNAIL'}
        for key, name in expected.items():
            ao = struct.unpack_from('<4I', data, 0x1072FE84 + 16 * Q4_KEYS[key] - base)
            self.assertEqual(ao, (1, 1, 1, names['ID_SW1_' + name]), key)
        # DISP belongs to SW2; AO71/ID_SW1_INFO is not the Z5 DISP input.
        entry = data[0x10737C70 - base:0x10737C70 - base + 40]
        self.assertEqual(entry.split(b'\0')[0], b'ID_SW2_DISP')
        self.assertEqual(struct.unpack_from('<I', entry, 36)[0], 0x100000)
        self.assertIsNone(Q4_KEYS['disp'])
        self.assertEqual(names['ID_SW0_RELEASE_HALF'], 0x80000000)

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
