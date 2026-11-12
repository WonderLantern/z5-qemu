"""The explicit UI stand-in must not hide unknown states or unrelated apps."""
import struct
import unittest

from shooting_ui import (ensure_ready, snapshot, ensure_i_menu_settings, I_MENU_SETTINGS,
                         UI_BUSY, ACTIVE_APP, DISPLAY_PAGE, UI_MODE,
                         quality_mirror_values, sync_quality_mirror, enable_simplified_chinese)


class Fake:
    def __init__(self, busy=1, app=3):
        self.data = {UI_BUSY: struct.pack('<I', busy), ACTIVE_APP: bytes([app]),
                     DISPLAY_PAGE: b'\x02', UI_MODE: b'\x03'}
        self.calls = []
    def memory(self, address, size):
        return self.data[address][:size]
    def call(self, *args):
        self.calls.append(args)
        self.data[UI_BUSY] = bytes(4)
        return dict(return_r0='0x0')


class ShootingUITests(unittest.TestCase):
    def test_simplified_chinese_uses_z5_native_language_and_checks_readback(self):
        calls, records = [], []
        def call(name, function, payload, arguments):
            calls.append((function, arguments))
            if function == 0x10456098:
                return {'return_r0': '0x1a'}
            if function == 0x10525c88:
                return {'return_r0': '0x8'}
            return {'return_r0': '0x1'}
        enable_simplified_chinese(call, records)
        self.assertEqual(calls[0], (0x10456098, [0x1400]))
        self.assertEqual(calls[1], (0x104560a4, [0x1400, 26]))
        self.assertIn((0x10525c70, [8]), calls)
        self.assertEqual(records[0]['before'], '0x1a')
        self.assertFalse(records[0]['camera_verified'])

    def test_quality_mirror_maps_native_combined_settings(self):
        self.assertEqual(quality_mirror_values(3, 1, 0), (6, 0))
        self.assertEqual(quality_mirror_values(0, 2, 0), (2, 0))
        self.assertEqual(quality_mirror_values(3, 0, 1), (5, 1))
        self.assertEqual(quality_mirror_values(1, 2, 1), (3, 1))
        self.assertIsNone(quality_mirror_values(0xffffffff, 1, 0))
        self.assertIsNone(quality_mirror_values(2, 1, 0))

    def test_quality_sync_updates_only_owned_values_and_skips_invalid(self):
        class Memory:
            values = (0, 2, 0)
            target = [0, 0]
            def memory(self, address, size):
                return (struct.pack('<III', *self.values) if size == 12
                        else struct.pack('<II', *self.target))
        remote = Memory()
        writes, records = [], []
        def call(name, function, payload, arguments):
            writes.append(tuple(arguments))
            remote.target[arguments[0] - 0x1803] = arguments[1]
            return {'return_r0': '0x1'}
        mirror = {0x1803: 0, 0x1804: 0}
        self.assertTrue(sync_quality_mirror(remote, call, mirror, {0x1803}, records))
        self.assertEqual(writes, [(0x1803, 2)])
        self.assertFalse(sync_quality_mirror(remote, call, mirror, {0x1803}, records))
        remote.values = (2, 1, 0)
        self.assertFalse(sync_quality_mirror(remote, call, mirror, {0x1803}, records))
        self.assertEqual(writes, [(0x1803, 2)])
        remote.values = (3, 1, 0)
        remote.target[0] = 7  # A native writer has taken over this setting.
        owned = {0x1803}
        self.assertFalse(sync_quality_mirror(remote, call, mirror, owned, records))
        self.assertEqual(owned, set())
        self.assertEqual(remote.target[0], 7)

    def test_i_menu_fixture_only_fills_unknown_values_and_preserves_existing(self):
        values = {key: 7 for key in I_MENU_SETTINGS}
        values[0x1803] = 0xffffffff
        calls = []
        def call(name, function, payload, arguments):
            key = arguments[0]
            calls.append((function, arguments))
            if len(arguments) == 2:
                values[key] = arguments[1]
                return {'return_r0': '0x1'}
            return {'return_r0': hex(values[key])}
        records = []
        ensure_i_menu_settings(Fake(), call, records)
        self.assertEqual(values[0x1803], 0)
        self.assertEqual(values[0x181d], 7)
        self.assertEqual(sum(len(args) == 2 for _, args in calls), 1)
        self.assertEqual([r['setting'] for r in records if r['injected']], ['0x1803'])
        self.assertTrue(all(not r['camera_verified'] for r in records))

    def test_i_menu_fixture_rejects_wrong_app_or_failed_write(self):
        with self.assertRaises(ValueError):
            ensure_i_menu_settings(Fake(app=1), lambda *a: None, [])
        def failed(name, function, payload, arguments):
            return {'return_r0': '0xffffffff' if len(arguments) == 1 else '0x0'}
        with self.assertRaises(RuntimeError):
            ensure_i_menu_settings(Fake(), failed, [])

    def test_native_setter_clears_only_a_known_pending_ui_state(self):
        device, records = Fake(), []
        ensure_ready(device, device.call, records)
        ensure_ready(device, device.call, records)
        self.assertEqual(len(device.calls), 1)
        self.assertEqual(device.calls[0][1], 0x1036815c)
        self.assertEqual(device.calls[0][3], [0])
        self.assertEqual(records[0]['before'], 1)
        self.assertEqual(records[0]['after'], 0)
        self.assertFalse(records[0]['firmware_pipeline'])

    def test_unknown_busy_state_is_rejected_and_menu_is_untouched(self):
        for value in (2, 0xffffffff):
            device = Fake(busy=value)
            with self.assertRaises(ValueError): ensure_ready(device, device.call, [])
            self.assertEqual(device.calls, [])
        device = Fake(app=1)
        ensure_ready(device, device.call, [])
        self.assertEqual(device.calls, [])
        self.assertEqual(struct.unpack('<I', device.data[UI_BUSY])[0], 1)

    def test_a_failed_native_call_is_not_reported_as_ready(self):
        device, records = Fake(), []
        with self.assertRaises(RuntimeError): ensure_ready(device, lambda *args: None, records)
        self.assertEqual(records, [])

    def test_state_snapshot_distinguishes_display_page_from_i_subpage(self):
        state = snapshot(Fake())
        self.assertEqual(state, dict(application=3, busy=1, display_page=2, ui_mode=3))


if __name__ == '__main__':
    unittest.main()
