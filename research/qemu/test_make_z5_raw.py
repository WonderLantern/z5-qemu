import unittest
from pathlib import Path

import make_z5_raw as raw
import port_source


class Z5RawTest(unittest.TestCase):
    def test_packed12_round_trip_and_size(self):
        data, preview = raw.build('ingress', 16, 8, 32, True)
        self.assertEqual(len(data), 32 * 8)
        self.assertEqual(len(preview), (1 + 8 * 3) * 4)

    def test_u16_round_trip_and_size(self):
        data, _ = raw.build('native0', 16, 8, 40, False)
        self.assertEqual(len(data), 40 * 8)

    def test_first_row_is_white_bar_rggb(self):
        row = raw.mosaic_row(raw.scene_row(16, 8, 0), 0)
        self.assertEqual(row[:2], [4095, 4095])

    def test_ingress_layout_matches_guest_registers(self):
        kind, w, h, stride, packed = raw.LAYOUTS[0]
        self.assertEqual((kind, w, h, stride, packed), ('ingress', 1508, 1006, 2272, True))
        self.assertEqual(stride * h, port_source.Z5_INGRESS_BYTES)

    def test_board_edits_apply_once_to_pinned_donor(self):
        donor = Path(port_source.ROOT / 'reference/z6-qemu/qemu/nikon-z6.c')
        if not donor.exists():
            self.skipTest('donor source not checked out')
        board = port_source.transform_board(donor.read_text(encoding='utf-8'))
        self.assertIn('!= 0x05e40000', board)
        self.assertIn('0x82b00000', board)
        self.assertIn('Z5_RAW_ENGINE_CONFIG', board)
        self.assertIn('Z5_LV_ENGINE1_EVENTS', board)
        self.assertNotIn('!= 0x05640000', board)
        self.assertIn('Z5_LV_BACKGROUND_COMPOSITE', board)
        self.assertIn('z5_lcd_overlay_coverage(r, w, h) * 2 < (size_t)w * h', board)

    def test_lv_background_is_720x480_rgb24(self):
        import make_lv_background as bg
        data = bg.color_bars()
        self.assertEqual(len(data), bg.SIZE)
        self.assertEqual(data[:3], b'\xff\xff\xff')

    def test_keep_awake_constants(self):
        import q3_display
        self.assertEqual((q3_display.SETTING_READ, q3_display.SETTING_WRITE), (0x10456098, 0x104560A4))
        self.assertEqual(q3_display.STANDBY_STATE, 0xC1819254)


if __name__ == '__main__':
    unittest.main()
