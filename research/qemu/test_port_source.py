"""Z5 机器派生规则测试；不运行或携带尼康程序。"""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import port_source

ROOT = Path(__file__).resolve().parents[2]


class PortSourceTests(unittest.TestCase):
    def test_calibration_input_is_opt_in_and_dma_limited(self):
        original = (ROOT / 'reference/z6-qemu/qemu/nikon-z6.c').read_text(encoding='utf-8')
        result = port_source.transform_board(original)
        self.assertIn('Z5_SYNTHETIC_CALIBRATION', result)
        self.assertIn('2500f5782cca0407d00dc525a2e9b565e4a94838cfe8d986a01c2f526e9fbc50', result)
        self.assertIn('s->calibration_input && r[1] >= 0x13e80000', result)
        self.assertIn('(uint64_t)r[1] + len <= 0x14000000', result)
    def test_memory_windows_merge_scatter_with_documented_runtime_range(self):
        rows = [dict(destination='0xC1800000', size=0x100),
                dict(destination='0x80800000', size=0x200000),
                dict(destination='0x04008FE0', size=0x20)]
        windows = port_source.derive_windows(rows)
        self.assertIn((0xC0000000, 0xCB00000), windows)
        self.assertIn((0x80800000, 0x200000), windows)
        self.assertNotIn((0x04008FE0, 0x20), windows)

    def test_board_retains_attribution_and_rejects_unknown_guest_accesses(self):
        original = (ROOT / 'reference/z6-qemu/qemu/nikon-z6.c').read_text(encoding='utf-8')
        result = port_source.transform_board(original)
        self.assertIn('GPL-2.0-or-later', result)
        self.assertIn('nikon-z5-profile.h', result)
        self.assertIn('0x02101000, &error_fatal', result)
        self.assertIn('Z5_MAIN_SHA256', result)
        self.assertNotIn('if (s->z5_profile && current_cpu)', result)
        self.assertIn('stopped without inventing a device response', result)
        self.assertNotIn('length != 33502842', result)

    def test_board_rejects_changed_donor_instead_of_partial_replacement(self):
        with self.assertRaisesRegex(ValueError, 'donor'):
            port_source.transform_board('not the pinned donor')

    def test_z5_profile_declares_assumptions_and_exact_fingerprint(self):
        result = port_source.make_profile([(0xC1800000, 0x6F00000)])
        self.assertIn('.main_bytes = 34603578', result)
        self.assertIn('1d9742a951ea8a8e', result)
        self.assertIn('not identified Z5 silicon', result)
        self.assertIn('{0xc1800000, 0x6f00000}', result)


if __name__ == '__main__':
    unittest.main()
