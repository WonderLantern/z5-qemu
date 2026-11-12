"""Compare i-panel images without distributing firmware-rendered assets."""
import unittest
from i_menu_icons import compare_panel


class IMenuIconTest(unittest.TestCase):
    def fixture(self):
        base = bytearray(720 * 480 * 3)
        candidate = bytearray(base)
        for row in range(2):
            for col in range(6):
                if (row, col) == (1, 3):
                    continue
                for y in range(290 + row * 72, 300 + row * 72):
                    for x in range(8 + col * 120, 18 + col * 120):
                        pos = (y * 720 + x) * 3
                        candidate[pos:pos+3] = b'\xff\xff\xff'
        # The twelfth cell already has the slot markers in both images.
        for y in range(362, 367):
            for x in range(368, 373):
                pos = (y * 720 + x) * 3
                base[pos:pos+3] = candidate[pos:pos+3] = b'\xff\xff\xff'
        return base, candidate

    def test_requires_each_changed_cell_and_preexisting_slot_markers(self):
        base, candidate = self.fixture()
        self.assertTrue(compare_panel(base, candidate)['passed'])
        for y in range(290, 300):
            for x in range(8, 18):
                pos = (y * 720 + x) * 3
                candidate[pos:pos+3] = b'\0\0\0'
        self.assertFalse(compare_panel(base, candidate)['passed'])

    def test_rejects_a_different_screen_or_missing_slot_markers(self):
        base, candidate = self.fixture()
        candidate[0] = 1
        self.assertFalse(compare_panel(base, candidate)['passed'])
        base, candidate = self.fixture()
        for y in range(362, 367):
            for x in range(368, 373):
                pos = (y * 720 + x) * 3
                base[pos:pos+3] = candidate[pos:pos+3] = b'\0\0\0'
        self.assertFalse(compare_panel(base, candidate)['passed'])
