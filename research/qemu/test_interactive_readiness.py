import unittest

from interactive_readiness import InteractiveReadiness


class InteractiveReadinessTest(unittest.TestCase):
    def test_waits_for_time_and_matching_visual_and_menu_state(self):
        barrier = InteractiveReadiness(100, minimum_ms=1000, maximum_ms=5000)
        app = {'application': 1, 'display_page': 0, 'ui_mode': 0}
        page = {'status': 'ok', 'page': {'page_id': 18, 'row': 0}}
        self.assertFalse(barrier.observe(200, 'a', True, app, page))
        self.assertFalse(barrier.observe(1100, 'b', True, app, page))
        self.assertTrue(barrier.observe(1200, 'b', True, app, page))

    def test_invalid_menu_blank_or_timeout_never_release(self):
        app = {'application': 1, 'display_page': 0, 'ui_mode': 0}
        barrier = InteractiveReadiness(0, minimum_ms=0, maximum_ms=100)
        self.assertFalse(barrier.observe(1, 'a', False, app, None))
        self.assertFalse(barrier.observe(2, 'a', True, app, {'status': 'invalid'}))
        with self.assertRaises(TimeoutError):
            barrier.observe(101, 'a', True, app, {'status': 'invalid'})

    def test_page_change_resets_stability(self):
        app = {'application': 1, 'display_page': 0, 'ui_mode': 0}
        page = lambda row: {'status': 'ok', 'page': {'page_id': 1, 'row': row}}
        barrier = InteractiveReadiness(0, minimum_ms=0, maximum_ms=100)
        self.assertFalse(barrier.observe(1, 'a', True, app, page(0)))
        self.assertFalse(barrier.observe(2, 'a', True, app, page(1)))
        self.assertTrue(barrier.observe(3, 'a', True, app, page(1)))
